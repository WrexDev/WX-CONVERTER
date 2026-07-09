/**
 * WX Converter â€” Worker gabungan
 *   - menyajikan situs (index.html) lewat Static Assets
 *   - menangani OAuth 2.0 Roblox + upload audio
 *
 * Karena situs dan API satu origin, tidak perlu CORS dan cookie jadi first-party.
 *
 * Yang perlu diatur di dashboard Cloudflare:
 *   Secrets : ROBLOX_CLIENT_ID, ROBLOX_CLIENT_SECRET
 *   KV      : binding bernama SESSIONS
 *   Assets  : binding bernama ASSETS (sudah otomatis kalau deploy dari GitHub)
 */

const OAUTH = {
  authorize: "https://apis.roblox.com/oauth/v1/authorize",
  token: "https://apis.roblox.com/oauth/v1/token",
  revoke: "https://apis.roblox.com/oauth/v1/token/revoke",
  userinfo: "https://apis.roblox.com/oauth/v1/userinfo",
};
const ASSETS_URL = "https://apis.roblox.com/assets/v1/assets";
const OPERATIONS_URL = "https://apis.roblox.com/assets/v1/operations/";

const SCOPES = "openid profile asset:read asset:write";
const SESSION_TTL = 60 * 60 * 24 * 30; // 30 hari
const MAX_BYTES = 20 * 1024 * 1024;    // batas Roblox: 20 MB

/* ---------------- utils ---------------- */

function b64url(buf) {
  let s = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomId(len = 32) {
  return b64url(crypto.getRandomValues(new Uint8Array(len)));
}
async function sha256(text) {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
function readCookie(req, name) {
  const raw = req.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}
function sessionCookie(value, maxAge) {
  return `wx_sid=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
/** Redirect URI dihitung dari alamat Worker sendiri, jadi tidak bisa salah ketik. */
function redirectUri(req) {
  return new URL(req.url).origin + "/auth/callback";
}

/* ---------------- OAuth ---------------- */

async function handleLogin(req, env) {
  const state = randomId(24);
  const verifier = randomId(48);
  const challenge = b64url(await sha256(verifier));

  await env.SESSIONS.put(`state:${state}`, JSON.stringify({ verifier }), { expirationTtl: 600 });

  const url = new URL(OAUTH.authorize);
  url.searchParams.set("client_id", env.ROBLOX_CLIENT_ID);
  url.searchParams.set("redirect_uri", redirectUri(req));
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");

  return Response.redirect(url.toString(), 302);
}

function popupHtml(payload) {
  const data = JSON.stringify(payload);
  return new Response(
    `<!doctype html><meta charset="utf-8"><title>Roblox</title>
<body style="background:#04090b;color:#eafcfb;font:14px system-ui;display:grid;place-items:center;height:100vh;margin:0">
<p>${payload.ok ? "Connected. You can close this window." : "Failed: " + String(payload.error || "unknown")}</p>
<script>
  try { if (window.opener) window.opener.postMessage(${data}, window.location.origin); } catch (e) {}
  setTimeout(function(){ try { window.close(); } catch(e){} }, 600);
</script>`,
    { headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}

async function exchangeToken(env, body) {
  const res = await fetch(OAUTH.token, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.ROBLOX_CLIENT_ID,
      client_secret: env.ROBLOX_CLIENT_SECRET,
      ...body,
    }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`token ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text);
}

async function handleCallback(req, env) {
  const url = new URL(req.url);
  const err = url.searchParams.get("error");
  if (err) return popupHtml({ ok: false, error: err, source: "wx-roblox" });

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return popupHtml({ ok: false, error: "missing code/state", source: "wx-roblox" });

  const rec = await env.SESSIONS.get(`state:${state}`, "json");
  if (!rec) return popupHtml({ ok: false, error: "state expired", source: "wx-roblox" });
  await env.SESSIONS.delete(`state:${state}`);

  try {
    const tok = await exchangeToken(env, {
      grant_type: "authorization_code",
      code,
      code_verifier: rec.verifier,
      redirect_uri: redirectUri(req),
    });

    const uiRes = await fetch(OAUTH.userinfo, { headers: { Authorization: `Bearer ${tok.access_token}` } });
    if (!uiRes.ok) throw new Error(`userinfo ${uiRes.status}`);
    const ui = await uiRes.json();

    const sid = randomId(32);
    await env.SESSIONS.put(
      `sess:${sid}`,
      JSON.stringify({
        userId: ui.sub,
        name: ui.preferred_username || ui.name || ("User " + ui.sub),
        access: tok.access_token,
        refresh: tok.refresh_token || null,
        exp: Date.now() + (tok.expires_in || 900) * 1000,
      }),
      { expirationTtl: SESSION_TTL }
    );

    const res = popupHtml({ ok: true, userId: ui.sub, source: "wx-roblox" });
    const out = new Response(res.body, res);
    out.headers.append("Set-Cookie", sessionCookie(sid, SESSION_TTL));
    return out;
  } catch (e) {
    return popupHtml({ ok: false, error: String(e.message || e), source: "wx-roblox" });
  }
}

async function getSession(req, env) {
  const sid = readCookie(req, "wx_sid");
  if (!sid) return null;
  const sess = await env.SESSIONS.get(`sess:${sid}`, "json");
  return sess ? { sid, ...sess } : null;
}

/** Access token Roblox umurnya ~15 menit. Refresh kalau mau habis. */
async function freshAccess(env, sess) {
  if (Date.now() < sess.exp - 60000) return sess.access;
  if (!sess.refresh) throw new Error("session expired, please reconnect");

  const tok = await exchangeToken(env, { grant_type: "refresh_token", refresh_token: sess.refresh });

  sess.access = tok.access_token;
  if (tok.refresh_token) sess.refresh = tok.refresh_token;
  sess.exp = Date.now() + (tok.expires_in || 900) * 1000;

  await env.SESSIONS.put(`sess:${sess.sid}`, JSON.stringify({
    userId: sess.userId, name: sess.name,
    access: sess.access, refresh: sess.refresh, exp: sess.exp,
  }), { expirationTtl: SESSION_TTL });

  return sess.access;
}

async function handleMe(req, env) {
  const sess = await getSession(req, env);
  if (!sess) return json({ connected: false });
  return json({ connected: true, userId: sess.userId, name: sess.name });
}

async function handleLogout(req, env) {
  const sess = await getSession(req, env);
  if (sess) {
    if (sess.refresh) {
      try {
        await fetch(OAUTH.revoke, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            token: sess.refresh,
            client_id: env.ROBLOX_CLIENT_ID,
            client_secret: env.ROBLOX_CLIENT_SECRET,
          }),
        });
      } catch (e) { /* best effort */ }
    }
    await env.SESSIONS.delete(`sess:${sess.sid}`);
  }
  const res = json({ connected: false });
  res.headers.append("Set-Cookie", sessionCookie("", 0));
  return res;
}

/* ---------------- upload ---------------- */

function cleanName(raw) {
  let n = String(raw || "").replace(/\.[a-z0-9]+$/i, "").trim();
  n = n.replace(/[^\p{L}\p{N} _.'\-]/gu, " ").replace(/\s+/g, " ").trim();
  if (n.length < 3) n = "WX Audio " + Date.now().toString().slice(-6);
  return n.slice(0, 50);
}

async function handleUpload(req, env) {
  const sess = await getSession(req, env);
  if (!sess) return json({ error: "not_connected" }, 401);

  let form;
  try { form = await req.formData(); }
  catch { return json({ error: "bad_form" }, 400); }

  const file = form.get("file");
  if (!file || typeof file === "string") return json({ error: "no_file" }, 400);
  if (file.size > MAX_BYTES) return json({ error: "too_large", detail: "Max 20 MB." }, 400);

  const displayName = cleanName(form.get("name") || file.name);

  let access;
  try { access = await freshAccess(env, sess); }
  catch (e) { return json({ error: "reauth_required", detail: String(e.message || e) }, 401); }

  const request = {
    assetType: "Audio",
    displayName,
    description: "Uploaded via WX Converter",
    creationContext: { creator: { userId: String(sess.userId) } },
  };

  const fd = new FormData();
  fd.append("request", JSON.stringify(request));
  fd.append("fileContent", new Blob([await file.arrayBuffer()], { type: "audio/ogg" }), "audio.ogg");

  const create = await fetch(ASSETS_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${access}` },
    body: fd,
  });
  const createText = await create.text();
  if (!create.ok) {
    return json({ error: "roblox_rejected", status: create.status, detail: createText.slice(0, 500) }, 400);
  }

  let op;
  try { op = JSON.parse(createText); }
  catch { return json({ error: "bad_response", detail: createText.slice(0, 300) }, 502); }

  if (op.done && op.response && op.response.assetId) {
    return json({ assetId: String(op.response.assetId), status: "pending_moderation" });
  }

  const opId = op.operationId || (op.path ? String(op.path).split("/").pop() : null);
  if (!opId) return json({ error: "no_operation", detail: createText.slice(0, 300) }, 502);

  for (let i = 0; i < 16; i++) {
    await new Promise((r) => setTimeout(r, i === 0 ? 800 : 1500));
    const pr = await fetch(OPERATIONS_URL + opId, { headers: { Authorization: `Bearer ${access}` } });
    const pt = await pr.text();
    if (!pr.ok) continue;
    let po;
    try { po = JSON.parse(pt); } catch { continue; }
    if (po.done) {
      if (po.error) return json({ error: "operation_failed", detail: JSON.stringify(po.error).slice(0, 400) }, 400);
      const assetId = po.response && po.response.assetId;
      if (assetId) return json({ assetId: String(assetId), status: "pending_moderation" });
      return json({ error: "no_asset_id", detail: pt.slice(0, 300) }, 502);
    }
  }
  return json({ error: "timeout", operationId: opId }, 504);
}

/* ---------------- router ---------------- */

export default {
  async fetch(req, env) {
    const { pathname } = new URL(req.url);

    try {
      if (pathname === "/auth/login") return handleLogin(req, env);
      if (pathname === "/auth/callback") return handleCallback(req, env);
      if (pathname === "/auth/me") return handleMe(req, env);
      if (pathname === "/auth/logout" && req.method === "POST") return handleLogout(req, env);
      if (pathname === "/api/upload" && req.method === "POST") return handleUpload(req, env);
    } catch (e) {
      return json({ error: "server_error", detail: String(e.message || e) }, 500);
    }

    // Selain rute di atas: serahkan ke file statis (index.html dll)
    if (env.ASSETS) return env.ASSETS.fetch(req);
    return new Response("ASSETS binding tidak ditemukan.", { status: 500 });
  },
};
