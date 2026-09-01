function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return match ? match[1] : null;
}

function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function handleContact(request, env) {
  try {
    const data = await request.json();
    const name = (data.name || "").trim();
    const email = (data.email || "").trim();
    const message = (data.message || "").trim();
    if (!name || !email) {
      return new Response(JSON.stringify({ ok: false, error: "Name and email are required." }), { status: 400, headers: { "Content-Type": "application/json" } });
    }
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
      return new Response(JSON.stringify({ ok: false, error: "Please enter a valid email." }), { status: 400, headers: { "Content-Type": "application/json" } });
    }
    await env.DB.prepare("INSERT INTO leads (name, email, message) VALUES (?, ?, ?)").bind(name, email, message).run();
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: "Something went wrong. Please try again." }), { status: 500, headers: { "Content-Type": "application/json" } });
  }
}

async function handleAdminLogin(request, env) {
  try {
    const data = await request.json();
    const password = data.password || "";
    if (!env.ADMIN_PASSWORD) {
      return new Response(JSON.stringify({ ok: false, error: "Admin password not configured yet." }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
    if (password !== env.ADMIN_PASSWORD) {
      return new Response(JSON.stringify({ ok: false, error: "Incorrect password." }), { status: 401, headers: { "Content-Type": "application/json" } });
    }
    const token = generateToken();
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 12);
    await env.DB.prepare("INSERT INTO admin_sessions (token, expires_at) VALUES (?, ?)").bind(token, expires.toISOString()).run();
    const cookie = `admin_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=${expires.toUTCString()}`;
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": cookie } });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: "Login failed. Please try again." }), { status: 500, headers: { "Content-Type": "application/json" } });
  }
}

async function handleAdminLeads(request, env) {
  const token = getCookie(request, "admin_session");
  if (!token) {
    return new Response(JSON.stringify({ ok: false, error: "Not authenticated." }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  const row = await env.DB.prepare("SELECT expires_at FROM admin_sessions WHERE token = ?").bind(token).first();
  if (!row || new Date(row.expires_at) < new Date()) {
    return new Response(JSON.stringify({ ok: false, error: "Session expired." }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  const { results } = await env.DB.prepare("SELECT id, name, email, message, created_at FROM leads ORDER BY created_at DESC").all();
  return new Response(JSON.stringify({ ok: true, leads: results }), { status: 200, headers: { "Content-Type": "application/json" } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/contact" && request.method === "POST") return handleContact(request, env);
    if (url.pathname === "/api/admin-login" && request.method === "POST") return handleAdminLogin(request, env);
    if (url.pathname === "/api/admin-leads" && request.method === "GET") return handleAdminLeads(request, env);
    return env.ASSETS.fetch(request);
  }
};
