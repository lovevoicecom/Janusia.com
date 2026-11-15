/**
 * JANUSIA SHIELD BACKEND  (Cloudflare Worker + KV)
 * ------------------------------------------------
 * Ye backend HAR visitor ka asli IP dekhta hai, isliye Chrome/Brave/Incognito
 * badalne se limit reset nahi hoti. Saara data yahin (KV) mein rehta hai,
 * isliye Owner tool mein sab users ek saath dikhte hain.
 *
 * SETUP: README-SETUP.txt dekho.
 * Bindings / secrets:
 *   KV namespace  -> JANUSIA          (Variables > KV Namespace Bindings)
 *   Secret        -> ADMIN_PASSWORD   (Owner password; HTML wale password jaisa hi rakho)
 *   Var (optional)-> ALLOWED_ORIGIN   (jaise https://yoursite.com ; khaali = sab)
 *   Var (optional)-> FREE_CHARS       (default 250)
 */

const DAY = 86400000;
const enc = new TextEncoder();

const cors = (env, req) => ({
  "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
  "Access-Control-Allow-Headers": "content-type,x-admin-pass",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin",
});
const json = (env, req, data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...cors(env, req) } });

const rid = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
const clip = (s, n) => String(s == null ? "" : s).slice(0, n);
const safeId = s => clip(s, 64).replace(/[^A-Za-z0-9_.:\-]/g, "");

async function kget(env, k, def) {
  const v = await env.JANUSIA.get(k, "json");
  return v == null ? def : v;
}
const kput = (env, k, v, ttlSec) => env.JANUSIA.put(k, JSON.stringify(v), ttlSec ? { expirationTtl: Math.max(60, ttlSec) } : undefined);

async function getCfg(env) {
  const c = await kget(env, "cfg", {});
  return {
    freeChars: c.freeChars || +env.FREE_CHARS || 250,
    budget: c.budget || 50000,
    pause: c.pause && c.pause.until > Date.now() ? c.pause : { until: 0, msg: "" },
    blocked: c.blocked || [],
    minGapSec: c.minGapSec || 8,
    maxPerMin: c.maxPerMin || 3,
    maxPerDay: c.maxPerDay || 18,
  };
}
const putCfg = (env, c) => kput(env, "cfg", c);

async function addEvent(env, e) {
  const k = "ev:" + String(9999999999999 - Date.now()).padStart(13, "0") + ":" + rid();
  await kput(env, k, { t: Date.now(), ...e }, 7 * 86400);
}
async function addAlert(env, type, msg, ip) {
  await addEvent(env, { kind: "alert", type, msg, ip });
}

/* IPv6 ko /64 par jod do (ek ghar/phone ke saare IPv6 ek user maane jayein) */
function normIp(ip) {
  if (!ip.includes(":")) return ip;
  const [h, t] = ip.split("::");
  const a = h ? h.split(":") : [], b = ip.includes("::") && t ? t.split(":") : [];
  const fill = ip.includes("::") ? Math.max(0, 8 - a.length - b.length) : 0;
  return [...a, ...Array(fill).fill("0"), ...b].slice(0, 4).map(x => x.replace(/^0+(?=.)/, "")).join(":") + "::/64";
}

function whoAmI(req, body) {
  const cf = req.cf || {};
  const ip = normIp(req.headers.get("CF-Connecting-IP") || "0.0.0.0");
  const org = cf.asOrganization || "";
  const reasons = [];
  if (/hosting|cloud|datacenter|data center|digitalocean|amazon|google cloud|ovh|linode|vultr|hetzner|vpn|proxy|tor |m247|choopa|leaseweb/i.test(org)) reasons.push("Datacenter/VPN network");
  const tz = clip(body && body.tz, 60);
  if (tz && cf.timezone && tz !== cf.timezone) reasons.push("Timezone mismatch");
  if (body && body.webdriver) reasons.push("Automated browser");
  return {
    ip, country: cf.country || "", city: cf.city || "", asn: org, tz: cf.timezone || "",
    vpnRisk: reasons.length >= 2 ? "High" : reasons.length === 1 ? "Medium" : "Low", reasons,
  };
}

const newUser = (w, now) => ({
  ip: w.ip, country: w.country, city: w.city, asn: w.asn, vpnRisk: w.vpnRisk,
  firstSeen: now, lastSeen: now, devs: [], cids: [], browsers: [], visits: 0,
  chars: 0, credits: 0, gens: 0, freeChars: 0, strikes: 0, tempUntil: 0, hits: [], custom: false,
});
const addUniq = (arr, v, max = 12) => { if (v && !arr.includes(v)) { arr.push(v); if (arr.length > max) arr.shift(); } };

function browserName(ua) {
  ua = ua || "";
  if (/Brave/i.test(ua)) return "Brave";
  if (/Edg\//.test(ua)) return "Edge";
  if (/OPR\//.test(ua)) return "Opera";
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/Chrome\//.test(ua)) return /Mobile/.test(ua) ? "Chrome Mobile" : "Chrome";
  if (/Safari\//.test(ua)) return "Safari";
  return "Other";
}

async function touchUser(env, req, body, now, countVisit) {
  const w = whoAmI(req, body);
  const ua = req.headers.get("User-Agent") || "";
  const u = (await kget(env, "u:" + w.ip, null)) || newUser(w, now);
  Object.assign(u, { country: w.country, city: w.city, asn: w.asn, vpnRisk: w.vpnRisk, lastSeen: now });
  addUniq(u.devs, safeId(body.dev)); addUniq(u.cids, safeId(body.cid));
  addUniq(u.browsers, browserName(ua) + (body.brave ? " (Brave)" : ""), 8);
  u.device = clip(body.device, 60) || u.device;
  if (countVisit) u.visits = (u.visits || 0) + 1;
  return { u, w };
}

function isBlocked(cfg, w, body) {
  const set = new Set(cfg.blocked);
  return set.has(w.ip) || (body.cid && set.has(safeId(body.cid)));
}

/* quota IP + browser-ID dono par chalta hai: browser badalne se IP wahi rehta hai,
   VPN badalne se browser-ID wahi rehta hai -> dono me se koi ek bhi limit paar kare to block.
   (Device fingerprint quota me use nahi hota: ek jaise phones ke alag log galti se ek na ho jayein) */
async function usageOf(env, w, body) {
  const keys = ["ip:" + w.ip];
  if (body.cid) keys.push("cid:" + safeId(body.cid));
  const vals = await Promise.all(keys.map(k => kget(env, "use:" + k, { chars: 0 })));
  return { keys, used: Math.max(...vals.map(v => v.chars || 0)) };
}
async function addUsage(env, keys, delta) {
  await Promise.all(keys.map(async k => {
    const v = await kget(env, "use:" + k, { chars: 0 });
    v.chars = Math.max(0, (v.chars || 0) + delta);
    await kput(env, "use:" + k, v);
  }));
}

async function getGlobal(env) { return kget(env, "g", { chars: 0, credits: 0, gens: 0, visits: 0 }); }

async function statusFor(env, cfg, w, body, u) {
  const { used } = await usageOf(env, w, body);
  const blocked = isBlocked(cfg, w, body);
  return {
    ip: w.ip, country: w.country, city: w.city, vpnRisk: w.vpnRisk,
    blocked, tempUntil: u && u.tempUntil > Date.now() ? u.tempUntil : 0,
    free: { limit: cfg.freeChars, used, left: Math.max(0, cfg.freeChars - used) },
    pause: cfg.pause.until > Date.now() ? cfg.pause : null,
  };
}

/* ------------------------------ PUBLIC ENDPOINTS ------------------------------ */
async function hello(env, req, body) {
  const now = Date.now();
  const cfg = await getCfg(env);
  const { u, w } = await touchUser(env, req, body, now, true);
  const g = await getGlobal(env); g.visits = (g.visits || 0) + 1; await kput(env, "g", g);
  await kput(env, "u:" + w.ip, u);
  if (u.cids.length > 3) await addAlert(env, "Multi-Account", `${w.ip} se ${u.cids.length} alag browser/ID mile (quota bypass ki koshish ho sakti hai)`, w.ip);
  await addEvent(env, { kind: "visit", ip: w.ip, country: w.country, browser: u.browsers[u.browsers.length - 1] });
  return statusFor(env, cfg, w, body, u);
}

async function ping(env, req, body) {
  const now = Date.now();
  const cfg = await getCfg(env);
  const { u, w } = await touchUser(env, req, body, now, false);
  await kput(env, "u:" + w.ip, u);
  const id = safeId(body.cid) || w.ip;
  await kput(env, "on:" + w.ip + ":" + id, { ip: w.ip, ts: now, tab: clip(body.tab, 20), browser: u.browsers[u.browsers.length - 1], country: w.country, city: w.city, custom: !!body.custom }, 60);
  return statusFor(env, cfg, w, body, u);
}

async function gate(env, req, body) {
  const now = Date.now();
  const cfg = await getCfg(env);
  const chars = Math.max(0, Math.min(25000, Math.floor(+body.chars || 0)));
  const custom = !!body.custom;
  const { u, w } = await touchUser(env, req, body, now, false);
  const fail = async (code, message, extra = {}) => {
    await kput(env, "u:" + w.ip, u);
    return { ok: false, code, message, ...(await statusFor(env, cfg, w, body, u)), ...extra };
  };

  if (!chars) return fail("EMPTY", "Text khaali hai.");
  if (isBlocked(cfg, w, body)) { await addEvent(env, { kind: "denied", why: "blocked", ip: w.ip }); return fail("BLOCKED", "Owner ne aapka IP/Device block kar diya hai."); }
  if (cfg.pause.until > now) return fail("PAUSED", cfg.pause.msg || "API abhi temporary band hai.");
  if (body.webdriver) { await addAlert(env, "Bot", "Automated browser ne generate try kiya", w.ip); return fail("BOT", "Automated bot activity detect hui."); }

  if (!custom) {
    if (u.tempUntil > now) return fail("TEMP", `Bar-bar rule todne par temporary block laga hai (${Math.ceil((u.tempUntil - now) / 1000)} sec).`);
    u.hits = (u.hits || []).filter(t => now - t < DAY);
    const last = u.hits[u.hits.length - 1] || 0;
    const gap = (u.vpnRisk === "High" ? 2 : 1) * cfg.minGapSec * 1000;
    const { keys, used } = await usageOf(env, w, body);

    if (used >= cfg.freeChars || used + chars > cfg.freeChars) {
      await addAlert(env, "Free Limit", `${w.ip} ne free ${cfg.freeChars} chars limit ke baad try kiya (used ${used}, maang ${chars})`, w.ip);
      return fail("QUOTA", used >= cfg.freeChars
        ? `Aapki free ${cfg.freeChars} characters ki limit poori ho chuki hai. Aage use karne ke liye Connect tab mein apni API key file upload ya connect karein.`
        : `Free limit mein sirf ${cfg.freeChars - used} characters bache hain, aapne ${chars} maange. Chhota text likhein ya API key connect karein.`);
    }
    if (now - last < gap) {
      u.strikes = (u.strikes || 0) + 1;
      if (u.strikes >= 3) { u.tempUntil = now + 15 * 60000; u.strikes = 0; await addAlert(env, "Auto Temp Block", "Repeated rapid requests -> 15 min block", w.ip); }
      return fail("RATE", `Thoda ruko, ${Math.ceil((gap - (now - last)) / 1000)} sec baad dobara try karein.`);
    }
    if (u.hits.filter(t => now - t < 60000).length >= cfg.maxPerMin || u.hits.length >= cfg.maxPerDay) {
      u.tempUntil = now + 15 * 60000;
      await addAlert(env, "Rate Limit", "Per-minute/day limit cross -> 15 min block", w.ip);
      return fail("RATE", "Rate limit poori ho gayi. 15 minute baad try karein ya apni API key connect karein.");
    }
    u.hits.push(now);
    await addUsage(env, keys, chars);
    u.freeChars = (u.freeChars || 0) + chars;
    var reservedKeys = keys;
  }

  const token = rid() + rid();
  await kput(env, "res:" + token, { ip: w.ip, keys: reservedKeys || [], chars, custom }, 900);
  await kput(env, "u:" + w.ip, u);
  const st = await statusFor(env, cfg, w, body, u);
  return { ok: true, token, ...st };
}

/* gen khatam: ok=true -> record, ok=false -> chars wapas (refund, sirf ek baar) */
async function done(env, req, body) {
  const now = Date.now();
  const tk = "res:" + clip(body.token, 40);
  const r = await kget(env, tk, null);
  if (!r) return { ok: false, code: "NO_TOKEN" };
  await env.JANUSIA.delete(tk);
  const u = (await kget(env, "u:" + r.ip, null));
  if (!body.ok) {
    if (r.keys.length) await addUsage(env, r.keys, -r.chars);
    if (u) { u.freeChars = Math.max(0, (u.freeChars || 0) - (r.custom ? 0 : r.chars)); u.hits = (u.hits || []).slice(0, -1); await kput(env, "u:" + r.ip, u); }
    return { ok: true, refunded: true };
  }
  const credits = Math.max(1, Math.ceil(r.chars / 10));
  if (u) {
    u.chars = (u.chars || 0) + r.chars; u.credits = (u.credits || 0) + credits; u.gens = (u.gens || 0) + 1;
    u.custom = u.custom || r.custom; u.lastGen = now; u.lastSeen = now;
    await kput(env, "u:" + r.ip, u);
  }
  const g = await getGlobal(env); g.chars += r.chars; g.credits += credits; g.gens += 1; await kput(env, "g", g);
  await addEvent(env, { kind: "gen", ip: r.ip, chars: r.chars, credits, voice: clip(body.voice, 40), key: r.custom ? "own-key" : "free", country: u && u.country });
  return { ok: true };
}

/* ------------------------------ ADMIN ENDPOINTS ------------------------------ */
async function authAdmin(env, req) {
  const ip = req.headers.get("CF-Connecting-IP") || "x";
  const fk = "adminfail:" + ip;
  const f = await kget(env, fk, { n: 0, until: 0 });
  if (f.until > Date.now()) return "LOCKED";
  const pass = req.headers.get("x-admin-pass") || "";
  const ok = env.ADMIN_PASSWORD && pass.length === env.ADMIN_PASSWORD.length && pass === env.ADMIN_PASSWORD;
  if (!ok) {
    f.n++; if (f.n >= 6) { f.until = Date.now() + 10 * 60000; f.n = 0; }
    await kput(env, fk, f, 900);
    return false;
  }
  return true;
}

async function listAll(env, prefix, limit = 500) {
  const out = []; let cursor;
  do {
    const r = await env.JANUSIA.list({ prefix, cursor, limit: 1000 });
    out.push(...r.keys.map(k => k.name)); cursor = r.list_complete ? null : r.cursor;
  } while (cursor && out.length < limit);
  return out.slice(0, limit);
}

async function overview(env) {
  const now = Date.now();
  const cfg = await getCfg(env);
  const [uk, ok, ek, g] = await Promise.all([listAll(env, "u:", 400), listAll(env, "on:", 300), env.JANUSIA.list({ prefix: "ev:", limit: 120 }), getGlobal(env)]);
  const users = (await Promise.all(uk.map(k => kget(env, k, null)))).filter(Boolean);
  const online = (await Promise.all(ok.map(k => kget(env, k, null)))).filter(o => o && now - o.ts < 75000);
  const events = (await Promise.all(ek.keys.map(k => kget(env, k.name, null)))).filter(Boolean);
  const set = new Set(cfg.blocked);
  const rows = users.map(u => ({
    ...u, hits: undefined,
    blocked: set.has(u.ip) || (u.devs || []).some(d => set.has(d)) || (u.cids || []).some(c => set.has(c)),
    tempBlocked: u.tempUntil > now,
    onlineNow: online.some(o => o.ip === u.ip),
  })).sort((a, b) => b.lastSeen - a.lastSeen);
  return {
    now, cfg: { freeChars: cfg.freeChars, budget: cfg.budget, pause: cfg.pause, blocked: cfg.blocked, minGapSec: cfg.minGapSec, maxPerMin: cfg.maxPerMin, maxPerDay: cfg.maxPerDay },
    global: g, online, users: rows, events,
    totals: { users: rows.length, blocked: rows.filter(r => r.blocked).length, onlineIps: new Set(online.map(o => o.ip)).size, onlineSessions: online.length },
  };
}

async function admin(env, req, path, body) {
  if (path === "/api/admin/overview") return overview(env);

  if (path === "/api/admin/block") {
    const t = clip(body.target, 80).trim(); if (!t) return { ok: false };
    const cfg = await getCfg(env);
    if (body.block) {
      if (!cfg.blocked.includes(t)) cfg.blocked.push(t);
      // IP block karte hi us IP ke saare device/browser IDs bhi block
      const u = await kget(env, "u:" + t, null);
      if (u) for (const id of (u.cids || [])) if (!cfg.blocked.includes(id)) cfg.blocked.push(id);
      await addAlert(env, "Admin Block", "Owner ne block kiya: " + t, t);
    } else {
      const u = await kget(env, "u:" + t, null);
      const drop = new Set([t, ...(u ? (u.cids || []) : [])]);
      cfg.blocked = cfg.blocked.filter(x => !drop.has(x));
      if (u) { u.tempUntil = 0; u.strikes = 0; await kput(env, "u:" + t, u); }
      await addAlert(env, "Admin Unblock", "Owner ne unblock kiya: " + t, t);
    }
    await putCfg(env, cfg);
    return { ok: true, blocked: cfg.blocked };
  }

  if (path === "/api/admin/reset-user") {
    const ip = clip(body.ip, 64);
    const u = await kget(env, "u:" + ip, null); if (!u) return { ok: false };
    const keys = ["ip:" + ip, ...(u.cids || []).map(c => "cid:" + c)];
    await Promise.all(keys.map(k => kput(env, "use:" + k, { chars: 0 })));
    u.freeChars = 0; u.hits = []; u.strikes = 0; u.tempUntil = 0; await kput(env, "u:" + ip, u);
    await addAlert(env, "Quota Reset", "Owner ne free quota reset kiya: " + ip, ip);
    return { ok: true };
  }

  if (path === "/api/admin/config") {
    const cfg = await getCfg(env);
    if (body.freeChars != null) cfg.freeChars = Math.max(10, Math.min(5000, +body.freeChars | 0));
    if (body.budget != null) cfg.budget = Math.max(1000, +body.budget | 0);
    if (body.minGapSec != null) cfg.minGapSec = Math.max(0, Math.min(120, +body.minGapSec | 0));
    if (body.maxPerMin != null) cfg.maxPerMin = Math.max(1, Math.min(60, +body.maxPerMin | 0));
    if (body.maxPerDay != null) cfg.maxPerDay = Math.max(1, Math.min(500, +body.maxPerDay | 0));
    if (body.pause) {
      const ms = (Math.max(0, +body.pause.days || 0) * 86400000) + (Math.max(0, +body.pause.hours || 0) * 3600000);
      cfg.pause = ms > 0 ? { until: Date.now() + ms, msg: clip(body.pause.msg, 160) || "Studio maintenance ke liye API temporary band hai." } : { until: 0, msg: "" };
    }
    await putCfg(env, cfg);
    return { ok: true };
  }

  if (path === "/api/admin/reset-usage") {
    await kput(env, "g", { chars: 0, credits: 0, gens: 0, visits: 0 });
    return { ok: true };
  }

  if (path === "/api/admin/wipe") {
    const keys = [...await listAll(env, "u:", 1000), ...await listAll(env, "use:", 3000), ...await listAll(env, "ev:", 1000), ...await listAll(env, "on:", 500)];
    await Promise.all(keys.map(k => env.JANUSIA.delete(k)));
    await kput(env, "g", { chars: 0, credits: 0, gens: 0, visits: 0 });
    return { ok: true, deleted: keys.length };
  }
  return null;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(env, req) });
    if (!env.JANUSIA) return json(env, req, { ok: false, error: "KV binding JANUSIA missing" }, 500);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    if (path === "/") return json(env, req, { ok: true, service: "janusia-shield", time: Date.now() });

    let body = {};
    if (req.method === "POST") { try { body = await req.json(); } catch (_) {} }
    try {
      if (path === "/api/hello") return json(env, req, await hello(env, req, body));
      if (path === "/api/ping") return json(env, req, await ping(env, req, body));
      if (path === "/api/gate") return json(env, req, await gate(env, req, body));
      if (path === "/api/done") return json(env, req, await done(env, req, body));
      if (path.startsWith("/api/admin/")) {
        const a = await authAdmin(env, req);
        if (a === "LOCKED") return json(env, req, { ok: false, error: "Bahut galat try. 10 min ruko." }, 429);
        if (!a) return json(env, req, { ok: false, error: "Admin password galat hai (Worker ke ADMIN_PASSWORD se match nahi hua)." }, 401);
        const r = await admin(env, req, path, body);
        return r ? json(env, req, r) : json(env, req, { ok: false, error: "not found" }, 404);
      }
    } catch (e) {
      return json(env, req, { ok: false, error: "server error: " + (e && e.message) }, 500);
    }
    return json(env, req, { ok: false, error: "not found" }, 404);
  },
};
