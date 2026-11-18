const { URL } = require("node:url");
const dns = require("node:dns/promises");
const net = require("node:net");

function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const p = address.split(".").map(Number);
    return p[0] === 0 || p[0] === 10 || p[0] === 127 || p[0] >= 224 ||
      (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }
  if (family === 6) {
    const a = address.toLowerCase();
    return a === "::1" || a === "::" || a.startsWith("fc") || a.startsWith("fd") ||
      a.startsWith("fe8") || a.startsWith("fe9") || a.startsWith("fea") || a.startsWith("feb") || a.startsWith("::ffff:127.");
  }
  return true;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  try {
    const input = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    if (!input || typeof input.url !== "string" || !["GET", "POST"].includes(input.method)) {
      return res.status(400).json({ error: "Expected url and GET/POST method." });
    }
    const target = new URL(input.url);
    if (target.protocol !== "https:" || target.username || target.password || (target.port && target.port !== "443")) {
      return res.status(400).json({ error: "Only public HTTPS endpoints on the standard port are allowed." });
    }
    const host = target.hostname.toLowerCase();
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || net.isIP(host) && isPrivateAddress(host)) {
      return res.status(400).json({ error: "Private or local network endpoints are not allowed." });
    }
    const addresses = await dns.lookup(host, { all: true, verbatim: true });
    if (!addresses.length || addresses.some(x => isPrivateAddress(x.address))) {
      return res.status(400).json({ error: "Endpoint host must resolve only to public IP addresses." });
    }
    const headers = { Accept: "application/json" };
    if (input.headers && typeof input.headers === "object") {
      if (typeof input.headers.Authorization === "string" && input.headers.Authorization.length < 4096) headers.Authorization = input.headers.Authorization;
      if (typeof input.headers["x-api-key"] === "string" && input.headers["x-api-key"].length < 4096) headers["x-api-key"] = input.headers["x-api-key"];
      if (input.method === "POST") headers["Content-Type"] = "application/json";
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 150000);
    let upstream;
    let raw;
    try {
      upstream = await fetch(target, {
        method: input.method,
        headers,
        body: input.method === "POST" ? JSON.stringify(input.body || {}) : undefined,
        redirect: "manual",
        signal: controller.signal
      });
      if (upstream.status >= 300 && upstream.status < 400) {
        return res.status(502).json({ error: "Endpoint redirected the request. Use its final HTTPS URL." });
      }
      raw = await upstream.text();
    } finally { clearTimeout(timeout); }
    if (raw.length > 2 * 1024 * 1024) return res.status(502).json({ error: "Endpoint response exceeded the 2 MB limit." });
    let data;
    try { data = JSON.parse(raw); } catch { data = { result: raw }; }
    if (!upstream.ok) {
      const message = data && (data.error?.message || data.error || data.message || data.detail);
      return res.status(502).json({ error: typeof message === "string" ? message : `Endpoint returned HTTP ${upstream.status}`, upstreamStatus: upstream.status, data });
    }
    return res.status(200).json({ ok: true, data });
  } catch (error) {
    const message = error.name === "AbortError" ? "The endpoint timed out." : (error.message || "Proxy request failed.");
    return res.status(502).json({ error: message });
  }
};
