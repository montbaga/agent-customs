// serve.mjs: a small static server that applies a folder's _headers file, the format
// Netlify and Cloudflare Pages read in production. So the headers checked locally are the
// headers the hosted site sends.
//
//   node tools/serve.mjs <folder> [--port 8081] [--host 127.0.0.1] [--log requests.jsonl]
//
// Binds to 127.0.0.1 by default. Refuses paths outside the folder. The log has one JSON
// line per request: method, path, status, Origin, and whether Authorization or cookies were
// sent (never their values), so you can show that a partner never receives a visitor's key.

import { appendFile, readFile, stat } from "node:fs/promises";
import http from "node:http";
import path from "node:path";

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
};
const root = path.resolve(args.find((a, i) => !a.startsWith("--") && !args[i - 1]?.startsWith("--")) || ".");
const port = Number(opt("--port", "8081"));
const host = opt("--host", "127.0.0.1");
const logFile = opt("--log", null);

const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
  ".png": "image/png", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8", ".hocon": "text/plain; charset=utf-8",
};

async function loadHeaderRules() {
  try {
    const text = await readFile(path.join(root, "_headers"), "utf8");
    const rules = [];
    let current = null;
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim() || line.trim().startsWith("#")) continue;
      if (/^\s/.test(line)) {
        const m = line.trim().match(/^([^:]+):\s*(.*)$/);
        if (m && current) current.headers[m[1]] = m[2];
      } else {
        current = { pattern: line.trim(), headers: {} };
        rules.push(current);
      }
    }
    return rules;
  } catch {
    return [];
  }
}

function matches(pattern, urlPath) {
  const re = new RegExp("^" + pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$");
  return re.test(urlPath);
}

const server = http.createServer(async (req, res) => {
  const urlPath = decodeURIComponent(new URL(req.url, "http://x").pathname);
  let file = path.join(root, urlPath);
  if (!file.startsWith(root)) { res.writeHead(403).end("Forbidden"); return; }
  let status = 200;
  let body;
  const headers = { "Cache-Control": "no-store" };
  try {
    const info = await stat(file);
    if (info.isDirectory()) file = path.join(file, "index.html");
    body = await readFile(file);
    headers["Content-Type"] = TYPES[path.extname(file).toLowerCase()] || "application/octet-stream";
    for (const rule of await loadHeaderRules()) if (matches(rule.pattern, urlPath)) Object.assign(headers, rule.headers);
  } catch {
    status = 404;
    body = "Not found";
    headers["Content-Type"] = "text/plain; charset=utf-8";
  }
  res.writeHead(status, headers);
  res.end(req.method === "HEAD" ? undefined : body);
  if (logFile) {
    const entry = { time: new Date().toISOString(), method: req.method, path: urlPath, status, origin: req.headers.origin || null,
      authorization: !!req.headers.authorization, cookies: (req.headers.cookie || "").split(";").map((c) => c.split("=")[0].trim()).filter(Boolean) };
    appendFile(logFile, JSON.stringify(entry) + "\n").catch(() => {});
  }
});

server.listen(port, host, () => {
  console.log(`Serving ${root} at http://${host === "127.0.0.1" ? "localhost" : host}:${port}/ (headers from _headers)`);
});
