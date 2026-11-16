// inspect-local.mjs: inspect networks from the command line, in local folders or on real websites.
//   npm run inspect -- <folder>/<network> [...]
//   npm run inspect -- https://site.example/<network> [...]
// A folder argument is a folder holding agent-manifest.json, then the network name.
// A web address is read directly from this computer. Node is not bound by CORS the way a
// browser is, so this also reports whether other sites' browsers could read the files: a
// site without the CORS header shows "Could not inspect" in the page, and no other site's
// agent can call it.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectNetworkUrl } from "../site/customs/inspect.js";
import { fsFetch } from "./fs-fetch.mjs";

// The Origin a caller's browser would send, so servers answer as they would to a caller.
const CALLER = "https://caller.example";

export async function inspectFolder(arg) {
  const folder = path.resolve(path.dirname(arg));
  const name = path.basename(arg);
  const origin = "https://inspect.local";
  return inspectNetworkUrl(`${origin}/${name}`, { fetchImpl: fsFetch({ [origin]: folder }), pageOrigin: "https://customs.local" });
}

export async function inspectWeb(url) {
  const unreadable = new Set();
  const fetchImpl = async (target, init = {}) => {
    const resp = await fetch(target, { ...init, headers: { Origin: CALLER } });
    if (resp.ok && !resp.headers.get("access-control-allow-origin")) {
      unreadable.add(new URL(resp.url || target).pathname.split("/").pop());
    }
    return resp;
  };
  const report = await inspectNetworkUrl(url, { fetchImpl, pageOrigin: CALLER });
  const cors = report.conformance.checks.find((c) => c.id === "P-CORS");
  if (cors && unreadable.size) {
    cors.status = "fail";
    cors.detail = `No Access-Control-Allow-Origin header on ${[...unreadable].join(", ")}. Other sites' browsers cannot read these files, so the page shows "Could not inspect" for this address, and no other site's agent can call this network.`;
    const c = report.conformance;
    c.passed = c.checks.filter((x) => x.status === "pass").length;
    c.warned = c.checks.filter((x) => x.status === "warn").length;
    c.failed = c.checks.filter((x) => x.status === "fail").length;
  }
  return report;
}

// Run as a command, not when another tool imports inspectWeb.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const arg of process.argv.slice(2)) {
    const report = /^https?:\/\//i.test(arg) ? await inspectWeb(arg) : await inspectFolder(arg);
    console.log(`\n== ${arg}\n   ${report.verdict.code}: ${report.verdict.summary}`);
    console.log(`   conformance ${report.conformance.passed}/${report.conformance.total}; fingerprint ${report.identity.short || "none"}`);
    for (const c of report.conformance.checks.filter((c) => c.status !== "pass")) console.log(`   [${c.status}] ${c.id} ${c.title}: ${c.detail}`);
    for (const f of report.findings) console.log(`   ${f.severity.padEnd(8)} ${f.rule.padEnd(16)} ${f.title} | ${f.where?.agent || ""} ${f.where?.field || ""} | ${(f.evidence || f.detail || "").slice(0, 140)}`);
  }
}
