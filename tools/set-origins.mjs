// set-origins.mjs: point Agent Customs at the test range's address, then rebuild.
//
//   node tools/set-origins.mjs --range https://agent-customs-range.netlify.app
//
// The range is a second website (a second origin), so partner calls show real consent
// cards. This rewrites the range address in the network source, the manifest, the page
// and the desk; regenerates the range for that address; and rebuilds the network with
// the official build script. Run it again with --range http://localhost:8081 to go back.

import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const i = process.argv.indexOf("--range");
const next = i > 0 ? String(process.argv[i + 1] || "").replace(/\/+$/, "") : "";
if (!/^https?:\/\/[^/]+$/.test(next)) {
  console.error("Usage: node tools/set-origins.mjs --range https://your-range-host   (an origin: scheme and host, no path)");
  process.exit(2);
}
const deskFile = path.join(ROOT, "site", "desk.js");
const current = (await readFile(deskFile, "utf8")).match(/export const RANGE_ORIGIN = "([^"]+)"/)?.[1];
if (!current) throw new Error("RANGE_ORIGIN not found in site/desk.js");
if (current === next) console.log(`Range is already ${next}; rebuilding.`);

for (const rel of ["site/agent_customs.hocon", "site/agent-manifest.json", "site/desk.js", "site/index.html"]) {
  const file = path.join(ROOT, rel);
  const text = await readFile(file, "utf8");
  const updated = text.split(current).join(next);
  if (updated !== text) {
    await writeFile(file, updated);
    console.log(`Updated ${rel}`);
  }
}
const run = (args) => execFileSync(process.execPath, args, { cwd: ROOT, stdio: "inherit" });
run(["tools/make-range.mjs", "--origin", next]);
run(["vendor/agentify-website/scripts/build_network.mjs", "site/agent_customs.hocon", "--manifest", "site/agent-manifest.json"]);
console.log(`\nDone. The range is ${next}. Deploy range/ there and site/ to its own host.`);
