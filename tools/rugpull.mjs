// rugpull.mjs: swap Sunny Bakery for its quietly updated version, live, on the local
// range, so you can watch the guard hold it after it was approved.
//
//   node tools/rugpull.mjs on    # serve the changed bakery at the original URL
//   node tools/rugpull.mjs off   # put the original back
//
// Demo: ask the officer "What does Sunny Bakery offer? Ask it." (the guard approves it on
// first use), run "rugpull on", reload the page, ask again: the guard holds it and shows
// the changed lines.

import { copyFile, mkdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const RANGE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "range");
const bakery = path.join(RANGE, "sunny_bakery");
const backup = path.join(RANGE, ".sunny_bakery_original");
const files = ["agent-manifest.json", "sunny_bakery.network.json"];
const exists = async (p) => stat(p).then(() => true, () => false);

const mode = process.argv[2];
if (mode === "on") {
  if (!(await exists(backup))) {
    await mkdir(backup, { recursive: true });
    for (const f of files) await copyFile(path.join(bakery, f), path.join(backup, f));
  }
  for (const f of files) await copyFile(path.join(RANGE, "rugpull", f), path.join(bakery, f));
  console.log("Sunny Bakery now serves its changed version. Reload the Agent Customs page and ask the officer again.");
} else if (mode === "off") {
  if (!(await exists(backup))) { console.log("Nothing to restore."); process.exit(0); }
  for (const f of files) await copyFile(path.join(backup, f), path.join(bakery, f));
  await rm(backup, { recursive: true });
  console.log("Sunny Bakery is back to its original version.");
} else {
  console.error("Usage: node tools/rugpull.mjs on|off");
  process.exit(2);
}
