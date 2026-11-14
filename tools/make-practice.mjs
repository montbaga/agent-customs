// make-practice.mjs: assembles the practice site, Main Street Guide, in practice/.
//
//   node tools/make-practice.mjs
//
// Main Street Guide plays the part of someone else's agentic website. This script does
// what the agentify-website kit does for every site, plus the guard's first step:
//   1. copies Cognizant's runtime, unchanged, into practice/runtime/ (the kit's step 3);
//   2. copies Agent Customs' customs/ folder into practice/customs/ (the guard's step 1);
//   3. copies the fonts the page uses;
//   4. builds the network with the kit's build script, which also writes the bridge and
//      the discovery files.
// The guard's step 2, the two lines in practice/site.js, is written by hand, as a site
// owner would. tests/practice.test.mjs checks that the copies match their sources.

import { execFileSync } from "node:child_process";
import { copyFile, cp, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "practice");

export const COPIED_FOLDERS = [
  ["vendor/agentify-website/runtime", "practice/runtime"],
  ["site/customs", "practice/customs"],
];
export const FONTS = [
  "Geist-Variable.ttf", "GeistMono-Variable.ttf", "InstrumentSerif-Italic.ttf",
  "OFL-Geist.txt", "OFL-GeistMono.txt", "OFL-InstrumentSerif.txt",
];

async function main() {
  for (const [from, to] of COPIED_FOLDERS) {
    await rm(path.join(ROOT, to), { recursive: true, force: true });
    await cp(path.join(ROOT, from), path.join(ROOT, to), { recursive: true });
    console.log(`Copied ${from}/ to ${to}/`);
  }
  await mkdir(path.join(OUT, "fonts"), { recursive: true });
  for (const font of FONTS) await copyFile(path.join(ROOT, "site", "fonts", font), path.join(OUT, "fonts", font));
  console.log(`Copied ${FONTS.length} font files to practice/fonts/`);
  execFileSync(process.execPath, [
    "vendor/agentify-website/scripts/build_network.mjs", "practice/main_street_guide.hocon",
    "--manifest", "practice/agent-manifest.json",
  ], { cwd: ROOT, stdio: "inherit" });
  console.log("\nDone. Serve it with: npm run serve:practice   (http://127.0.0.1:8082/)");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
