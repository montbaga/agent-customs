// make-vault.mjs: copy vault/ and the license into a clone of the vault's own repository,
// which GitHub Pages publishes at agent-customs-vault.github.io. Old files are removed; .git stays.
//
//   npm run vault -- ../agent-customs-vault.github.io
//
// The license goes in as a plain LICENSE file, the Apache text from LICENSE.md. That page's
// images and links point into this repository, so they would be broken there.

import { cp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "vault");
const target = process.argv[2];
if (!target) {
  console.error("Usage: npm run vault -- <checkout of the vault repository>");
  process.exit(1);
}
const dest = path.resolve(target);
try {
  if (!(await stat(path.join(dest, ".git"))).isDirectory()) throw new Error();
} catch {
  console.error(`${dest} is not a git checkout. Clone the vault repository there first.`);
  process.exit(1);
}
for (const name of await readdir(dest)) {
  if (name !== ".git") await rm(path.join(dest, name), { recursive: true, force: true });
}
await cp(SOURCE, dest, { recursive: true });
const page = await readFile(path.join(SOURCE, "..", "LICENSE.md"), "utf8");
const text = page.match(/<summary><b>Apache License, Version 2\.0<\/b><\/summary>\s*```text\r?\n([\s\S]*?)\r?\n```/)?.[1];
if (!text?.includes("TERMS AND CONDITIONS")) {
  console.error("LICENSE.md has no Apache License text block to copy.");
  process.exit(1);
}
await writeFile(path.join(dest, "LICENSE"), `${text}\n`);
console.log(`Copied ${path.relative(process.cwd(), SOURCE) || SOURCE} to ${dest}. Commit and push there to publish.`);
