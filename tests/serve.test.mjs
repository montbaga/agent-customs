// Checks the local server (tools/serve.mjs): it never serves a file outside its folder,
// and a malformed address cannot stop it.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("the local server refuses paths outside its folder and survives malformed escapes", async (t) => {
  const child = spawn(process.execPath, ["tools/serve.mjs", "site", "--port", "0"], { cwd: ROOT });
  t.after(() => child.kill());
  const port = await new Promise((resolve, reject) => {
    let out = "";
    child.stdout.on("data", (data) => {
      out += data;
      const found = out.match(/:(\d+)\//);
      if (found) resolve(Number(found[1]));
    });
    child.on("exit", (code) => reject(new Error(`the server stopped (exit code ${code})`)));
  });
  const status = (p) => fetch(`http://127.0.0.1:${port}${p}`).then((r) => r.status);

  assert.equal(await status("/index.html"), 200);
  assert.equal(await status("/%E0%A4%A"), 400);
  assert.equal(await status("/..%2fpackage.json"), 403);
  // A sibling whose name starts with the folder's name, like range-requests.jsonl next to range/.
  assert.equal(await status("/..%2fsite-notes.txt"), 403);
  assert.equal(await status("/index.html"), 200, "the server is still running");
});
