// The one-file build (dist/agent-customs.js): current, fingerprinted, self-contained, and the
// same guard as the source files.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { BUNDLE, INTEGRITY_NEAR_BUNDLE, buildBundle } from "../tools/make-bundle.mjs";
import { fsFetch } from "../tools/fs-fetch.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const built = await buildBundle();

test("the one-file build matches its sources (run npm run bundle after changing them)", async () => {
  const onDisk = await readFile(path.join(ROOT, BUNDLE), "utf8");
  assert.equal(onDisk, built.code);
});

test("the README and the site show the one-file build's real fingerprint", async () => {
  for (const doc of ["README.md", "site/index.html"]) {
    const text = await readFile(path.join(ROOT, doc), "utf8");
    const found = [...text.matchAll(INTEGRITY_NEAR_BUNDLE)].map((m) => m[2]);
    assert.ok(found.length >= 1, `${doc} shows the one-line install with its fingerprint`);
    for (const hash of found) assert.equal(hash, built.integrity, doc);
  }
});

test("the one-file build loads nothing else, so its fingerprint covers all the code", () => {
  assert.doesNotMatch(built.code, /^\s*import[\s{*(]/m);
  assert.doesNotMatch(built.code, /\bimport\(/);
  assert.doesNotMatch(built.code, /import\.meta/);
  assert.ok(built.files.includes("site/customs/guard.js") && built.files.includes("site/runtime/kernel.js"));
});

test("the one-file build gives every sample and range network the same report as the source files", async () => {
  const bundled = await import(pathToFileURL(path.join(ROOT, BUNDLE)).href);
  const { inspectNetworkUrl } = await import("../site/customs/inspect.js");
  const fetchImpl = fsFetch({ "https://range.test": path.join(ROOT, "range"), "https://samples.test": path.join(ROOT, "site", "samples") });
  const targets = [
    "sunny_bakery/sunny_bakery", "shady_pizza/shady_pizza", "bank_helper/bank_helper", "loop_maze/loop_maze", "rugpull/sunny_bakery",
    "official/pizza_restaurant_agentified/pizza_restaurant_website_assistant", "official/guesthouse_agentified/tidewhistle_guesthouse",
    "official/harbor_tours_agentified/marrow_point_harbor_tours",
  ].map((p) => `https://range.test/${p}`).concat([
    "a2a-clean/.well-known/agent.json", "mcp-poisoned/mcp.json", "trifecta-polite/mcp.json", "transitive-hub/hub", "ai-check-demo/mcp.json",
  ].map((p) => `https://samples.test/${p}`));
  const summary = (r) => ({ verdict: r.verdict?.code, fingerprint: r.identity?.short, rules: r.findings.map((f) => `${f.rule}:${f.severity}`).sort() });
  const verdicts = new Set();
  for (const url of targets) {
    const options = { fetchImpl, pageOrigin: "https://customs.example" };
    const a = summary(await inspectNetworkUrl(url, options));
    const b = summary(await bundled.inspectNetworkUrl(url, options));
    assert.deepEqual(b, a, url);
    verdicts.add(a.verdict);
  }
  assert.ok(verdicts.size >= 3, `the samples cover several verdicts: ${[...verdicts]}`);
});
