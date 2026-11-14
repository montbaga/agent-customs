// The hero replay must show what the engine really finds. This inspects each test-range
// network and compares every value the replay displays.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { EXAMPLES } from "../site/desk.js";
import { CHECK_NAMES, HERO_DEMO } from "../site/hero-data.js";
import { inspectNetworkUrl } from "../site/customs/inspect.js";
import { normalizeForRules } from "../site/customs/unicode.js";
import { fsFetch } from "../tools/fs-fetch.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RANGE = "http://localhost:8081";
const fetchImpl = fsFetch({ [RANGE]: path.join(ROOT, "range") });
const RANK = ["critical", "high", "medium", "low", "info"];
const CATEGORY = { contraband: "contraband", itinerary: "itinerary", privacy: "privacy", identity: "identity" };

for (const demo of HERO_DEMO) {
  test(`the hero replay of ${demo.label} matches a real inspection`, async () => {
    const example = EXAMPLES.find((e) => e.id === demo.id);
    assert.ok(example, `no test-range example with id ${demo.id}`);
    const report = await inspectNetworkUrl(example.url, { fetchImpl, pageOrigin: "http://127.0.0.1:8080" });
    assert.equal(report.verdict.code, demo.verdict);
    assert.equal(report.verdict.stamp, demo.stamp);
    assert.equal(report.verdict.tone, demo.tone);
    assert.equal(report.findings.length, demo.findings);
    assert.deepEqual(Object.keys(demo.checks), CHECK_NAMES);
    // Papers: no failed spec check. (The only warning on the local range is plain HTTP.)
    assert.equal(report.conformance.failed, 0);
    assert.equal(demo.checks.papers.state, "pass");
    for (const [check, category] of Object.entries(CATEGORY)) {
      const found = report.findings.filter((f) => f.category === category);
      const worst = RANK.find((s) => found.some((f) => f.severity === s));
      const expected = found.length ? { state: worst, count: found.length } : { state: "pass" };
      assert.deepEqual(demo.checks[check], expected, `${demo.label}: ${check}`);
    }
    if (demo.quote) {
      // The quoted line is really in the network's instructions (hidden text included).
      const file = path.join(ROOT, "range", new URL(example.url).pathname.split("/").slice(1, -1).join("/"));
      const name = new URL(example.url).pathname.split("/").pop();
      const network = await readFile(path.join(file, `${name}.network.json`), "utf8");
      assert.ok(normalizeForRules(JSON.parse(network).tools.map((t) => t.instructions).join("\n")).includes(demo.quote),
        `${demo.label}: the quote is not in the network`);
    }
  });
}
