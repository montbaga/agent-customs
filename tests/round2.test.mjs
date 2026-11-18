// Regression tests for every frozen Round-2 red-team probe (capability splits,
// social engineering, secondary schema fields, short non-English text, and ROT13)
// and benign counter-examples, verifying detection without false blocks.
// Run from the project folder: node --test tests/round2.test.mjs
import assert from "node:assert/strict";
import test from "node:test";
import { analyzeNetwork } from "../site/customs/analyze.js";
import { normalizeForeignSpec } from "../site/customs/protocols.js";
import { ROUND2_DETECTION_CASES } from "../tools/round2-corpus.mjs";

async function evalRound2Case(c) {
  if (c.kind === "text") {
    return analyzeNetwork({
      networkUrl: "https://bench-r2.invalid/shop",
      frontMan: "greeter",
      entry: { name: "r2", front_man: "greeter", hocon: "./net.json" },
      manifest: { networks: [{ name: "r2", front_man: "greeter", hocon: "./net.json" }], peer_policy: { mode: "closed" } },
      config: {
        metadata: { description: "Round-2 bench agent." },
        tools: [{ name: "greeter", instructions: c.text, function: { description: "Handle", parameters: { type: "object", properties: { q: { type: "string" } } } }, tools: [] }],
      },
    });
  }
  if (c.kind === "oaw_param") {
    return analyzeNetwork({
      networkUrl: "https://bench-r2.invalid/shop",
      frontMan: "greeter",
      entry: { name: "r2", front_man: "greeter", hocon: "./net.json" },
      manifest: { networks: [{ name: "r2", front_man: "greeter", hocon: "./net.json" }], peer_policy: { mode: "closed" } },
      config: {
        metadata: { description: "Round-2 bench agent." },
        tools: [{ name: "greeter", instructions: "Help.", function: { description: "Handle", parameters: { type: "object", properties: { [c.paramName]: { type: "string" } } } }, tools: [] }],
      },
    });
  }
  const n = normalizeForeignSpec(c.doc, c.url, c.protocol);
  return analyzeNetwork({ networkUrl: c.url, ...n });
}

test("all frozen Round-2 red-team detection probes and benign counter-examples get the expected verdict", async () => {
  for (const c of ROUND2_DETECTION_CASES) {
    const rep = await evalRound2Case(c);
    const rules = rep.findings.map((f) => f.rule);
    if (c.benign) {
      assert.equal(rep.verdict.code, "CLEARED", `${c.name} -> ${rep.verdict.code}: ${rules.join(", ")}`);
    } else if (c.expected === "flag_off_origin") {
      assert.ok(rules.includes("R-CROSS-ORIGIN-ENDPOINT"), `${c.name} must flag R-CROSS-ORIGIN-ENDPOINT, got ${rules.join(", ")}`);
    } else {
      assert.ok(
        rep.verdict.code === "DENIED" || rep.verdict.code === "HOLD",
        `${c.name} escaped: ${rep.verdict.code} (${rules.join(", ")})`,
      );
    }
  }
});
