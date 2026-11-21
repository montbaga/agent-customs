// The "Wrong result? Tell us" link: a prefilled GitHub issue with only what the report shows.
// Run from the project folder: node --test tests/wrong-result.test.mjs
import assert from "node:assert/strict";
import test from "node:test";
import { ISSUES_NEW, wrongResultUrl } from "../site/wrong-result.js";

test("the wrong-result link fills in the address, the verdict and what was found", () => {
  const report = {
    target: { url: "https://tools.example/mcp" },
    verdict: { code: "DENIED", stamp: "Denied" },
    aiCheck: { status: "skipped" },
    findings: [
      { rule: "C-SECRETS", severity: "critical", title: "Asks for passwords, codes or card details", evidence: "Use REST with a bearer API key." },
      { rule: "C-URGENCY", severity: "low", title: "Uses pressure language", evidence: "act now" },
    ],
  };
  const url = new URL(wrongResultUrl(report));
  assert.equal(`${url.origin}${url.pathname}`, ISSUES_NEW);
  assert.equal(url.searchParams.get("title"), "Wrong result: tools.example (Denied)");
  const body = url.searchParams.get("body");
  assert.match(body, /\*\*Address checked:\*\* https:\/\/tools\.example\/mcp/);
  assert.match(body, /\*\*Result:\*\* Denied/);
  assert.match(body, /\(C-SECRETS, critical\): "Use REST with a bearer API key\."/);
  assert.doesNotMatch(body, /C-URGENCY/, "low notes are left out");
  assert.match(body, /\*\*AI double-check:\*\* on, not asked/);
  assert.match(body, /holds nothing private/);
});

test("the wrong-result link stays short, and there is none without a report", () => {
  const long = "x".repeat(5000);
  const findings = Array.from({ length: 20 }, (_, i) => ({ rule: `R-${i}`, severity: "high", title: "Something", evidence: long }));
  const url = wrongResultUrl({ target: { url: "https://a.example/" }, verdict: { stamp: "Held for review" }, findings });
  assert.ok(url.length < 8000, `the link is ${url.length} characters`);
  assert.equal((new URL(url).searchParams.get("body").match(/^- /gm) || []).length, 6);
  assert.equal(wrongResultUrl(null), "");
  assert.equal(wrongResultUrl({ verdict: { stamp: "Cleared" } }), "");
});
