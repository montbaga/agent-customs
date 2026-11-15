// What the visitor's notice says after each guard decision (site/customs/guard-notice.js).
// The notice must list everything Agent Customs found, in Agent Customs' own words only,
// and link to the full report.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { DEFAULT_REPORT_PAGE, noticeContent, reportLink } from "../site/customs/guard-notice.js";
import { inspectNetworkUrl } from "../site/customs/inspect.js";
import { RANGE_ORIGIN } from "../site/desk.js";
import { fsFetch } from "../tools/fs-fetch.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fetchImpl = fsFetch({ [RANGE_ORIGIN]: path.join(ROOT, "range") });
const HOST = new URL(RANGE_ORIGIN).host;
async function reportFor(folder, name, guard) {
  const report = await inspectNetworkUrl(`${RANGE_ORIGIN}/${folder}/${name}`, { fetchImpl, pageOrigin: "http://127.0.0.1:8080" });
  report.guard = guard;
  return report;
}
// Words the test networks wrote. None of them may appear in a notice.
const THEIR_WORDS = /card number|CVV|website_place_order|certified safe|gift card|maze_runner|discount code|\{conversation\}/i;

test("a refused partner: blocked, every finding listed worst first, and a link to the full report", async () => {
  const report = await reportFor("shady_pizza", "shady_pizza", { decision: "refused", pinned: false });
  const c = noticeContent(report);
  assert.equal(c.tone, "bad");
  assert.equal(c.title, `Blocked "shady_pizza" from ${HOST}`);
  assert.equal(c.stamp, "Entry denied");
  assert.match(c.lines.join(" "), /Nothing from it ran/);
  const distinct = new Set(report.findings.map((f) => `${f.severity}|${f.title}`));
  assert.equal(c.items.length, distinct.size, "every distinct finding is listed");
  assert.equal(c.items.reduce((n, i) => n + i.count, 0), report.findings.length, "repeats are counted, not dropped");
  assert.equal(c.items[0].severity, "critical");
  assert.equal(c.link, `${DEFAULT_REPORT_PAGE}?inspect=${encodeURIComponent(report.target.url)}`);
  assert.doesNotMatch(JSON.stringify(c), THEIR_WORDS);
});

test("a held partner the visitor turned away, and one let in after review", async () => {
  const away = noticeContent(await reportFor("loop_maze", "loop_maze", { decision: "declined", pinned: false }));
  assert.equal(away.tone, "warn");
  assert.equal(away.title, `Turned away "loop_maze" from ${HOST}`);
  assert.equal(away.stamp, "Held for review");
  assert.match(away.lines[0], /held for review, and you chose not to let it run\. Nothing from it ran\./);
  assert.ok(away.items.length >= 4);
  assert.doesNotMatch(JSON.stringify(away), THEIR_WORDS);

  const letIn = noticeContent(await reportFor("loop_maze", "loop_maze", { decision: "admitted after review", pinned: true }));
  assert.equal(letIn.title, `Let in "loop_maze" from ${HOST}`);
  assert.match(letIn.lines[0], /now approved in this browser, and if it changes, you will be asked again/);
});

test("a partner that changed since approval says so, whichever way the visitor decides", async () => {
  const report = await reportFor("rugpull", "sunny_bakery", { decision: "declined", pinned: false });
  report.drift = { changed: true, changes: [{ title: "Instructions changed" }, { title: "New partner" }, { title: "New origin" }] };
  const away = noticeContent(report);
  assert.match(away.lines[0], /changed since you approved it, and you chose not to let the new version run/);
  assert.match(away.lines.join(" "), /3 change\(s\) since you approved it/);
  assert.doesNotMatch(JSON.stringify(away), THEIR_WORDS);
  report.guard = { decision: "admitted after review", pinned: true };
  assert.match(noticeContent(report).lines[0], /You let the changed version run after review/);
});

test("a cleared partner: checked, approved on first use, then recognized", async () => {
  const report = await reportFor("sunny_bakery", "sunny_bakery", { decision: "admitted", pinned: true });
  const first = noticeContent(report);
  assert.equal(first.tone, "ok");
  assert.equal(first.title, `Checked "sunny_bakery" from ${HOST}`);
  assert.equal(first.stamp, "Cleared");
  assert.deepEqual(first.items, []);
  assert.match(first.lines[0], /passed inspection, so it ran\. This version is now approved in this browser/);
  report.guard = { decision: "admitted", pinned: false };
  report.drift = { changed: false, changes: [] };
  assert.match(noticeContent(report).lines[0], /matches the version approved in this browser/);
});

test("papers not in order: the failed spec checks come first", async () => {
  const report = await reportFor("sunny_bakery", "sunny_bakery", { decision: "refused", pinned: false });
  report.verdict = { ...report.verdict, code: "INVALID", stamp: "Papers not in order" };
  report.conformance.checks[0] = { ...report.conformance.checks[0], status: "fail" };
  const c = noticeContent(report);
  assert.equal(c.tone, "bad");
  assert.equal(c.stamp, "Papers not in order");
  assert.match(c.lines[0], /do not follow the Open Agentic Web spec/);
  assert.equal(c.items[0].severity, "spec");
  assert.equal(c.items[0].title, report.conformance.checks[0].title);
});

test("the full-report link opens the page you choose, with the address filled in", async () => {
  const report = await reportFor("shady_pizza", "shady_pizza", { decision: "refused", pinned: false });
  const link = new URL(reportLink(report, "http://127.0.0.1:8080/"));
  assert.equal(link.origin + link.pathname, "http://127.0.0.1:8080/");
  assert.equal(link.searchParams.get("inspect"), report.target.url);
});
