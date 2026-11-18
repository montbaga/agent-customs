// Real-world 135-target regression suite (17 well-known MCP servers, 83 MCP Registry servers, 35 A2A cards).
// Pre-fix baseline recorded on origin/main @ 17e8bc8 (2026-11-18):
//   86 correct, 43 false alarms (HOLD/DENIED on benign targets), 6 debatable.
// Acceptance target: <= 5 false alarms, all 10 must-keep hosts HOLD/DENIED, and zero regressions
// on previously CLEARED / CONDITIONS targets.
// Run from the project folder: node --test tests/realworld.test.mjs
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { inspectNetworkUrl } from "../site/customs/inspect.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REALWORLD_DIR = path.join(ROOT, "tests", "fixtures", "realworld");

const KEEPERS = [
  "game.spacemolt.com",
  "aibotoffice.ai",
  "mcp.getle.ad",
  "mcp.pantheon.ad",
  "mcp.aivikings.ai",
  "www.aim-shield.ai",
  "zoll.agency",
  "justidea.agency",
  "service.agilex.ai",
  "beevr.ai",
];

const DEBATABLE = [
  "chainflip-broker.io",
  "afg.ai",
  "agentroam.ai",
  "cronjob.agentasy.ai",
  "www.agentboard.ai",
  "agents.avasis.ai",
];

function loadRealworldSnapshots() {
  const out = [];
  for (const dir of ["servers", "reg-servers", "a2a-cards"]) {
    for (const file of readdirSync(path.join(REALWORLD_DIR, dir)).sort()) {
      const { url, doc } = JSON.parse(readFileSync(path.join(REALWORLD_DIR, dir, file), "utf8"));
      const u = new URL(url);
      const target = dir === "a2a-cards"
        ? url
        : (/\/mcp$/i.test(u.pathname) ? `${u.origin}${u.pathname}` : `${u.origin}${u.pathname.replace(/\/$/, "")}/mcp`);
      out.push({ url, target, doc });
    }
  }
  return out;
}

test("135 real-world MCP and A2A targets stay at <= 5 false alarms while keeping risky targets flagged", async () => {
  const labelled = JSON.parse(readFileSync(path.join(REALWORLD_DIR, "labelled.json"), "utf8"));
  const baselineByUrl = new Map(labelled.map((row) => [row.url, row]));
  const snapshots = loadRealworldSnapshots();
  assert.equal(snapshots.length, 135);

  const falseAlarms = [];
  const missedKeepers = [];
  const regressions = [];

  for (const snap of snapshots) {
    const body = JSON.stringify(snap.doc);
    const fetchImpl = async (req) => {
      const asked = typeof req === "string" ? req : req.url;
      if (asked.split("?")[0] === snap.target) {
        return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response("not found", { status: 404 });
    };
    const report = await inspectNetworkUrl(snap.target, { fetchImpl, pageOrigin: null, timeoutMs: 10000 });
    const verdict = report.verdict.code;
    const baseline = baselineByUrl.get(snap.url);
    assert.ok(baseline, `missing baseline entry for ${snap.url}`);

    const isKeeper = KEEPERS.some((h) => snap.url.includes(h));
    const isDebatable = DEBATABLE.some((h) => snap.url.includes(h));
    const blocked = verdict === "HOLD" || verdict === "DENIED";

    if (isKeeper) {
      if (!blocked) missedKeepers.push(`${snap.url} -> ${verdict}`);
      continue;
    }
    if (baseline.verdict === "CLEARED" || baseline.verdict === "CONDITIONS") {
      if (blocked) regressions.push(`${snap.url}: was ${baseline.verdict} -> ${verdict}`);
      continue;
    }
    if (!isDebatable && blocked) {
      falseAlarms.push(`${snap.url} (${verdict}: ${report.findings.map((f) => f.rule).join(",")})`);
    }
  }

  assert.deepEqual(missedKeepers, [], `keepers dropped: ${missedKeepers.join("; ")}`);
  assert.deepEqual(regressions, [], `previously unblocked targets regressed: ${regressions.join("; ")}`);
  assert.ok(falseAlarms.length <= 5, `expected <= 5 false alarms, got ${falseAlarms.length}:\n${falseAlarms.join("\n")}`);
});
