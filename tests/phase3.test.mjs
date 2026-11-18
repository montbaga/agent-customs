// Tests for Phase 3 deliverables: CLI + SARIF + GitHub Action, Agent Customs Bench, and MV3 Extension.
// Run from the project folder: node --test tests/phase3.test.mjs
import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { exitCodeForReports, formatSarif, runCli } from "../bin/agent-customs.mjs";
import { inspectOriginAgents } from "../extension/inspector.js";
import { certificateSvg } from "../site/certificate.js";
import { inspectNetworkUrl } from "../site/customs/inspect.js";
import { formatBenchReport, runBenchmark } from "../tools/bench.mjs";
import { fsFetch } from "../tools/fs-fetch.mjs";
import { EXTENSION_COPIED_FOLDERS } from "../tools/make-extension.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function filesUnder(dir, prefix = "") {
  const out = [];
  for (const entry of await readdir(path.join(dir, prefix), { withFileTypes: true })) {
    const rel = path.join(prefix, entry.name);
    if (entry.isDirectory()) out.push(...await filesUnder(dir, rel));
    else out.push(rel);
  }
  return out.sort();
}

function makeIo() {
  const stdout = [];
  const stderr = [];
  return {
    stdout,
    stderr,
    io: { out: (msg) => stdout.push(String(msg)), error: (msg) => stderr.push(String(msg)) },
  };
}

// ---- CLI & GitHub Action ---------------------------------------------------------------

test("CLI check handles cleared, held, denied, JSON, and SARIF output accurately", async () => {
  const okRun = makeIo();
  const codeOk = await runCli(["check", path.join(ROOT, "site/agent_customs"), "--json"], okRun.io);
  assert.equal(codeOk, 0);
  const parsedOk = JSON.parse(okRun.stdout.join("\n"));
  assert.equal(parsedOk[0].verdict.code, "CLEARED");

  const a2aRun = makeIo();
  assert.equal(await runCli(["check", path.join(ROOT, "site/samples/a2a-clean/.well-known/agent.json")], a2aRun.io), 0);

  const badRun = makeIo();
  const codeBad = await runCli(["check", path.join(ROOT, "site/samples/mcp-poisoned/mcp.json"), "--sarif"], badRun.io);
  assert.equal(codeBad, 2);
  const sarif = JSON.parse(badRun.stdout.join("\n"));
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.length >= 1);

  const holdDefault = makeIo();
  assert.equal(await runCli(["check", path.join(ROOT, "site/samples/trifecta-polite/mcp.json")], holdDefault.io), 1);
  const holdAllowed = makeIo();
  assert.equal(await runCli(["check", path.join(ROOT, "site/samples/trifecta-polite/mcp.json"), "--allow-hold"], holdAllowed.io), 0);

  assert.equal(exitCodeForReports([{ verdict: { code: "CONDITIONS" } }], { strict: false }), 0);
  assert.equal(exitCodeForReports([{ verdict: { code: "CONDITIONS" } }], { strict: true }), 2);

  const sarifEmpty = formatSarif([{ target: { url: "https://clean.invalid" }, findings: [] }]);
  assert.equal(sarifEmpty.runs[0].results.length, 0);
});

test("CLI verify validates authentic ES256 artifacts and rejects tampered copies", async () => {
  const receiptPath = path.join(ROOT, "site/receipts/agent-customs-range.github.io/sunny_bakery/sunny_bakery.json");
  const validIo = makeIo();
  assert.equal(await runCli(["verify", receiptPath], validIo.io), 0);
  assert.match(validIo.stdout.join("\n"), /^VERIFIED/m);

  const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
  const sunnyServe = fsFetch({ "https://agent-customs-range.github.io": path.join(ROOT, "range") });
  const live = await inspectNetworkUrl("https://agent-customs-range.github.io/sunny_bakery/sunny_bakery", { fetchImpl: sunnyServe, pageOrigin: ROOT });
  const svg = certificateSvg(live, {
    receiptCheck: { valid: true, expired: false, matches: true, receipt: receipt.receipt },
    signedReceipt: receipt,
    verifyUrl: "https://montbaga.github.io/agent-customs/?inspect=sunny",
  });
  const tmp = await mkdtemp(path.join(os.tmpdir(), "ac-cli-"));
  try {
    const tamperedPath = path.join(tmp, "tampered.svg");
    await writeFile(tamperedPath, svg.replace("&quot;verdict&quot;:&quot;CLEARED&quot;", "&quot;verdict&quot;:&quot;DENIED&quot;"), "utf8");
    const tamperIo = makeIo();
    assert.equal(await runCli(["verify", tamperedPath], tamperIo.io), 2);
    assert.match(tamperIo.stdout.join("\n"), /^TAMPERED/m);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

test("root action.yml exposes composite inputs safely via env vars and pins setup-node SHA", async () => {
  const yml = await readFile(path.join(ROOT, "action.yml"), "utf8");
  assert.match(yml, /using:\s*["']composite["']/);
  assert.match(yml, /bin\/agent-customs\.mjs/);
  assert.match(yml, /target:/);
  assert.match(yml, /sarif-file:/);
  assert.match(yml, /actions\/setup-node@[0-9a-f]{40}\b/);
  const runPart = yml.split(/\n\s*run:\s*\|\r?\n/)[1] || "";
  assert.ok(runPart.length > 0, "expected run: | block in action.yml");
  assert.doesNotMatch(runPart, /\$\{\{/, "run script must read inputs via env vars, never inline ${{ }} expansion");
});

// ---- Agent Customs Bench ---------------------------------------------------------------

test("Agent Customs Bench runs reproducibly, separates detection from self-tests, and matches bench.json", async () => {
  const res = await runBenchmark();
  assert.ok(res.totalCases >= 100);
  assert.ok(res.hostileTotal >= 60);
  assert.ok(res.benignTotal >= 25);
  assert.equal(res.selfTestPassed, res.selfTestTotal);
  assert.ok(res.agentCustoms.catchRate > res.naiveRegexBaseline.catchRate);
  assert.equal(res.agentCustoms.falseBlocks, 0);
  assert.equal(res.agentCustoms.falsePositiveRate, 0);
  assert.match(formatBenchReport(res), /Agent Customs Bench/);

  const saved = JSON.parse(await readFile(path.join(ROOT, "site/bench.json"), "utf8"));
  assert.equal(saved.totalCases, res.totalCases);
  assert.equal(saved.hostileTotal, res.hostileTotal);
  assert.equal(saved.benignTotal, res.benignTotal);
  assert.equal(saved.selfTestTotal, res.selfTestTotal);
  assert.equal(saved.selfTestPassed, res.selfTestPassed);
  assert.equal(saved.agentCustoms.caught, res.agentCustoms.caught);
  assert.equal(saved.agentCustoms.round2Caught, res.agentCustoms.round2Caught);
  assert.equal(saved.agentCustoms.round3Caught, res.agentCustoms.round3Caught);
  assert.equal(saved.agentCustoms.heldoutCaught, res.agentCustoms.heldoutCaught);
  assert.equal(saved.agentCustoms.externalQuotedCaught, res.agentCustoms.externalQuotedCaught);
  assert.equal(saved.agentCustoms.falseBlocks, res.agentCustoms.falseBlocks);
});

// ---- Chrome / Edge MV3 Extension -------------------------------------------------------

test("extension/customs matches site/customs, manifest is valid MV3, and origin discovery works across protocols", async () => {
  for (const [from, to] of EXTENSION_COPIED_FOLDERS) {
    const srcFiles = await filesUnder(path.join(ROOT, from));
    const extFiles = await filesUnder(path.join(ROOT, to));
    assert.deepEqual(extFiles, srcFiles, `${to} drifted from ${from}: run npm run extension`);
    for (const rel of srcFiles) {
      const a = await readFile(path.join(ROOT, from, rel));
      const b = await readFile(path.join(ROOT, to, rel));
      assert.ok(a.equals(b), `${to}/${rel} differs from ${from}/${rel}: run npm run extension`);
    }
  }

  const manifest = JSON.parse(await readFile(path.join(ROOT, "extension/manifest.json"), "utf8"));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ["activeTab"]);
  assert.equal(manifest.host_permissions, undefined, "must not claim blanket up-front host_permissions");
  assert.deepEqual(manifest.optional_host_permissions, ["https://*/*"], "uses scoped optional HTTPS host permission");
  for (const iconRel of Object.values(manifest.icons)) {
    const png = await readFile(path.join(ROOT, "extension", iconRel));
    assert.deepEqual([...png.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  }
  const popupHtml = await readFile(path.join(ROOT, "extension/popup.html"), "utf8");
  assert.doesNotMatch(popupHtml, /<script(?![^>]*src=)/i, "MV3 CSP forbids inline scripts");

  // Discovery across A2A, MCP, Open Agentic Web, and plain HTML pages
  const a2aFetch = fsFetch({ "https://a2a.test": path.join(ROOT, "site/samples/a2a-clean") });
  const a2aRes = await inspectOriginAgents("https://a2a.test/about", { fetchImpl: a2aFetch });
  assert.equal(a2aRes.found, true);
  assert.equal(a2aRes.report.protocol, "a2a");
  assert.equal(a2aRes.report.verdict.code, "CLEARED");

  const mcpFetch = fsFetch({ "https://mcp.test": path.join(ROOT, "site/samples/mcp-poisoned") });
  const mcpRes = await inspectOriginAgents("https://mcp.test", { fetchImpl: mcpFetch });
  assert.equal(mcpRes.found, true);
  assert.equal(mcpRes.report.protocol, "mcp");
  assert.equal(mcpRes.report.verdict.code, "DENIED");

  const siteFetch = fsFetch({ "https://site.test": path.join(ROOT, "site") });
  const oawRes = await inspectOriginAgents("https://site.test", { fetchImpl: siteFetch });
  assert.equal(oawRes.found, true);
  assert.equal(oawRes.report.verdict.code, "CLEARED");

  const emptyFetch = fsFetch({ "https://plain.test": path.join(ROOT, "tools/fixtures") });
  const emptyRes = await inspectOriginAgents("https://plain.test", { fetchImpl: emptyFetch });
  assert.equal(emptyRes.found, false);
});
