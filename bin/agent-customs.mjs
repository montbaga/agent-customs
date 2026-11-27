#!/usr/bin/env node
// agent-customs CLI: inspect agent networks, verify certificates, run benchmarks, or serve MCP.
import { realpathSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyDroppedArtifact } from "../site/certificate.js";
import { inspectTarget, inspectWeb } from "../tools/inspect-local.mjs";
import { formatBenchReport, runBenchmark } from "../tools/bench.mjs";
import { serveMcpStdio } from "../tools/mcp-server.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PUBLIC_KEY_FILE = path.join(ROOT, "site", ".well-known", "agent-customs-key.json");
const BENCH_OUT_FILE = path.join(ROOT, "site", "bench.json");

const SEVERITY_TO_SARIF = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

/**
 * Determine CI exit code from inspected reports (0 clear, 1 held, 2 denied/unreadable).
 */
export function exitCodeForReports(reports, { strict = false, allowHold = false } = {}) {
  let code = 0;
  for (const r of reports) {
    const v = r?.verdict?.code;
    if (v === "DENIED" || v === "INVALID" || v === "UNREADABLE" || r?.failure) return 2;
    if (v === "HOLD" && !allowHold) code = Math.max(code, strict ? 2 : 1);
    if (v === "CONDITIONS" && strict) code = Math.max(code, 2);
  }
  return code;
}

/**
 * Convert inspection reports into a SARIF v2.1.0 document for GitHub Code Scanning.
 */
export function formatSarif(reports) {
  const rules = new Map();
  const results = [];
  for (const r of reports) {
    const uri = r.target?.url || "unknown";
    for (const f of r.findings || []) {
      const ruleId = f.rule || "AC-FINDING";
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          shortDescription: { text: f.title || ruleId },
          defaultConfiguration: { level: SEVERITY_TO_SARIF[f.severity] || "warning" },
        });
      }
      const where = [f.where?.agent, f.where?.field].filter(Boolean).join(".");
      results.push({
        ruleId,
        level: SEVERITY_TO_SARIF[f.severity] || "warning",
        message: { text: `${f.title}${where ? ` (${where})` : ""}: ${f.detail || f.evidence || r.verdict?.summary || ""}` },
        locations: [{ physicalLocation: { artifactLocation: { uri } } }],
      });
    }
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Agent Customs", informationUri: "https://montbaga.github.io/agent-customs/", rules: [...rules.values()] } },
      results,
    }],
  };
}

function parseFlags(args) {
  const flags = new Set();
  const values = new Map();
  const positionals = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === "--out" || a === "--sarif-file" || a === "--pins") {
      values.set(a, args[i + 1] || "");
      i += 1;
    } else if (a.startsWith("--")) {
      flags.add(a);
    } else {
      positionals.push(a);
    }
  }
  return { flags, values, positionals };
}

function helpText() {
  return [
    "Usage:",
    "  agent-customs check <url-or-path...> [--strict] [--allow-hold] [--transitive] [--json] [--sarif]",
    "  agent-customs verify <file> [--live] [--json]",
    "  agent-customs bench [--json] [--write]",
    "  agent-customs mcp [--pins <file>]",
  ].join("\n");
}

async function cmdCheck(positionals, flags, log) {
  if (!positionals.length) {
    log.error("Specify one or more URLs, local folders, or JSON manifests.");
    return 2;
  }
  const strict = flags.has("--strict");
  const allowHold = flags.has("--allow-hold");
  const transitive = flags.has("--transitive");
  const asJson = flags.has("--json");
  const asSarif = flags.has("--sarif");

  const reports = [];
  for (const target of positionals) {
    reports.push(await inspectTarget(target, { transitive }));
  }

  if (asSarif) {
    log.out(JSON.stringify(formatSarif(reports), null, 2));
  } else if (asJson) {
    log.out(JSON.stringify(reports.map((r) => ({
      target: r.target?.url,
      protocol: r.protocol,
      verdict: r.verdict,
      fingerprint: r.identity?.hash || "",
      conformance: { passed: r.conformance?.passed, total: r.conformance?.total, failed: r.conformance?.failed },
      findings: (r.findings || []).map((f) => ({ severity: f.severity, rule: f.rule, title: f.title, where: f.where })),
    })), null, 2));
  } else {
    for (const r of reports) {
      log.out(`${r.verdict.code.padEnd(10)} ${r.target?.url || "unknown"} (${r.conformance?.passed}/${r.conformance?.total} checks, ${r.identity?.short || "no hash"})`);
      if (r.failure && r.verdict.summary) log.out(`  ${r.verdict.summary}`);
      for (const f of r.findings || []) {
        log.out(`  [${f.severity}] ${f.rule}: ${f.title}`);
      }
    }
  }
  return exitCodeForReports(reports, { strict, allowHold });
}

async function cmdVerify(positionals, flags, log) {
  const file = positionals[0];
  if (!file) {
    log.error("Specify a certificate or receipt file (.svg, .json, .html, or .pdf).");
    return 2;
  }
  const bytes = new Uint8Array(await readFile(path.resolve(file)));
  const keyDoc = JSON.parse(await readFile(PUBLIC_KEY_FILE, "utf8"));
  const initial = await verifyDroppedArtifact({ bytes, name: path.basename(file) }, {
    fileName: path.basename(file),
    publicJwk: keyDoc.publicKey,
  });
  let finalRes = initial;
  if (flags.has("--live") && initial.ok && initial.status !== "tampered" && initial.artifact?.url) {
    const liveReport = await inspectWeb(initial.artifact.url);
    finalRes = await verifyDroppedArtifact({ bytes, name: path.basename(file) }, {
      fileName: path.basename(file),
      publicJwk: keyDoc.publicKey,
      liveReport,
    });
  }
  if (flags.has("--json")) {
    log.out(JSON.stringify(finalRes, null, 2));
  } else if (!finalRes.ok) {
    log.out(`INVALID   ${file}: ${finalRes.reason}`);
  } else {
    log.out(`${finalRes.status.toUpperCase().padEnd(9)} ${file}: ${finalRes.headline}`);
    if (finalRes.liveSummary) log.out(`          ${finalRes.liveSummary}`);
  }
  return !finalRes.ok || finalRes.status === "tampered" || finalRes.status === "changed" ? 2 : 0;
}

async function cmdBench(flags, values, log) {
  const bench = await runBenchmark();
  if (flags.has("--write") || values.get("--out")) {
    const outPath = path.resolve(values.get("--out") || BENCH_OUT_FILE);
    await writeFile(outPath, JSON.stringify(bench, null, 2) + "\n", "utf8");
  }
  if (flags.has("--json")) {
    log.out(JSON.stringify(bench, null, 2));
  } else {
    log.out(formatBenchReport(bench));
  }
  return 0;
}

export async function runCli(argv = process.argv.slice(2), io = { out: console.log, error: console.error }) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === "--help" || cmd === "-h") {
    io.out(helpText());
    return 0;
  }
  const { flags, values, positionals } = parseFlags(rest);
  if (cmd === "check") return cmdCheck(positionals, flags, io);
  if (cmd === "verify") return cmdVerify(positionals, flags, io);
  if (cmd === "bench") return cmdBench(flags, values, io);
  if (cmd === "mcp") {
    const pinsFile = values.get("--pins");
    await serveMcpStdio(pinsFile ? { pinsFile } : {});
    return 0;
  }
  io.error(`Unknown command "${cmd}".\n${helpText()}`);
  return 2;
}

// npx and global installs on macOS and Linux start this file through a link, and npx in
// this repository links the folder itself, so compare real paths.
function startedDirectly(argvPath) {
  try { return realpathSync(argvPath) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
}

if (process.argv[1] && startedDirectly(process.argv[1])) {
  const exitCode = await runCli();
  if (exitCode) process.exit(exitCode);
}
