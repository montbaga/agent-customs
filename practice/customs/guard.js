// guard.js: Agent Customs as a drop-in guard for any open agentic website.
//
//   import { installCustomsGuard } from "./customs/guard.js";
//   const { engine } = await boot("#agent-app", {...});
//   installCustomsGuard(engine);
//
// Every partner network the runtime loads is inspected after the visitor's consent
// card (so consent still comes before any contact) and before any of its agents run.
// The guard inspects the exact objects the runtime compiled, not a second download,
// so a partner cannot show one file to the inspector and run another.
//
//   DENIED / INVALID  -> refused. The calling agent gets an error that says why,
//                        and nothing from the partner runs (spec section 5, fail closed).
//   HOLD (or changed  -> the visitor sees the findings and decides. Approving pins
//    since approved)     the new version.
//   CONDITIONS/CLEARED-> admitted; the first version seen is pinned.
//
// It wraps engine._compile on this engine instance only. The runtime files are not
// edited, and uninstall() restores the original.

import { analyzeNetwork } from "./analyze.js";
import { PinStore, pinFromReport } from "./pins.js";

export const DEFAULT_POLICY = Object.freeze({
  deny: ["DENIED", "INVALID"],
  ask: ["HOLD"],
  pinOnFirstUse: true,
});

/**
 * Install the guard on a runtime engine.
 *
 * :param engine: The Engine from the runtime's boot().
 * :param options.policy: Override DEFAULT_POLICY fields.
 * :param options.store: A PinStore (defaults to this origin's localStorage).
 * :param options.confirmEntry: async (report) => boolean, for held networks. Defaults to
 *   a built-in dialog in a browser and to "refuse" anywhere else.
 * :param options.onReport: Called with every report, for logs and UI.
 * :return: {store, log, uninstall()}
 */
export function installCustomsGuard(engine, options = {}) {
  if (!engine || typeof engine._compile !== "function") {
    throw new Error("Agent Customs: this runtime has no _compile step to guard.");
  }
  if (engine.__agentCustoms) return engine.__agentCustoms;
  const policy = { ...DEFAULT_POLICY, ...(options.policy || {}) };
  const store = options.store || new PinStore();
  const log = [];
  const original = engine._compile;

  engine._compile = async function customsCompile(base, manifest, entry, opts = {}) {
    const compiled = await original.call(this, base, manifest, entry, opts);
    if (opts && opts.isTop) return compiled; // the site trusts its own network
    const name = entry?.name || compiled?.network?.name || "";
    const networkUrl = `${String(base).replace(/\/$/, "")}/${name}`;
    const network = compiled.network;
    let frontMan = null;
    try { frontMan = network.findFrontMan(); } catch { frontMan = null; }
    const pin = store.get(networkUrl);
    const report = await analyzeNetwork({
      networkUrl, manifest, entry, config: network.config, frontMan,
      linkSlots: [...(network.linkSlots || [])],
      validation: { errors: compiled.validation?.errors || [], warnings: compiled.validation?.warnings || [] },
      pin,
    });
    report.guard = { decision: "pending" };
    log.push(report);

    const code = report.verdict.code;
    if (policy.deny.includes(code)) {
      report.guard.decision = "refused";
      options.onReport?.(report);
      throw refusal(report);
    }
    if (policy.ask.includes(code) || report.drift?.changed) {
      const confirm = options.confirmEntry || defaultConfirm;
      let approved = false;
      try { approved = await confirm(report); } catch { approved = false; }
      if (!approved) {
        report.guard.decision = "declined";
        options.onReport?.(report);
        throw refusal(report, true);
      }
      store.set(networkUrl, pinFromReport(report, "reviewed"));
      report.guard.decision = "admitted after review";
    } else {
      if (!pin && policy.pinOnFirstUse) store.set(networkUrl, pinFromReport(report, "first-use"));
      report.guard.decision = "admitted";
    }
    options.onReport?.(report);
    return compiled;
  };

  const guard = {
    store, log, policy,
    uninstall() {
      engine._compile = original;
      delete engine.__agentCustoms;
    },
  };
  engine.__agentCustoms = guard;
  return guard;
}

/**
 * The error the calling agent receives. It names the verdict and our own rule
 * titles only: quoted text from the refused network never reaches the model.
 */
export function refusal(report, declinedByVisitor = false) {
  const titles = [...new Set(report.findings.filter((f) => ["critical", "high"].includes(f.severity)).map((f) => f.title))].slice(0, 3);
  const failed = report.conformance.checks.filter((c) => c.status === "fail").map((c) => c.title).slice(0, 2);
  const reasons = titles.concat(failed).join("; ") || report.verdict.summary;
  const who = `"${report.target.network}" from ${report.target.host}`;
  const message = declinedByVisitor
    ? `Agent Customs held ${who} for review and the visitor turned it away (${reasons}). Nothing from that network ran.`
    : `Agent Customs refused entry to ${who}: ${report.verdict.title.toLowerCase()} (${reasons}). Nothing from that network ran.`;
  const error = new Error(message);
  error.code = "AGENT_CUSTOMS_REFUSED";
  error.report = report;
  return error;
}

async function defaultConfirm(report) {
  if (typeof document === "undefined" || typeof HTMLDialogElement === "undefined") return false;
  const { confirmEntryDialog } = await import("./guard-ui.js");
  return confirmEntryDialog(report);
}
