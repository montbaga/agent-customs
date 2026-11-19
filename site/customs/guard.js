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
// After every decision the visitor gets a notice (guard-notice.js): what was decided, the
// full list of findings and a link to the full report.
//
// It wraps engine._compile on this engine instance only. The runtime files are not
// edited, and uninstall() restores the original.
//
// It also puts on two locks that hold whatever a scam says (locks.js): a real card number
// or IBAN never goes to a partner, and after a partner answers, website actions that change
// something wait for the visitor's click.

import { analyzeNetwork } from "./analyze.js";
import { applyJudge, createEngineJudge } from "./judge.js";
import { installLocks } from "./locks.js";
import { PinStore, pinFromReport } from "./pins.js";

export const DEFAULT_POLICY = Object.freeze({
  deny: ["DENIED", "INVALID"],
  ask: ["HOLD"],
  pinOnFirstUse: true,
});

export const STRICT_POLICY = Object.freeze({
  deny: ["DENIED", "INVALID"],
  ask: ["HOLD", "CONDITIONS", "CLEARED"],
  pinOnFirstUse: false,
});

/**
 * Install the guard on a runtime engine.
 *
 * :param engine: The Engine from the runtime's boot().
 * :param options.policy: Override DEFAULT_POLICY fields.
 * :param options.strict: Zero-trust mode: ask before every partner, never pin on first use,
 *   ignore trustedActions once a partner answers, block PII outbound and require
 *   declarative facts-only partner replies.
 * :param options.store: A PinStore (defaults to this origin's localStorage).
 * :param options.confirmEntry: async (report) => boolean, for held networks. Defaults to
 *   a built-in dialog in a browser and to "refuse" anywhere else.
 * :param options.onReport: Called with every report, for logs and UI.
 * :param options.notice: false shows the visitor no notice; a function (report) => boolean
 *   shows your own. By default, in a browser, a notice appears in the chat (guard-notice.js).
 * :param options.reportPage: The Agent Customs page that "See the full report" opens, with
 *   the network's address filled in. Defaults to the public Agent Customs site.
 * :param options.openReport: (url) => void. Shows the full report on this page instead.
 * :param options.locks: false turns off the runtime locks and reply quarantine (locks.js).
 *   They are on by default.
 * :param options.canary: false disables the synthetic Lock 3 canary tripwire (on by default).
 * :param options.canaryToken: Optional fixed canary token for tests or interactive demos.
 * :param options.onCanaryTrip: Called with {encoding, where, partners, revoked} when tripped.
 * :param options.semanticJudge: The AI double-check, off by default so checks stay
 *   deterministic and use no tokens. true turns it on. A function () => boolean is asked
 *   before each check, so a switch on the page can turn it on and off. When on, the site's
 *   AI also reads partners the rules cleared, their MCP tool lists and their replies, and it
 *   can only make a verdict stricter.
 * :param options.aiJudge: Your own judge, async ({kind, text, host}) => {checked, flagged,
 *   reason}, used in place of the site's AI. semanticJudge, when a function, still turns it
 *   on and off.
 * :param options.trustedActions: Names of website actions that only change harmless things
 *   on the page, or ask the visitor themselves, so the action lock lets them run.
 * :param options.onLock: Called with {lock, kind, where, reason} whenever a lock blocks
 *   something.
 * :return: {store, log, policy, locks, uninstall()}
 */
export function installCustomsGuard(engine, options = {}) {
  if (!engine || typeof engine._compile !== "function") {
    throw new Error("Agent Customs: this runtime has no _compile step to guard.");
  }
  if (engine.__agentCustoms) return engine.__agentCustoms;
  const strict = Boolean(options.strict);
  const policy = { ...(strict ? STRICT_POLICY : DEFAULT_POLICY), ...(options.policy || {}) };
  const store = options.store || new PinStore();
  const log = [];
  const partnerInfo = new Map();
  const original = engine._compile;
  const switchable = typeof options.semanticJudge === "function";
  const judgeOn = switchable
    ? () => { try { return options.semanticJudge() === true; } catch { return false; } }
    : () => true;
  const baseJudge = typeof options.aiJudge === "function"
    ? options.aiJudge
    : (options.semanticJudge === true || switchable ? createEngineJudge(engine) : null);
  // Replies and tool lists are checked through this one, so turning the switch off stops
  // every AI call at once.
  const aiJudge = baseJudge
    ? async (request) => (judgeOn() ? baseJudge(request) : { checked: false, flagged: false })
    : null;

  let locks = null;

  engine._compile = async function customsCompile(base, manifest, entry, opts = {}) {
    const compiled = await original.call(this, base, manifest, entry, opts);
    if (opts && opts.isTop) {
      if (compiled?.network) engine.top = { ...(engine.top || {}), network: compiled.network, base, manifest };
      locks?.syncTopCanary?.();
      return compiled; // the site trusts its own network
    }
    const name = entry?.name || compiled?.network?.name || "";
    const networkUrl = `${String(base).replace(/\/$/, "")}/${name}`;
    const network = compiled.network;
    let frontMan = null;
    try { frontMan = network.findFrontMan(); } catch { frontMan = null; }
    const pin = store.get(networkUrl);
    let report = await analyzeNetwork({
      networkUrl, manifest, entry, config: network.config, frontMan,
      linkSlots: [...(network.linkSlots || [])],
      validation: { errors: compiled.validation?.errors || [], warnings: compiled.validation?.warnings || [] },
      pin,
    });
    // Layer 2, the AI double-check: when it is on and the rules cleared the partner, the
    // isolated zero-tool judge reads it too. It can raise the verdict to Held, never lower it.
    if (baseJudge && judgeOn()) {
      report = await applyJudge(report, baseJudge, { config: network.config });
    }
    report.guard = { decision: "pending", pinned: false };
    log.push(report);
    partnerInfo.set(networkUrl, {
      allowLanguage: report.findings.some((f) => f.rule === "C-LANGUAGE"),
    });
    // Each decision goes to the site's log and, in a notice, to the visitor.
    const tell = async () => {
      options.onReport?.(report);
      return showNotice(report, options);
    };

    const code = report.verdict.code;
    if (policy.deny.includes(code)) {
      report.guard.decision = "refused";
      throw refusal(report, false, await tell());
    }
    if (policy.ask.includes(code) || report.drift?.changed) {
      const confirm = options.confirmEntry || defaultConfirm;
      let approved = false;
      try { approved = await confirm(report); } catch { approved = false; }
      if (!approved) {
        report.guard.decision = "declined";
        throw refusal(report, true, await tell());
      }
      store.set(networkUrl, pinFromReport(report, "reviewed"));
      report.guard.decision = "admitted after review";
      report.guard.pinned = true;
    } else {
      if (!pin && policy.pinOnFirstUse) {
        store.set(networkUrl, pinFromReport(report, "first-use"));
        report.guard.pinned = true;
      }
      report.guard.decision = "admitted";
    }
    await tell();
    return compiled;
  };

  locks = options.locks === false ? null : installLocks(engine, {
    trustedActions: options.trustedActions || [],
    strict,
    aiJudge,
    store,
    canary: options.canary,
    canaryToken: options.canaryToken,
    onCanaryTrip: (event) => {
      const revoked = [];
      for (const url of event.partners || []) {
        if (store.delete(url)) revoked.push(url);
      }
      for (const r of log) {
        if (r?.target?.url && (event.partners || []).includes(r.target.url)) {
          r.guard.canaryTripped = true;
          if (revoked.includes(r.target.url)) r.guard.pinned = false;
        }
      }
      options.onCanaryTrip?.({ ...event, revoked });
    },
    isForeignPartner: (base, name) => Boolean(partnerInfo.get(`${String(base).replace(/\/$/, "")}/${name || ""}`)?.allowLanguage),
    notify: (event) => {
      options.onLock?.(event);
      showLockNoticeSafe(event, options);
    },
  });

  const guard = {
    store, log, policy, locks, canary: locks?.canary || null,
    uninstall() {
      engine._compile = original;
      locks?.uninstall();
      delete engine.__agentCustoms;
    },
  };
  engine.__agentCustoms = guard;
  return guard;
}

/**
 * The error the calling agent receives. It names the verdict and our own rule
 * titles only: quoted text from the refused network never reaches the model.
 * It also says plainly what to tell the visitor, because a model that only reads
 * "error" may describe the partner as if it had answered. When the visitor got a
 * notice, it says so, so the agent can point to it.
 */
export function refusal(report, declinedByVisitor = false, noticeShown = false) {
  const titles = [...new Set(report.findings.filter((f) => ["critical", "high"].includes(f.severity)).map((f) => f.title))].slice(0, 3);
  const failed = report.conformance.checks.filter((c) => c.status === "fail").map((c) => c.title).slice(0, 2);
  const reasons = titles.concat(failed).join("; ") || report.verdict.summary;
  const who = `"${report.target.network}" from ${report.target.host}`;
  const seen = noticeShown ? " The visitor sees the full list in a notice on the page." : "";
  const message = declinedByVisitor
    ? `Agent Customs held ${who} for review and the visitor turned it away (${reasons}). Nothing from that network ran, so it gave no answer. Tell the visitor it was not used because they turned it away, and do not call it again in this turn.${seen}`
    : `Agent Customs refused entry to ${who}: ${report.verdict.title.toLowerCase()} (${reasons}). Nothing from that network ran, so it gave no answer. Tell the visitor that Agent Customs blocked this partner's assistant for safety, and do not call it again in this turn.${seen}`;
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

/**
 * Show the visitor what the guard decided. A notice never changes a decision.
 *
 * :return: true when a notice is on the page.
 */
async function showLockNoticeSafe(event, options) {
  if (options.notice === false || typeof options.notice === "function" || typeof document === "undefined") return;
  try {
    const { showLockNotice } = await import("./guard-notice.js");
    showLockNotice(event);
  } catch { /* a notice never changes a decision */ }
}

async function showNotice(report, options) {
  if (options.notice === false) return false;
  try {
    if (typeof options.notice === "function") return Boolean(await options.notice(report));
    if (typeof document === "undefined") return false;
    const { showGuardNotice } = await import("./guard-notice.js");
    return showGuardNotice(report, { reportPage: options.reportPage, openReport: options.openReport });
  } catch {
    return false;
  }
}
