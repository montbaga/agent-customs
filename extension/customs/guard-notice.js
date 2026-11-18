// guard-notice.js: what the visitor sees after the guard decides about a partner network.
// A notice goes into the chat, just after the partner's consent card, or into a corner of
// the page when the page has no runtime chat. It gives the decision, the full list of what
// Agent Customs found and a link to the full report.
//
// Self-contained (inline styles), so any site can use it without our stylesheet. Every word
// in the notice is Agent Customs' own: rule titles, verdicts and counts. Nothing written by
// the inspected network is shown, not even its decoded hidden text. So even a page tool that
// reads the whole page cannot hand that network's words to the AI. The full report shows
// them, on the Agent Customs page.

export const DEFAULT_REPORT_PAGE = "https://montbaga.github.io/agent-customs/";

const SEVERITY_ORDER = ["spec", "critical", "high", "medium", "low", "info"];
const TONE = { ok: "var(--ok, #8fd1a6)", caution: "var(--caution, #e9c46a)", warn: "var(--warn, #f0a35e)", bad: "var(--bad, #f2665a)" };
const SEVERITY = {
  spec: { label: "Spec", color: TONE.bad }, critical: { label: "Critical", color: TONE.bad },
  high: { label: "High", color: TONE.warn }, medium: { label: "Medium", color: TONE.caution },
  low: { label: "Low", color: "#9aa6bd" }, info: { label: "Info", color: "#9aa6bd" },
};
const SHOWN = 6; // items shown before "Show more"

/**
 * The Agent Customs page that shows the full report, with the network's address filled in.
 * The visitor still presses Inspect there, so nothing is contacted until they choose to.
 *
 * :param report: The guard's report.
 * :param page: The Agent Customs page to open.
 * :return: The link.
 */
export function reportLink(report, page = DEFAULT_REPORT_PAGE) {
  const link = new URL(page);
  link.searchParams.set("inspect", report.target.url);
  return link.href;
}

/**
 * What the notice says, as plain data, for every decision the guard makes.
 *
 * :param report: The guard's report, with report.guard.decision set.
 * :param options.reportPage: The page "See the full report" opens.
 * :return: {tone, title, stamp, lines, items: [{severity, label, title, count}], link, url}
 */
export function noticeContent(report, { reportPage = DEFAULT_REPORT_PAGE } = {}) {
  const decision = report.guard?.decision;
  const who = `"${report.target.network}" from ${report.target.host}`;
  const changed = Boolean(report.drift?.changed);
  const pinned = Boolean(report.guard?.pinned);
  let tone, title, lines;
  if (decision === "refused") {
    tone = "bad";
    title = `Blocked ${who}`;
    lines = [report.verdict.code === "INVALID"
      ? "Its files do not follow the Open Agentic Web spec, so it was refused before it could run. Nothing from it ran."
      : "Agent Customs inspected it before it could run, and refused it. Nothing from it ran.",
    "Your assistant was told why, in Agent Customs' own words."];
  } else if (decision === "declined") {
    tone = "warn";
    title = `Turned away ${who}`;
    lines = [changed
      ? "It changed since you approved it, and you chose not to let the new version run. Nothing from it ran."
      : "It was held for review, and you chose not to let it run. Nothing from it ran."];
  } else if (decision === "admitted after review") {
    tone = "warn";
    title = `Let in ${who}`;
    lines = [changed
      ? "You let the changed version run after review. It is now the approved version in this browser."
      : "You let it run after review. This version is now approved in this browser, and if it changes, you will be asked again."];
  } else {
    tone = report.verdict.code === "CLEARED" ? "ok" : "caution";
    title = `Checked ${who}`;
    lines = [report.drift && !changed
      ? "It matches the version approved in this browser, so it ran."
      : pinned
        ? "It passed inspection, so it ran. This version is now approved in this browser, and if it changes, you will be asked first."
        : "It passed inspection, so it ran."];
  }

  // Every distinct finding, worst first, plus any spec check that failed.
  const groups = new Map();
  const add = (severity, text) => {
    const key = `${severity}|${text}`;
    const g = groups.get(key) || { severity, label: SEVERITY[severity]?.label || severity, title: text, count: 0 };
    g.count += 1;
    groups.set(key, g);
  };
  for (const c of report.conformance?.checks || []) if (c.status === "fail") add("spec", c.title);
  for (const f of report.findings || []) add(f.severity, f.title);
  const items = [...groups.values()].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  if (changed) lines.push(`${report.drift.changes.length} change(s) since you approved it: the full report lists each one.`);

  return { tone, title, stamp: report.verdict.stamp, lines, items, link: reportLink(report, reportPage), url: report.target.url };
}

/**
 * Show the notice for one decision.
 *
 * :param report: The guard's report.
 * :param options.reportPage: The page "See the full report" opens in a new tab.
 * :param options.openReport: (url) => void. Shows the full report on this page instead.
 * :return: true once the notice is on the page.
 */
export function showGuardNotice(report, { reportPage, openReport } = {}) {
  const c = noticeContent(report, { reportPage });
  const tone = TONE[c.tone];
  const ink = `color-mix(in oklab, ${tone} 72%, currentColor)`;
  const box = el("section", "", `margin:10px 0;padding:12px 14px 12px 16px;border-radius:14px;border:1px solid color-mix(in oklab, ${tone} 45%, transparent);border-left:4px solid ${tone};background:color-mix(in oklab, ${tone} 9%, transparent);font-family:inherit;font-size:14px;line-height:1.5;max-width:680px;overflow-wrap:anywhere`);
  box.className = "customs-notice";
  box.dataset.decision = report.guard?.decision || "";
  box.dataset.verdict = report.verdict.code;
  box.setAttribute("role", "status");
  box.setAttribute("aria-label", `Agent Customs: ${c.title}`);

  const head = el("div", "", "display:flex;align-items:center;justify-content:space-between;gap:10px");
  head.append(el("span", "Agent Customs", `font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:${ink}`),
    el("span", c.stamp, `flex:none;font:700 11px/1 ui-monospace,"Geist Mono",Menlo,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase;color:${ink};border:2px double ${tone};border-radius:6px;padding:4px 7px;transform:rotate(-3deg)`));
  box.append(head, el("p", c.title, "margin:6px 0 4px;font-size:15px;font-weight:600"));
  for (const line of c.lines) box.append(el("p", line, "margin:0 0 4px;opacity:.88"));

  if (c.items.length) {
    box.append(el("p", c.items.length === 1 ? "What Agent Customs found:" : `What Agent Customs found (${c.items.length}):`, "margin:10px 0 6px;font-weight:600;font-size:13px"));
    const list = el("ul", "", "list-style:none;margin:0 0 4px;padding:0;display:grid;gap:5px");
    const more = el("ul", "", "list-style:none;margin:6px 0 0;padding:0;display:grid;gap:5px");
    c.items.forEach((item, i) => (i < SHOWN || c.items.length <= SHOWN + 1 ? list : more).append(itemRow(item)));
    box.append(list);
    if (more.children.length) {
      const details = el("details", "", "margin:2px 0 0");
      details.append(el("summary", `Show ${more.children.length} more`, "cursor:pointer;font-size:13px;opacity:.85"), more);
      box.append(details);
    }
  }

  const actions = el("div", "", "display:flex;flex-wrap:wrap;align-items:center;gap:6px 16px;margin-top:10px");
  const link = el("a", "See the full report", `font-weight:600;color:inherit;text-decoration:underline;text-decoration-color:${tone};text-underline-offset:3px`);
  link.href = c.link;
  if (openReport) {
    link.addEventListener("click", (event) => { event.preventDefault(); openReport(c.url); });
  } else {
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.append(el("span", " (opens Agent Customs)", "font-weight:400;opacity:.75"));
  }
  actions.append(link);
  box.append(actions);

  place(box);
  return true;
}

/**
 * Show that a lock kept a secret back or blocked an unsafe runtime reply (locks.js).
 *
 * :param event: {lock, kind, where, reason} from the lock.
 * :return: true once the notice is on the page.
 */
export function showLockNotice({ lock = 1, kind, where, reason = "" }) {
  const tone = TONE.bad;
  const ink = `color-mix(in oklab, ${tone} 72%, currentColor)`;
  const box = el("section", "", `margin:10px 0;padding:12px 14px 12px 16px;border-radius:14px;border:1px solid color-mix(in oklab, ${tone} 45%, transparent);border-left:4px solid ${tone};background:color-mix(in oklab, ${tone} 9%, transparent);font-family:inherit;font-size:14px;line-height:1.5;max-width:680px;overflow-wrap:anywhere`);
  box.className = "customs-notice";
  box.dataset.lock = kind;
  box.setAttribute("role", "status");
  const isReplyBlock = lock === 2;
  const isCanaryTrip = lock === 3;
  box.setAttribute("aria-label", isCanaryTrip ? `Agent Customs tripped a ${kind}` : isReplyBlock ? `Agent Customs blocked an ${kind}` : `Agent Customs kept a ${kind} back`);
  const head = el("div", "", "display:flex;align-items:center;justify-content:space-between;gap:10px");
  head.append(el("span", "Agent Customs", `font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:${ink}`),
    el("span", isCanaryTrip ? "Canary tripped" : isReplyBlock ? "Blocked" : "Kept safe", `flex:none;font:700 11px/1 ui-monospace,"Geist Mono",Menlo,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase;color:${ink};border:2px double ${tone};border-radius:6px;padding:4px 7px;transform:rotate(-3deg)`));
  const titleText = isCanaryTrip ? `Tripped ${kind} in ${where}` : isReplyBlock ? `Blocked ${kind} in ${where}` : `Kept a ${kind} out of ${where}`;
  const detailText = isCanaryTrip
    ? `${reason ? `${reason}. ` : ""}Protected host context tried to leave its boundary, so execution stopped and involved partner approvals were removed.`
    : isReplyBlock
      ? `${reason ? `${reason}. ` : ""}Nothing from that reply reached the assistant or the page.`
      : "Card numbers, bank account numbers, keys and passwords never go to a partner's assistant, an outside tool or a website action a partner could have prompted. Nothing was sent.";
  box.append(head, el("p", titleText, "margin:6px 0 4px;font-size:15px;font-weight:600"),
    el("p", detailText, "margin:0 0 4px;opacity:.88"),
    el("div", "", "display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:4px"));
  place(box);
  return true;
}

function itemRow(item) {
  const sev = SEVERITY[item.severity] || SEVERITY.info;
  const row = el("li", "", "display:flex;gap:8px;align-items:baseline");
  row.append(el("span", sev.label, `flex:none;box-sizing:border-box;width:74px;text-align:center;font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:1px 6px;border-radius:999px;color:color-mix(in oklab, ${sev.color} 72%, currentColor);border:1px solid color-mix(in oklab, ${sev.color} 50%, transparent)`),
    el("span", item.count > 1 ? `${item.title} (${item.count})` : item.title));
  return row;
}

// In the runtime's chat, right after the consent card the visitor just answered for this
// partner. With no card in this turn (say, after "Always allow"), at the end of the chat.
// Without a chat, in a corner of the page.
function place(box) {
  const msgs = document.querySelector("#ns-msgs");
  if (msgs) {
    const inChat = (node) => { while (node && node.parentElement !== msgs) node = node.parentElement; return node; };
    const last = (selector) => { const all = msgs.querySelectorAll(selector); return inChat(all[all.length - 1]); };
    const card = last(".ns-consent"), asked = last(".ns-msg.user");
    const thisTurn = card && (!asked || (asked.compareDocumentPosition(card) & Node.DOCUMENT_POSITION_FOLLOWING));
    if (thisTurn) card.after(box); else msgs.append(box);
    msgs.scrollTop = msgs.scrollHeight;
    return;
  }
  let corner = document.getElementById("customs-notices");
  if (!corner) {
    corner = el("div", "", "position:fixed;right:16px;bottom:16px;z-index:2147483000;width:min(440px,calc(100vw - 32px));max-height:calc(100vh - 32px);overflow:auto;display:grid;gap:10px");
    corner.id = "customs-notices";
    document.body.append(corner);
  }
  box.style.margin = "0";
  box.style.background = "#10161f";
  box.style.color = "#eef2f8";
  box.style.boxShadow = "0 18px 50px rgba(0,0,0,.45)";
  const close = el("button", "Close", "margin-left:auto;font:inherit;font-size:13px;padding:4px 10px;border-radius:8px;border:1px solid rgba(255,255,255,.25);background:transparent;color:inherit;cursor:pointer");
  close.type = "button";
  close.addEventListener("click", () => box.remove());
  box.lastElementChild.append(close);
  corner.append(box);
}

function el(tag, text, css) {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (css) node.style.cssText = css;
  return node;
}
