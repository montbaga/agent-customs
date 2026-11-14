// guard-ui.js: the visitor's review dialog for a network Agent Customs held.
//
// Self-contained (inline styles), so any site can use it without our stylesheet.
// Everything from the inspected network is shown with textContent, never as HTML.

const SEVERITY_COLORS = { critical: "#ff5f6d", high: "#ff9a4d", medium: "#ffc65c", low: "#9aa6bd", info: "#9aa6bd" };

/**
 * Ask the visitor whether to let a held network run.
 *
 * :param report: The inspection report.
 * :return: Promise<boolean>, true when the visitor lets it in.
 */
export function confirmEntryDialog(report) {
  return new Promise((resolve) => {
    const dialog = document.createElement("dialog");
    dialog.className = "customs-review";
    dialog.setAttribute("aria-labelledby", "customs-review-title");
    dialog.style.cssText = "max-width:560px;width:calc(100% - 32px);border:1px solid rgba(255,255,255,.14);border-radius:18px;padding:0;color:var(--c2,#eef2f8);background:color-mix(in oklab,var(--c1,#0d1422) 94%,var(--c2,#fff));box-shadow:0 30px 80px rgba(0,0,0,.6);font:15px/1.5 Geist,system-ui,-apple-system,Segoe UI,Roboto,sans-serif";
    const head = el("div", "", "padding:20px 22px 14px;border-bottom:1px solid rgba(255,255,255,.1)");
    const kicker = el("p", "Agent Customs · secondary inspection", "margin:0 0 4px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--c3,#ffb84d);font-weight:700");
    const title = el("h2", `Let "${report.target.network}" from ${report.target.host} run?`, "margin:0;font-size:19px;line-height:1.3");
    title.id = "customs-review-title";
    title.tabIndex = -1;
    head.append(kicker, title);
    const body = el("div", "", "padding:14px 20px;max-height:52vh;overflow:auto");
    body.append(el("p", report.drift?.changed
      ? "It changed since you approved it. Review what is different before it runs on this page with your AI key."
      : "Inspection found issues to review before it runs on this page with your AI key.", "margin:0 0 10px"));
    const list = el("ul", "", "margin:0 0 10px;padding-left:18px");
    for (const f of report.findings.filter((x) => ["critical", "high", "medium"].includes(x.severity)).slice(0, 6)) {
      const li = el("li", "", "margin:0 0 6px");
      const sev = el("strong", f.severity.toUpperCase() + " ", `color:${SEVERITY_COLORS[f.severity]};font-size:12px`);
      li.append(sev, document.createTextNode(f.title));
      if (f.detail) li.append(el("div", f.detail, "color:#8d99ad;font-size:13px"));
      list.append(li);
    }
    body.append(list);
    if (report.drift?.changed) {
      const changes = el("details", "", "margin:0 0 8px");
      changes.append(el("summary", `What changed (${report.drift.changes.length})`, "cursor:pointer;font-weight:600"));
      for (const c of report.drift.changes.slice(0, 8)) {
        const block = el("div", "", "margin:8px 0");
        block.append(el("div", c.title, "font-weight:600;font-size:13px"));
        for (const line of (c.added || []).slice(0, 6)) block.append(el("pre", "+ " + line, "margin:2px 0;white-space:pre-wrap;font-size:12px;background:rgba(61,220,151,.1);color:#7fefbf;padding:2px 6px;border-radius:4px"));
        for (const line of (c.removed || []).slice(0, 4)) block.append(el("pre", "− " + line, "margin:2px 0;white-space:pre-wrap;font-size:12px;background:rgba(255,95,109,.1);color:#ff9aa3;padding:2px 6px;border-radius:4px"));
        changes.append(block);
      }
      body.append(changes);
    }
    body.append(el("p", `Fingerprint ${report.identity.short}. Letting it in pins this version for this browser.`, "margin:8px 0 0;color:#8d99ad;font-size:12px"));
    const foot = el("div", "", "display:flex;gap:10px;justify-content:flex-end;padding:14px 22px 18px;border-top:1px solid rgba(255,255,255,.1);flex-wrap:wrap");
    const deny = el("button", "Turn it away", "font:inherit;font-weight:600;padding:10px 16px;border-radius:10px;border:0;background:var(--c3,#eef2f8);color:var(--on-c3,#061019);cursor:pointer");
    const admit = el("button", "Let it in this time", "font:inherit;padding:10px 16px;border-radius:10px;border:1px solid rgba(255,255,255,.2);background:transparent;color:#eef2f8;cursor:pointer");
    deny.addEventListener("click", () => dialog.close("deny"));
    admit.addEventListener("click", () => dialog.close("admit"));
    foot.append(admit, deny);
    dialog.append(head, body, foot);
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(dialog.returnValue === "admit");
    });
    document.body.append(dialog);
    dialog.showModal();
    title.focus();
  });
}

function el(tag, text, css) {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (css) node.style.cssText = css;
  return node;
}
