// view.js: renders the desk (desk.js) into the page and wires the page's own forms.
//
// Everything that comes from an inspected network is inserted with text nodes, never
// as HTML, so a hostile network cannot put markup into this page.
import { ARENA_SCENARIOS, runArenaScenario } from "./arena.js";
import { EXAMPLES, NOT_APPROVABLE, PROTOCOL_SAMPLES, desk } from "./desk.js";
import { certificateFilename, certificateHtml, certificateMeta, certificateSvg, verifyDroppedArtifact } from "./certificate.js";
import { matchesPin } from "./customs/diff.js";
import { inspectNetworkUrl } from "./customs/inspect.js";
import { verifyReceipt } from "./customs/receipts.js";

const SEVERITY_TONE = { critical: "bad", high: "warn", medium: "caution", low: "info", info: "info" };
const SEVERITY_RANK = ["critical", "high", "medium", "low", "info"];
const PROTOCOL_LABELS = { "open-agentic-web": "Open Agentic Web", a2a: "Google A2A", mcp: "MCP Catalog" };
const PAPER_TITLES = { "open-agentic-web": "Open Agentic Web spec", a2a: "A2A Agent Card checks", mcp: "MCP catalog checks" };
const $ = (sel) => document.querySelector(sel);

// ---- Workspace tabs: one panel at a time ---------------------------------------------
const TAB_PANELS = { report: "report-section", officer: "assistant", compare: "compare", verify: "verify-panel", approvals: "desk" };

function showTab(name, { focus = false } = {}) {
  for (const [tab, panelId] of Object.entries(TAB_PANELS)) {
    const button = document.querySelector(`[role="tab"][data-tab="${tab}"]`);
    const panel = document.getElementById(panelId);
    const active = tab === name;
    if (button) {
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
      if (active && focus) button.focus();
    }
    if (panel) panel.hidden = !active;
  }
  const resetBtn = $("#report-reset");
  if (resetBtn) resetBtn.hidden = name !== "report" || !$("#report") || $("#report").hidden;
  moveHighlight();
}

function moveHighlight() {
  const list = document.querySelector(".tabs");
  const highlight = list?.querySelector(".tabs-highlight");
  const selected = list?.querySelector('[role="tab"][aria-selected="true"]');
  if (!highlight || !selected) return;
  list.style.setProperty("--tabs-w", `${list.scrollWidth}px`);
  const left = selected.offsetLeft;
  const right = list.scrollWidth - (left + selected.offsetWidth);
  highlight.style.clipPath = `inset(4px ${right}px 4px ${left}px round 10px)`;
}

function revealWorkspace(behavior = "smooth") {
  document.querySelector("#workspace")?.scrollIntoView({ block: "start", behavior });
}

function wireTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"][data-tab]')];
  for (const tab of tabs) {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
    tab.addEventListener("keydown", (event) => {
      const i = tabs.indexOf(tab);
      const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[event.key];
      if (next === undefined) return;
      event.preventDefault();
      showTab(tabs[(next + tabs.length) % tabs.length].dataset.tab, { focus: true });
    });
  }
  // Links such as "Officer" in the navigation open their tab.
  for (const link of document.querySelectorAll("a[data-tab-link]")) {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      showTab(link.dataset.tabLink);
      revealWorkspace();
    });
  }
  if (location.hash === "#assistant") showTab("officer");
  // Place the highlight before turning its transition on, so the first paint does not slide.
  moveHighlight();
  requestAnimationFrame(() => document.querySelector(".tabs")?.classList.add("ready"));
  window.addEventListener("resize", moveHighlight, { passive: true });
  document.fonts?.ready.then(moveHighlight);
}

/** Build an element. Strings become text nodes. */
const SVG_NS = "http://www.w3.org/2000/svg";
/** An icon from the page's SVG sprite. */
function icon(id, className) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", className);
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `#${id}`);
  svg.append(use);
  return svg;
}

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : String(child));
  }
  return el;
}

function fmtDate(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch {
    return String(iso);
  }
}

function stampDate(iso) {
  try {
    return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }).toUpperCase();
  } catch {
    return "";
  }
}

function worstTone(findings) {
  const worst = SEVERITY_RANK.find((s) => findings.some((f) => f.severity === s));
  return worst ? (SEVERITY_TONE[worst] === "info" ? "ok" : SEVERITY_TONE[worst]) : "ok";
}

function pill(severity) {
  return h("span", { class: `pill sev-${severity}` }, severity);
}

// ---- Report ----------------------------------------------------------------------

function renderReport({ animate = false } = {}) {
  const report = desk.latest;
  const box = $("#report");
  if (!report) return;
  $("#report-empty").hidden = true;
  box.hidden = false;
  box.replaceChildren();
  const resetBtn = $("#report-reset");
  if (resetBtn) resetBtn.hidden = $("#report-section")?.hidden ?? false;
  const tone = report.verdict.tone;
  const title = report.identity.brand || report.target.network || report.target.host || "Inspection";

  const facts = h("dl", { class: "facts" });
  const fact = (label, value, mono = false) => {
    if (value === "" || value === null || value === undefined) return;
    facts.append(h("div", null, h("dt", null, label), h("dd", { class: mono ? "mono" : null }, value)));
  };
  fact("Protocol", PROTOCOL_LABELS[report.protocol] || report.protocol || "Open Agentic Web");
  fact("Fingerprint", report.identity.short, true);
  fact("Agents", report.identity.agents.length || "");
  fact("Front agent", report.identity.frontMan, true);
  fact("Model hint", report.identity.model, true);
  fact("Spec checks", `${report.conformance.passed}/${report.conformance.total} pass`);
  // Agent Customs' signed stamp for this network, when one is published (receipts/).
  const receiptLine = h("p", { class: "receipt-line", hidden: true, "aria-live": "polite" });
  if (!report.failure) showReceipt(report, receiptLine);

  // What the AI double-check did, or that it was off.
  const aiLine = h("p", { id: "ai-line", class: "ai-line", hidden: Boolean(report.failure) });
  if (!report.failure) fillAiLine(report, aiLine);

  box.append(h("header", { class: "report-head" },
    h("div", { class: "stamp-stack" },
      h("div", { class: `stamp tone-${tone}${animate ? " animate" : ""}`, role: "img", "aria-label": `Verdict: ${report.verdict.stamp}` },
        h("strong", null, report.verdict.stamp),
        h("small", null, h("span", null, "Agent Customs"), h("span", null, stampDate(report.inspectedAt)))),
      report.failure ? null : countersign(report.aiCheck, animate)),
    h("div", null,
      h("h2", { id: "report-title", tabindex: "-1" }, title),
      h("p", { class: "report-url" }, report.target.url),
      h("p", { class: "report-summary" }, report.verdict.summary),
      aiLine,
      receiptLine,
      facts)));

  if (!report.failure) box.append(renderLights(report));

  const main = h("div", { class: "report-main" });
  const side = h("div", { class: "report-side" });
  if (!report.failure) main.append(renderFindings(report));
  main.append(renderPapers(report));
  if (report.drift?.changed) side.append(renderDrift(report));
  if (!report.failure) {
    side.append(renderItinerary(report));
    if (report.capabilities && (report.capabilities.trifecta || report.capabilities.sensitiveAccess?.length || report.capabilities.externalEgress?.length)) {
      side.append(renderCapabilities(report));
    }
    if (report.transitive?.checked?.length) side.append(renderTransitive(report));
    if (report.privacy.length) side.append(renderPrivacy(report));
    if (report.conditions.length) {
      side.append(h("div", { class: "report-block" }, h("h3", null, "Conditions of entry"),
        h("ul", { class: "conditions" }, report.conditions.map((c) => h("li", null, c)))));
    }
  } else if (report.choices?.length) {
    side.append(h("div", { class: "report-block" }, h("h3", null, "Networks on this site"),
      h("ul", { class: "stops" }, report.choices.map((url) => h("li", null,
        h("button", { type: "button", class: "ghost small", onclick: () => runInspect(url) }, "Inspect"), " ",
        h("span", { class: "host" }, url))))));
  }
  box.append(h("div", { class: "report-body" }, main, side));
  if (animate) {
    // One entrance: the stamp lands (lead), the first findings rise after it with
    // shrinking gaps (support), the lights fade together (decoration).
    const gaps = [60, 100, 135, 165, 190, 210];
    [...box.querySelectorAll(".finding")].slice(0, gaps.length).forEach((el, i) => {
      el.style.setProperty("--sd", `${gaps[i]}ms`);
      el.classList.add("stagger");
    });
    box.querySelectorAll(".light").forEach((el) => { el.style.setProperty("--sd", "40ms"); el.classList.add("stagger"); });
  }
  box.append(renderReportActions(report));
}

// ---- AI double-check -------------------------------------------------------------------
// When the visitor's AI has read a network, a round seal countersigns the verdict stamp.

const SEAL_RING = { clear: "AI double-check · nothing found · ", flagged: "AI double-check · flagged for review · " };

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  return node;
}

function countersign(check, animate) {
  const ring = SEAL_RING[check?.status];
  if (!ring) return null;
  const seal = svgEl("svg", {
    class: `countersign tone-${check.status === "flagged" ? "warn" : "ok"}${animate ? " animate" : ""}`,
    viewBox: "0 0 100 100", "aria-hidden": "true",
  });
  const words = svgEl("textPath", { href: "#countersign-ring", textLength: 224, lengthAdjust: "spacing" });
  words.textContent = ring.toUpperCase();
  const text = svgEl("text");
  text.append(words);
  seal.append(
    svgEl("circle", { class: "rim", cx: 50, cy: 50, r: 47 }),
    svgEl("circle", { class: "rim inner", cx: 50, cy: 50, r: 30 }),
    svgEl("path", { id: "countersign-ring", d: "M50 50 m-35.5 0 a35.5 35.5 0 1 1 71 0 a35.5 35.5 0 1 1 -71 0", fill: "none" }),
    text,
    svgEl("path", { class: "glyph", d: check.status === "flagged" ? "M50 38.5v13.5 M50 60.5v.5" : "M40.5 50.5l6.5 6.5 12.5-13.5" }));
  return seal;
}

function fillAiLine(report, line) {
  const check = report.aiCheck;
  const yourAi = check?.model ? `your AI (${check.model})` : "your AI";
  const again = (label) => [label, () => runInspect(report.target.url)];
  let tone = "off";
  let text;
  let action = null;
  switch (check?.status) {
    case "clear":
      tone = "ok";
      text = `${yourAi} read it too and found nothing. The rules' verdict stands.`;
      break;
    case "flagged":
      tone = "warn";
      text = `${yourAi} flagged it: "${check.reason}". The verdict was raised to Held for review.`;
      break;
    case "skipped":
      text = "not needed. The rules had already stopped this network, so your AI was not asked.";
      break;
    case "failed":
      tone = "caution";
      text = `${yourAi} gave no usable answer, so only the rules decided.`;
      action = again("Try again");
      break;
    case "needs-key":
      tone = "caution";
      text = "waiting for your AI key, so only the rules checked this.";
      action = ["Set up a free key", () => startKeySetup(report.target.url)];
      break;
    case "locked":
      tone = "caution";
      text = "your saved key is locked, so only the rules checked this.";
      action = ["Unlock your key", () => startKeySetup(report.target.url)];
      break;
    default:
      // Your AI is only asked about what the rules clear, so a stopped network needs no offer.
      if (!["CLEARED", "CONDITIONS"].includes(report.verdict.code)) {
        text = "not needed here. The rules already stopped this network.";
        break;
      }
      text = desk.aiCheckOn ? "off when this was inspected." : "off. Only the rules checked this.";
      if (!desk.hasAiKey()) action = ["Set up AI double-check", () => startKeySetup(report.target.url)];
      else if (desk.aiCheckOn) action = again("Check again with AI");
      else action = ["Turn on and check again", () => { desk.setAiCheck(true); runInspect(report.target.url); }];
  }
  line.dataset.tone = tone;
  line.replaceChildren(
    icon("i-seal", "ai-line-icon"),
    h("span", null, h("strong", null, "AI double-check:"), " ", text),
    ...(action ? [h("button", { type: "button", class: "ai-line-action", onclick: action[1] }, action[0])] : []));
}

function openKeySettings() {
  showTab("officer");
  const picker = $("#model-picker");
  // Leave room for the floating navigation bar, as the return after Save and start does.
  if (picker) window.scrollTo({ top: picker.getBoundingClientRect().top + window.scrollY - 110, behavior: "smooth" });
  // The key field is inside the key vault's frame; site.js moves focus there.
  if ($("#mp-vault")?.offsetParent) document.dispatchEvent(new CustomEvent("customs:focus-key"));
}

// A visitor who sets up a key for the AI double-check goes back to their inspection after
// Save and start reloads the page, or as soon as a locked key is unlocked, instead of staying
// on the Officer tab.
const AI_SETUP_KEY = "agent-customs-ai-setup";
const AFTER_SAVE_KEY = "agent-customs-after-save";
let aiJustReady = false;

function readAiSetup() {
  try {
    const setup = JSON.parse(sessionStorage.getItem(AI_SETUP_KEY) || "null");
    return setup && Date.now() - Number(setup.at) < 30 * 60_000 ? setup : null;
  } catch {
    return null;
  }
}

function clearAiSetup() {
  try { sessionStorage.removeItem(AI_SETUP_KEY); } catch { /* storage blocked */ }
}

function startKeySetup(url = "") {
  desk.setAiCheck(true);
  try { sessionStorage.setItem(AI_SETUP_KEY, JSON.stringify({ at: Date.now(), url: String(url || "") })); } catch { /* storage blocked */ }
  syncAiCheck();
  openKeySettings();
}

function switchLabel(state) {
  if (state === "off") return desk.aiSettled && !desk.hasAiKey() ? "Off · needs an AI key" : "Off";
  return { connecting: "On · connecting", "needs-key": "Waiting for your key", locked: "On · key locked", ready: "On · your key" }[state] || "Off";
}

function aiUnlockCard() {
  const url = () => $("#inspect-url")?.value.trim() || desk.latest?.target.url || "";
  return [
    h("strong", null, "Your saved key is locked."),
    " Unlock it in the key vault, and your AI takes a second look at what the rules clear.",
    h("span", { class: "ai-note-actions" },
      h("button", { type: "button", class: "primary small", onclick: () => startKeySetup(url()) }, "Unlock your key"),
      h("button", { type: "button", class: "ghost small", onclick: () => { clearAiSetup(); desk.setAiCheck(false); $("#ai-check")?.focus(); } }, "Not now")),
  ];
}

function aiSetupCard() {
  const url = () => $("#inspect-url")?.value.trim() || desk.latest?.target.url || "";
  return [
    h("strong", null, "Your own AI takes a second look."),
    " It reads what the rules clear, and it can only make a verdict stricter.",
    h("span", { class: "ai-note-more" },
      "It needs an AI key: a code from an AI company that lets this page use its AI for you. Google AI Studio and Groq give free keys. Yours goes into a separate key vault, which this page cannot read."),
    h("span", { class: "ai-note-actions" },
      h("button", { type: "button", class: "primary small", onclick: () => startKeySetup(url()) }, "Set up a free key"),
      h("button", { type: "button", class: "ghost small", onclick: () => { clearAiSetup(); desk.setAiCheck(false); $("#ai-check")?.focus(); } }, "Not now")),
  ];
}

const CATALOG_TITLE = "Inspect any agent URL, or try a fixture";

function catalogCopy() {
  return desk.aiCheckOn
    ? "Rules run inside your browser. With the AI double-check on, your AI also reads what they clear."
    : "Deterministic rules run inside your browser without using an API key.";
}

function syncAiCheck() {
  const state = desk.aiCheckState();
  const on = desk.aiCheckOn;
  const button = $("#ai-check");
  if (button) {
    button.setAttribute("aria-checked", String(on));
    button.dataset.state = state;
  }
  const label = $("#ai-check-state");
  if (label) label.textContent = switchLabel(state);
  const note = $("#ai-check-note");
  if (note) {
    note.hidden = !on;
    note.dataset.state = state;
    if (!on) note.replaceChildren();
    else if (state === "needs-key") note.replaceChildren(...aiSetupCard());
    else if (state === "locked") note.replaceChildren(...aiUnlockCard());
    else {
      note.replaceChildren(aiJustReady ? "Your key is saved and the AI double-check is on. " : "",
        "Your AI also reads anything the rules clear, and can only make a verdict stricter. The network's public text goes to your AI provider, on your key.");
    }
  }
  const hint = $("#mp-ai-hint");
  if (hint) {
    hint.hidden = state !== "needs-key" && state !== "locked";
    hint.textContent = state === "locked"
      ? (readAiSetup() ? "Unlock your key in the vault box. You then go straight back to your inspection." : "Unlock your key in the vault box to run the AI double-check.")
      : readAiSetup()
        ? "This key will also run the AI double-check. After Save and start, you go straight back to your inspection."
        : "This key will also run the AI double-check.";
  }
  const fact = $("#privacy-fact");
  if (fact) fact.textContent = on ? "AI double-check on: public agent text also goes to your AI provider" : "No server: nothing you inspect leaves your browser";
  const emptyTitle = $("#report-empty h3");
  const emptyCopy = $("#report-empty p");
  if (emptyTitle?.textContent === CATALOG_TITLE && emptyCopy) emptyCopy.textContent = catalogCopy();
  const line = $("#ai-line");
  if (line && desk.latest && !desk.latest.failure) fillAiLine(desk.latest, line);
}

function wireAiCheck() {
  $("#ai-check")?.addEventListener("click", () => {
    if (!desk.setAiCheck(!desk.aiCheckOn)) clearAiSetup();
  });
  syncAiCheck();
}

function aiProofLine(check) {
  if (!check) return null;
  const said = {
    clear: "the visitor's AI found nothing",
    flagged: `the visitor's AI flagged it ("${check.reason}"), so the verdict was raised to Held`,
    skipped: "not asked, the rules had already stopped it",
    failed: "the visitor's AI gave no usable answer",
    "needs-key": "on, but no AI key was set",
    locked: "on, but the saved key was locked",
  }[check.status];
  return said ? `AI double-check: ${said}${check.model ? ` (${check.model})` : ""}` : null;
}

function renderLights(report) {
  const by = (cat) => report.findings.filter((f) => f.category === cat);
  const external = report.itinerary.filter((s) => !s.sameSite);
  // Compare with the approval stored now, not the one at inspection time: the visitor
  // may have approved this version since.
  const pin = desk.pins.get(report.target.url);
  const pinnedNow = matchesPin(pin, report.snapshot);
  const changed = !!pin && !!report.snapshot && !pinnedNow;
  const c = report.conformance;
  const identityFindings = by("identity").filter((f) => f.rule !== "D-DRIFT");
  let identityValue = "Not approved yet";
  let identityTone = identityFindings.length ? worstTone(identityFindings) : "info";
  if (changed) { identityValue = "Changed since approved"; identityTone = "warn"; }
  else if (pinnedNow) { identityValue = "Matches your approval"; identityTone = identityFindings.length ? worstTone(identityFindings) : "ok"; }
  if (identityFindings.length && !changed) identityValue = `${identityFindings.length} finding(s)`;
  const contraband = by("contraband").filter((f) => f.severity !== "info");
  const lights = [
    ["Papers", `${c.passed}/${c.total} pass`, c.failed ? "bad" : c.warned ? "caution" : "ok"],
    ["Contraband", contraband.length ? `${contraband.length} finding(s)` : "None found", worstTone(contraband)],
    ["Identity", identityValue, identityTone],
    ["Itinerary", external.length ? `${external.length} other site(s)` : "Stays home", worstTone(by("itinerary"))],
    ["Privacy", by("privacy").some((f) => f.rule === "S-SECRET") ? "Publishes a key"
      : report.privacy.length ? `${report.privacy.length} sharing rule(s)` : "Shares nothing", worstTone(by("privacy"))],
    ["Budget", report.budget.maxSteps ? `Up to ${report.budget.maxSteps} steps` : "Runtime default", worstTone(by("budget"))],
  ];
  return h("div", { class: "lights" }, lights.map(([name, value, t]) =>
    h("div", { class: `light tone-${t}` }, h("div", { class: "name" }, h("span", { class: "dot", "aria-hidden": "true" }), name),
      h("div", { class: "value" }, value))));
}

function renderFindings(report) {
  const block = h("div", { class: "report-block" }, h("h3", null, `Findings (${report.findings.length})`));
  if (!report.findings.length) {
    block.append(h("p", { class: "none" }, "Nothing found. Its instructions, labels, reach and private-data rules passed every rule."));
    return block;
  }
  report.findings.forEach((f, i) => {
    const where = [f.where?.agent && `agent ${f.where.agent}`, f.where?.field].filter(Boolean).join(" · ");
    const body = h("div", { class: "finding-body" },
      h("p", null, f.detail),
      f.hidden ? [h("span", { class: "label" }, "Hidden text, decoded"), h("p", { class: "hidden-text" }, f.hidden)] : null,
      f.evidence ? [h("span", { class: "label" }, "Evidence"), h("pre", { class: "evidence" }, f.evidence)] : null,
      f.why ? [h("span", { class: "label" }, "Why it matters"), h("p", null, f.why)] : null,
      f.fix ? [h("span", { class: "label" }, "Fix"), h("p", null, f.fix)] : null);
    block.append(h("details", { class: `finding sev-${f.severity}`, open: i === 0 && ["critical", "high"].includes(f.severity) },
      h("summary", null, pill(f.severity), h("span", { class: "ftitle" }, f.title), where ? h("span", { class: "where" }, `${f.id} · ${where}`) : h("span", { class: "where" }, f.id)),
      body));
  });
  return block;
}

function renderPapers(report) {
  const c = report.conformance;
  const marks = { pass: ["i-check", "ok"], warn: ["i-alert", "caution"], fail: ["i-x", "bad"] };
  const row = (check) => {
    const [glyph, tone] = marks[check.status] || marks.warn;
    return h("li", { class: `tone-${tone}` },
      icon(glyph, "icon"),
      h("span", null, h("strong", null, check.title), " ", h("span", { class: "sec" }, `§${check.section}`),
        h("span", { class: "cdetail" }, check.detail),
        check.status !== "pass" && check.fix ? h("span", { class: "cfix" }, `Fix: ${check.fix}`) : null));
  };
  const problems = c.checks.filter((x) => x.status !== "pass");
  const passes = c.checks.filter((x) => x.status === "pass");
  const paperHeading = PAPER_TITLES[report.protocol] || PAPER_TITLES["open-agentic-web"];
  const block = h("div", { class: "report-block" }, h("h3", null, `Papers: ${paperHeading} (${c.passed}/${c.total})`));
  if (problems.length) block.append(h("ul", { class: "checks" }, problems.map(row)));
  if (passes.length) {
    block.append(h("details", { class: "more", open: !problems.length },
      h("summary", null, `${passes.length} check(s) passed`), h("ul", { class: "checks" }, passes.map(row))));
  }
  return block;
}

function renderDrift(report) {
  return h("div", { class: "report-block" },
    h("h3", null, "Changed since you approved it"),
    h("p", { class: "none" }, `Approved ${fmtDate(report.drift.pinnedAt)} as ${String(report.drift.pinnedHash).slice(7, 19)}.`),
    renderChanges(report.drift.changes));
}

function renderChanges(changes) {
  if (!changes.length) return h("p", { class: "none" }, "No differences: both versions have the same fingerprint.");
  return h("ul", { class: "changes" }, changes.map((c) => h("li", { class: `sev-${c.severity}` },
    h("div", null, pill(c.severity), " ", h("strong", null, c.title)),
    (c.added || []).slice(0, 8).map((l) => h("pre", { class: "diffline add" }, `+ ${l}`)),
    (c.removed || []).slice(0, 6).map((l) => h("pre", { class: "diffline del" }, `− ${l}`)))));
}

function renderItinerary(report) {
  const stops = report.itinerary.filter((s) => !s.sameSite);
  const block = h("div", { class: "report-block" }, h("h3", null, "Itinerary"));
  if (!stops.length) {
    block.append(h("p", { class: "none" }, "It names no other site, MCP server or code bundle."));
    return block;
  }
  block.append(h("ul", { class: "stops" }, stops.map((s) => h("li", null,
    h("span", { class: "host" }, s.host),
    h("div", { class: "tags" }, s.kinds.map((k) => h("span", { class: "tag" }, k)),
      s.refused ? h("span", { class: "tag no" }, "refused by its own policy") : null)))));
  return block;
}

function renderPrivacy(report) {
  return h("div", { class: "report-block" }, h("h3", null, "Private context it shares"),
    h("ul", { class: "stops" }, report.privacy.map((p) => h("li", null,
      h("span", { class: "host" }, p.agent), h("div", { class: "tags" }, h("span", { class: "tag" }, p.direction.replace("_", " ")),
        p.fields.map((f) => h("span", { class: "tag" }, f)))))));
}

function renderCapabilities(report) {
  const cap = report.capabilities;
  const rows = [
    ["Untrusted input", cap.untrustedInput?.[0]?.detail || "None detected"],
    ["Sensitive access", cap.sensitiveAccess?.length ? cap.sensitiveAccess.map((s) => s.detail).slice(0, 2).join("; ") : "None detected"],
    ["External egress", cap.externalEgress?.length ? cap.externalEgress.map((e) => e.detail).slice(0, 2).join("; ") : "Stays local"],
  ];
  const block = h("div", { class: `report-block${cap.trifecta ? " trifecta-alert" : ""}` },
    h("h3", null, cap.trifecta ? "Capability flow (Lethal Trifecta)" : "Capability profile"),
    h("ul", { class: "stops" }, rows.map(([label, val]) => h("li", null,
      h("span", { class: "host" }, label),
      h("p", { class: "none" }, val)))));
  if (cap.paths?.length) {
    block.append(h("p", { class: "trifecta-path" }, `Path: ${cap.paths[0].from} → ${cap.paths[0].through} → ${cap.paths[0].to}`));
  }
  return block;
}

function renderTransitive(report) {
  const checked = report.transitive?.checked || [];
  return h("div", { class: "report-block" }, h("h3", null, `Transitive dependencies (${checked.length})`),
    h("ul", { class: "stops" }, checked.map((c) => h("li", null,
      h("span", { class: "host" }, c.url),
      h("div", { class: "tags" },
        h("span", { class: "tag" }, PROTOCOL_LABELS[c.protocol] || c.protocol),
        h("span", { class: `tag${c.verdict === "DENIED" ? " no" : ""}` }, c.verdict))))));
}

// A message for the next report drawing. Approving redraws the report, so a message put
// in the old drawing would never be seen.
let reportNotice = "";

async function changeApproval(change, done) {
  const result = await change();
  reportNotice = result.ok ? done : result.reason;
  renderReport();
}

function renderReportActions(report) {
  const bar = h("div", { class: "report-actions" });
  const toast = h("span", { class: "toast", role: "status" }, reportNotice);
  reportNotice = "";
  const pin = desk.pins.get(report.target.url);
  const pinnedNow = matchesPin(pin, report.snapshot);
  if (report.snapshot) {
    if (pinnedNow) {
      bar.append(h("button", { type: "button", class: "ghost",
        onclick: () => changeApproval(() => desk.unpin(report.target.url), "Approval forgotten. Its next use is inspected as new."),
      }, "Forget approval"));
    } else {
      const blocked = NOT_APPROVABLE.has(report.verdict.code);
      bar.append(h("button", {
        type: "button", class: "primary", disabled: blocked, title: blocked ? "Denied networks cannot be approved." : null,
        onclick: () => changeApproval(() => desk.pin(report.target.url), "Approved. If this network changes, it will be held for your review."),
      }, pin ? "Approve this new version" : report.verdict.code === "HOLD" ? "Approve after review" : "Approve this version"));
    }
  }
  bar.append(h("button", { type: "button", class: "ghost", onclick: () => askOfficer(report) }, "Ask the officer about it"));
  bar.append(h("span", { class: "spacer" }));
  const cleared = report.verdict.code === "CLEARED";
  const certLabel = cleared ? "Clearance certificate" : "Inspection advisory";
  const certTone = cleared ? "is-cleared" : report.verdict.code === "HOLD" ? "is-hold" : "is-denied";
  bar.append(h("button", { type: "button", class: `small cert-trigger ${certTone}`, onclick: () => openCertificateDialog(report, toast) },
    certificateSealIcon(cleared), h("span", null, certLabel)));
  bar.append(h("button", { type: "button", class: "ghost small", onclick: () => copy(proofText(report), toast, "Proof copied.") }, "Copy proof"));
  bar.append(h("button", { type: "button", class: "ghost small", onclick: () => copy(JSON.stringify({ ...report, snapshot: undefined }, null, 2), toast, "Report JSON copied.") }, "Copy JSON"));
  bar.append(toast);
  return bar;
}

function certificateSealIcon(cleared) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "cert-seal-ico");
  svg.setAttribute("viewBox", "0 0 20 20");
  svg.setAttribute("aria-hidden", "true");
  const ribbon = document.createElementNS(SVG_NS, "path");
  ribbon.setAttribute("d", "M6.8 14.3 L5.6 18.8 L10 16.9 L14.4 18.8 L13.2 14.3");
  const ring = document.createElementNS(SVG_NS, "circle");
  ring.setAttribute("cx", "10");
  ring.setAttribute("cy", "9");
  ring.setAttribute("r", "6.2");
  const mark = document.createElementNS(SVG_NS, "path");
  mark.setAttribute("d", cleared ? "M7.5 9.2 L9.3 11 L12.7 7.4" : "M10 6.3 V9.6 M10 11.7 V11.9");
  svg.append(ribbon, ring, mark);
  return svg;
}

function reportVerifyUrl(report) {
  const link = new URL(location.href);
  link.search = `?inspect=${encodeURIComponent(report.target.url)}`;
  link.hash = "";
  return link.href;
}

function activePaletteTheme() {
  const cs = getComputedStyle(document.documentElement);
  const pick = (name) => cs.getPropertyValue(name).trim() || undefined;
  return {
    bgMid: pick("--c1"),
    parchment: pick("--c2"),
    cleared: pick("--c3"),
    ok: pick("--ok"),
    caution: pick("--caution"),
    warn: pick("--warn"),
    bad: pick("--bad"),
  };
}

function downloadBlob(blob, filename) {
  const href = URL.createObjectURL(blob);
  const link = h("a", { href, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1500);
}

async function svgImageToPngBlob(img, width = 2800, height = 1880) {
  if (!img.complete) await new Promise((resolve, reject) => {
    img.addEventListener("load", resolve, { once: true });
    img.addEventListener("error", () => reject(new Error("Could not render certificate image.")), { once: true });
  });
  if (typeof img.decode === "function") await img.decode().catch(() => {});
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, width, height);
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("PNG export blocked by browser."))), "image/png");
  });
}

let activeCertUrl = null;
function revokeCertUrl() {
  if (!activeCertUrl) return;
  URL.revokeObjectURL(activeCertUrl);
  activeCertUrl = null;
}

async function openCertificateDialog(report, reportToast) {
  const verified = await verifyReportReceipt(report);
  const receiptCheck = verified?.check || null;
  const meta = certificateMeta(report, receiptCheck);
  const verifyUrl = reportVerifyUrl(report);
  const svg = certificateSvg(report, { receiptCheck, signedReceipt: verified?.found?.signed || null, verifyUrl, theme: activePaletteTheme() });
  const svgBlob = new Blob([svg], { type: "image/svg+xml;charset=utf-8" });
  revokeCertUrl();
  activeCertUrl = URL.createObjectURL(svgBlob);

  let dialog = $("#cert-dialog");
  if (!dialog) {
    dialog = h("dialog", { id: "cert-dialog", class: "cert-dialog", "aria-labelledby": "cert-dialog-title" });
    dialog.addEventListener("close", revokeCertUrl);
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
    document.body.append(dialog);
  }

  const titleText = report.identity.brand || report.identity.network || report.target.host || "Network";
  const img = h("img", { class: "cert-preview-img", src: activeCertUrl, alt: `${meta.documentTitle} for ${titleText}` });
  const reverifyHit = h("a", {
    class: "cert-reverify-hit",
    href: verifyUrl,
    target: "_blank",
    rel: "noopener noreferrer",
    title: `Click to re-verify live: ${verifyUrl}`,
    "aria-label": `Re-verify live and open result page: ${verifyUrl}`,
  }, "Open live result ↗");
  const dialogToast = h("span", { class: "toast", role: "status" });
  const statusTone = meta.clearanceAllowed
    ? (receiptCheck?.valid && !receiptCheck.expired && receiptCheck.matches !== false ? "ok" : "caution")
    : (meta.code === "HOLD" ? "warn" : "bad");

  dialog.replaceChildren(
    h("div", { class: "cert-shell" },
      h("header", { class: "cert-head" },
        h("div", { class: "cert-head-meta" },
          h("h3", { id: "cert-dialog-title" }, meta.documentTitle),
          h("span", { class: `pill tone-${statusTone}`, style: `--tone: var(--${statusTone})` }, meta.signedStatus)),
        h("button", { type: "button", class: "ghost small", "aria-label": "Close certificate preview", onclick: () => dialog.close() }, "Close")),
      h("div", { class: "cert-stage" },
        h("div", { class: "cert-stage-frame" }, img, reverifyHit)),
      h("footer", { class: "cert-foot" },
        h("p", { class: "cert-note" },
          meta.signedDetail,
          " · ",
          h("a", { class: "cert-verify-link", href: verifyUrl, target: "_blank", rel: "noopener noreferrer" }, "Re-verify live ↗")),
        h("div", { class: "cert-buttons" },
          dialogToast,
          h("button", { type: "button", class: "ghost small", onclick: () => {
            document.body.classList.add("printing-cert");
            const clearPrint = () => document.body.classList.remove("printing-cert");
            window.addEventListener("afterprint", clearPrint, { once: true });
            window.print();
            setTimeout(clearPrint, 1000);
          } }, "Print / PDF"),
          h("button", { type: "button", class: "ghost small", onclick: () => {
            const htmlBlob = new Blob([certificateHtml(svg, `${meta.documentTitle} — ${titleText}`)], { type: "text/html;charset=utf-8" });
            downloadBlob(htmlBlob, certificateFilename(report, "html"));
            dialogToast.textContent = "Saved HTML.";
            setTimeout(() => { dialogToast.textContent = ""; }, 2500);
          } }, "Download HTML"),
          h("button", { type: "button", class: "ghost small", onclick: () => {
            downloadBlob(svgBlob, certificateFilename(report, "svg"));
            dialogToast.textContent = "Saved SVG.";
            setTimeout(() => { dialogToast.textContent = ""; }, 2500);
          } }, "Download SVG"),
          h("button", { type: "button", class: "primary small", onclick: async () => {
            try {
              const png = await svgImageToPngBlob(img);
              downloadBlob(png, certificateFilename(report, "png"));
              dialogToast.textContent = "Saved 2× PNG.";
              if (reportToast) reportToast.textContent = "Certificate downloaded.";
            } catch (err) {
              dialogToast.textContent = err.message;
            }
            setTimeout(() => { dialogToast.textContent = ""; if (reportToast) reportToast.textContent = ""; }, 2500);
          } }, "Download PNG")))));

  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
}

function proofText(report) {
  const link = reportVerifyUrl(report);
  return [
    `Agent Customs inspection, ${report.inspectedAt}`,
    `Network: ${report.target.url}`,
    `Verdict: ${report.verdict.stamp} (${report.verdict.summary})`,
    `Fingerprint: ${report.identity.hash || "n/a"}`,
    `Spec checks: ${report.conformance.passed}/${report.conformance.total} passed (${report.profile || "Open Agentic Web MVP"})`,
    aiProofLine(report.aiCheck),
    `Re-check it yourself: ${link}`,
  ].filter(Boolean).join("\n");
}

async function copy(text, toast, done) {
  try {
    await navigator.clipboard.writeText(text);
    toast.textContent = done;
  } catch {
    toast.textContent = "Copy failed: your browser blocked the clipboard.";
  }
  setTimeout(() => { toast.textContent = ""; }, 3000);
}

function askOfficer(report) {
  const input = document.querySelector("#ns-input");
  showTab("officer");
  revealWorkspace();
  if (!input) return;
  input.value = `Explain the inspection of ${report.target.url} in plain words, and what the publisher should fix.`;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.focus({ preventScroll: true });
}

// ---- Approvals, comparison, border log --------------------------------------------

function renderPins() {
  const list = $("#pins-list");
  const pins = desk.pins.list();
  const count = $("#pins-count");
  if (count) {
    if (pins.length > Number(count.textContent || 0)) {
      count.classList.remove("pop");
      void count.offsetWidth;
      count.classList.add("pop");
    }
    count.hidden = !pins.length;
    count.textContent = String(pins.length);
  }
  list.replaceChildren();
  if (!pins.length) {
    list.append(h("li", { class: "none" }, "Nothing approved yet. To approve a network, inspect it on the Report tab and press Approve this version. The guard also approves a clean partner the first time the officer calls it."));
    return;
  }
  for (const p of pins) {
    const isMcp = p.kind === "mcp-tools" || String(p.url || "").startsWith("mcp:");
    const rawTarget = isMcp ? String(p.url || "").replace(/^mcp:/, "") : p.url;
    const summary = isMcp
      ? `${p.short || p.hash?.slice(7, 19) || "pinned"} · ${p.count ?? "?"} MCP tool(s) · pinned ${fmtDate(p.pinnedAt)}`
      : `${p.short} · ${p.verdict} · approved ${fmtDate(p.pinnedAt)}${p.how === "first-use" ? " by the guard on first use" : p.how === "reviewed" ? " after review" : ""}`;
    list.append(h("li", null,
      h("span", { class: "ptitle" }, p.brand || p.network || p.host || rawTarget),
      h("span", { class: "pmeta" }, rawTarget),
      h("span", { class: "pmeta" }, summary),
      h("div", { class: "pactions" },
        h("button", { type: "button", class: "ghost small", onclick: () => runInspect(rawTarget) }, "Check for changes"),
        h("button", { type: "button", class: "danger small", onclick: () => desk.unpin(p.url) }, "Forget"))));
  }
}

function renderCompare() {
  const box = $("#compare-result");
  const cmp = desk.comparison;
  box.replaceChildren();
  if (!cmp) return;
  const side = (r) => h("div", { class: "v" }, h("span", { class: `pill tone-${r.verdict.tone}`, style: "--tone: var(--" + r.verdict.tone + ")" }, r.verdict.stamp),
    h("code", null, r.target.url), h("code", null, r.identity.short));
  box.append(h("div", { class: "versions" }, side(cmp.before), icon("i-arrow", "arrow"), side(cmp.after)));
  box.append(renderChanges(cmp.changes));
}

function renderBorderLog() {
  const list = $("#border-log");
  list.replaceChildren();
  if (!desk.borderLog.length) {
    list.append(h("li", { class: "none" }, "No partner has been called yet. Ask the officer: \"What does the Sunny Bakery test network offer? Ask it.\""));
    return;
  }
  for (const e of desk.borderLog) {
    const tone = e.decision.startsWith("admitted") ? "ok" : "bad";
    list.append(h("li", null,
      h("span", { class: `pill`, style: `--tone: var(--${tone})` }, e.decision || e.stamp),
      h("span", { class: "bwho" }, `${e.network} · ${e.host}`),
      h("span", { class: "bwhy" }, `${e.stamp}: ${e.summary} (${e.fingerprint}, ${fmtDate(e.at)})`)));
  }
}

// ---- Forms -------------------------------------------------------------------------

// ---- Signed stamps (receipts) ----------------------------------------------------------
// Published at receipts/ with an index, and checked with the public key at
// .well-known/agent-customs-key.json. Both are loaded once, from this site.
let receiptIndex = null;
let receiptKey = null;
const receiptCache = new WeakMap();

async function loadJson(relative) {
  const response = await fetch(new URL(relative, location.href), { cache: "no-store" });
  if (!response.ok) throw new Error(String(response.status));
  return response.json();
}

async function findReceipt(networkUrl) {
  receiptIndex ||= loadJson("receipts/index.json").catch(() => ({ receipts: [] }));
  receiptKey ||= loadJson(".well-known/agent-customs-key.json").catch(() => null);
  const [index, key] = await Promise.all([receiptIndex, receiptKey]);
  const entry = (index.receipts || []).find((e) => e.network === networkUrl);
  if (!entry || !key) return null;
  const url = new URL(`receipts/${entry.path}`, location.href).href;
  return { signed: await loadJson(url), key, url };
}

async function verifyReportReceipt(report) {
  if (!report || report.failure) return null;
  if (!receiptCache.has(report)) {
    receiptCache.set(report, (async () => {
      try {
        const found = await findReceipt(report.target.url);
        if (!found) return null;
        const check = await verifyReceipt(found.signed, found.key.publicKey, { fingerprint: report.identity.hash });
        return { found, check };
      } catch {
        return null;
      }
    })());
  }
  return receiptCache.get(report);
}

// Shows whether the signed stamp checks out and still fits this exact version.
async function showReceipt(report, line) {
  const verified = await verifyReportReceipt(report);
  if (!verified || desk.latest !== report) return;
  const { found, check } = verified;
  const r = check.receipt;
  let state = "ok";
  let text = `Signed stamp verified: ${r?.stamp}, ${stampDate(r?.inspectedAt)}. It matches this exact version.`;
  if (!check.valid) { state = "bad"; text = `A signed stamp was found, but it fails the check: ${check.reason}`; }
  else if (check.matches === false) { state = "warn"; text = `The signed stamp from ${stampDate(r.inspectedAt)} (${r.stamp}) is for an earlier version: this network has changed since.`; }
  else if (check.expired) { state = "warn"; text = `The signed stamp from ${stampDate(r.inspectedAt)} (${r.stamp}) has expired.`; }
  line.replaceChildren(h("span", null, text), " ", h("a", { href: found.url, target: "_blank", rel: "noopener noreferrer" }, "See the signed receipt"));
  line.dataset.state = state;
  line.hidden = false;
}

async function runInspect(url, { scrollBehavior = "smooth", transitive = $("#inspect-transitive")?.checked || false } = {}) {
  const input = $("#inspect-url");
  const error = $("#inspect-error");
  const button = $("#inspect-button");
  const reportBox = $("#report");
  const emptyTitle = $("#report-empty h3");
  const emptyCopy = $("#report-empty p");
  input.value = url;
  error.hidden = true;
  button.disabled = true;
  button.textContent = "Inspecting…";
  showTab("report");
  reportBox.classList.add("busy");
  if (reportBox.hidden && emptyTitle && emptyCopy) {
    emptyTitle.textContent = "Checking network…";
    emptyCopy.textContent = url;
  }
  try {
    const result = await desk.inspect(url, { transitive });
    if (result.ok === false) {
      error.textContent = result.reason;
      error.hidden = false;
      if (reportBox.hidden && emptyTitle && emptyCopy) {
        emptyTitle.textContent = "Could not inspect";
        emptyCopy.textContent = result.reason;
      }
      return;
    }
    revealWorkspace(scrollBehavior);
    document.querySelector("#report-title")?.focus({ preventScroll: true });
  } catch (err) {
    const msg = `Inspection failed: ${err.message}`;
    error.textContent = msg;
    error.hidden = false;
    if (reportBox.hidden && emptyTitle && emptyCopy) {
      emptyTitle.textContent = "Inspection failed";
      emptyCopy.textContent = err.message;
    }
  } finally {
    button.disabled = false;
    button.textContent = "Inspect a network";
    reportBox.classList.remove("busy");
  }
}

async function runCompare(before, after) {
  const error = $("#compare-error");
  const button = $("#compare-button");
  error.hidden = true;
  button.disabled = true;
  button.textContent = "Comparing…";
  try {
    const result = await desk.compare(before, after);
    if (result.ok === false) {
      error.textContent = result.reason;
      error.hidden = false;
    }
  } catch (err) {
    error.textContent = `Comparison failed: ${err.message}`;
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Compare versions";
  }
}

function wire() {
  wireTabs();
  document.addEventListener("customs:inspect", (event) => runInspect(event.detail.url));
  const examples = $("#examples");
  // The dot hints at the verdict each test-range network is built to get.
  const EXAMPLE_TONE = { sunny: "ok", shady: "bad", bank: "bad", maze: "warn", rug: "warn", oven: "ok", guesthouse: "ok", harbor: "ok" };
  const exampleItem = (label, note, url, tone) => h("li", null,
    h("button", { type: "button", onclick: () => runInspect(url), title: url },
      h("span", { class: `dot tone-${tone || "info"}`, "aria-hidden": "true" }),
      label, " ",
      h("small", { class: "example-tag" }, note)));
  const officialExamples = $("#examples-official");
  for (const e of EXAMPLES) {
    const dest = e.group === "official" && officialExamples ? officialExamples : examples;
    dest.append(exampleItem(e.label, e.note, e.url, EXAMPLE_TONE[e.id]));
  }
  const protocolExamples = $("#examples-protocols");
  if (protocolExamples) {
    for (const s of PROTOCOL_SAMPLES) {
      protocolExamples.append(exampleItem(s.label, s.note, new URL(s.path, location.href).href, s.tone));
    }
  }
  const resetBtn = $("#report-reset");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      $("#report").hidden = true;
      $("#report-empty").hidden = false;
      const emptyTitle = $("#report-empty h3");
      const emptyCopy = $("#report-empty p");
      if (emptyTitle) emptyTitle.textContent = CATALOG_TITLE;
      if (emptyCopy) emptyCopy.textContent = catalogCopy();
      resetBtn.hidden = true;
    });
  }
  $("#inspect-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const url = $("#inspect-url").value.trim();
    if (!url) {
      $("#inspect-error").textContent = "Paste a network URL first.";
      $("#inspect-error").hidden = false;
      return;
    }
    runInspect(url);
  });
  $("#compare-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const before = $("#compare-before").value.trim();
    const after = $("#compare-after").value.trim();
    if (!before || !after) {
      $("#compare-error").textContent = "Give both URLs.";
      $("#compare-error").hidden = false;
      return;
    }
    runCompare(before, after);
  });
  $("#compare-demo").addEventListener("click", () => {
    const sunny = EXAMPLES.find((e) => e.id === "sunny").url;
    const rug = EXAMPLES.find((e) => e.id === "rug").url;
    $("#compare-before").value = sunny;
    $("#compare-after").value = rug;
    runCompare(sunny, rug);
  });
  wireVerifyPanel();
  wireArenaPanel();
  wireBenchStrip();
  wireBuilderCodeTabs();
  $("#copy-guard").addEventListener("click", (event) => {
    const toast = { set textContent(v) { event.target.textContent = v || "Copy"; } };
    copy($("#guard-code").textContent, toast, "Copied");
  });
  const rangeLink = $("#range-link");
  if (rangeLink) rangeLink.href = EXAMPLES[0].url.replace(/\/sunny_bakery\/sunny_bakery$/, "/");

  desk.onChange((kind) => {
    if (kind === "report") renderReport({ animate: true });
    if (kind === "pins") { renderPins(); renderReport(); }
    if (kind === "compare") renderCompare();
    if (kind === "border") renderBorderLog();
    if (kind === "ai-check") { resumeAfterUnlock(); syncAiCheck(); }
    if (kind === "busy" && desk.phase === "ai") {
      const button = $("#inspect-button");
      if (button?.disabled) button.textContent = "AI double-check…";
    }
  });
  wireAiCheck();
  renderPins();
  renderBorderLog();

  // A shared or certificate re-verify link (?inspect=URL) opens the Report tab and
  // runs a live check so the visitor immediately sees CLEARED, HOLD, or DENIED.
  const shared = new URLSearchParams(location.search).get("inspect");
  if (shared) {
    const targetUrl = shared.trim();
    $("#inspect-url").value = targetUrl;
    showTab("report");
    revealWorkspace("instant");
    runInspect(targetUrl, { scrollBehavior: "instant" });
  }
}

const VERIFY_TONE = { verified: "ok", unsigned: "info", changed: "warn", expired: "warn", tampered: "bad", invalid: "bad" };

function renderVerifyResult(result, { label = "", liveState = null, onRecheck = null } = {}) {
  const box = $("#verify-result");
  if (!box) return;
  box.replaceChildren();
  if (!result.ok) {
    box.append(h("div", { class: "verify-card" },
      h("div", { class: "verify-head" },
        h("span", { class: "pill tone-bad", style: "--tone: var(--bad)" }, "Unrecognized"),
        h("h4", null, label || "Could not verify file")),
      h("p", { class: "none" }, result.reason)));
    return;
  }

  const art = result.artifact;
  const tone = VERIFY_TONE[result.status] || "info";
  const sourceLabel = result.signature?.valid
    ? (result.signedSource === "published" ? "Verified vs. published receipt" : "ES256 signed artifact")
    : result.status === "tampered"
      ? "Tampered ES256 artifact"
      : art.pdfExtracted
        ? "PDF link extract"
        : "Unsigned snapshot";
  const facts = [
    ["Target URL", art.url || "not present"],
    ["Verdict recorded", art.stamp || art.verdict || "unknown"],
    ["SHA-256 fingerprint", art.fingerprint || "not present"],
    ["Issued", art.inspectedAt ? fmtDate(art.inspectedAt) : "unknown"],
    ["ES256 key ID", result.signature?.receipt?.inspector?.keyId || "unsigned"],
    ["Proof source", sourceLabel],
  ];

  const liveTone = liveState?.status === "match" ? "ok" : liveState?.status === "changed" ? "bad" : "info";
  const liveText = liveState?.message || "Ready to compare against the live endpoint.";

  const liveActions = [];
  if (art.url) {
    if (onRecheck) {
      liveActions.push(h("button", { type: "button", class: "ghost small", onclick: onRecheck }, "Check live site"));
    }
    liveActions.push(h("button", { type: "button", class: "ghost small", onclick: () => runInspect(art.url) }, "Open full report"));
  }

  box.append(h("div", { class: "verify-card" },
    h("div", { class: "verify-head" },
      h("span", { class: `pill tone-${tone}`, style: `--tone: var(--${tone})` }, result.status),
      h("h4", null, result.headline),
      label ? h("span", { class: "where" }, label) : null),
    h("p", { class: "none" }, result.detail),
    h("dl", { class: "verify-grid" }, facts.map(([dt, dd]) => h("div", null, h("dt", null, dt), h("dd", null, dd)))),
    art.url ? h("div", { class: "verify-live", style: `--tone: var(--${liveTone})` },
      h("span", null, liveText),
      h("div", { class: "tags" }, liveActions)) : null));
}

async function verifyArtifactInput(input, label) {
  const keyDoc = await (receiptKey ||= loadJson(".well-known/agent-customs-key.json").catch(() => null));
  const lookupSignedReceipt = async (url) => (await findReceipt(url).catch(() => null))?.signed || null;
  let result = await verifyDroppedArtifact(input, {
    fileName: label,
    publicJwk: keyDoc?.publicKey || null,
    lookupSignedReceipt,
  });

  const runLiveCheck = async () => {
    if (!result.ok || !result.artifact?.url) return;
    renderVerifyResult(result, { label, liveState: { status: "checking", message: `Checking ${result.artifact.url} live…` } });
    let liveReport = null;
    try {
      liveReport = await inspectNetworkUrl(result.artifact.url, { fetchImpl: desk.fetchImpl || undefined, pageOrigin: desk.pageOrigin });
    } catch { liveReport = null; }
    result = await verifyDroppedArtifact(input, {
      fileName: label,
      publicJwk: keyDoc?.publicKey || null,
      lookupSignedReceipt,
      liveReport,
    });
    const liveMsg = result.liveStatus === "match"
      ? `Matches live endpoint (${liveReport.identity.short}).`
      : result.liveStatus === "changed"
        ? `Live endpoint drifted since issue! Now ${liveReport.verdict.stamp} (${liveReport.identity.short}).`
        : result.liveSummary || "Live check unavailable offline or blocked by CORS.";
    renderVerifyResult(result, { label, liveState: { status: result.liveStatus, message: liveMsg }, onRecheck: runLiveCheck });
  };

  renderVerifyResult(result, {
    label,
    liveState: result.ok && result.status !== "tampered" && result.artifact?.url
      ? { status: "checking", message: `Checking ${result.artifact.url} live…` }
      : { status: "skipped", message: "Skipped live check because signature failed." },
    onRecheck: result.status === "tampered" ? null : runLiveCheck,
  });
  if (result.ok && result.status !== "tampered" && result.artifact?.url) {
    await runLiveCheck();
  }
}

function wireVerifyPanel() {
  const drop = $("#verify-drop");
  const fileInput = $("#verify-file");
  const pickBtn = $("#verify-pick");
  if (!drop || !fileInput) return;

  const readFile = async (file) => {
    if (!file) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    await verifyArtifactInput({ bytes, name: file.name }, file.name);
  };

  pickBtn?.addEventListener("click", (e) => { e.stopPropagation(); fileInput.click(); });
  drop.addEventListener("click", (e) => {
    if (e.target.closest("button")) return;
    fileInput.click();
  });
  fileInput.addEventListener("change", () => {
    const picked = fileInput.files?.[0];
    fileInput.value = "";
    readFile(picked);
  });
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("drag"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("drag");
    readFile(e.dataTransfer?.files?.[0]);
  });
}

function wireArenaPanel() {
  const picks = $("#arena-picks");
  const box = $("#arena-result");
  if (!picks || !box) return;

  let activeId = ARENA_SCENARIOS[0].id;
  const run = async (id) => {
    activeId = id;
    for (const btn of picks.querySelectorAll("button")) {
      btn.setAttribute("aria-pressed", String(btn.dataset.scenario === id));
    }
    const res = await runArenaScenario(id);
    const col = (cls, title, data) => h("section", { class: `arena-card ${cls}` },
      h("div", { class: "arena-card-head" },
        h("h4", null, title),
        h("span", { class: `pill ${cls === "bad" ? "sev-critical" : ""}`, style: cls === "ok" ? "--tone: var(--ok)" : null }, data.outcome)),
      h("ol", { class: "arena-steps" }, data.steps.map((s) => h("li", null,
        h("strong", null, s.stage),
        h("span", null, s.detail)))));

    box.replaceChildren(
      h("p", { class: "arena-summary" }, res.scenario.summary),
      h("div", { class: "arena-grid" },
        col("bad", "Without Agent Customs", res.unprotected),
        col("ok", "Protected by Agent Customs", res.protected)),
      h("div", { class: "arena-foot" },
        h("span", null, `Checked live in browser in ${res.elapsedMs} ms · zero external API keys`),
        h("a", { class: "draw", href: "#workspace" }, "Inspect a live URL in the Desk ↑")));
  };

  for (const sc of ARENA_SCENARIOS) {
    picks.append(h("li", null, h("button", {
      type: "button",
      "data-scenario": sc.id,
      "aria-pressed": String(sc.id === activeId),
      onclick: () => run(sc.id),
    }, sc.label)));
  }
  run(activeId);
}

async function wireBenchStrip() {
  const list = $("#bench-strip");
  if (!list) return;
  try {
    const bench = await loadJson("bench.json");
    if (!bench?.agentCustoms || !bench?.naiveRegexBaseline) return;
    const ac = bench.agentCustoms;
    const baseline = bench.naiveRegexBaseline;
    const items = [
      [`${bench.hostileTotal} attack vectors + ${bench.benignTotal} benign`, `R1 ${ac.round1Caught}/${ac.round1Total} · R2 ${ac.round2Caught}/${ac.round2Total} · R3 ${ac.round3Caught}/${ac.round3Total} · Held-out ${ac.heldoutCaught}/${ac.heldoutTotal} · Ext ${ac.externalQuotedCaught}/${ac.externalQuotedTotal} · ${bench.selfTestPassed}/${bench.selfTestTotal} lock/cert`],
      [`${ac.catchRate}% attacks blocked/held`, `${ac.flaggedRate}% flagged incl. conditions · vs. ${baseline.catchRate}% normalized regex`],
      [`${ac.falsePositiveRate}% benign false blocks`, `${ac.benignCleared}/${bench.benignTotal} clean cleared · vs. ${baseline.falsePositiveRate}% normalized regex`],
      [`~${ac.medianDetectionMs} ms median check`, `${ac.llmTokenCost} · reproducible via npm run bench`],
    ];
    list.replaceChildren(...items.map(([stat, note]) => h("li", null, h("strong", null, stat), h("span", null, note))));
  } catch {
    list.hidden = true;
  }
}

function wireBuilderCodeTabs() {
  const codeEl = $("#guard-code");
  const tabs = [...document.querySelectorAll(".code-tab[data-code-tab]")];
  if (!codeEl || !tabs.length) return;
  const siteMarkup = codeEl.innerHTML;
  const snippets = {
    npm: [
      "# For projects with a build step",
      "npm install agent-customs",
      "",
      "import { installCustomsGuard } from \"agent-customs\";",
      "installCustomsGuard(booted.engine);",
    ].join("\n"),
    cli: [
      "# Inspect a site, a folder, or an MCP / A2A file",
      "npx agent-customs check https://your-site.example/",
      "npx agent-customs check ./my-network --strict",
      "",
      "# Run the reproducible benchmark",
      "npx agent-customs bench",
    ].join("\n"),
    action: [
      "# .github/workflows/agent-customs.yml",
      "- uses: montbaga/agent-customs@main",
      "  with:",
      "    target: site/agent_customs",
      "    strict: \"true\"",
      "    sarif-file: agent-customs.sarif",
    ].join("\n"),
    extension: [
      "# Inspect external sites past browser CORS walls",
      "npm run extension",
      "",
      "# Edge / Chrome -> chrome://extensions",
      "# Enable Developer mode -> Load unpacked -> select extension/",
    ].join("\n"),
  };

  for (const tab of tabs) {
    tab.addEventListener("click", () => {
      const mode = tab.dataset.codeTab;
      for (const b of tabs) b.setAttribute("aria-selected", String(b === tab));
      if (mode === "site") codeEl.innerHTML = siteMarkup;
      else codeEl.textContent = snippets[mode] || "";
    });
  }
}

// A locked key was unlocked while the visitor was setting up the AI double-check: back to the
// inspection, which runs again with the key. No reload happens, unlike after Save and start.
let lastAiState = "";
function resumeAfterUnlock() {
  const state = desk.aiCheckState();
  const was = lastAiState;
  lastAiState = state;
  if (was !== "locked" || state !== "ready") return;
  const setup = readAiSetup();
  if (!setup) return;
  clearAiSetup();
  aiJustReady = true;
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (setup.url) runInspect(setup.url);
}

// Back from the officer's Save and start, which reloads the page: reopen the Officer tab and
// scroll to its model settings before anything else draws. The browser does not restore the
// old position for this reload (model-picker.js turned that off before reloading), and the
// head of index.html keeps the page hidden until this has run.
function returnToOfficer() {
  let at = 0;
  try { at = Number(sessionStorage.getItem(AFTER_SAVE_KEY) || 0); } catch { /* storage blocked */ }
  const saved = at && Date.now() - at < 60_000;
  const setup = saved ? readAiSetup() : null;
  if (setup) {
    // The key was set up for the AI double-check: back to the inspection, which runs again
    // with it. Removing the note also keeps model-picker.js from scrolling to the Officer tab.
    try { sessionStorage.removeItem(AFTER_SAVE_KEY); } catch { /* storage blocked */ }
    clearAiSetup();
    aiJustReady = true;
    syncAiCheck();
    window.scrollTo({ top: 0, behavior: "instant" });
    if (setup.url) runInspect(setup.url, { scrollBehavior: "instant" });
    else $("#inspect-url")?.focus({ preventScroll: true });
  } else if (saved) {
    showTab("officer");
    const picker = document.querySelector("#model-picker");
    if (picker) window.scrollTo({ top: picker.getBoundingClientRect().top + window.scrollY - 110, behavior: "instant" });
  }
  document.documentElement.classList.remove("returning");
}

wire();
returnToOfficer();
