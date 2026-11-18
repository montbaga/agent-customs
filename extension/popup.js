import { inspectOriginAgents } from "./inspector.js";

const $ = (sel) => document.querySelector(sel);

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v !== null && v !== undefined) el.setAttribute(k, v);
    }
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    el.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return el;
}

const DESK_BASE = "https://montbaga.github.io/agent-customs/";

async function runCheck(targetUrl) {
  const out = $("#ext-out");
  const proto = $("#ext-proto");
  const deskLink = $("#ext-open-desk");
  proto.hidden = true;
  out.replaceChildren(h("p", { class: "muted" }, `Inspecting ${targetUrl}…`));

  try {
    const res = await inspectOriginAgents(targetUrl);
    if (!res.found) {
      deskLink.href = DESK_BASE;
      out.replaceChildren(
        h("p", { class: "title" }, "No AI agent endpoint found"),
        h("p", { class: "muted" }, `Checked ${res.checked.map((u) => new URL(u).pathname).join(", ")} on ${res.origin}.`),
      );
      return;
    }

    const r = res.report;
    proto.textContent = r.protocol || "open-agentic-web";
    proto.hidden = false;
    deskLink.href = `${DESK_BASE}?inspect=${encodeURIComponent(res.endpoint)}`;

    const items = (r.findings || []).slice(0, 5).map((f) => h("li", null,
      h("strong", null, `[${f.severity}] ${f.title}`),
      h("span", null, f.detail || f.rule)));

    out.replaceChildren(
      h("div", { class: "verdict" },
        h("span", { class: `pill ${r.verdict.tone || "warn"}` }, r.verdict.stamp),
        h("span", { class: "hash" }, `${r.conformance.passed}/${r.conformance.total} pass · ${r.identity.short || "no hash"}`)),
      h("p", { class: "title" }, r.identity.brand || r.target.host || res.endpoint),
      h("p", { class: "summary" }, r.verdict.summary),
      items.length ? h("ul", { class: "findings" }, items) : h("p", { class: "muted" }, "Zero contraband or privacy issues detected."),
    );
  } catch (err) {
    out.replaceChildren(h("p", { class: "muted" }, `Inspection failed: ${err.message}`));
  }
}

async function bootPopup() {
  const input = $("#ext-url");
  $("#ext-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const val = input.value.trim();
    if (val) runCheck(val);
  });

  if (typeof chrome !== "undefined" && chrome.tabs?.query) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:/i.test(tab.url)) {
      const origin = new URL(tab.url).origin;
      input.value = origin;
      await runCheck(origin);
      return;
    }
  }
  $("#ext-out").replaceChildren(h("p", { class: "muted" }, "Open an https:// tab or enter an agent endpoint URL above."));
}

bootPopup();
