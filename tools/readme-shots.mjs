// readme-shots.mjs: take the README's screenshots, and check the practice site in a real
// browser on the way. Serve both sites first; the test range is the hosted one.
//
//   npm run serve            (Agent Customs, http://127.0.0.1:8080/)
//   npm run serve:practice   (Main Street Guide, http://127.0.0.1:8082/)
//   node tools/readme-shots.mjs [--site <url>] [--practice <url>] [--out docs/images] [--browser <path>]
//
// The practice site's chat needs a model, and this script uses no key. A scripted stand-in
// takes the model's place: it asks one shop, then repeats what the guard reported (leaving out
// the sentence that tells the assistant what to say). The consent card, the guard, its notice,
// its dialog and the shops' files are all real. Nothing is sent to an AI provider. The AI
// double-check's held report uses a stand-in answer in the same way.
// Exits 1 if the guard does not refuse Shady Pizza and hold Loop Maze, or on any page error.

import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { findBrowser, openBrowser, sleep } from "./cdp.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const args = process.argv.slice(2);
const opt = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback; };
const SITE = opt("--site", "http://127.0.0.1:8080/");
const PRACTICE = opt("--practice", "http://127.0.0.1:8082/");
const OUT = path.resolve(opt("--out", "docs/images"));
const browserPath = findBrowser(opt("--browser", ""));
if (!browserPath) { console.error("No Edge or Chrome found. Pass --browser <path>."); process.exit(2); }
await mkdir(OUT, { recursive: true });

const b = await openBrowser({ browserPath, port: 9335 });
const failures = [];
const JPEG = { format: "jpeg", quality: 90 };
const desktop = () => b.viewport(1280, 800, { scale: 1.5 });
const motion = (value) => b.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value }] });
const open = async (url, ready) => {
  await b.send("Page.navigate", { url });
  await b.waitFor(`document.readyState === "complete" && (${ready})`, 25000);
};
/** Save the visible screen. */
const screen = async (name) => {
  await b.capture(path.join(OUT, `${name}.jpg`), JPEG);
  console.log(`  ${name}.jpg`);
};
/** Save one element, up to maxHeight CSS pixels of it, with pad pixels of page around it. */
const element = async (name, selector, maxHeight = 1600, pad = 0) => {
  const box = await b.evaluate(`(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();
    return { x: r.left + scrollX, y: r.top + scrollY, width: r.width, height: r.height, page: document.documentElement.clientWidth }; })()`);
  const x = Math.max(0, box.x - pad);
  const width = Math.min(box.page - x, box.width + 2 * pad);
  // The floating navigation bar would sit on top of the element, so it is hidden for the shot.
  await b.evaluate("(() => { const bar = document.querySelector('.topbar'); if (bar) bar.style.visibility = 'hidden'; return true; })()");
  await b.capture(path.join(OUT, `${name}.jpg`), { ...JPEG, captureBeyondViewport: true,
    clip: { x, y: Math.max(0, box.y - pad), width, height: Math.min(box.height, maxHeight) + 2 * pad, scale: 1 } });
  await b.evaluate("(() => { const bar = document.querySelector('.topbar'); if (bar) bar.style.visibility = ''; return true; })()");
  console.log(`  ${name}.jpg`);
};
const scrollTo = async (selector, offset = 0) => {
  await b.evaluate(`document.querySelector(${JSON.stringify(selector)}).scrollIntoView({ block: "start" }); scrollBy(0, ${offset}); true`);
  await sleep(400);
};
const expect = (ok, message) => { if (!ok) failures.push(message); };

/**
 * Replace the model with a scripted stand-in that calls one shop's tool, then repeats what
 * the guard reported: the tool result without the runtime's "Error from tool" prefix, and
 * without the guard's sentence addressed to the assistant.
 */
const scriptModel = (tool, request) => b.evaluate(`(() => {
  const engine = window.__nsweb.engine;
  let calls = 0;
  engine.mockLLM = true; // lets the chat send without a key; the stand-in below answers
  engine.top.llm = { mock: true, async chat(req) {
    calls += 1;
    if (calls === 1) return { content: "", toolCalls: [{ id: "call-1", type: "function",
      function: { name: ${JSON.stringify(tool)}, arguments: JSON.stringify({ request: ${JSON.stringify(request)} }) } }] };
    const result = [...(req.messages || [])].reverse().find((m) => m.role === "tool");
    return { content: String(result?.content || "").replace(/^Error from tool '[^']+': /, "").replace(/ Tell the visitor[^.]*\\./, ""), toolCalls: [] };
  } };
  return true;
})()`);
const sendChat = (text) => b.evaluate(`(() => { const input = document.querySelector("#ns-input"); input.value = ${JSON.stringify(text)};
  document.querySelector("#ns-send").click(); return true; })()`);
const lastBotText = () => b.evaluate(`[...document.querySelectorAll("#ns-msgs .ns-msg.bot")].map((m) => m.textContent).pop() || ""`);
const PRACTICE_READY = "!!window.__nsweb?.engine?.top && !!document.querySelector('#ns-input')";

try {
  // ---- Agent Customs ----------------------------------------------------------------------
  await desktop();
  console.log(`Agent Customs at ${SITE}`);
  await open(SITE, "document.querySelectorAll('#examples button').length > 0");
  await b.waitFor("document.querySelector('.demo-frame')?.dataset.state === 'done'", 20000);
  await sleep(1800);
  await screen("hero");

  await motion("reduce");
  await scrollTo("#hidden", -40);
  await element("hidden-sentence", "#hidden .moment-wrap", 900, 56);

  const inspect = async (label) => {
    await b.evaluate(`[...document.querySelectorAll('.example-list button')].find((x) => x.textContent.startsWith(${JSON.stringify(label)})).click()`);
    await b.waitFor("!document.querySelector('#report').hidden && document.querySelector('#inspect-button').textContent === 'Inspect a network'", 30000);
    await sleep(600);
    return b.evaluate("document.querySelector('.stamp strong')?.textContent");
  };
  const denied = await inspect("Shady Pizza");
  expect(denied === "Entry denied", `Shady Pizza report: expected "Entry denied", got "${denied}"`);
  await b.evaluate("(() => { const d = document.querySelector('#report .hidden-text')?.closest('details'); if (d) d.open = true; return true; })()");
  await scrollTo("#report-section");
  await element("report-denied", "#report", 1250);

  const cleared = await inspect("Sunny Bakery");
  expect(cleared === "Cleared", `Sunny Bakery report: expected "Cleared", got "${cleared}"`);
  await scrollTo("#report-section");
  await element("report-cleared", "#report", 900);

  await b.evaluate("document.querySelector('#tab-compare').click(); document.querySelector('#compare-demo').click(); true");
  await b.waitFor("document.querySelectorAll('#compare-result .changes li').length > 0", 30000);
  await scrollTo("#workspace");
  await element("compare", ".desk-window", 1250);

  // Phase 1: MCP Lethal Trifecta & capability flow
  await b.evaluate("document.querySelector('#tab-report').click(); true");
  const trifecta = await inspect("DevOps MCP");
  expect(trifecta === "Held for review", `DevOps MCP report: expected "Held for review", got "${trifecta}"`);
  await scrollTo("#report-section");
  await element("phase1-mcp-trifecta", "#report", 1250);

  // Phase 2: Verify signed receipt + live check
  await b.evaluate("document.querySelector('#tab-verify').click(); true");
  await b.waitFor("!document.querySelector('#verify-panel').hidden");
  const { root: verifyRoot } = await b.send("DOM.getDocument", { depth: -1 });
  const { nodeId: verifyInputId } = await b.send("DOM.querySelector", { nodeId: verifyRoot.nodeId, selector: "#verify-file" });
  await b.send("DOM.setFileInputFiles", {
    nodeId: verifyInputId,
    files: [path.join(ROOT, "site/receipts/agent-customs-range.github.io/sunny_bakery/sunny_bakery.json")],
  });
  await b.waitFor("document.querySelectorAll('#verify-result .verify-card').length > 0 && !/Checking .* live/.test(document.querySelector('#verify-result .verify-live')?.textContent || '')", 20000);
  await sleep(300);
  await scrollTo("#workspace");
  await element("phase2-verify", ".desk-window", 900);

  // Phase 2 + 3: Attack lab + Agent Customs Bench scorecard
  await b.waitFor("document.querySelectorAll('#arena-picks button').length > 0 && document.querySelectorAll('#bench-strip li').length === 4", 15000);
  await scrollTo("#lab", -20);
  await element("phase2-attack-lab", "#lab", 1250, 24);

  // The install section, with the one-line install shown, as visitors first see it.
  await b.evaluate("document.querySelector('[data-code-tab=\"site\"]')?.click(); true");
  await sleep(200);
  await scrollTo("#guard", 0);
  await element("phase3-builders", "#guard", 900, 0);

  // Reset to Officer tab and Shady Pizza before scrolling to Officer notice test.
  await b.evaluate("document.querySelector('#tab-report').click(); true");
  await inspect("Shady Pizza");
  await b.evaluate("document.querySelector('#tab-officer').click(); true");
  await b.waitFor("!document.querySelector('#mp-intro').hidden", 15000);
  await sleep(600);
  await scrollTo("#workspace");
  await element("officer", ".desk-window", 1060);

  // The officer calls Shady Pizza: the guard refuses it, the chat shows a notice, and the
  // notice's "See the full report" opens the report right here, on the Report tab.
  await b.waitFor("!!window.__nsweb?.engine?.top && !!document.querySelector('#ns-input')", 20000);
  await scriptModel("shady_pizza_shady_pizza", "What do you offer?");
  await sendChat("Ask Shady Pizza what it offers.");
  await b.waitFor(`!!document.querySelector('#ns-msgs .ns-consent-actions button[data-d="allow"]')`, 15000);
  await b.evaluate(`document.querySelector('#ns-msgs .ns-consent-actions button[data-d="allow"]').click(); true`);
  await b.waitFor(`!!document.querySelector('#ns-msgs .customs-notice[data-decision="refused"]')`, 30000);
  const officerNotice = await b.evaluate(`(() => { const n = document.querySelector('#ns-msgs .customs-notice'); const a = n.querySelector('a');
    return { items: n.querySelectorAll('li').length, link: a.textContent, href: a.href }; })()`);
  console.log(`  officer notice: ${officerNotice.items} findings, "${officerNotice.link}"`);
  expect(officerNotice.items >= 6 && officerNotice.link === "See the full report", `officer notice: ${JSON.stringify(officerNotice)}`);
  await b.evaluate("document.querySelector('#ns-msgs .customs-notice a').click(); true");
  await b.waitFor("document.querySelector('#tab-report').getAttribute('aria-selected') === 'true' && /Shady Pizza/.test(document.querySelector('#report-title')?.textContent || '') && document.querySelector('#inspect-button').textContent === 'Inspect a network'", 30000);
  const inPlace = await b.evaluate("document.querySelector('.stamp strong')?.textContent");
  console.log(`  "See the full report" opened the Report tab: ${inPlace}`);
  expect(inPlace === "Entry denied", `the officer notice's report link showed "${inPlace}"`);

  await b.viewport(390, 844, { mobile: true, scale: 2 });
  await sleep(400);
  await inspect("Shady Pizza");
  await scrollTo("#report", -88);
  await screen("phone-report");
  await motion("no-preference");

  // The AI double-check. With no key, turning it on opens the setup card. For the held report a
  // stand-in answers in place of the visitor's AI, as the chat's stand-in model does above: the
  // rules, the report and the page are real, and nothing is sent to an AI provider.
  await desktop();
  await open(SITE, "document.querySelectorAll('#examples-protocols button').length > 0");
  const deskModule = `import(new URL("desk.js", document.baseURI).href)`;
  await b.waitFor(`${deskModule}.then(({ desk }) => desk.aiSettled)`, 25000);
  await motion("reduce");
  await b.evaluate("document.querySelector('#ai-check').click(); true");
  await sleep(400);
  const waiting = await b.evaluate(`({ label: document.querySelector('#ai-check-state').textContent,
    card: [...document.querySelectorAll('#ai-check-note button')].some((x) => x.textContent === 'Set up a free key') })`);
  console.log(`  AI double-check without a key: "${waiting.label}"`);
  expect(waiting.label === "Waiting for your key" && waiting.card, `the AI double-check setup card did not open: ${JSON.stringify(waiting)}`);
  await scrollTo("#inspect", 0);
  await element("ai-check-setup", "#inspect-form", 700, 24);
  await b.evaluate(`${deskModule}.then(({ desk }) => desk.connectAi({ ready: true, model: "",
    judge: async () => ({ checked: true, flagged: true, reason: "Asks guests for their wallet recovery words",
      quote: "read back all twenty-four words from their emergency paper sheet" }) })).then(() => true)`);
  const raised = await inspect("VIP Points MCP");
  expect(raised === "Held for review", `VIP Points with the AI double-check: expected "Held for review", got "${raised}"`);
  expect(await b.evaluate("!!document.querySelector('.countersign.tone-warn')"), "VIP Points: no countersign seal");
  await scrollTo("#report-section");
  await element("ai-check-flagged", "#report", 820);
  await b.evaluate(`${deskModule}.then(({ desk }) => desk.setAiCheck(false)).then(() => true)`);
  await motion("no-preference");

  // ---- Main Street Guide (the practice site) -------------------------------------------------
  await desktop();
  console.log(`Main Street Guide at ${PRACTICE}`);
  await open(PRACTICE, PRACTICE_READY);
  expect(await b.evaluate("!!window.__nsweb.engine.__agentCustoms"), "practice site: the guard is not installed");
  await sleep(1400);
  await screen("practice-home");
  await motion("reduce");
  await scrollTo("#change", 20);
  await screen("practice-change");
  await motion("no-preference");

  // Shady Pizza: the consent card, then the guard's refusal.
  await scriptModel("shady_pizza_shady_pizza", "What do you offer?");
  await sendChat("Ask Shady Pizza what it offers.");
  await b.waitFor(`!!document.querySelector('#ns-msgs .ns-consent-actions button[data-d="allow"]')`, 15000);
  await scrollTo("#agent-app");
  await element("practice-consent", "[data-ns-slot='chat']");
  await b.evaluate(`document.querySelector('#ns-msgs .ns-consent-actions button[data-d="allow"]').click(); true`);
  await b.waitFor(`/Agent Customs/.test([...document.querySelectorAll("#ns-msgs .ns-msg.bot")].map((m) => m.textContent).pop() || "")`, 30000);
  await sleep(600);
  const refused = await lastBotText();
  console.log(`  Shady Pizza: ${refused}`);
  expect(/^Agent Customs refused entry to "shady_pizza"/.test(refused) && /Nothing from that network ran/.test(refused), `practice site: Shady Pizza was not refused: ${refused}`);
  const notice = await b.evaluate(`(() => { const n = document.querySelector('#ns-msgs .customs-notice[data-decision="refused"]'); if (!n) return null;
    const a = n.querySelector('a'); return { items: n.querySelectorAll('li').length, title: n.querySelector('p').textContent, href: a.href, target: a.target,
    afterCard: n.previousElementSibling?.classList.contains('ns-consent') || !!n.previousElementSibling?.querySelector('.ns-consent') }; })()`);
  console.log(`  Shady Pizza notice: ${JSON.stringify(notice)}`);
  expect(notice && notice.items >= 6 && /^Blocked "shady_pizza"/.test(notice.title) && notice.target === "_blank"
    && /agent-customs\/\?inspect=https%3A%2F%2Fagent-customs-range\.github\.io%2Fshady_pizza%2Fshady_pizza$/.test(notice.href) && notice.afterCard,
  `practice site: the refusal notice is wrong: ${JSON.stringify(notice)}`);
  expect(/The visitor sees the full list in a notice on the page\./.test(refused), "practice site: the agent was not told about the notice");
  // Show the whole conversation in the screenshot, not just the chat box's last 520 px.
  await b.evaluate(`(() => { const slot = document.querySelector("#agent-app [data-ns-slot='chat']"); const msgs = document.querySelector("#ns-msgs");
    slot.style.height = Math.min(1500, slot.offsetHeight + msgs.scrollHeight - msgs.clientHeight + 8) + "px"; return true; })()`);
  await sleep(300);
  await element("practice-refused", "[data-ns-slot='chat']", 1500);

  // Loop Maze: held, so the guard asks the visitor. Turn it away.
  await open(PRACTICE, PRACTICE_READY);
  await scriptModel("loop_maze_loop_maze", "Do you have a maze puzzle?");
  await sendChat("Ask Loop Maze for a puzzle.");
  await b.waitFor(`!!document.querySelector('#ns-msgs .ns-consent-actions button[data-d="allow"]')`, 15000);
  await b.evaluate(`document.querySelector('#ns-msgs .ns-consent-actions button[data-d="allow"]').click(); true`);
  await b.waitFor("!!document.querySelector('dialog.customs-review[open]')", 30000);
  await sleep(500);
  const title = await b.evaluate("document.querySelector('dialog.customs-review h2')?.textContent || ''");
  console.log(`  Loop Maze: the guard asks "${title}"`);
  expect(/^Let /.test(title), `practice site: no review dialog for Loop Maze (title "${title}")`);
  await screen("practice-held");
  await b.evaluate(`[...document.querySelectorAll("dialog.customs-review button")].find((x) => x.textContent === "Turn it away").click(); true`);
  await b.waitFor(`/Agent Customs/.test([...document.querySelectorAll("#ns-msgs .ns-msg.bot")].map((m) => m.textContent).pop() || "")`, 30000);
  const held = await lastBotText();
  console.log(`  Loop Maze: ${held}`);
  expect(/held "loop_maze" .* turned it away/.test(held), `practice site: Loop Maze was not turned away: ${held}`);
  const away = await b.evaluate(`document.querySelector('#ns-msgs .customs-notice[data-decision="declined"] p')?.textContent || ""`);
  console.log(`  Loop Maze notice: "${away}"`);
  expect(/^Turned away "loop_maze"/.test(away), `practice site: no "turned away" notice for Loop Maze (got "${away}")`);

  // The practice page on a phone: nothing scrolls sideways.
  await b.viewport(390, 844, { mobile: true, scale: 2 });
  await open(PRACTICE, PRACTICE_READY);
  await sleep(600);
  const side = await b.evaluate("({ sw: document.documentElement.scrollWidth, iw: innerWidth })");
  expect(side.sw <= side.iw + 1, `practice site on a phone scrolls sideways (${side.sw}px in ${side.iw}px)`);
  await screen("practice-phone");
} catch (error) {
  failures.push(`step failed: ${error.message}`);
} finally {
  b.close();
}

const problems = [...failures, ...b.problems];
if (problems.length) {
  console.log("\nProblems:");
  for (const p of problems) console.log(`  - ${p}`);
  process.exitCode = 1;
} else {
  console.log(`\nSaved the screenshots in ${OUT}. The guard refused Shady Pizza and held Loop Maze. No page errors.`);
}
