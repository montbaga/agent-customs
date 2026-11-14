// smoke.mjs: open the running site in headless Edge or Chrome, click through the main
// flows, record JavaScript errors and take screenshots. Uses the browser's DevTools
// protocol over Node's built-in WebSocket (Node 22+). No dependencies.
//
//   node tools/smoke.mjs [--url http://127.0.0.1:8080/] [--out ./screenshots] [--browser <path>]
//
// Serve the site and the range first (see README). Exits 1 on any page error.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const args = process.argv.slice(2);
const opt = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback; };
const URL_ = opt("--url", "http://127.0.0.1:8080/");
const OUT = path.resolve(opt("--out", "screenshots"));
const PORT = 9333;
const candidates = [
  opt("--browser", ""),
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
].filter(Boolean);
const browserPath = candidates.find((p) => existsSync(p));
if (!browserPath) { console.error("No Edge or Chrome found. Pass --browser <path>."); process.exit(2); }

await mkdir(OUT, { recursive: true });
const profile = await mkdtemp(path.join(os.tmpdir(), "agent-customs-smoke-"));
const browser = spawn(browserPath, [`--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, "--headless=new",
  "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--window-size=1366,900", "about:blank"], { stdio: "ignore" });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let targets;
for (let i = 0; i < 50; i += 1) {
  try { targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json(); if (targets.some((t) => t.type === "page")) break; } catch { /* starting */ }
  await sleep(200);
}
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let seq = 0;
const pending = new Map();
const events = [];
const problems = [];
ws.addEventListener("message", (msg) => {
  const data = JSON.parse(msg.data);
  if (data.id && pending.has(data.id)) { pending.get(data.id)(data); pending.delete(data.id); return; }
  events.push(data);
  if (data.method === "Runtime.exceptionThrown") problems.push(`exception: ${data.params.exceptionDetails.exception?.description || data.params.exceptionDetails.text}`);
  if (data.method === "Runtime.consoleAPICalled" && data.params.type === "error") problems.push(`console.error: ${data.params.args.map((a) => a.value ?? a.description).join(" ")}`);
  if (data.method === "Log.entryAdded" && data.params.entry.level === "error") problems.push(`log: ${data.params.entry.text} ${data.params.entry.url || ""}`);
});
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++seq;
  pending.set(id, (d) => (d.error ? reject(new Error(`${method}: ${d.error.message}`)) : resolve(d.result)));
  ws.send(JSON.stringify({ id, method, params }));
});
const evaluate = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  return r.result.value;
};
const waitFor = async (expression, ms = 15000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await evaluate(expression)) return true; await sleep(150); }
  throw new Error(`Timed out waiting for: ${expression}`);
};
const shot = async (name, { full = true } = {}) => {
  let params = { format: "png" };
  if (full) {
    // Scroll-in animations only run while scrolling, so a full-page capture would show
    // them unplayed. Reduced motion shows everything (and checks that fallback).
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
    await sleep(300);
    const m = await send("Page.getLayoutMetrics");
    const { width, height } = m.cssContentSize || m.contentSize;
    params = { ...params, captureBeyondViewport: true, clip: { x: 0, y: 0, width, height: Math.min(height, 12000), scale: 1 } };
  }
  const { data } = await send("Page.captureScreenshot", params);
  if (full) await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  await writeFile(path.join(OUT, `${name}.png`), Buffer.from(data, "base64"));
  console.log(`  screenshot ${name}.png`);
};
const viewport = (width, height, mobile = false) => send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile });
const noSideScroll = async (label) => {
  const r = await evaluate("({sw: document.documentElement.scrollWidth, iw: window.innerWidth})");
  if (r.sw > r.iw + 1) problems.push(`${label}: page scrolls sideways (${r.sw}px content in ${r.iw}px)`);
};

try {
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Log.enable");
  await viewport(1366, 900);
  console.log(`Opening ${URL_} in ${path.basename(browserPath)}`);
  await send("Page.navigate", { url: URL_ });
  await waitFor("document.readyState === 'complete' && document.querySelectorAll('#examples button').length > 0");
  await waitFor("!/Connecting the officer/.test(document.querySelector('#assistant-status').textContent)");
  console.log("  assistant status:", await evaluate("document.querySelector('#assistant-status').textContent"));
  await shot("01-home");

  const inspect = async (label) => {
    await evaluate(`[...document.querySelectorAll('#examples button')].find(b => b.textContent.startsWith(${JSON.stringify(label)})).click()`);
    await waitFor(`!document.querySelector('#report').hidden && document.querySelector('#report-title') && document.querySelector('#inspect-button').textContent === 'Inspect a network'`);
    await sleep(500);
    return evaluate("({stamp: document.querySelector('.stamp strong')?.textContent, findings: document.querySelectorAll('.finding').length, summary: document.querySelector('.report-summary')?.textContent})");
  };
  for (const [label, file, expected] of [
    ["Shady Pizza", "02-shady-pizza", "Entry denied"],
    ["Bank look-alike", "03-bank-lookalike", "Entry denied"],
    ["Loop Maze", "04-loop-maze", "Held for review"],
    ["Sunny Bakery", "05-sunny-bakery", "Cleared"],
  ]) {
    const r = await inspect(label);
    console.log(`  ${label}: ${r.stamp} · ${r.findings} finding(s) · ${r.summary}`);
    if (r.stamp !== expected) problems.push(`${label}: expected "${expected}", got "${r.stamp}"`);
    await evaluate("document.querySelector('#report-section').scrollIntoView()");
    const box = await evaluate("(() => { const r = document.querySelector('#report').getBoundingClientRect(); return {x: r.left + scrollX, y: r.top + scrollY, w: r.width, h: r.height}; })()");
    const { data } = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip: { x: box.x, y: box.y, width: box.w, height: Math.min(box.h, 5000), scale: 1 } });
    await writeFile(path.join(OUT, `${file}.png`), Buffer.from(data, "base64"));
    console.log(`  screenshot ${file}.png`);
  }

  // Approve the bakery, then compare it with the rug-pulled version.
  await evaluate("[...document.querySelectorAll('.report-actions button')].find(b => /Approve/.test(b.textContent))?.click()");
  await waitFor("document.querySelectorAll('#pins-list li .ptitle').length > 0");
  await waitFor("[...document.querySelectorAll('.report-actions button')].some((b) => b.textContent === 'Forget approval')");
  const approved = await evaluate(`({
    identity: [...document.querySelectorAll('#report .light')].find((l) => /Identity/.test(l.textContent))?.querySelector('.value')?.textContent,
    notice: document.querySelector('.report-actions .toast')?.textContent || "",
  })`);
  console.log(`  after approving: ${approved.identity} · "${approved.notice}"`);
  if (approved.identity !== "Matches your approval" || !/^Approved/.test(approved.notice)) problems.push(`after approving the bakery: identity "${approved.identity}", message "${approved.notice}"`);
  // Dialogs: answer one, then report what it asked and what came of it.
  const answerDialog = (start, button, after = "") => evaluate(`(async () => {
    const { desk } = await import(new URL("desk.js", location.href).href);
    const answer = (${start})();
    await new Promise((r) => setTimeout(r, 300));
    const dialog = document.querySelector("dialog.customs-review");
    const title = dialog?.querySelector("h2")?.textContent || "";
    [...(dialog?.querySelectorAll("button") || [])].find((b) => b.textContent === ${JSON.stringify(button)})?.click();
    const result = await answer;
    return { title, result, ${after} };
  })()`);
  // When the officer asks to forget an approval, the visitor is asked first. Say no.
  const asked = await answerDialog("() => desk.unpin(desk.latest.target.url, { askFirst: true })", "Keep it", "kept: !!desk.pins.get(desk.latest.target.url)");
  console.log(`  officer asks to forget: "${asked.title}" · ${asked.result.ok ? "forgotten" : "kept"}`);
  if (!/^Forget your approval/.test(asked.title) || asked.result.ok !== false || !asked.kept) problems.push(`the officer's request to forget an approval was not put to the visitor: ${JSON.stringify(asked)}`);
  await evaluate("document.querySelector('#tab-approvals').click(); document.querySelector('#workspace').scrollIntoView()");
  await sleep(300);
  await shot("06a-approvals", { full: false });
  await evaluate("document.querySelector('#tab-officer').click(); document.querySelector('#workspace').scrollIntoView()");
  await sleep(400);
  await shot("06b-officer", { full: false });
  await evaluate("document.querySelector('#tab-compare').click(); document.querySelector('#compare-demo').click()");
  await waitFor("document.querySelectorAll('#compare-result .changes li').length > 0");
  console.log("  compare:", await evaluate("[...document.querySelectorAll('#compare-result .changes li strong')].map(s => s.textContent).join(' | ')"));
  // The guard's dialog for a held partner (the rug-pulled bakery): turn it away.
  const held = await answerDialog(`async () => { const { confirmEntryDialog } = await import(new URL("customs/guard-ui.js", location.href).href);
    return confirmEntryDialog(desk.comparison.after); }`, "Turn it away");
  console.log(`  guard asks: "${held.title}" · ${held.result ? "let in" : "turned away"}`);
  if (!/^Let /.test(held.title) || held.result !== false) problems.push(`the guard's review dialog did not work: ${JSON.stringify(held)}`);
  // The model picker: choosing another provider shows its models and empties the key field.
  const picked = await evaluate(`(() => {
    const key = document.querySelector("#mp-key");
    key.value = "a key typed for another provider";
    document.querySelector('#mp-cards input[value="claude"]').click();
    return { cards: document.querySelectorAll("#mp-cards .mp-card").length, keyCleared: key.value === "",
      model: document.querySelector("#mp-model").selectedOptions[0]?.textContent || "", link: document.querySelector("#mp-key-link").href };
  })()`);
  console.log(`  model picker: ${picked.cards} cards · Claude shows "${picked.model}" · key field ${picked.keyCleared ? "emptied" : "kept"}`);
  if (picked.cards !== 5 || !picked.keyCleared || !/Claude/.test(picked.model) || !/anthropic/.test(picked.link)) problems.push(`model picker: ${JSON.stringify(picked)}`);
  await evaluate("document.querySelector('#workspace').scrollIntoView()");
  await sleep(300);
  const desk = await evaluate("(() => { const r = document.querySelector('#workspace').getBoundingClientRect(); return {x: r.left + scrollX, y: r.top + scrollY, w: r.width, h: r.height}; })()");
  const { data: deskShot } = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip: { x: desk.x, y: desk.y, width: desk.w, height: desk.h, scale: 1 } });
  await writeFile(path.join(OUT, "06-approvals-and-compare.png"), Buffer.from(deskShot, "base64"));
  console.log("  screenshot 06-approvals-and-compare.png");

  // Close-ups of each section at real size.
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  for (const id of ["hidden", "workspace", "how", "guard"]) {
    await evaluate(`document.getElementById(${JSON.stringify(id)}).scrollIntoView({block: "start"}); scrollBy(0, -90)`);
    await sleep(350);
    await shot(`section-${id}`, { full: false });
  }
  // The closing section, at rest.
  await evaluate("document.querySelector('footer.closing').scrollIntoView({block: 'start'})");
  await sleep(300);
  await shot("section-closing", { full: false });
  // The hidden sentence half lit: motion on, the section's top half way up the screen.
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  await evaluate("scrollTo(0, document.getElementById('hidden').offsetTop - innerHeight * 0.55)");
  await sleep(500);
  await shot("moment-mid-scrub", { full: false });
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  // Each palette: the hero and the light band.
  for (const palette of ["forest", "terracotta", "navy", "espresso"]) {
    await evaluate(`document.querySelector('.palette-picker button[data-palette="${palette}"]')?.click()`);
    await evaluate("scrollTo(0, 0)");
    await sleep(350);
    await shot(`palette-${palette}-top`, { full: false });
    await evaluate("document.getElementById('how').scrollIntoView({block: 'start'}); scrollBy(0, -40)");
    await sleep(350);
    await shot(`palette-${palette}-band`, { full: false });
  }
  await evaluate(`document.querySelector('.palette-picker button[data-palette="forest"]')?.click()`);
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  await noSideScroll("desktop");
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
  await evaluate("scrollTo(0, 0)");
  await sleep(300);
  await shot("07-dark-top", { full: false });
  await inspect("Shady Pizza");
  await evaluate("document.querySelector('#report-section').scrollIntoView()");
  await sleep(300);
  await shot("08-dark-report", { full: false });
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
  await viewport(390, 844, true);
  await sleep(400);
  await noSideScroll("phone");
  await evaluate("scrollTo(0, 0)");
  await sleep(200);
  await shot("09-phone-top", { full: false });
  await evaluate("document.querySelector('#report-section').scrollIntoView()");
  await sleep(300);
  await shot("10-phone-report", { full: false });
  await evaluate("document.querySelector('#tab-compare').click(); document.querySelector('#workspace').scrollIntoView()");
  await sleep(300);
  await noSideScroll("phone compare");
  await shot("11-phone-compare", { full: false });
} catch (error) {
  problems.push(`smoke step failed: ${error.message}`);
} finally {
  ws.close();
  browser.kill();
}

if (problems.length) {
  console.log("\nProblems:");
  for (const p of problems) console.log(`  - ${p}`);
  process.exitCode = 1;
} else {
  console.log("\nNo page errors.");
}
