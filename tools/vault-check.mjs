// vault-check.mjs: checks the key vault end to end in a real browser.
//
//   npm run vault:check
//
// Serves the site (port 8087) and the vault (port 8090, where a page on this computer looks for
// it), plus a stand-in AI service on port 8099 that answers like an OpenAI-style provider and
// records which key and which origin each request came with. Then, in a headless browser:
//   0. pastes a Groq key and an Otari key on the Gemini card: each must pick its own card,
//   1. saves a key through the vault box ("Other", the stand-in's address),
//   2. checks that the page's own storage never holds the key and the vault's does,
//   3. chats with the officer and runs the AI double-check on the VIP Points sample: every AI
//      request must reach the stand-in from the vault's origin, with the key,
//   4. remembers the key with a password from the header's Remember key button, checks the
//      stored record is encrypted, starts a new visit (locked), unlocks it, and chats again,
//   5. forgets the key,
//   6. connects with Otari: a blocked window, a closed window, a cancel, two forged replies, then
//      a real approval that saves the new key for this visit and chats with it.
// Nothing leaves this computer: the stand-in is the only AI service, and it is local. Requests to
// the real Groq and Otari are blocked, so the made-up keys in step 0 go nowhere. In step 6 a
// stand-in plays otari.ai inside the vault's frame (OTARI_STAND_IN below).

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { findBrowser, openBrowser, sleep } from "./cdp.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "http://localhost:8087/";
const VAULT_ORIGIN = "http://localhost:8090";
const AI = "http://127.0.0.1:8099/v1";
const KEY = "stand-in-secret-key-4b1d";
const PASSWORD = "correct horse battery";
const OTARI_KEY = "otk_v1_stand_in_connected_7c2e";

// Plays otari.ai in the vault's frame. The vault's own code runs unchanged: only window.open
// and fetch calls for otari.ai addresses are answered here, and each is logged in the vault's
// sessionStorage. The Otari window opens for real, then goes straight to the vault's
// otari.html with the reply that data-otari-mode on the vault's <html> asks for.
const OTARI_STAND_IN = `(() => {
  if (location.origin !== ${JSON.stringify(VAULT_ORIGIN)}) return;
  const log = (entry) => {
    const all = JSON.parse(sessionStorage.getItem("otari-stand-in") || "[]");
    all.push(entry);
    sessionStorage.setItem("otari-stand-in", JSON.stringify(all));
  };
  const open = window.open;
  window.open = function (url, name, features) {
    if (!String(url).startsWith("https://otari.ai/")) return open.apply(this, arguments);
    const popup = open.call(window, "about:blank", name, features);
    if (!popup) return null;
    log({ open: String(url) });
    const asked = new URL(url).searchParams;
    const mode = document.documentElement.dataset.otariMode || "approve";
    setTimeout(() => {
      if (mode === "close") { popup.close(); return; }
      const answer = {
        state: mode === "other-state" ? "not-this-sign-in" : asked.get("state"),
        iss: mode === "other-issuer" ? "https://otari.example" : "https://otari.ai",
      };
      if (mode === "deny") answer.error = "access_denied";
      else answer.code = "stand-in-code";
      const back = new URL(asked.get("redirect_uri"));
      back.search = new URLSearchParams(answer).toString();
      popup.location.href = back.href;
    }, mode === "close" ? 1200 : 400);
    return popup;
  };
  const realFetch = window.fetch;
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  window.fetch = async function (input, init = {}) {
    const url = String(input instanceof Request ? input.url : input);
    if (!["https://otari.ai/", "https://api.otari.ai/", "https://eu.api.otari.ai/"].some((start) => url.startsWith(start))) return realFetch.apply(this, arguments);
    const headers = new Headers(init.headers || {});
    const body = init.body ? String(init.body) : "";
    log({ fetch: url, method: init.method || "GET", auth: headers.get("Authorization") || "", body: url.endsWith("/token") ? body : "" });
    if (url === "https://otari.ai/api/v1/oauth/apps/token") {
      return new URLSearchParams(body).get("code") === "stand-in-code"
        ? json({ access_token: ${JSON.stringify(OTARI_KEY)}, token_type: "Bearer" })
        : json({ error: "invalid_grant", error_description: "Unknown code." }, 400);
    }
    if (headers.get("Authorization") !== "Bearer " + ${JSON.stringify(OTARI_KEY)}) return json({ error: { message: "invalid api key" } }, 401);
    if (url.endsWith("/models")) return json({ data: [{ id: "alibaba/qwen3.8-flash" }, { id: "openai/gpt-oss-120b" }] });
    if (url.endsWith("/chat/completions")) {
      const chunk = (delta, finish = null) => "data: " + JSON.stringify({ model: "alibaba/qwen3.8-flash", choices: [{ index: 0, delta, finish_reason: finish }] }) + String.fromCharCode(10, 10);
      return new Response(chunk({ role: "assistant", content: "Hello from the stand-in AI, through Otari." }) + chunk({}, "stop") + "data: [DONE]" + String.fromCharCode(10, 10),
        { headers: { "Content-Type": "text/event-stream" } });
    }
    return json({}, 404);
  };
})();`;

// The stand-in AI service.
const seen = [];
const reply = (res, status, body, type = "application/json") => {
  res.writeHead(status, { "Content-Type": type, "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*" });
  res.end(body);
};
const ai = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") { reply(res, 204, ""); return; }
  let body = "";
  for await (const chunk of req) body += chunk;
  seen.push({ path: req.url, auth: req.headers.authorization || "", origin: req.headers.origin || "" });
  if (req.headers.authorization === "Bearer wrong-key-400") {
    reply(res, 400, JSON.stringify({ error: { code: 400, message: "Please pass a valid API key", status: "INVALID_ARGUMENT" } }));
    return;
  }
  if (req.headers.authorization !== `Bearer ${KEY}`) { reply(res, 401, JSON.stringify({ error: { message: "invalid api key" } })); return; }
  if (req.url === "/v1/models") { reply(res, 200, JSON.stringify({ data: [{ id: "stand-in-model" }] })); return; }
  if (req.url !== "/v1/chat/completions") { reply(res, 404, "{}"); return; }
  const text = body.includes("UNTRUSTED_INPUT")
    ? JSON.stringify(body.includes("twenty-four words")
      ? { flagged: true, category: "credential-theft", reason: "Asks guests for wallet recovery words", quote: "read back all twenty-four words from their emergency paper sheet" }
      : { flagged: false, category: "none", reason: "Nothing found", quote: "" })
    : "Hello from the stand-in AI.";
  const chunk = (delta, finish = null) => `data: ${JSON.stringify({ model: "stand-in-model", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
  reply(res, 200, chunk({ role: "assistant", content: text }) + chunk({}, "stop") + "data: [DONE]\n\n", "text/event-stream");
});

const servers = [
  spawn(process.execPath, [path.join(ROOT, "tools", "serve.mjs"), path.join(ROOT, "site"), "--port", "8087"], { stdio: "ignore" }),
  spawn(process.execPath, [path.join(ROOT, "tools", "serve.mjs"), path.join(ROOT, "vault"), "--port", "8090"], { stdio: "ignore" }),
];
await new Promise((resolve, reject) => ai.listen(8099, "127.0.0.1", resolve).on("error", reject));
await sleep(800);
const b = await openBrowser({ browserPath: findBrowser(), port: 9365 });
const failures = [];
const check = (ok, what, detail = "") => {
  console.log(`${ok ? "  ok  " : "  FAIL"} ${what}${detail ? ` · ${detail}` : ""}`);
  if (!ok) failures.push(what);
};

// Runs code inside the vault's frame. gesture: as if the visitor clicked, so a window may open.
async function inVault(expression, { gesture = false } = {}) {
  const { frameTree } = await b.send("Page.getFrameTree");
  const frame = (frameTree.childFrames || []).find((f) => f.frame.url.startsWith(VAULT_ORIGIN));
  if (!frame) throw new Error("The vault's frame is not on the page.");
  const { executionContextId } = await b.send("Page.createIsolatedWorld", { frameId: frame.frame.id, worldName: "vault-check" });
  const r = await b.send("Runtime.evaluate", { expression, contextId: executionContextId, awaitPromise: true, returnByValue: true, userGesture: gesture });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  return r.result.value;
}
const waitInVault = async (expression, ms = 15000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { if (await inVault(expression)) return true; } catch { /* frame still loading */ }
    await sleep(150);
  }
  throw new Error(`Timed out in the vault waiting for: ${expression}`);
};
const pageStorage = `JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage }, cookie: document.cookie })`;
const vaultStorage = `JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } })`;
const officer = async () => {
  await b.evaluate("document.querySelector('#tab-officer').click(); true");
  await b.waitFor("document.querySelector('#mp-vault iframe') && !/Loading/.test(document.querySelector('#mp-current').textContent)", 20000);
};
const chat = async (text) => {
  const before = await b.evaluate("document.querySelectorAll('#ns-msgs .ns-msg.bot').length");
  await b.evaluate(`(() => { const i = document.querySelector('#ns-input'); i.value = ${JSON.stringify(text)}; i.dispatchEvent(new Event('input', { bubbles: true })); document.querySelector('#ns-send').click(); return true; })()`);
  await b.waitFor(`document.querySelectorAll('#ns-msgs .ns-msg.bot').length > ${before} && /stand-in AI|vault|Error/i.test([...document.querySelectorAll('#ns-msgs .ns-msg.bot')].at(-1).textContent)`, 30000);
  return b.evaluate("[...document.querySelectorAll('#ns-msgs .ns-msg.bot')].at(-1).textContent.trim()");
};

try {
  await b.viewport(1366, 1000);
  await b.send("Network.enable", {});
  await b.send("Network.setBlockedURLs", { urls: ["*api.groq.com*", "*otari.ai*"] });
  await b.send("Page.addScriptToEvaluateOnNewDocument", { source: OTARI_STAND_IN });
  await b.send("Page.navigate", { url: SITE });
  await b.waitFor("document.readyState === 'complete'", 20000);
  await officer();
  await waitInVault("document.body.dataset.ready === 'true'");
  check(true, "the vault opened its private channel with the page");

  // 0. A key from a known company picks its own card, whatever card was selected.
  for (const [key, card, company] of [["gsk_madeup0000000000000000000000000000000000000000", "open", "Groq"], ["otk_v1_eu_madeup000000000000000000000000", "other", "Otari EU"]]) {
    await b.evaluate("document.querySelector('#mp-cards input[value=\"gemini\"]').click(); true");
    await waitInVault("/Google AI Studio/.test(document.querySelector('#key-note')?.textContent || '')");
    await inVault(`(() => { const k = document.querySelector('#key'); k.value = ${JSON.stringify(key)}; k.dispatchEvent(new InputEvent('input', { inputType: 'insertFromPaste' })); return true; })()`);
    await b.waitFor(`document.querySelector('#mp-cards input:checked')?.value === ${JSON.stringify(card)}`, 10000);
    await waitInVault(`/sent only to ${company}/.test(document.querySelector('#key-note')?.textContent || '') && !document.querySelector('.draft-row[data-tone="warn"]')`, 10000);
    const said = await b.evaluate("document.querySelector('#mp-status').textContent");
    check(new RegExp(`Switched to .* for your ${company} key`).test(said), `${/^[aeiou]/i.test(company) ? "an" : "a"} ${company} key pasted on the Gemini card moves to its own card`, said.slice(0, 90));
    await inVault("[...document.querySelectorAll('button')].find((x) => x.textContent === 'Clear').click(); true");
  }
  await b.evaluate("window.beforeReload = true");
  await b.send("Page.reload", {});
  await b.waitFor("!window.beforeReload && document.readyState === 'complete'", 20000);
  await officer();
  await waitInVault("document.body.dataset.ready === 'true'");

  // 1. Save a key through the vault box.
  await b.evaluate("document.querySelector('#mp-cards input[value=\"other\"]').click(); true");
  await waitInVault("!!document.querySelector('#address')");
  const fieldOrder = await inVault("!!(document.querySelector('#key').compareDocumentPosition(document.querySelector('#address')) & Node.DOCUMENT_POSITION_FOLLOWING)");
  check(fieldOrder, "on Other the key field comes before the optional service address");
  await b.evaluate("document.querySelector('#mp-start').click(); true");
  await b.waitFor("/Paste your key first/.test(document.querySelector('#mp-status').textContent)", 5000);
  check((await inVault("document.activeElement?.id")) === "key", "an empty Other form asks for the key first and focuses it");

  // A rejected key (401 or 400 INVALID_ARGUMENT) surfaces its refusal instead of saving.
  await inVault(`(() => {
    const a = document.querySelector('#address'); a.value = ${JSON.stringify(AI)}; a.dispatchEvent(new Event('change'));
    const k = document.querySelector('#key'); k.value = "wrong-key-400"; k.dispatchEvent(new Event('input')); return true; })()`);
  await b.evaluate("document.querySelector('#mp-start').click(); true");
  await b.waitFor("!document.querySelector('#mp-start').disabled && /didn't accept this key/.test(document.querySelector('#mp-status').textContent)", 10000);
  check(seen.some((s) => s.auth === "Bearer wrong-key-400"), "a 400 invalid-key refusal is shown and never saves");
  await b.evaluate("document.querySelector('#mp-status').textContent = ''; true");
  await inVault(`(() => {
    const k = document.querySelector('#key'); k.value = "wrong-stand-in-key"; k.dispatchEvent(new Event('input')); return true; })()`);
  await b.evaluate("document.querySelector('#mp-start').click(); true");
  await b.waitFor("!document.querySelector('#mp-start').disabled && /didn't accept this key/.test(document.querySelector('#mp-status').textContent)", 10000);
  check(seen.some((s) => s.auth === "Bearer wrong-stand-in-key"), "a 401 key refusal is shown instead of being lost in the vault reply");

  // Pasting a valid key and immediately pressing Save and start works without waiting for the debounce timer.
  await inVault(`(() => {
    const k = document.querySelector('#key'); k.value = ${JSON.stringify(KEY)}; k.dispatchEvent(new Event('input')); return true; })()`);
  await b.evaluate("window.beforeSave = true; document.querySelector('#mp-start').click(); true");
  try {
    await b.waitFor("!window.beforeSave && document.readyState === 'complete'", 20000);
  } catch {
    throw new Error(`Save and start did not reload the page: ${await b.evaluate("document.querySelector('#mp-status').textContent")}`);
  }
  await officer();
  const inUse = await b.evaluate("document.querySelector('#mp-current').textContent");
  check(/Using .*127\.0\.0\.1:8099.*kept for this visit only/.test(inUse), "after Save and start the officer uses the key from the vault", inUse);
  check(seen.some((s) => s.path === "/v1/models" && s.auth === `Bearer ${KEY}`), "the vault listed the key's models from the stand-in");

  // 2. Where the key is.
  const pageHas = (await b.evaluate(pageStorage)).includes(KEY);
  check(!pageHas, "the page's own storage and cookies never hold the key");
  check((await inVault(vaultStorage)).includes(KEY), "the vault's storage holds it, for this visit only");
  const runtimeKey = await b.evaluate("window.__nsweb?.engine?.byokKey");
  check(runtimeKey === "kept-in-the-key-vault", "the runtime holds only the stand-in key", runtimeKey);

  // A key the practice site or an older version left in the page's storage is pointed out,
  // even with the settings folded, and one click removes it.
  const OLD_KEY = "otk_v1_madeup_left_by_the_practice_site";
  await b.evaluate(`localStorage.setItem("nsweb-byok-profiles-v1", JSON.stringify({ version: 1, selectedId: "old", updatedAt: "",
    profiles: [{ id: "old", key: ${JSON.stringify(OLD_KEY)}, router: "https://api.otari.ai/api/v1", model: "alibaba/qwen3.8-flash" }] })); window.beforeReload = true`);
  await b.send("Page.reload", {});
  await b.waitFor("!window.beforeReload && document.readyState === 'complete'", 20000);
  await officer();
  await b.waitFor("document.querySelector('#mp-body').hidden && /Using/.test(document.querySelector('#mp-current').textContent)", 10000);
  const oldNote = await b.evaluate("document.querySelector('#mp-legacy').checkVisibility() ? document.querySelector('#mp-legacy').textContent.trim() : ''");
  check(/1 key from an older version/.test(oldNote), "an old key in the page's storage is pointed out while the settings are folded", oldNote.slice(0, 90));
  await b.evaluate("document.querySelector('#mp-legacy button').click(); true");
  const cleaned = await b.evaluate(`document.querySelector('#mp-legacy').textContent.trim() + " | " + ${pageStorage}`);
  check(/Old copy deleted/.test(cleaned) && !cleaned.includes(OLD_KEY), "Delete the old copy removes it from the page's storage and says so", cleaned.slice(0, 60));

  // 3. Chat, and the AI double-check.
  const answer = await chat("hello");
  check(/stand-in AI/.test(answer), "the officer answers through the vault", answer.slice(0, 80));
  await b.evaluate("document.querySelector('#ai-check').getAttribute('aria-checked') === 'true' || document.querySelector('#ai-check').click(); true");
  await b.evaluate(`(() => { document.querySelector('#inspect-url').value = new URL('samples/ai-check-demo/mcp.json', location.href).href; document.querySelector('#inspect-form').requestSubmit(); return true; })()`);
  await b.waitFor("!document.querySelector('#report').hidden && document.querySelector('#inspect-button').textContent === 'Inspect a network' && document.querySelector('#report-title')", 30000);
  const stamp = await b.evaluate("document.querySelector('.stamp strong')?.textContent + ' | ' + document.querySelector('#ai-line')?.textContent");
  check(/HELD|Held/i.test(stamp) && /flagged/.test(stamp), "the AI double-check ran through the vault and held VIP Points", stamp.slice(0, 120));
  const aiRequests = seen.filter((s) => s.path === "/v1/chat/completions");
  check(aiRequests.length >= 2 && aiRequests.every((s) => s.auth === `Bearer ${KEY}` && s.origin === VAULT_ORIGIN),
    "every AI request came from the vault's origin with the key", `${aiRequests.length} requests, origins ${[...new Set(seen.map((s) => s.origin))].join(", ")}`);

  // 4. Remember with a password from the header's button, start a new visit, unlock.
  await officer();
  await b.waitFor("document.querySelector('#mp-body').hidden && !document.querySelector('#mp-remember').hidden", 10000);
  check(true, "a key kept for this visit offers Remember key without opening the settings");
  await b.evaluate("document.querySelector('#mp-remember').click(); true");
  await waitInVault("!!document.querySelector('input[name=\"lock\"]')");
  check(await inVault("(() => { const r = [...document.querySelectorAll('input[name=\"lock\"]')]; return r.length === 2 && r[0].value === 'passkey' && !r[0].disabled && r[0].checked && r[1].value === 'password'; })()"),
    "both lock options stay visible with passkey first and enabled on localhost");
  await inVault("document.querySelector('input[name=\"lock\"][value=\"password\"]').click(); true");
  await waitInVault("!!document.querySelector('#password')");
  await inVault(`(() => { document.querySelector('#password').value = ${JSON.stringify(PASSWORD)};
    [...document.querySelectorAll('button')].find((x) => /Save and lock/.test(x.textContent)).click(); return true; })()`);
  await waitInVault("/protected by your password/.test(document.body.textContent)", 20000);
  await b.waitFor("document.querySelector('#mp-body').hidden && document.querySelector('#mp-remember').hidden && /saved on this device/.test(document.querySelector('#mp-current').textContent)", 10000);
  check(true, "once saved, the settings fold again and the header says the key is saved on this device");
  const box = await inVault("localStorage.getItem('vault-box') || ''");
  const rounds = (() => { const b = JSON.parse(box); return (Object.values(b.entries || {})[0] || b).rounds; })();
  check(box.length > 0 && !box.includes(KEY), "the remembered key is stored only encrypted", `${box.length} characters, PBKDF2 rounds ${rounds}`);
  // A new visit: the tab's copy is gone, the encrypted record stays.
  await inVault("sessionStorage.clear(); true");
  await b.evaluate("window.beforeReload = true");
  await b.send("Page.reload", {});
  await b.waitFor("!window.beforeReload && document.readyState === 'complete'", 20000);
  await officer();
  await waitInVault("/is locked/.test(document.body.textContent)");
  const lockedNow = await b.evaluate("document.querySelector('#mp-current').textContent + ' | ' + document.querySelector('#ai-check-state').textContent");
  check(/locked/.test(lockedNow), "a new visit starts locked, and the page says so", lockedNow);
  const refused = await chat("hello again");
  check(/locked in the key vault/i.test(refused), "a chat while locked is refused in plain words", refused.slice(0, 90));
  await inVault(`(() => { document.querySelector('#unlock-password').value = "wrong password";
    [...document.querySelectorAll('button')].find((x) => /^Unlock$/.test(x.textContent)).click(); return true; })()`);
  await waitInVault("/Wrong password/.test(document.body.textContent)", 20000);
  check(true, "a wrong password does not open it");
  await inVault(`(() => { document.querySelector('#unlock-password').value = ${JSON.stringify(PASSWORD)};
    [...document.querySelectorAll('button')].find((x) => /^Unlock$/.test(x.textContent)).click(); return true; })()`);
  await waitInVault("/Unlocked/.test(document.body.textContent)", 20000);
  await b.waitFor("/Using/.test(document.querySelector('#mp-current').textContent)", 10000);
  const again = await chat("hello once more");
  check(/stand-in AI/.test(again), "after unlocking, the officer answers again", again.slice(0, 80));

  // 5. Collapsed bar shows Forget for the active service; open card switching hides it so empty cards never show a phantom Forget button.
  await b.evaluate("if (!document.querySelector('#mp-body').hidden) document.querySelector('#mp-change')?.click(); true");
  await b.waitFor("!document.querySelector('#mp-forget').hidden && /Forget 127\\.0\\.0\\.1:8099 key/.test(document.querySelector('#mp-forget').textContent)", 10000);
  await b.evaluate("if (document.querySelector('#mp-body').hidden) document.querySelector('#mp-change')?.click(); true");
  await b.evaluate("document.querySelector('#mp-cards input[value=\"gemini\"]').click(); true");
  await b.waitFor("document.querySelector('#mp-forget').hidden", 10000);
  await waitInVault("/Your saved 127\\.0\\.0\\.1:8099 key stays saved when you switch\\./.test(document.body.textContent) && !document.body.querySelector('.state')", 10000);
  check(true, "collapsed header names its Forget button and open card switching keeps Forget inside saved cards only");
  await b.evaluate("document.querySelector('#mp-cards input[value=\"other\"]').click(); true");
  await b.waitFor("document.querySelector('#mp-forget').hidden", 10000);
  await waitInVault("/Forget this key/.test(document.body.textContent)", 10000);
  await inVault("[...document.querySelectorAll('button')].find((x) => /Forget this key/.test(x.textContent)).click(); true");
  await inVault("[...document.querySelectorAll('button')].find((x) => /Click again/.test(x.textContent)).click(); true");
  await waitInVault("/key removed/.test(document.body.textContent)", 10000);
  const after = await inVault(vaultStorage);
  check(!after.includes(KEY) && !JSON.parse(after).local["vault-box"], "forgetting removes the key and the encrypted record", after.slice(0, 120));

  // 6. Connect with Otari, on the Other card.
  const connectButton = "[...document.querySelectorAll('button')].find((x) => x.textContent === 'Connect with Otari')";
  const pressConnect = async (mode, gesture = true) => {
    await waitInVault(`${connectButton} && !${connectButton}.disabled`, 10000);
    await inVault(`document.documentElement.dataset.otariMode = ${JSON.stringify(mode)}; ${connectButton}.click(); true`, { gesture });
  };
  const notice = "document.querySelector('.notice')?.textContent || ''";
  // Other windows still open after a moment for the browser to close them.
  const otariWindows = async () => {
    let open = [];
    for (let i = 0; i < 20; i += 1) {
      // Edge's own pages (edge://...) are not ours.
      open = (await (await fetch("http://127.0.0.1:9365/json/list")).json())
        .filter((t) => t.type === "page" && /^(?:https?:|about:)/.test(t.url) && !t.url.startsWith("http://localhost:8087"));
      if (!open.length) break;
      await sleep(150);
    }
    return open.map((t) => t.url || "(blank)").join(", ");
  };
  const keyHeld = async () => {
    const stored = JSON.parse(await inVault(vaultStorage));
    return `${stored.session["vault-session"] || ""}${stored.local["vault-box"] || ""}`.includes(OTARI_KEY);
  };
  check(await inVault(`!!${connectButton} && !!(${connectButton}.compareDocumentPosition(document.querySelector('#key')) & Node.DOCUMENT_POSITION_FOLLOWING)`),
    "Other offers Connect with Otari above the key field");
  await pressConnect("approve", false);
  await waitInVault(`/blocked the Otari window/.test(${notice})`, 5000);
  check(true, "a window opened without a click is blocked, and the vault says how to allow it");
  await pressConnect("close");
  await waitInVault("/Cancel Otari sign-in/.test(document.body.textContent)", 3000);
  await waitInVault(`/Otari sign-in cancelled/.test(${notice})`, 6000);
  check(true, "closing the Otari window cancels the sign-in");
  await pressConnect("deny");
  await waitInVault(`/Otari sign-in cancelled/.test(${notice})`, 6000);
  check(true, "cancelling on otari.ai's screen comes back as cancelled");
  await pressConnect("other-state");
  await waitInVault(`/didn't match this sign-in/.test(${notice})`, 6000);
  await pressConnect("other-issuer");
  await waitInVault(`/didn't come from otari.ai/.test(${notice})`, 6000);
  const forgedLog = await inVault("sessionStorage.getItem('otari-stand-in') || '[]'");
  check(!forgedLog.includes("/token"), "a reply for another sign-in, or not from otari.ai, is never swapped for a key");
  const leftOpen = await otariWindows();
  check(!leftOpen, "every Otari window is closed again", leftOpen);

  await b.evaluate("window.beforeSave = true");
  await pressConnect("approve");
  try {
    await b.waitFor("!window.beforeSave && document.readyState === 'complete'", 20000);
  } catch {
    throw new Error(`Connect with Otari did not save and start: ${await b.evaluate("document.querySelector('#mp-status').textContent")} | ${await inVault(notice)}`);
  }
  await officer();
  const usingOtari = await b.evaluate("document.querySelector('#mp-current').textContent");
  check(/Using .+ on Otari\. Your key is kept for this visit only/.test(usingOtari), "after approving, the officer uses the new Otari key at once", usingOtari);
  const otariLog = JSON.parse(await inVault("sessionStorage.getItem('otari-stand-in') || '[]'"));
  const asked = new URL(otariLog.filter((e) => e.open).at(-1).open).searchParams;
  const swap = new URLSearchParams(otariLog.find((e) => e.fetch?.endsWith("/token")).body);
  check(asked.get("client_id") === VAULT_ORIGIN && asked.get("redirect_uri") === `${VAULT_ORIGIN}/otari.html` && asked.get("code_challenge_method") === "S256",
    "otari.ai is asked for a key for the vault, and sends the visitor back to the vault", `${asked.get("client_id")} → ${asked.get("redirect_uri")}`);
  check(createHash("sha256").update(swap.get("code_verifier")).digest("base64url") === asked.get("code_challenge") && swap.get("code") === "stand-in-code",
    "the code is swapped with the secret that matches the challenge");
  const otariApi = otariLog.filter((e) => e.fetch?.startsWith("https://api.otari.ai/api/v1/"));
  check(otariApi.length > 0 && otariApi.every((e) => e.auth === `Bearer ${OTARI_KEY}`), "the new key is used only at Otari's own address", otariApi.map((e) => e.fetch.split("/").pop()).join(", "));
  check(!(await b.evaluate(pageStorage)).includes(OTARI_KEY) && (await keyHeld()), "the page never holds the Otari key; the vault does");
  const stillOpen = await otariWindows();
  check(!stillOpen, "the Otari window closed itself after handing the reply back", stillOpen);
  const otariAnswer = await chat("hello through otari");
  check(/through Otari/.test(otariAnswer), "the officer answers with the connected key", otariAnswer.slice(0, 80));
  await b.evaluate("if (document.querySelector('#mp-body').hidden) document.querySelector('#mp-change')?.click(); true");
  await waitInVault("/Forget this key/.test(document.body.textContent)", 10000);
  await inVault("[...document.querySelectorAll('button')].find((x) => /Forget this key/.test(x.textContent)).click(); true");
  await inVault("[...document.querySelectorAll('button')].find((x) => /Click again/.test(x.textContent)).click(); true");
  await waitInVault("/Otari key removed/.test(document.body.textContent) && !!document.querySelector('.connect')", 10000);
  check(!(await keyHeld()), "forgetting the Otari key removes it and offers Connect with Otari again");

  // The vault opened on its own explains itself instead of taking a key.
  await b.send("Page.navigate", { url: `${VAULT_ORIGIN}/` });
  await b.waitFor("document.readyState === 'complete'");
  await sleep(300);
  const alone = await b.evaluate("document.body.textContent.trim() + ' | inputs: ' + document.querySelectorAll('input').length");
  check(/Open it from Agent Customs/.test(alone) && /inputs: 0/.test(alone), "the vault opened on its own takes no key", alone.slice(0, 90));

  const problems = b.problems.filter((p) => !/the server responded with a status of (?:400|401)|ERR_NAME_NOT_RESOLVED|ERR_BLOCKED_BY_CLIENT/.test(p));
  check(problems.length === 0, "no page errors or blocked scripts", problems.slice(0, 3).join(" / "));
} catch (error) {
  failures.push(String(error.message || error));
  console.error(error);
} finally {
  await b.close();
  for (const s of servers) s.kill();
  ai.close();
}
console.log(failures.length ? `\n${failures.length} check(s) failed.` : "\nAll vault checks passed.");
process.exit(failures.length ? 1 : 0);
