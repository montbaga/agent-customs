// vault-check.mjs: checks the key vault end to end in a real browser.
//
//   npm run vault:check
//
// Serves the site (port 8087) and the vault (port 8090, where a page on this computer looks for
// it), plus a stand-in AI service on port 8099 that answers like an OpenAI-style provider and
// records which key and which origin each request came with. Then, in a headless browser:
//   1. saves a key through the vault box ("Other", the stand-in's address),
//   2. checks that the page's own storage never holds the key and the vault's does,
//   3. chats with the officer and runs the AI double-check on the VIP Points sample: every AI
//      request must reach the stand-in from the vault's origin, with the key,
//   4. remembers the key with a password, checks the stored record is encrypted, starts a new
//      visit (locked), unlocks it, and chats again,
//   5. forgets the key.
// Nothing leaves this computer: the stand-in is the only AI service, and it is local.

import { spawn } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { findBrowser, openBrowser, sleep } from "./cdp.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "http://127.0.0.1:8087/";
const VAULT_ORIGIN = "http://127.0.0.1:8090";
const AI = "http://127.0.0.1:8099/v1";
const KEY = "stand-in-secret-key-4b1d";
const PASSWORD = "correct horse battery";

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

// Runs code inside the vault's frame.
async function inVault(expression) {
  const { frameTree } = await b.send("Page.getFrameTree");
  const frame = (frameTree.childFrames || []).find((f) => f.frame.url.startsWith(VAULT_ORIGIN));
  if (!frame) throw new Error("The vault's frame is not on the page.");
  const { executionContextId } = await b.send("Page.createIsolatedWorld", { frameId: frame.frame.id, worldName: "vault-check" });
  const r = await b.send("Runtime.evaluate", { expression, contextId: executionContextId, awaitPromise: true, returnByValue: true });
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
  await b.send("Page.navigate", { url: SITE });
  await b.waitFor("document.readyState === 'complete'", 20000);
  await officer();
  await waitInVault("document.body.dataset.ready === 'true'");
  check(true, "the vault opened its private channel with the page");

  // 1. Save a key through the vault box.
  await b.evaluate("document.querySelector('#mp-cards input[value=\"other\"]').click(); true");
  await waitInVault("!!document.querySelector('#address')");
  await inVault(`(() => {
    const a = document.querySelector('#address'); a.value = ${JSON.stringify(AI)}; a.dispatchEvent(new Event('change'));
    const k = document.querySelector('#key'); k.value = ${JSON.stringify(KEY)}; k.dispatchEvent(new Event('input')); return true; })()`);
  await b.waitFor("document.querySelector('#mp-model').value === 'stand-in-model'", 15000);
  check(true, "the vault listed the key's models", await b.evaluate("document.querySelector('#mp-status').textContent"));
  await b.evaluate("window.beforeSave = true; document.querySelector('#mp-start').click(); true");
  try {
    await b.waitFor("!window.beforeSave && document.readyState === 'complete'", 20000);
  } catch {
    throw new Error(`Save and start did not reload the page: ${await b.evaluate("document.querySelector('#mp-status').textContent")}`);
  }
  await officer();
  const inUse = await b.evaluate("document.querySelector('#mp-current').textContent");
  check(/In use: .*127\.0\.0\.1:8099.*key vault/.test(inUse), "after Save and start the officer uses the key from the vault", inUse);

  // 2. Where the key is.
  const pageHas = (await b.evaluate(pageStorage)).includes(KEY);
  check(!pageHas, "the page's own storage and cookies never hold the key");
  check((await inVault(vaultStorage)).includes(KEY), "the vault's storage holds it, for this visit only");
  const runtimeKey = await b.evaluate("window.__nsweb?.engine?.byokKey");
  check(runtimeKey === "kept-in-the-key-vault", "the runtime holds only the stand-in key", runtimeKey);

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

  // 4. Remember with a password, start a new visit, unlock.
  await officer();
  await b.evaluate("document.querySelector('#mp-change')?.hidden || document.querySelector('#mp-change').click(); true");
  await inVault("[...document.querySelectorAll('button')].find((x) => /Remember on this computer/.test(x.textContent)).click(); true");
  await waitInVault("!!document.querySelector('input[name=\"lock\"]')");
  await inVault("document.querySelector('input[name=\"lock\"][value=\"password\"]').click(); true");
  await waitInVault("!!document.querySelector('#password')");
  await inVault(`(() => { document.querySelector('#password').value = ${JSON.stringify(PASSWORD)};
    [...document.querySelectorAll('button')].find((x) => /Remember it/.test(x.textContent)).click(); return true; })()`);
  await waitInVault("/Saved on this computer, locked with your password/.test(document.body.textContent)", 20000);
  const box = await inVault("localStorage.getItem('vault-box') || ''");
  check(box.length > 0 && !box.includes(KEY), "the remembered key is stored only encrypted", `${box.length} characters, PBKDF2 rounds ${JSON.parse(box).rounds}`);
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
  await waitInVault("/does not open the vault/.test(document.body.textContent)", 20000);
  check(true, "a wrong password does not open it");
  await inVault(`(() => { document.querySelector('#unlock-password').value = ${JSON.stringify(PASSWORD)};
    [...document.querySelectorAll('button')].find((x) => /^Unlock$/.test(x.textContent)).click(); return true; })()`);
  await waitInVault("/Unlocked/.test(document.body.textContent)", 20000);
  await b.waitFor("/In use/.test(document.querySelector('#mp-current').textContent)", 10000);
  const again = await chat("hello once more");
  check(/stand-in AI/.test(again), "after unlocking, the officer answers again", again.slice(0, 80));

  // 5. Forget.
  await inVault("[...document.querySelectorAll('button')].find((x) => /Forget this key/.test(x.textContent)).click(); true");
  await inVault("[...document.querySelectorAll('button')].find((x) => /Click again/.test(x.textContent)).click(); true");
  await waitInVault("/gone from the vault/.test(document.body.textContent)", 10000);
  const after = await inVault(vaultStorage);
  check(!after.includes(KEY) && !JSON.parse(after).local["vault-box"], "forgetting removes the key and the encrypted record", after.slice(0, 120));

  // The vault opened on its own explains itself instead of taking a key.
  await b.send("Page.navigate", { url: `${VAULT_ORIGIN}/` });
  await b.waitFor("document.readyState === 'complete'");
  await sleep(300);
  const alone = await b.evaluate("document.body.textContent.trim() + ' | inputs: ' + document.querySelectorAll('input').length");
  check(/Open it from Agent Customs/.test(alone) && /inputs: 0/.test(alone), "the vault opened on its own takes no key", alone.slice(0, 90));

  const problems = b.problems.filter((p) => !/the server responded with a status of 401|ERR_NAME_NOT_RESOLVED/.test(p));
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
