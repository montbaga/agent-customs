// vault.js: the key vault's box, and its end of the private channel with Agent Customs.
//
// The page may ask: select, use, models, commit, fetch, focus, theme, status.
// The vault tells it: status (never a key), detected, draft, submit, height.
// Keys for this visit, and unlocked ones, are in sessionStorage "vault-session". Remembered
// keys are in localStorage "vault-box", encrypted.

import {
  CUSTOM, IDLE_LOCK_MS, MIN_PASSWORD, PASSWORD_ROUNDS, PROVIDERS, RateLimit, allowedPage, checkRequest, cleanTheme,
  fromBase64, lockKeys, openKeys, passkeyLock, passwordLock, providerForKey, providerHeaders, providerNamed,
  randomBytes, relockKeys, serviceAddress, toBase64, unlockKeys,
} from "./vault-core.js";

const SESSION = "vault-session";
const BOX = "vault-box";
const HELLO = "agent-customs-vault:hello";

const $ = (selector) => document.querySelector(selector);
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs || {})) {
    if (name.startsWith("on")) node.addEventListener(name.slice(2), value);
    else if (value === true) node.setAttribute(name, "");
    else if (value !== false && value != null) node.setAttribute(name, value);
  }
  node.append(...children.filter((c) => c != null && c !== false));
  return node;
};

function readSession() {
  try {
    const s = JSON.parse(sessionStorage.getItem(SESSION) || "null");
    if (s && typeof s === "object" && s.keys && typeof s.keys === "object") return s;
  } catch { /* storage blocked or damaged */ }
  return { keys: {}, active: "", raw: "", until: 0 };
}

function writeSession(s) {
  try { sessionStorage.setItem(SESSION, JSON.stringify(s)); } catch { /* storage blocked */ }
}

function readBox() {
  try {
    const box = JSON.parse(localStorage.getItem(BOX) || "null");
    return box?.v === 1 && box.wrapped && box.keys ? box : null;
  } catch {
    return null;
  }
}

function writeBox(box) {
  try {
    if (box) localStorage.setItem(BOX, JSON.stringify(box));
    else localStorage.removeItem(BOX);
  } catch { /* storage blocked */ }
}

const limit = new RateLimit(60, 60_000);
let page = null; // the port to Agent Customs, once it said hello
let selection = { provider: "Google AI Studio" };
let draftKey = "";
let busy = "";
let panel = ""; // "remember" while the visitor chooses how to lock
let armed = 0; // the first click of a two-click forget
let notice = { text: "", tone: "" };
let passkeyReady = false;

const keyInput = el("input", { id: "key", type: "password", autocomplete: "off", spellcheck: "false", "aria-describedby": "key-note" });
const addressInput = el("input", { id: "address", type: "url", inputmode: "url", autocomplete: "off", spellcheck: "false", placeholder: "https://api.otari.ai/api/v1 or http://127.0.0.1:11434/v1" });
const passwordInput = el("input", { id: "password", type: "password", autocomplete: "new-password", spellcheck: "false" });
const unlockInput = el("input", { id: "unlock-password", type: "password", autocomplete: "current-password", spellcheck: "false", "aria-label": "Vault password" });

function selectedRouter() {
  if (selection.provider === CUSTOM) return serviceAddress(addressInput.value);
  return providerNamed(selection.provider)?.router || "";
}

const providerAt = (router) => PROVIDERS.find((p) => p.router === router) || null;

function nameFor(router) {
  const known = providerAt(router);
  if (known) return known.name;
  try { return new URL(router).host; } catch { return "your service"; }
}

function selectedName() {
  if (selection.provider !== CUSTOM) return selection.provider;
  const router = selectedRouter();
  return router ? nameFor(router) : "your service";
}

// Every service the vault holds a key for: this visit's keys and the remembered ones.
function held() {
  const s = readSession();
  const box = readBox();
  const map = new Map();
  for (const entry of box?.saved || []) map.set(entry.router, entry.name);
  for (const [router, entry] of Object.entries(s.keys)) map.set(router, entry.name);
  return map;
}

function lockIfIdle() {
  const s = readSession();
  if (!s.raw || !s.until || Date.now() < s.until) return false;
  lockNow();
  return true;
}

function touch() {
  const s = readSession();
  if (!s.raw) return;
  s.until = Date.now() + IDLE_LOCK_MS;
  writeSession(s);
}

function lockNow() {
  const s = readSession();
  for (const [router, entry] of Object.entries(s.keys)) if (entry.remembered) delete s.keys[router];
  s.raw = "";
  s.until = 0;
  writeSession(s);
}

function status() {
  lockIfIdle();
  const s = readSession();
  const box = readBox();
  const router = selectedRouter();
  const boxHas = (r) => !!box?.saved?.some((entry) => entry.router === r);
  const entryFor = (r) => (r ? s.keys[r] : null);
  const active = s.active && (s.keys[s.active] || boxHas(s.active))
    ? { name: s.keys[s.active]?.name || box.saved.find((e) => e.router === s.active).name, router: s.active, custom: !providerAt(s.active) }
    : null;
  return {
    state: !active ? "empty" : s.keys[active.router] ? "ready" : "locked",
    active,
    selection: {
      provider: selection.provider,
      name: selectedName(),
      router,
      draft: !!draftKey,
      saved: !!entryFor(router) || boxHas(router),
      locked: !entryFor(router) && boxHas(router),
    },
    saved: [...held()].map(([r, name]) => ({ name, router: r, custom: !providerAt(r) })),
    lock: box?.kind || "",
    unlocked: !!s.raw,
  };
}

function tell(message) {
  page?.postMessage(message);
}

function changed() {
  if (!page) return;
  render();
  tell({ event: "status", status: status() });
  tellHeight();
}

// Measured on the box: the document's scrollHeight never drops below the frame's height.
function tellHeight() {
  if (window.scrollY) window.scrollTo(0, 0);
  const rect = $("#vault").getBoundingClientRect();
  tell({ event: "height", px: Math.ceil(rect.height + Math.max(0, rect.top)) });
}

window.addEventListener("message", (event) => {
  if (page || event.source !== window.parent || event.data?.type !== HELLO || !event.ports?.[0]) return;
  if (!allowedPage(event.origin, location.hostname)) {
    showOnly("This key vault works only inside Agent Customs.");
    return;
  }
  page = event.ports[0];
  page.onmessage = (e) => answer(e.data, e.ports?.[0]);
  applyTheme(event.data.theme);
  document.body.dataset.ready = "true";
  changed();
});

async function answer(message, port) {
  const { id, type } = message || {};
  let reply;
  try {
    if (type === "fetch") { if (port) relay(port, message); return; }
    reply = await handle(type, message);
  } catch (error) {
    reply = { ok: false, reason: "error", message: String(error?.message || error) };
  }
  if (id) tell({ id, reply: { ...reply, status: status() } });
}

async function handle(type, message) {
  switch (type) {
    case "status": return { ok: true };
    case "theme": applyTheme(message.theme); return { ok: true };
    case "focus": focusField(); return { ok: true };
    case "select": select(message); changed(); return { ok: true };
    case "use": use(message); changed(); return { ok: true };
    case "models": return listModels();
    case "commit": { const done = await commit(); changed(); return done; }
    default: return { ok: false, reason: "unknown" };
  }
}

function select({ provider, keepDraft = false }) {
  const next = provider === CUSTOM || providerNamed(provider) ? provider : selection.provider;
  if (next !== selection.provider && !(keepDraft && providerForKey(draftKey)?.name === next)) clearDraft();
  selection = { provider: next };
  notice = { text: "", tone: "" };
  if (next === CUSTOM && !addressInput.value.trim()) {
    const custom = [...held()].map(([router]) => router).find((router) => !providerAt(router));
    if (custom) addressInput.value = custom;
  }
  panel = "";
}

function use({ provider, router }) {
  const target = provider === CUSTOM ? serviceAddress(router) : providerNamed(provider)?.router || "";
  if (!target || !held().has(target)) return;
  selection = { provider: provider === CUSTOM ? CUSTOM : provider };
  if (provider === CUSTOM) addressInput.value = target;
  const s = readSession();
  s.active = target;
  writeSession(s);
}

function keyForSelection() {
  if (draftKey) return draftKey;
  return readSession().keys[selectedRouter()]?.key || "";
}

function ownProviderForDraft() {
  const own = providerForKey(draftKey);
  if (!own) return null;
  if (selection.provider !== CUSTOM) return own;
  const router = selectedRouter();
  if (!router || router === own.router || own.name.startsWith("Otari")) return own;
  return null;
}

// A key with another provider's prefix is not sent until that provider is selected.
function mismatched() {
  const own = ownProviderForDraft();
  return !!own && own.name !== selection.provider;
}

async function listModels() {
  const router = selectedRouter();
  if (!router) return { ok: false, reason: "address" };
  if (mismatched()) return { ok: false, reason: "mismatch" };
  const key = keyForSelection();
  if (!key) return { ok: false, reason: status().selection.locked ? "locked" : "empty" };
  if (!limit.take()) return { ok: false, status: 429 };
  touch();
  try {
    const response = await fetch(`${router}/models`, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", headers: providerHeaders(router, key, false) });
    if (!response.ok) return { ok: false, status: response.status };
    const body = await response.json();
    return { ok: true, ids: (Array.isArray(body?.data) ? body.data : []).map((m) => String(m?.id || "").trim()).filter(Boolean) };
  } catch {
    return { ok: false, status: 0 };
  }
}

// A key with a known prefix is kept for its own provider, whatever the page selected.
async function commit() {
  const own = draftKey ? ownProviderForDraft() : null;
  if (own) selection = { provider: own.name };
  let router = selectedRouter();
  if (!router) return { ok: false, reason: "address" };
  const s = readSession();
  if (draftKey) {
    s.keys[router] = { name: nameFor(router), key: draftKey, remembered: false };
    clearDraft();
    s.active = router;
    writeSession(s);
    if (s.raw) await rememberIn(readBox());
    return { ok: true };
  }
  if (!s.keys[router]) return { ok: false, reason: status().selection.locked ? "locked" : "empty" };
  s.active = router;
  writeSession(s);
  touch();
  return { ok: true };
}

function clearDraft() {
  draftKey = "";
  keyInput.value = "";
}

async function relay(port, { path, method, body }) {
  const controller = new AbortController();
  port.onmessage = (e) => { if (e.data?.abort) controller.abort(); };
  const refuse = (code, text) => {
    port.postMessage({ head: { status: code, statusText: "", type: "application/json" } });
    port.postMessage({ chunk: new TextEncoder().encode(JSON.stringify({ error: { message: text } })).buffer });
    port.postMessage({ end: true });
    port.close();
  };
  const check = checkRequest({ path, method, body });
  if (!check.ok) { refuse(check.status, check.message); return; }
  lockIfIdle();
  const s = readSession();
  const entry = s.keys[s.active];
  if (!entry) {
    if (s.active && readBox()?.saved?.some((e) => e.router === s.active)) {
      refuse(423, "Your saved key is locked in the key vault. Unlock it under AI model settings, then try again.");
      changed();
    } else {
      refuse(401, "There is no key in the key vault yet. Paste your key under AI model settings.");
    }
    return;
  }
  if (!limit.take()) { refuse(429, "The key vault paused this request: more than 60 AI requests in one minute."); return; }
  touch();
  try {
    const response = await fetch(`${s.active}${path}`, {
      method, body: method === "POST" ? body : undefined, signal: controller.signal, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer",
      headers: providerHeaders(s.active, entry.key, method === "POST"),
    });
    port.postMessage({ head: { status: response.status, statusText: response.statusText, type: response.headers.get("content-type") || "" } });
    if (response.body) {
      const reader = response.body.getReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        const copy = value.slice();
        port.postMessage({ chunk: copy.buffer }, [copy.buffer]);
      }
    }
    port.postMessage({ end: true });
  } catch {
    port.postMessage({ error: controller.signal.aborted ? "abort" : "network" });
  } finally {
    port.close();
  }
}

async function rememberIn(box) {
  const s = readSession();
  if (!box || !s.raw) return;
  for (const entry of Object.values(s.keys)) entry.remembered = true;
  writeSession(s);
  const all = { ...(await openKeys(box, fromBase64(s.raw))), ...plain(s.keys) };
  writeBox(await relockKeys(box, fromBase64(s.raw), all));
}

function plain(keys) {
  return Object.fromEntries(Object.entries(keys).map(([router, { name, key }]) => [router, { name, key }]));
}

async function remember(kind) {
  const s = readSession();
  const keys = plain(s.keys);
  if (!Object.keys(keys).length) return;
  let lock;
  if (kind === "password") {
    const password = passwordInput.value;
    if (password.length < MIN_PASSWORD) { say(`Use at least ${MIN_PASSWORD} characters.`, "warn"); passwordInput.focus(); return; }
    const salt = randomBytes(16);
    lock = { kind, key: await passwordLock(password, salt), salt: toBase64(salt), rounds: PASSWORD_ROUNDS };
  } else {
    lock = await newPasskeyLock();
  }
  const { box, raw } = await lockKeys(lock, keys);
  writeBox(box);
  for (const entry of Object.values(s.keys)) entry.remembered = true;
  s.raw = toBase64(raw);
  s.until = Date.now() + IDLE_LOCK_MS;
  writeSession(s);
  passwordInput.value = "";
  panel = "";
  say(kind === "password" ? "Saved on this computer, locked with your password." : "Saved on this computer, locked with your passkey.");
}

async function unlock() {
  const box = readBox();
  if (!box) return;
  let lockKey;
  if (box.kind === "password") {
    if (!unlockInput.value) { unlockInput.focus(); return; }
    lockKey = await passwordLock(unlockInput.value, fromBase64(box.salt), box.rounds);
  } else {
    lockKey = await passkeyLock(await passkeyOutput(fromBase64(box.credential), fromBase64(box.prfSalt)));
  }
  let opened;
  try {
    opened = await unlockKeys(box, lockKey);
  } catch {
    say(box.kind === "password" ? "That password does not open the vault. Try again." : "That passkey does not open the vault.", "warn");
    unlockInput.select();
    return;
  }
  const s = readSession();
  for (const [router, entry] of Object.entries(opened.keys)) {
    if (!s.keys[router]) s.keys[router] = { ...entry, remembered: true };
  }
  s.raw = toBase64(opened.raw);
  s.until = Date.now() + IDLE_LOCK_MS;
  writeSession(s);
  unlockInput.value = "";
  say("Unlocked. It locks again after 15 minutes without use.");
}

async function forget() {
  const router = selectedRouter();
  const removedName = nameFor(router);
  const s = readSession();
  const box = readBox();
  const remembered = !!s.keys[router]?.remembered || !!box?.saved?.some((e) => e.router === router);
  delete s.keys[router];
  if (s.active === router) s.active = "";
  writeSession(s);
  if (remembered && box) {
    if (s.raw) {
      const rest = await openKeys(box, fromBase64(s.raw));
      delete rest[router];
      if (Object.keys(rest).length) writeBox(await relockKeys(box, fromBase64(s.raw), rest));
      else forgetBox();
    } else {
      forgetBox();
    }
  }
  clearDraft();
  if (selection.provider.startsWith("Otari")) selection = { provider: CUSTOM };
  say(`The ${removedName} key is gone from the vault.`);
}

function forgetBox() {
  writeBox(null);
  lockNow();
}

// With the PRF extension, the authenticator turns a salt into 32 secret bytes after the
// visitor's fingerprint, face or PIN. Those bytes are the lock.
async function newPasskeyLock() {
  const prfSalt = randomBytes(32);
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: "Agent Customs key vault" },
      user: { id: randomBytes(16), name: "Agent Customs key vault", displayName: "Agent Customs key vault" },
      challenge: randomBytes(32),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  const prf = credential.getClientExtensionResults().prf;
  if (!prf?.enabled) throw new Error("This passkey cannot lock the vault. Choose a password instead.");
  const id = new Uint8Array(credential.rawId);
  const output = prf.results?.first || await passkeyOutput(id, prfSalt);
  return { kind: "passkey", key: await passkeyLock(output), credential: toBase64(id), prfSalt: toBase64(prfSalt) };
}

async function passkeyOutput(credentialId, prfSalt) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  const output = assertion.getClientExtensionResults().prf?.results?.first;
  if (!output) throw new Error("This passkey did not give the vault its lock.");
  return output;
}

async function checkPasskeys() {
  try {
    const caps = await window.PublicKeyCredential?.getClientCapabilities?.();
    passkeyReady = caps?.["extension:prf"] === true;
  } catch {
    passkeyReady = false;
  }
}

function applyTheme(theme) {
  const t = cleanTheme(theme);
  const root = document.documentElement.style;
  if (t.c1) root.setProperty("--c1", t.c1);
  if (t.c2) root.setProperty("--c2", t.c2);
  if (t.c3) root.setProperty("--c3", t.c3);
  if (t.onC3) root.setProperty("--on-c3", t.onC3);
}

function say(text, tone = "") {
  notice = { text, tone };
}

function showOnly(text) {
  $("#vault").replaceChildren(el("p", { class: "note" }, text));
}

function focusField() {
  const target = $("#vault [data-focus]") || (selection.provider === CUSTOM && !selectedRouter() ? addressInput : keyInput);
  target.focus({ preventScroll: true });
  if (window.scrollY) window.scrollTo(0, 0);
}

async function run(label, work) {
  if (busy) return;
  busy = label;
  render();
  try {
    await work();
  } catch (error) {
    say(error?.name === "NotAllowedError" ? "The passkey was cancelled." : String(error?.message || error), "warn");
  } finally {
    busy = "";
    changed();
  }
}

function button(text, onclick, { kind = "ghost", focus = false } = {}) {
  return el("button", { type: "button", class: `${kind} small`, onclick, disabled: !!busy, "data-focus": focus || null }, text);
}

function render() {
  const s = status();
  const sel = s.selection;
  const name = sel.name;
  const custom = selection.provider === CUSTOM;
  const entry = readSession().keys[sel.router];
  const box = readBox();

  keyInput.placeholder = sel.locked ? `Or paste a new ${name} key`
    : sel.saved ? `Saved ${name} key will be used` : `Paste your ${custom ? "service's" : name} key`;
  keyInput.setAttribute("aria-label", `${name} key`);

  const rows = [];
  if (custom) {
    rows.push(el("div", { class: "field" }, el("label", { for: "address" }, "Service address (or leave blank and paste an Otari key below)"), addressInput));
  }
  rows.push(keyInput);
  rows.push(el("p", { id: "key-note", class: "note" },
    el("span", { class: "dot", "aria-hidden": "true" }),
    `The vault sends your key only to ${name}.`));

  if (sel.locked && !draftKey) rows.push(lockedRow(name, box));
  else if (entry && panel === "remember") rows.push(rememberPanel());
  else if (entry) rows.push(entry.remembered ? rememberedRow(name, box) : visitRow(name, box));

  if (notice.text) rows.push(el("p", { class: "notice", "data-tone": notice.tone || null, role: "status" }, notice.text));
  rows.push(el("p", { class: "foot" }, `Key vault · ${location.host}`));
  $("#vault").replaceChildren(...rows);
}

function visitRow(name, box) {
  const lockedBox = box && !readSession().raw;
  return el("div", { class: "state" },
    el("p", null, el("strong", null, `Your ${name} key is in the vault for this visit.`), " It is forgotten when you close this tab.",
      lockedBox ? " To remember it too, first unlock the keys saved on this computer." : null),
    el("div", { class: "actions" },
      lockedBox ? null : button("Remember on this computer", () => { panel = "remember"; notice = { text: "", tone: "" }; render(); passwordInput.focus(); }),
      forgetButton(name)));
}

function rememberedRow(name, box) {
  const how = box?.kind === "passkey" ? "your passkey" : "your password";
  return el("div", { class: "state" },
    el("p", null, el("strong", null, `Saved on this computer, locked with ${how}.`), " Unlocked now; it locks again after 15 minutes without use."),
    el("div", { class: "actions" },
      button("Lock now", () => { lockNow(); say("Locked."); changed(); }),
      forgetButton(name)));
}

function lockedRow(name, box) {
  const passkey = box?.kind === "passkey";
  const unlockButton = button(busy === "unlock" ? "Unlocking…" : passkey ? "Unlock with your passkey" : "Unlock",
    () => run("unlock", unlock), { kind: "primary", focus: passkey });
  if (!passkey) unlockInput.dataset.focus = "true";
  else delete unlockInput.dataset.focus;
  return el("div", { class: "state" },
    el("p", null, el("strong", null, `Your saved ${name} key is locked.`), passkey ? " Your passkey opens it." : " Type the vault password to open it."),
    el("div", { class: "actions" }, passkey ? null : unlockInput, unlockButton),
    el("div", { class: "actions" }, forgetBoxButton()));
}

function rememberPanel() {
  const choose = (kind) => el("label", { class: "choice" },
    el("input", { type: "radio", name: "lock", value: kind, checked: (panelLock() === kind) || null, onchange: render }),
    kind === "passkey" ? "With a passkey: your fingerprint, face or device PIN" : "With a password");
  const usePassword = panelLock() === "password";
  return el("div", { class: "state" },
    el("p", null, el("strong", null, "Lock it, so a copied file is useless."), " You unlock it once each visit."),
    el("div", { class: "choices", role: "radiogroup", "aria-label": "Lock" }, passkeyReady ? choose("passkey") : null, choose("password")),
    usePassword ? el("div", { class: "field" }, el("label", { for: "password" }, `Vault password (at least ${MIN_PASSWORD} characters)`), passwordInput,
      el("p", { class: "hint" }, "Nobody can recover it. If you forget it, paste your key again.")) : null,
    el("div", { class: "actions" },
      button(busy === "remember" ? "Locking…" : "Remember it", () => run("remember", () => remember(panelLock())), { kind: "primary" }),
      button("Cancel", () => { panel = ""; passwordInput.value = ""; render(); })),
    el("p", { class: "hint" }, "Safest: a free-tier key, or one with a spending limit."));
}

let lockChoice = "";
function panelLock() {
  const picked = document.querySelector('#vault input[name="lock"]:checked')?.value;
  if (picked) lockChoice = picked;
  if (!passkeyReady) return "password";
  return lockChoice || "passkey";
}

function forgetButton(name) {
  return button(armed ? "Click again to forget it" : "Forget this key", () => {
    if (!armed) { armed = setTimeout(() => { armed = 0; render(); }, 4000); render(); return; }
    clearTimeout(armed);
    armed = 0;
    run("forget", forget);
  }, { kind: "ghost" });
}

function forgetBoxButton() {
  return button(armed ? "Click again to forget the saved keys" : "Forget the saved keys", () => {
    if (!armed) { armed = setTimeout(() => { armed = 0; render(); }, 4000); render(); return; }
    clearTimeout(armed);
    armed = 0;
    forgetBox();
    say("The saved keys are gone from this computer.");
    changed();
  }, { kind: "ghost" });
}

let typing = 0;
let typingAddress = 0;
keyInput.addEventListener("input", () => {
  draftKey = keyInput.value.trim();
  clearTimeout(typing);
  typing = setTimeout(() => {
    if (!draftKey && selection.provider.startsWith("Otari") && !status().selection.saved) {
      selection = { provider: CUSTOM };
    }
    const own = ownProviderForDraft();
    changed();
    if (!draftKey) return;
    if (own && own.name !== selection.provider) tell({ event: "detected", provider: own.name });
    else tell({ event: "draft" });
  }, 400);
});
// Enter while an input method (Chinese, Japanese, Korean...) is composing picks a character, not submit.
const enter = (e) => e.key === "Enter" && !e.isComposing && e.keyCode !== 229;
keyInput.addEventListener("keydown", (e) => { if (enter(e)) { e.preventDefault(); tell({ event: "submit" }); } });
addressInput.addEventListener("input", () => {
  clearTimeout(typingAddress);
  typingAddress = setTimeout(() => { changed(); if (keyForSelection()) tell({ event: "draft" }); }, 400);
});
addressInput.addEventListener("change", () => { clearTimeout(typingAddress); changed(); if (keyForSelection()) tell({ event: "draft" }); });
unlockInput.addEventListener("keydown", (e) => { if (enter(e)) { e.preventDefault(); run("unlock", unlock); } });
passwordInput.addEventListener("keydown", (e) => { if (enter(e)) { e.preventDefault(); run("remember", () => remember("password")); } });

new ResizeObserver(tellHeight).observe($("#vault"));
setInterval(() => { if (lockIfIdle()) { say("Locked after 15 minutes without use."); changed(); } }, 30_000);

checkPasskeys().then(() => { if (page) render(); });
if (window.parent === window) {
  showOnly("This is the Agent Customs key vault. It keeps your AI key apart from the page. Open it from Agent Customs: montbaga.github.io/agent-customs.");
} else {
  showOnly("Opening the key vault…");
  setTimeout(() => { if (!page) showOnly("This key vault works only inside Agent Customs."); }, 8000);
}
