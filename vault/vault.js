// vault.js: the key vault's box, and its end of the private channel with Agent Customs.
//
// The page may ask: select, use, models, commit, fetch, focus, theme, status.
// The vault tells it: status (never a key), detected, draft, submit, height.
// Keys for this visit, and unlocked ones, are in sessionStorage "vault-session". Remembered
// keys are in localStorage "vault-box", encrypted.

import {
  CUSTOM, IDLE_LOCK_MS, MIN_PASSWORD, PASSWORD_ROUNDS, PROVIDERS, RateLimit, allowedPage, checkRequest, cleanTheme,
  fromBase64, lockKeys, passkeyLock, passwordLock, providerForKey, providerHeaders, providerNamed,
  randomBytes, serviceAddress, toBase64, unlockKeys,
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

function readBoxes() {
  try {
    const raw = JSON.parse(localStorage.getItem(BOX) || "null");
    if (raw?.v === 2 && raw.entries && typeof raw.entries === "object") {
      const entries = {};
      for (const [router, entry] of Object.entries(raw.entries)) {
        if (entry?.v === 1 && entry.wrapped && entry.keys) entries[router] = entry;
      }
      return entries;
    }
    if (raw?.v === 1 && raw.wrapped && raw.keys) {
      const entries = {};
      for (const item of raw.saved || []) entries[item.router] = raw;
      return entries;
    }
  } catch { /* storage blocked or damaged */ }
  return {};
}

function boxFor(router) {
  return router ? readBoxes()[router] || null : null;
}

function writeRouterBox(router, box) {
  if (!router) return;
  const entries = readBoxes();
  if (box) entries[router] = box;
  else delete entries[router];
  try {
    if (Object.keys(entries).length) localStorage.setItem(BOX, JSON.stringify({ v: 2, entries }));
    else localStorage.removeItem(BOX);
  } catch { /* storage blocked */ }
}

const limit = new RateLimit(60, 60_000);
let page = null; // the port to Agent Customs, once it said hello
let selection = { provider: "Google AI Studio" };
let draftKey = "";
let busy = "";
let panel = ""; // "remember" while choosing how to lock, or "replace" while swapping a saved key
let armed = 0; // the first click of a two-click forget
let notice = { text: "", tone: "" };
let passkeyReady = false;

const keyInput = el("input", { id: "key", type: "password", autocomplete: "off", spellcheck: "false", "aria-describedby": "key-note" });
const addressInput = el("input", { id: "address", type: "url", inputmode: "url", autocomplete: "off", spellcheck: "false", placeholder: "https://api.example.com/v1 or http://127.0.0.1:11434/v1" });
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
  const map = new Map();
  for (const [router, box] of Object.entries(readBoxes())) {
    const saved = box.saved?.find((e) => e.router === router) || box.saved?.[0];
    map.set(router, saved?.name || nameFor(router));
  }
  for (const [router, entry] of Object.entries(s.keys)) map.set(router, entry.name);
  return map;
}

function lockIfIdle() {
  const s = readSession();
  const now = Date.now();
  let changedSession = false;
  for (const [router, entry] of Object.entries(s.keys)) {
    if (!entry.remembered) continue;
    if (entry.touchedAt && now - entry.touchedAt >= IDLE_LOCK_MS) {
      delete s.keys[router];
      changedSession = true;
    }
  }
  if (s.raw || s.until) {
    s.raw = "";
    s.until = 0;
    changedSession = true;
  }
  if (!changedSession) return false;
  writeSession(s);
  return true;
}

function touch(router = "") {
  const s = readSession();
  const target = router || s.active;
  if (!target || !s.keys[target]) return;
  s.keys[target].touchedAt = Date.now();
  writeSession(s);
}

function lockNow(router = "") {
  const s = readSession();
  if (router) {
    if (s.keys[router]?.remembered) delete s.keys[router];
  } else {
    for (const [r, entry] of Object.entries(s.keys)) if (entry.remembered) delete s.keys[r];
  }
  writeSession(s);
}

function status() {
  lockIfIdle();
  const s = readSession();
  const boxes = readBoxes();
  const router = selectedRouter();
  const box = router ? boxes[router] || null : null;
  const nameInBox = (r) => {
    const b = boxes[r];
    const item = b?.saved?.find((e) => e.router === r) || b?.saved?.[0];
    return item?.name || nameFor(r);
  };
  const entryFor = (r) => (r ? s.keys[r] : null);
  const active = s.active && (s.keys[s.active] || boxes[s.active])
    ? {
      name: s.keys[s.active]?.name || nameInBox(s.active),
      router: s.active,
      custom: !providerAt(s.active),
      locked: !s.keys[s.active],
    }
    : null;
  return {
    state: !active ? "empty" : s.keys[active.router] ? "ready" : "locked",
    active,
    selection: {
      provider: selection.provider,
      name: selectedName(),
      router,
      draft: !!draftKey,
      saved: !!entryFor(router) || !!box,
      locked: !entryFor(router) && !!box,
    },
    saved: [...held()].map(([r, name]) => ({ name, router: r, custom: !providerAt(r), locked: !s.keys[r] })),
    lock: box?.kind || "",
    unlocked: router ? !!s.keys[router] : false,
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
    case "flush": flushInputs({ notify: true, draft: message.draft !== false }); return { ok: true };
    case "models": flushInputs({ notify: false }); return listModels();
    case "commit": { flushInputs({ notify: false }); const done = await commit(); changed(); return done; }
    case "forget": { await forget(message.router || readSession().active || Object.keys(readBoxes())[0]); changed(); return { ok: true }; }
    default: return { ok: false, reason: "unknown" };
  }
}

function select({ provider, keepDraft = false }) {
  const next = provider === CUSTOM || providerNamed(provider) ? provider : selection.provider;
  if (next !== selection.provider) {
    if (!(keepDraft && providerForKey(draftKey)?.name === next)) clearDraft();
    notice = { text: "", tone: "" };
  }
  if ((panel === "custom" || panel === "replace") && !keepDraft) {
    addressInput.value = next === CUSTOM ? (backTarget?.address || "") : "";
  }
  selection = { provider: next };
  clearTimeout(armed);
  armed = 0;
  if (next === CUSTOM && !addressInput.value.trim()) {
    const s = readSession();
    const custom = (s.active && !providerAt(s.active) && held().has(s.active) ? s.active : "")
      || [...held().keys()].find((router) => !providerAt(router));
    if (custom) addressInput.value = custom;
  }
  panel = "";
  lockChoice = "";
  backTarget = null;
}

function use({ provider, router }) {
  const target = provider === CUSTOM ? serviceAddress(router) : providerNamed(provider)?.router || "";
  if (!target || !held().has(target)) return;
  clearTimeout(armed);
  armed = 0;
  panel = "";
  lockChoice = "";
  backTarget = null;
  selection = { provider: provider === CUSTOM ? CUSTOM : provider };
  if (provider === CUSTOM) addressInput.value = target;
  const s = readSession();
  s.active = target;
  if (s.keys[target]) s.keys[target].touchedAt = Date.now();
  writeSession(s);
}

function keyForSelection() {
  if (draftKey) return draftKey;
  return readSession().keys[selectedRouter()]?.key || "";
}

function wrongCardProvider() {
  const own = providerForKey(draftKey);
  if (!own) return "";
  if (own.name === selection.provider) return "";
  if (selection.provider === CUSTOM || selection.provider.startsWith("Otari")) {
    return own.name.startsWith("Otari") ? "" : own.name;
  }
  return own.name;
}

function ownProviderForDraft() {
  if (wrongCardProvider()) return null;
  const own = providerForKey(draftKey);
  if (!own) return null;
  if (selection.provider === CUSTOM || selection.provider.startsWith("Otari")) {
    return own.name.startsWith("Otari") ? own : null;
  }
  return own;
}

// A key with another provider's prefix is not sent until its own card is selected.
function mismatched() {
  return !!wrongCardProvider();
}

async function listModels() {
  const router = selectedRouter();
  if (!router) return { ok: false, reason: "address" };
  const wrong = wrongCardProvider();
  if (wrong) return { ok: false, reason: "mismatch", provider: wrong };
  const key = keyForSelection();
  if (!key) return { ok: false, reason: status().selection.locked ? "locked" : "empty" };
  if (!limit.take()) return { ok: false, code: 429 };
  touch(draftKey ? "" : router);
  try {
    const response = await fetch(`${router}/models`, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", headers: providerHeaders(router, key, false) });
    if (!response.ok) {
      const detail = response.status === 400 ? await response.text().catch(() => "") : "";
      const rejected = response.status === 401
        || response.status === 403
        || (response.status === 400 && /key|auth|token|credential|invalid_argument|permission|unauthorized/i.test(detail));
      return { ok: false, code: response.status, rejected };
    }
    const body = await response.json();
    return { ok: true, ids: (Array.isArray(body?.data) ? body.data : []).map((m) => String(m?.id || "").trim()).filter(Boolean) };
  } catch {
    return { ok: false, code: 0 };
  }
}

// A key with a known prefix is kept for its own provider, whatever the page selected.
async function commit() {
  const wrong = wrongCardProvider();
  if (wrong) return { ok: false, reason: "mismatch", provider: wrong };
  const own = draftKey ? ownProviderForDraft() : null;
  if (own) selection = { provider: own.name };
  const router = selectedRouter();
  if (!router) return { ok: false, reason: "address" };
  const s = readSession();
  const now = Date.now();
  const kept = Object.fromEntries(Object.entries(s.keys).filter(([, entry]) => entry.remembered));
  if (draftKey) {
    writeRouterBox(router, null);
    kept[router] = { name: nameFor(router), key: draftKey, remembered: false, touchedAt: now };
    clearDraft();
    panel = "";
    lockChoice = "";
    backTarget = null;
    s.keys = kept;
    s.active = router;
    writeSession(s);
    return { ok: true };
  }
  if (!s.keys[router]) return { ok: false, reason: status().selection.locked ? "locked" : "empty" };
  kept[router] = { ...s.keys[router], touchedAt: now };
  panel = "";
  lockChoice = "";
  backTarget = null;
  s.keys = kept;
  s.active = router;
  writeSession(s);
  touch(router);
  return { ok: true };
}

function clearDraft() {
  clearTimeout(typing);
  typing = 0;
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
    if (s.active && boxFor(s.active)) {
      refuse(423, "Your saved key is locked in the key vault. Unlock it under AI model settings, then try again.");
      changed();
    } else {
      refuse(401, "There is no key in the key vault yet. Paste your key under AI model settings.");
    }
    return;
  }
  if (!limit.take()) { refuse(429, "The key vault paused this request: more than 60 AI requests in one minute."); return; }
  touch(s.active);
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

async function remember(kind) {
  const s = readSession();
  const router = selectedRouter();
  const entry = router ? s.keys[router] : null;
  if (!entry) return;
  let lock;
  if (kind === "password") {
    const password = passwordInput.value;
    if (password.length < MIN_PASSWORD) { say(`Use at least ${MIN_PASSWORD} characters.`, "warn"); passwordInput.focus(); return; }
    const salt = randomBytes(16);
    lock = { kind, key: await passwordLock(password, salt), salt: toBase64(salt), rounds: PASSWORD_ROUNDS };
  } else {
    lock = await newPasskeyLock();
  }
  const { box } = await lockKeys(lock, { [router]: { name: entry.name, key: entry.key } });
  writeRouterBox(router, box);
  entry.remembered = true;
  entry.touchedAt = Date.now();
  writeSession(s);
  passwordInput.value = "";
  panel = "";
  lockChoice = "";
  backTarget = null;
  say(kind === "password" ? "Saved on this computer, locked with your password." : "Saved on this computer, locked with your passkey.");
}

async function unlock(router = selectedRouter()) {
  const box = boxFor(router);
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
  const now = Date.now();
  const entry = opened.keys[router] || Object.values(opened.keys)[0];
  if (entry) s.keys[router] = { ...entry, remembered: true, touchedAt: now };
  writeSession(s);
  unlockInput.value = "";
  say("Unlocked. Locks after 15 minutes without using this AI.");
}

async function forget(router = selectedRouter()) {
  if (!router) return;
  const removedName = nameFor(router);
  const s = readSession();
  const hadDraftForRemoved = router === selectedRouter();
  delete s.keys[router];
  if (s.active === router) s.active = "";
  writeSession(s);
  writeRouterBox(router, null);
  if (hadDraftForRemoved) {
    clearDraft();
    if (selection.provider.startsWith("Otari")) selection = { provider: CUSTOM };
  }
  panel = "";
  lockChoice = "";
  backTarget = null;
  say(`The ${removedName} key is gone from the vault.`);
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
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      extensions: { prf: {} },
    },
  });
  const prf = credential.getClientExtensionResults().prf;
  if (!prf?.enabled) {
    const err = new Error("This passkey cannot lock the vault. Choose a password below instead.");
    err.usePassword = true;
    throw err;
  }
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
  const host = location.hostname || "";
  if (!host || /^\d+(?:\.\d+){3}$/.test(host) || host.includes(":")) {
    passkeyReady = false;
    return;
  }
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
  const target = (panel === "replace" && keyInput.isConnected && keyInput)
    || $("#vault [data-focus]")
    || (selection.provider === CUSTOM && draftKey && !ownProviderForDraft() && !selectedRouter() ? addressInput : keyInput);
  target.focus({ preventScroll: true });
  if (window.scrollY) window.scrollTo(0, 0);
}

async function run(label, work) {
  if (busy) return;
  busy = label;
  render();
  let focusPassword = false;
  try {
    await work();
  } catch (error) {
    if (error?.usePassword) {
      lockChoice = "password";
      panel = "remember";
      focusPassword = true;
    }
    const message = error?.name === "NotAllowedError" ? "The passkey was cancelled."
      : error?.name === "SecurityError" ? "Passkeys need localhost or a domain name (not an IP address). Choose a password instead."
      : String(error?.message || error);
    say(message, "warn");
  } finally {
    busy = "";
    changed();
    if (focusPassword && passwordInput.isConnected) passwordInput.focus({ preventScroll: true });
  }
}

function button(text, onclick, { kind = "ghost", focus = false, armed: isArmed = false } = {}) {
  return el("button", { type: "button", class: `${kind} small`, onclick, disabled: !!busy, "data-focus": focus || null, "data-armed": isArmed ? "true" : null }, text);
}

function clearDraftAndNotify() {
  clearDraft();
  if (panel === "custom" || (selection.provider.startsWith("Otari") && !status().selection.saved)) {
    selection = { provider: CUSTOM };
  }
  notice = { text: "", tone: "" };
  changed();
  tell({ event: "draft-cleared" });
  keyInput.focus({ preventScroll: true });
}

function render() {
  const s = status();
  const sel = s.selection;
  const name = sel.name;
  const custom = selection.provider === CUSTOM;
  const entry = sel.router ? readSession().keys[sel.router] : null;
  const box = boxFor(sel.router);
  const wrong = wrongCardProvider();
  const showInputs = !!draftKey || panel === "replace" || panel === "custom" || (!entry && !sel.locked);

  if (draftKey) keyInput.dataset.state = wrong ? "warn" : "ready";
  else delete keyInput.dataset.state;

  keyInput.placeholder = panel === "replace" ? `Paste a new ${name} key`
    : custom ? "Paste your AI model key" : `Paste your ${name} key`;
  keyInput.setAttribute("aria-label", `${name} key`);

  const rows = [];
  if (showInputs) {
    rows.push(keyInput);
    if (draftKey) {
      rows.push(el("div", { class: "draft-row", "data-tone": wrong ? "warn" : null },
        el("span", { class: "dot", "aria-hidden": "true" }),
        el("span", null, wrong
          ? "This key belongs to another card and cannot be used here."
          : custom && !sel.router
            ? `Key entered (${draftKey.length} characters, hidden). Add the service address below.`
            : `Key entered (${draftKey.length} characters, hidden). Press Save and start below.`),
        button("Clear", clearDraftAndNotify)));
    }
    if (custom) {
      rows.push(el("div", { class: "field" }, el("label", { for: "address" }, "Service address (https://... or http://127.0.0.1:...)"), addressInput));
    }
    rows.push(el("p", { id: "key-note", class: "note" },
      el("span", { class: "dot", "aria-hidden": "true" }),
      `The vault sends your key only to ${name}.`));
    if (panel === "replace" || (panel === "custom" && backTarget)) {
      rows.push(el("div", { class: "actions" }, button("Cancel", cancelSubPanel)));
    }
  } else {
    rows.push(el("p", { id: "key-note", class: "note" },
      el("span", { class: "dot", "aria-hidden": "true" }),
      `The vault sends your key only to ${name}.`));
  }

  if (panel !== "replace" && panel !== "custom" && sel.locked && !draftKey) rows.push(lockedRow(name, box, sel.router));
  else if (entry && panel === "remember") rows.push(rememberPanel());
  else if (panel !== "replace" && panel !== "custom" && entry && !draftKey) rows.push(entry.remembered ? rememberedRow(name, box, sel.router) : visitRow(name));
  else if (!entry && !sel.locked) {
    const activeSaved = s.active && (boxFor(s.active.router) || readSession().keys[s.active.router]?.remembered);
    const otherSaved = [...held()].filter(([r]) => r !== sel.router && (boxFor(r) || readSession().keys[r]?.remembered)).map(([, label]) => label);
    if (s.active && s.active.router !== sel.router && !activeSaved) {
      rows.push(el("p", { class: "hint" }, `Saving here replaces your temporary ${s.active.name} key.`));
    } else if (otherSaved.length === 1) {
      rows.push(el("p", { class: "hint" }, `Your saved ${otherSaved[0]} key stays stored when you switch.`));
    } else if (otherSaved.length > 1) {
      rows.push(el("p", { class: "hint" }, `Your saved keys (${otherSaved.slice(0, -1).join(", ")} and ${otherSaved.at(-1)}) stay stored when you switch.`));
    }
  }

  if (notice.text) rows.push(el("p", { class: "notice", "data-tone": notice.tone || null, role: "status" }, notice.text));
  rows.push(el("p", { class: "foot" }, `Key vault · ${location.host}`));

  const focused = document.activeElement;
  const keepFocus = focused === keyInput || focused === addressInput || focused === passwordInput || focused === unlockInput;
  const pos = keepFocus ? [focused.selectionStart, focused.selectionEnd] : null;
  $("#vault").replaceChildren(...rows);
  if (keepFocus && focused.isConnected && document.activeElement !== focused) {
    focused.focus({ preventScroll: true });
    if (pos && pos[0] != null) try { focused.setSelectionRange(pos[0], pos[1]); } catch {}
  }
}

let backTarget = null;

function cancelSubPanel() {
  const hadDraft = !!draftKey;
  clearDraft();
  if (backTarget) {
    selection = { provider: backTarget.provider };
    addressInput.value = backTarget.address;
    backTarget = null;
  }
  panel = "";
  clearTimeout(armed);
  armed = 0;
  notice = { text: "", tone: "" };
  changed();
  if (hadDraft) tell({ event: "draft-cleared" });
  const next = unlockInput.isConnected ? unlockInput : $("#vault button, #vault input");
  next?.focus({ preventScroll: true });
}

function useCustomAddress() {
  backTarget = { provider: selection.provider, address: addressInput.value };
  panel = "custom";
  clearDraft();
  clearTimeout(armed);
  armed = 0;
  notice = { text: "", tone: "" };
  selection = { provider: CUSTOM };
  addressInput.value = "";
  changed();
  addressInput.focus({ preventScroll: true });
}

function anotherAddressButton() {
  return selection.provider.startsWith("Otari") || selection.provider === CUSTOM
    ? button("Use another address", useCustomAddress)
    : null;
}

function replaceButton() {
  return button("Replace key", () => {
    backTarget = { provider: selection.provider, address: addressInput.value };
    panel = "replace";
    clearTimeout(armed);
    armed = 0;
    notice = { text: "", tone: "" };
    changed();
    keyInput.focus({ preventScroll: true });
  });
}

function stateCard(name, title, detail, ...primary) {
  const buttons = primary.filter(Boolean);
  const hasInput = buttons.includes(unlockInput);
  const another = anotherAddressButton();
  const secondary = [replaceButton(), another, forgetButton(name)].filter(Boolean);
  if (hasInput) {
    return el("div", { class: "state" },
      el("p", null, el("strong", null, title), detail),
      el("div", { class: "actions" }, ...buttons),
      el("div", { class: "actions actions-fill" }, ...secondary));
  }
  const all = [...buttons, ...secondary];
  return el("div", { class: "state" },
    el("p", null, el("strong", null, title), detail),
    el("div", { class: all.length === 4 ? "actions actions-grid" : "actions actions-fill" }, ...all));
}

function visitRow(name) {
  const rememberClick = () => {
    panel = "remember";
    lockChoice = "";
    clearTimeout(armed);
    armed = 0;
    notice = { text: "", tone: "" };
    changed();
    if (panelLock() === "password") passwordInput.focus({ preventScroll: true });
  };
  return stateCard(name, `Your ${name} key is in the vault for this visit.`, " It is forgotten when you close this tab or switch to another model.",
    button("Remember on this computer", rememberClick, { kind: "soft" }));
}

function rememberedRow(name, box, router) {
  const how = box?.kind === "passkey" ? "your passkey" : "your password";
  return stateCard(name, `Saved on this computer, locked with ${how}.`, " Unlocked now; locks automatically after 15 minutes without using this AI.",
    button("Lock now", () => { lockNow(router); clearTimeout(armed); armed = 0; say(`Locked ${name}.`); changed(); }, { kind: "soft" }));
}

function lockedRow(name, box, router) {
  const passkey = box?.kind === "passkey";
  const unlockButton = button(busy === "unlock" ? "Unlocking…" : passkey ? "Unlock with your passkey" : "Unlock",
    () => run("unlock", () => unlock(router)), { kind: "primary", focus: passkey });
  if (!passkey) unlockInput.dataset.focus = "true";
  else delete unlockInput.dataset.focus;
  return stateCard(name, `Your saved ${name} key is locked.`, passkey ? " Your passkey opens it." : " Type the vault password to open it.",
    passkey ? null : unlockInput, unlockButton);
}

function rememberPanel() {
  const choose = (kind) => el("label", { class: "choice" },
    el("input", { type: "radio", name: "lock", value: kind, checked: (panelLock() === kind) || null, onchange: (e) => { lockChoice = e.target.value; changed(); } }),
    kind === "passkey" ? "With a passkey: your fingerprint, face or device PIN" : "With a password");
  const usePassword = panelLock() === "password";
  return el("div", { class: "state" },
    el("p", null, el("strong", null, "Lock it, so a copied file is useless."), " You unlock it once each visit."),
    el("div", { class: "choices", role: "radiogroup", "aria-label": "Lock" },
      passkeyReady ? choose("passkey") : null,
      choose("password")),
    usePassword ? el("div", { class: "field" }, el("label", { for: "password" }, `Vault password (at least ${MIN_PASSWORD} characters)`), passwordInput,
      el("p", { class: "hint" }, "Nobody can recover it. If you forget it, paste your key again.")) : null,
    el("div", { class: "actions" },
      button(busy === "remember" ? "Locking…" : "Remember it", () => run("remember", () => remember(panelLock())), { kind: "primary" }),
      button("Cancel", () => { panel = ""; lockChoice = ""; notice = { text: "", tone: "" }; passwordInput.value = ""; changed(); })),
    el("p", { class: "hint" }, "Safest: a free-tier key, or one with a spending limit."));
}

let lockChoice = "";
function panelLock() {
  if (!passkeyReady) return "password";
  return lockChoice || "passkey";
}

function forgetButton(name) {
  return button(armed ? "Click again to forget it" : "Forget this key", () => {
    if (!armed) { armed = setTimeout(() => { armed = 0; render(); }, 4000); render(); return; }
    clearTimeout(armed);
    armed = 0;
    run("forget", () => forget());
  }, { kind: "danger", armed: !!armed });
}

let typing = 0;
let typingAddress = 0;

function applyDraftInput({ notify = true, draft = true } = {}) {
  draftKey = keyInput.value.trim();
  const prevProvider = selection.provider;
  if (!draftKey && (panel === "custom" || (selection.provider.startsWith("Otari") && !status().selection.saved))) {
    selection = { provider: CUSTOM };
  }
  const wrong = wrongCardProvider();
  const own = wrong ? null : ownProviderForDraft();
  if (own && own.name !== selection.provider && (selection.provider === CUSTOM || selection.provider.startsWith("Otari"))) {
    selection = { provider: own.name };
  }
  const detected = !!(own && own.name !== prevProvider);
  changed();
  if (!notify) return;
  if (!draftKey) {
    tell({ event: "draft-cleared" });
    return;
  }
  if (wrong) tell({ event: "mismatch", provider: wrong });
  else if (detected) tell({ event: "detected", provider: own.name });
  else if (draft) tell({ event: "draft" });
}

function flushInputs({ notify = true, draft = true } = {}) {
  const pendingKey = !!typing || keyInput.value.trim() !== draftKey;
  const pendingAddress = !!typingAddress;
  clearTimeout(typing);
  typing = 0;
  clearTimeout(typingAddress);
  typingAddress = 0;
  if (!pendingKey && !pendingAddress) return;
  if (pendingKey) {
    applyDraftInput({ notify, draft });
    return;
  }
  changed();
  if (notify && draft && keyForSelection()) tell({ event: "draft" });
}

keyInput.addEventListener("input", (event) => {
  draftKey = keyInput.value.trim();
  clearTimeout(typing);
  typing = 0;
  if (event.inputType === "insertFromPaste") {
    applyDraftInput({ notify: true });
    return;
  }
  typing = setTimeout(() => {
    typing = 0;
    applyDraftInput({ notify: true });
  }, 400);
});
// Enter while an input method (Chinese, Japanese, Korean...) is composing picks a character, not submit.
const enter = (e) => e.key === "Enter" && !e.isComposing && e.keyCode !== 229;
keyInput.addEventListener("keydown", (e) => { if (enter(e)) { e.preventDefault(); flushInputs({ notify: true, draft: false }); tell({ event: "submit" }); } });
addressInput.addEventListener("input", () => {
  clearTimeout(typingAddress);
  typingAddress = setTimeout(() => { typingAddress = 0; changed(); if (keyForSelection()) tell({ event: "draft" }); }, 400);
});
addressInput.addEventListener("change", () => { clearTimeout(typingAddress); typingAddress = 0; changed(); if (keyForSelection()) tell({ event: "draft" }); });
addressInput.addEventListener("keydown", (e) => { if (enter(e)) { e.preventDefault(); flushInputs({ notify: true, draft: false }); tell({ event: "submit" }); } });
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
