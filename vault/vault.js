// vault.js: the key vault's box, and its end of the private channel with Agent Customs.
//
// The page may ask: select, use, models, commit, remember, fetch, focus, theme, status.
// The vault tells it: status (never a key), detected, draft, submit, height.
// Keys for this visit, and unlocked ones, are in sessionStorage "vault-session". Remembered
// keys are in localStorage "vault-box", encrypted.
// Connect with Otari opens otari.ai in a window of its own. otari.html, on the vault's own
// address, hands the one-time code back here, and the vault swaps it for the key.

import {
  CUSTOM, IDLE_LOCK_MS, MIN_PASSWORD, OTARI, PASSWORD_ROUNDS, PROVIDERS, RateLimit, allowedPage, checkRequest, cleanTheme,
  fromBase64, lockKeys, otariAuthorizeUrl, otariKey, otariReply, otariSignIn, passkeyLock, passwordLock, providerForKey,
  providerHeaders, providerNamed, randomBytes, serviceAddress, toBase64, unlockKeys,
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
const addressInput = el("input", { id: "address", type: "url", inputmode: "url", autocomplete: "off", spellcheck: "false", placeholder: "https://api.example.com/v1" });
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
      remembered: !!boxes[s.active],
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
    case "remember": return openRemember();
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

// A key with a known prefix goes only to its own provider. Pasting one selects that provider
// (applyDraftInput), so this is only a last check before the key is used.
function wrongCardProvider() {
  const own = providerForKey(draftKey);
  return own && own.name !== selection.provider ? own.name : "";
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

async function commit() {
  const wrong = wrongCardProvider();
  if (wrong) return { ok: false, reason: "mismatch", provider: wrong };
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

// Connect with Otari. Each sign-in's secret is made ahead, so a click opens the Otari window
// at once: browsers block a window opened after a wait as a pop-up.
let otariNext = null;
let otari = null; // the sign-in waiting in the Otari window: {popup, verifier, state, watch}

function prepareOtari() {
  otariSignIn().then((signIn) => { otariNext = signIn; if (page) render(); }, () => {});
}

function connectOtari() {
  const signIn = otariNext;
  if (!signIn || otari || busy) return;
  const popup = window.open(otariAuthorizeUrl(location.origin, signIn), "agent-customs-otari", "popup,width=520,height=720");
  if (!popup) {
    say("Your browser blocked the Otari window. Allow pop-ups for this page, then try again.", "warn");
    changed();
    return;
  }
  otariNext = null;
  prepareOtari();
  // otari.html posts its reply, then closes; the second look gives that reply time to arrive.
  const watch = setInterval(() => {
    if (!popup.closed) return;
    if (otari.closing) endOtari("Otari sign-in cancelled.");
    else otari.closing = true;
  }, 500);
  otari = { popup, verifier: signIn.verifier, state: signIn.state, watch };
  say("");
  changed();
}

function endOtari(text = "") {
  if (!otari) return null;
  const done = otari;
  clearInterval(done.watch);
  otari = null;
  if (!done.popup.closed) done.popup.close();
  say(text, text ? "warn" : "");
  changed();
  return done;
}

window.addEventListener("message", (event) => {
  if (!otari || event.source !== otari.popup || event.origin !== location.origin || event.data?.type !== OTARI.reply) return;
  const { verifier, state } = endOtari();
  const reply = otariReply(event.data, state);
  if (!reply.code) {
    say(reply.problem, "warn");
    changed();
    return;
  }
  run("otari", async () => {
    let key;
    try {
      key = await otariKey(reply.code, verifier, location.origin);
    } catch (error) {
      throw new Error(`Couldn't connect to Otari: ${error.message}. Try again.`);
    }
    // As if pasted, then Enter: the page shows the Otari key under Other, and Save and start
    // lists its models and saves it for this visit.
    keyInput.value = key;
    applyDraftInput({ notify: true });
    say("Connected to Otari.");
    tell({ event: "submit" });
  });
});

// The Otari button, then "or paste a key" above the key field.
function otariRows() {
  const waiting = !!otari;
  return [
    el("div", { class: "connect" },
      el("button", {
        type: "button",
        class: waiting ? "ghost small" : "primary small",
        onclick: waiting ? () => endOtari("Otari sign-in cancelled.") : connectOtari,
        disabled: !waiting && (!otariNext || !!busy),
      }, waiting ? "Cancel Otari sign-in" : busy === "otari" ? "Connecting…" : "Connect with Otari"),
      el("p", { class: "hint" }, waiting
        ? "Finish in the Otari window: sign in, then approve the key."
        : "Sign in to otari.ai and approve a key. You set its spending limit there.")),
    el("p", { class: "or" }, "or paste a key"),
  ];
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
      refuse(423, "Your saved key is locked in the key vault. Unlock it in AI model settings, then try again.");
      changed();
    } else {
      refuse(401, "There's no key in the key vault yet. Add one in AI model settings.");
    }
    return;
  }
  if (!limit.take()) { refuse(429, "The key vault paused this request: more than 60 AI requests in a minute. Wait a moment, then try again."); return; }
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
  say(kind === "password" ? "Done. It's protected by your password." : "Done. It's protected by your passkey.");
}

// The page's "Remember key" button, shown once a key is in use: the lock choices for that key.
function openRemember() {
  const s = readSession();
  const router = s.active;
  const entry = router ? s.keys[router] : null;
  if (!entry || entry.remembered) return { ok: false, reason: "none" };
  const known = providerAt(router);
  selection = { provider: known ? known.name : CUSTOM };
  if (!known) addressInput.value = router;
  clearDraft();
  clearTimeout(armed);
  armed = 0;
  panel = "remember";
  lockChoice = "";
  backTarget = null;
  notice = { text: "", tone: "" };
  changed();
  return { ok: true };
}

async function unlock(router = selectedRouter()) {
  const box = boxFor(router);
  if (!box) return;
  let lockKey;
  if (box.kind === "password") {
    if (!unlockInput.value) { unlockInput.focus(); return; }
    lockKey = await passwordLock(unlockInput.value, fromBase64(box.salt), box.rounds);
  } else {
    const output = await passkeyOutput(fromBase64(box.credential), fromBase64(box.prfSalt));
    if (!output) throw new Error("This passkey can't unlock your key. Try again.");
    lockKey = await passkeyLock(output);
  }
  let opened;
  try {
    opened = await unlockKeys(box, lockKey);
  } catch {
    say(box.kind === "password" ? "Wrong password. Try again." : "That passkey didn't unlock your key.", "warn");
    unlockInput.select();
    return;
  }
  const s = readSession();
  const now = Date.now();
  const entry = opened.keys[router] || Object.values(opened.keys)[0];
  if (entry) s.keys[router] = { ...entry, remembered: true, touchedAt: now };
  writeSession(s);
  unlockInput.value = "";
  say("Unlocked. It locks again after 15 minutes without use.");
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
  say(`${removedName} key removed.`);
}

// With the PRF extension, the authenticator turns a salt into 32 secret bytes after the
// visitor's fingerprint, face or PIN. Those bytes are the lock. Some authenticators, Windows
// Hello among them, make the passkey without saying whether PRF works, so the new passkey is
// asked once more before falling back to a password.
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
  const id = new Uint8Array(credential.rawId);
  let output = credential.getClientExtensionResults().prf?.results?.first || null;
  if (!output) {
    say("One more check to finish.");
    changed();
    try {
      output = await passkeyOutput(id, prfSalt);
    } catch (error) {
      forgetPasskey(id);
      throw error;
    }
  }
  if (!output) {
    forgetPasskey(id);
    const err = new Error("This device can't lock keys with a passkey. Use a password instead.");
    err.usePassword = true;
    throw err;
  }
  return { kind: "passkey", key: await passkeyLock(output), credential: toBase64(id), prfSalt: toBase64(prfSalt) };
}

// The PRF output for this salt, or null when the passkey gives none.
async function passkeyOutput(credentialId, prfSalt) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  return assertion.getClientExtensionResults().prf?.results?.first || null;
}

// A passkey that cannot lock anything is of no use; ask the device to remove it, where the
// browser supports that.
function forgetPasskey(id) {
  try {
    const credentialId = toBase64(id).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    PublicKeyCredential.signalUnknownCredential?.({ rpId: location.hostname, credentialId })?.catch?.(() => {});
  } catch { /* not supported */ }
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
    || (panel === "remember" && ($("#vault #password") || $("#vault input[name='lock']:checked")))
    || $("#vault [data-focus]")
    || (selection.provider === CUSTOM && draftKey && !selectedRouter() ? addressInput : keyInput);
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
      // This device's passkeys cannot lock a key, so stop offering them for this visit.
      passkeyReady = false;
      lockChoice = "password";
      panel = "remember";
      focusPassword = true;
    }
    const message = error?.name === "NotAllowedError" ? (label === "remember" ? "Passkey cancelled. Try again, or use a password." : "Passkey cancelled. Try again.")
      : error?.name === "SecurityError" ? "Passkeys don't work on this address. Use a password instead."
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
    : custom ? "Paste your key" : `Paste your ${name} key`;
  keyInput.setAttribute("aria-label", `${name} key`);

  const rows = [];
  if (showInputs) {
    if (!draftKey && !panel && (custom || selection.provider.startsWith("Otari"))) rows.push(...otariRows());
    rows.push(keyInput);
    if (draftKey) {
      rows.push(el("div", { class: "draft-row", "data-tone": wrong ? "warn" : null },
        el("span", { class: "dot", "aria-hidden": "true" }),
        el("span", null, wrong
          ? `This key is for ${wrong}, not ${name}.`
          : custom && !sel.router
            ? "Key added. Now add the service's address below."
            : "Key added. Press Save and start below."),
        button("Clear", clearDraftAndNotify)));
    }
    if (custom) {
      rows.push(el("div", { class: "field" }, el("label", { for: "address" }, "Service address"), addressInput));
    }
    rows.push(el("p", { id: "key-note", class: "note" },
      el("span", { class: "dot", "aria-hidden": "true" }),
      `Your key is sent only to ${name}.`));
    if (panel === "replace" || (panel === "custom" && backTarget)) {
      rows.push(el("div", { class: "actions" }, button("Cancel", cancelSubPanel)));
    }
  } else {
    rows.push(el("p", { id: "key-note", class: "note" },
      el("span", { class: "dot", "aria-hidden": "true" }),
      `Your key is sent only to ${name}.`));
  }

  if (panel !== "replace" && panel !== "custom" && sel.locked && !draftKey) rows.push(lockedRow(name, box, sel.router));
  else if (entry && panel === "remember") rows.push(rememberPanel());
  else if (panel !== "replace" && panel !== "custom" && entry && !draftKey) rows.push(entry.remembered ? rememberedRow(name, sel.router) : visitRow(name));
  else if (!entry && !sel.locked) {
    const activeSaved = s.active && (boxFor(s.active.router) || readSession().keys[s.active.router]?.remembered);
    const otherSaved = [...held()].filter(([r]) => r !== sel.router && (boxFor(r) || readSession().keys[r]?.remembered)).map(([, label]) => label);
    if (s.active && s.active.router !== sel.router && !activeSaved) {
      rows.push(el("p", { class: "hint" }, `Saving here replaces the ${s.active.name} key you added for this visit.`));
    } else if (otherSaved.length === 1) {
      rows.push(el("p", { class: "hint" }, `Your saved ${otherSaved[0]} key stays saved when you switch.`));
    } else if (otherSaved.length > 1) {
      rows.push(el("p", { class: "hint" }, `Your saved keys (${otherSaved.slice(0, -1).join(", ")} and ${otherSaved.at(-1)}) stay saved when you switch.`));
    }
  }

  if (notice.text) rows.push(el("p", { class: "notice", "data-tone": notice.tone || null, role: "status" }, notice.text));

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
  return stateCard(name, `${name} key added for this visit.`, " It's removed when you close this tab or save another key.",
    button("Remember on this device", rememberClick, { kind: "soft" }));
}

function rememberedRow(name, router) {
  return stateCard(name, `${name} key saved on this device.`, " Unlocked now. It locks again after 15 minutes without use.",
    button("Lock now", () => { lockNow(router); clearTimeout(armed); armed = 0; say(`${name} key locked.`); changed(); }, { kind: "soft" }));
}

function lockedRow(name, box, router) {
  const passkey = box?.kind === "passkey";
  const unlockButton = button(busy === "unlock" ? "Unlocking…" : passkey ? "Unlock with passkey" : "Unlock",
    () => run("unlock", () => unlock(router)), { kind: "primary", focus: passkey });
  if (!passkey) unlockInput.dataset.focus = "true";
  else delete unlockInput.dataset.focus;
  return stateCard(name, `Your saved ${name} key is locked.`, passkey ? " Unlock it with your passkey." : " Enter your password to unlock it.",
    passkey ? null : unlockInput, unlockButton);
}

function rememberPanel() {
  const choose = (kind) => el("label", { class: "choice" },
    el("input", { type: "radio", name: "lock", value: kind, checked: (panelLock() === kind) || null, onchange: (e) => { lockChoice = e.target.value; changed(); } }),
    kind === "passkey" ? "Passkey (fingerprint, face or PIN)" : "Password");
  const usePassword = panelLock() === "password";
  return el("div", { class: "state" },
    el("p", null, el("strong", null, "Save it on this device."), " You'll unlock it once per visit, so no one else using this device can use it."),
    el("div", { class: "choices", role: "radiogroup", "aria-label": "Protect it with" },
      passkeyReady ? choose("passkey") : null,
      choose("password")),
    usePassword ? el("div", { class: "field" }, el("label", { for: "password" }, `Password (at least ${MIN_PASSWORD} characters)`), passwordInput,
      el("p", { class: "hint" }, "It can't be reset. If you forget it, just paste your key again.")) : null,
    el("div", { class: "actions" },
      button(busy === "remember" ? "Saving…" : "Save and lock", () => run("remember", () => remember(panelLock())), { kind: "primary" }),
      button("Cancel", () => { panel = ""; lockChoice = ""; notice = { text: "", tone: "" }; passwordInput.value = ""; changed(); })));
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
  // A key with a known prefix selects its own provider, and the page follows with its card.
  const own = providerForKey(draftKey);
  if (own && own.name !== selection.provider) selection = { provider: own.name };
  const detected = !!(own && own.name !== prevProvider);
  changed();
  if (!notify) return;
  if (!draftKey) {
    tell({ event: "draft-cleared" });
    return;
  }
  if (detected) tell({ event: "detected", provider: own.name });
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
prepareOtari();
if (window.parent === window) {
  showOnly("This is the Agent Customs key vault. It keeps your AI key apart from the page. Open it from Agent Customs at montbaga.github.io/agent-customs.");
} else {
  showOnly("Opening the key vault…");
  setTimeout(() => { if (!page) showOnly("This key vault works only inside Agent Customs."); }, 8000);
}
