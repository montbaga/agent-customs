// vault-core.js: the key vault's rules and encryption, kept apart from its screen for tests.
//
// A key goes only to its own AI company, or to the address typed into the vault; the page never
// chooses. Only Agent Customs may use the vault, for two requests: list models and chat. A
// remembered key is encrypted with AES-256-GCM, locked by a passkey (WebAuthn PRF) or a
// password (PBKDF2), and the lock itself is never stored.

export const AGENT_CUSTOMS = "https://montbaga.github.io";

// The one address each company's keys go to. The prefixes are the runtime's. An Otari key
// belongs to one region, and the other region refuses it, so EU keys come first.
export const PROVIDERS = [
  { name: "Otari EU", router: "https://eu.api.otari.ai/api/v1", prefixes: ["otk_v1_eu_"] },
  { name: "Otari", router: "https://api.otari.ai/api/v1", prefixes: ["otk_"] },
  { name: "Google AI Studio", router: "https://generativelanguage.googleapis.com/v1beta/openai", prefixes: ["AIza"] },
  { name: "Groq", router: "https://api.groq.com/openai/v1", prefixes: ["gsk_"] },
  { name: "OpenAI", router: "https://api.openai.com/v1", prefixes: ["sk-proj-", "sk-svcacct-"] },
  { name: "Anthropic", router: "https://api.anthropic.com/v1", prefixes: ["sk-ant-"] },
  { name: "OpenRouter", router: "https://openrouter.ai/api/v1", prefixes: ["sk-or-"] },
];

export const CUSTOM = "custom";
export const IDLE_LOCK_MS = 15 * 60_000;
export const PASSWORD_ROUNDS = 600_000;
export const MIN_PASSWORD = 8;
export const MAX_BODY = 4 * 1024 * 1024;

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const enc = new TextEncoder();
const dec = new TextDecoder();

export function providerNamed(name) {
  return PROVIDERS.find((p) => p.name === name) || null;
}

/** The provider a pasted key belongs to, by its prefix, or null. */
export function providerForKey(key) {
  const text = String(key || "").trim();
  return PROVIDERS.find((p) => p.prefixes.some((prefix) => text.startsWith(prefix))) || null;
}

/** A typed address without a trailing slash: https, or http on this computer only. "" if unusable. */
export function serviceAddress(text) {
  let url;
  try { url = new URL(String(text || "").trim()); } catch { return ""; }
  if (url.username || url.password || url.search || url.hash) return "";
  const local = url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (url.protocol !== "https:" && !local) return "";
  if (url.hostname === "otari.ai") url.hostname = "api.otari.ai";
  url.pathname = url.pathname.replace(/\/(?:chat\/completions|models)\/?$/i, "").replace(/\/+$/, "");
  if ((url.hostname === "api.otari.ai" || url.hostname === "eu.api.otari.ai") && (!url.pathname || url.pathname === "/" || url.pathname === "/v1")) {
    url.pathname = "/api/v1";
  }
  return url.href.replace(/\/+$/, "");
}

/** Only Agent Customs may use the vault. A vault on this computer also serves pages on it. */
export function allowedPage(origin, vaultHost) {
  if (origin === AGENT_CUSTOMS) return true;
  if (!LOOPBACK.has(vaultHost)) return false;
  try {
    const url = new URL(origin);
    return url.protocol === "http:" && LOOPBACK.has(url.hostname);
  } catch {
    return false;
  }
}

/** Only GET /models and POST /chat/completions (JSON, at most 4 MB) are sent. */
export function checkRequest({ path, method = "GET", body = null }) {
  const verb = String(method).toUpperCase();
  if (path === "/models" && verb === "GET") return { ok: true };
  if (path === "/chat/completions" && verb === "POST") {
    if (typeof body !== "string") return { ok: false, status: 400, message: "The chat request has no body." };
    if (body.length > MAX_BODY) return { ok: false, status: 413, message: "The chat request is too large for the key vault." };
    try { JSON.parse(body); } catch { return { ok: false, status: 400, message: "The chat request is not JSON." }; }
    return { ok: true };
  }
  return { ok: false, status: 403, message: `The key vault does not send ${verb} ${path}.` };
}

/** The key, plus the header Anthropic requires for calls from a browser. */
export function providerHeaders(router, key, hasBody) {
  const headers = { Authorization: `Bearer ${key}` };
  if (hasBody) headers["Content-Type"] = "application/json";
  if (new URL(router).hostname === "api.anthropic.com") headers["anthropic-dangerous-direct-browser-access"] = "true";
  return headers;
}

/** At most `limit` requests in any `windowMs`. */
export class RateLimit {
  constructor(limit = 60, windowMs = 60_000, now = () => Date.now()) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.now = now;
    this.times = [];
  }

  take() {
    const t = this.now();
    this.times = this.times.filter((at) => t - at < this.windowMs);
    if (this.times.length >= this.limit) return false;
    this.times.push(t);
    return true;
  }
}

/** Only plain hex colours from the page reach the vault's styles. */
export function cleanTheme(theme) {
  const out = {};
  for (const name of ["c1", "c2", "c3", "onC3"]) {
    const value = String(theme?.[name] || "").trim();
    if (/^#[0-9a-f]{3,8}$/i.test(value)) out[name] = value;
  }
  return out;
}

export function toBase64(bytes) {
  let text = "";
  for (const b of new Uint8Array(bytes)) text += String.fromCharCode(b);
  return btoa(text);
}

export function fromBase64(text) {
  return Uint8Array.from(atob(String(text || "")), (c) => c.charCodeAt(0));
}

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** The lock from a password. Each guess costs `rounds` rounds of PBKDF2-SHA-256. */
export async function passwordLock(password, salt, rounds = PASSWORD_ROUNDS) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: rounds },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** The lock from a passkey's PRF output, which the authenticator gives only after fingerprint, face or PIN. */
export async function passkeyLock(prfOutput) {
  const base = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode("agent-customs-vault lock v1") },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function dataKey(raw) {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function seal(key, bytes) {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  return { iv: toBase64(iv), data: toBase64(data) };
}

/** Throws when the key is wrong or the data was changed. */
export async function unseal(key, box) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(box.iv) }, key, fromBase64(box.data)));
}

// A random data key encrypts the keys, and the lock encrypts the data key. Keeping the data key
// after one unlock lets keys saved later in the visit join the box without asking again.
// lock: {kind, key, ...what to store to rebuild it}. Returns {box, raw}.
export async function lockKeys({ kind, key, ...details }, keys, raw = randomBytes(32)) {
  return {
    raw,
    box: {
      v: 1,
      kind,
      ...details,
      wrapped: await seal(key, raw),
      keys: await seal(await dataKey(raw), enc.encode(JSON.stringify(keys))),
      saved: savedList(keys),
    },
  };
}

export async function relockKeys(box, raw, keys) {
  return { ...box, keys: await seal(await dataKey(raw), enc.encode(JSON.stringify(keys))), saved: savedList(keys) };
}

/** {keys, raw}, or throws when the lock is wrong. */
export async function unlockKeys(box, lockKey) {
  const raw = await unseal(lockKey, box.wrapped);
  return { raw, keys: await openKeys(box, raw) };
}

export async function openKeys(box, raw) {
  return JSON.parse(dec.decode(await unseal(await dataKey(raw), box.keys)));
}

/** The services that hold a key, without the keys. */
export function savedList(keys) {
  return Object.entries(keys || {}).map(([router, entry]) => ({ name: entry.name, router }));
}
