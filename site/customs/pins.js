// pins.js: remember which version of a network the visitor approved.
//
// A pin is the fingerprint and snapshot of a network at the moment it was approved,
// stored in this browser only (origin-scoped localStorage). Nothing is sent anywhere.
// When the published network no longer matches its pin, the guard holds it for review.

const KEY = "agent-customs-pins-v1";

/**
 * A Storage-like object kept in memory, for tests and for browsers that block storage.
 */
export class MemoryStorage {
  constructor() { this.map = new Map(); }
  getItem(k) { return this.map.has(k) ? this.map.get(k) : null; }
  setItem(k, v) { this.map.set(k, String(v)); }
  removeItem(k) { this.map.delete(k); }
}

function defaultStorage() {
  try {
    const s = globalThis.localStorage;
    const probe = "__agent_customs_probe__";
    s.setItem(probe, "1");
    s.removeItem(probe);
    return s;
  } catch {
    return new MemoryStorage();
  }
}

/**
 * Pins by network URL.
 */
export class PinStore {
  /**
   * :param storage: A Storage-like object; defaults to localStorage, or memory when blocked.
   * :param key: The storage key.
   */
  constructor(storage = defaultStorage(), key = KEY) {
    this.storage = storage;
    this.key = key;
    this.listeners = new Set();
  }

  all() {
    try {
      const raw = this.storage.getItem(this.key);
      const parsed = raw ? JSON.parse(raw) : {};
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }

  save(all) {
    try { this.storage.setItem(this.key, JSON.stringify(all)); } catch { /* storage full or blocked */ }
    for (const fn of this.listeners) { try { fn(); } catch { /* listener errors stay local */ } }
  }

  get(url) {
    return this.all()[normalize(url)] || null;
  }

  set(url, pin) {
    const all = this.all();
    all[normalize(url)] = pin;
    this.save(all);
  }

  delete(url) {
    const all = this.all();
    const existed = normalize(url) in all;
    delete all[normalize(url)];
    this.save(all);
    return existed;
  }

  list() {
    return Object.values(this.all()).sort((a, b) => String(b.pinnedAt).localeCompare(String(a.pinnedAt)));
  }

  onChange(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
}

/**
 * Make a pin from an inspection report.
 *
 * :param report: A report from analyzeNetwork.
 * :param how: "manual" when the visitor pinned it, "first-use" when the guard did.
 * :return: The pin.
 */
export function pinFromReport(report, how = "manual") {
  return {
    url: report.target.url,
    host: report.target.host,
    network: report.target.network,
    brand: report.identity.brand,
    hash: report.identity.hash,
    short: report.identity.short,
    verdict: report.verdict.code,
    pinnedAt: new Date().toISOString(),
    how,
    snapshot: report.snapshot,
  };
}

function normalize(url) {
  const raw = String(url || "").trim();
  if (raw.startsWith("mcp:")) return `mcp:${normalize(raw.slice(4))}`;
  try {
    const u = new URL(raw);
    return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
  } catch {
    return raw;
  }
}
