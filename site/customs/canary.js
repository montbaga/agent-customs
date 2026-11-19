// canary.js: synthetic canary tokens and multi-encoding exfiltration detection.
//
// A canary token sits in protected host context that outside partners should never see or
// echo back. If a partner or compromised turn tries to exfiltrate the token in raw,
// URL-encoded, Base64 (at any 0/1/2-byte offset), Base64url, hex, ROT13, spaced, or
// reversed form, detectCanaryLeak() flags the channel.
//
// Known limit: a token split piece-by-piece across separate fields or separate tool calls
// cannot be reassembled reliably in general without high false-positive risk.

function randomHex(bytes = 6) {
  const buf = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < bytes; i += 1) buf[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function toBase64Bytes(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function toBase64(text) {
  return toBase64Bytes(new TextEncoder().encode(text));
}

function toHex(text) {
  const bytes = new TextEncoder().encode(text);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function rot13(text) {
  return String(text || "").replace(/[A-Za-z]/g, (c) => {
    const base = c <= "Z" ? 90 : 122;
    const n = c.charCodeAt(0) + 13;
    return String.fromCharCode(base >= n ? n : n - 26);
  });
}

function fromBase64Chunk(blob) {
  const std = blob.replace(/-/g, "+").replace(/_/g, "/");
  if (std.length % 4 === 1) return "";
  const padded = std.includes("=") ? std : std + "=".repeat((4 - (std.length % 4)) % 4);
  try {
    const bin = typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("binary");
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return "";
  }
}

// Compute alignment-independent Base64/Base64url interior substrings for offsets k = 0, 1, 2
// so tokens embedded mid-string (e.g. btoa("ctx:" + token + "}")) match reliably.
function base64OffsetNeedles(token) {
  const rawBytes = new TextEncoder().encode(token);
  const b64Needles = [];
  const b64uNeedles = [];
  for (let k = 0; k < 3; k += 1) {
    const buf = new Uint8Array(k + rawBytes.length);
    buf.set(rawBytes, k);
    const fullB64 = toBase64Bytes(buf);
    const fullB64u = fullB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const start = k > 0 ? 4 : 0;
    const cleanEnd = Math.floor(buf.length / 3) * 4;
    if (cleanEnd - start >= 12) {
      b64Needles.push(fullB64.slice(start, cleanEnd));
      b64uNeedles.push(fullB64u.slice(start, cleanEnd));
    }
  }
  return { b64Needles, b64uNeedles };
}

/**
 * Create a high-entropy canary token for runtime tripwire checks.
 *
 * :param prefix: Identifier prefix (default "ac_cnr_").
 * :return: A canary string unlikely to occur in normal traffic.
 */
export function generateCanaryToken(prefix = "ac_cnr_") {
  return `${prefix}${randomHex(6)}`;
}

/**
 * Compute encodings an attacker might use to disguise a canary token in transit.
 *
 * :param token: The active canary token.
 * :return: Object mapping encoding label to encoded string.
 */
export function canaryEncodings(token) {
  const raw = String(token || "");
  if (!raw) return null;
  const b64 = toBase64(raw);
  return {
    raw,
    reversed: [...raw].toReversed().join(""),
    base64: b64,
    base64url: b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    hex: toHex(raw),
    rot13: rot13(raw),
  };
}

function fromHexBytes(hexStr) {
  if (!hexStr || hexStr.length % 2 !== 0) return "";
  try {
    const bytes = new Uint8Array(hexStr.length / 2);
    for (let i = 0; i < hexStr.length; i += 2) {
      bytes[i / 2] = parseInt(hexStr.slice(i, i + 2), 16);
    }
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return "";
  }
}

function canaryTargets(token) {
  const raw = String(token || "");
  if (!raw) return [];
  const targets = [raw];
  // Extract the random entropy suffix when present (e.g. 12 hex chars in ac_cnr_...);
  // 10+ hex/token suffix chars carry negligible chance-match risk if sent without the prefix.
  const suffixMatch = raw.match(/^(?:[a-z][a-z0-9]*_[a-z]+_|ac_cnr_)([0-9a-f]{10,}|[a-z0-9]{11,})$/i);
  if (suffixMatch && suffixMatch[1] && suffixMatch[1].length < raw.length) {
    targets.push(suffixMatch[1]);
  }
  return targets;
}

function buildTargetCheck(target) {
  const enc = canaryEncodings(target);
  const { b64Needles, b64uNeedles } = base64OffsetNeedles(enc.raw);
  return {
    enc,
    b64Needles,
    b64uNeedles,
    compactToken: enc.raw.replace(/[^a-z0-9]/gi, "").toLowerCase(),
    compactRev: enc.reversed.replace(/[^a-z0-9]/gi, "").toLowerCase(),
    compactRot13: enc.rot13.replace(/[^a-z0-9]/gi, "").toLowerCase(),
  };
}

function matchSinglePass(text, isUrlDecoded, c) {
  const { enc, b64Needles, b64uNeedles, compactToken, compactRev, compactRot13 } = c;
  const lower = text.toLowerCase();
  const noWs = /(?:\\[nrt]|\s)/.test(text) ? text.replace(/(?:\\[nrt]|\s)+/g, "") : "";
  const compactText = text.replace(/[^a-z0-9]/gi, "").toLowerCase();
  const compactHex = text.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "").toLowerCase();

  if (text.includes(enc.raw) || lower.includes(enc.raw.toLowerCase())) {
    return { leaked: true, encoding: isUrlDecoded ? "url" : "raw" };
  }
  if (text.includes(enc.reversed) || lower.includes(enc.reversed.toLowerCase())) {
    return { leaked: true, encoding: "reversed" };
  }
  if (text.includes(enc.rot13) || lower.includes(enc.rot13.toLowerCase())) {
    return { leaked: true, encoding: "rot13" };
  }
  if (text.includes(enc.base64) || (noWs && noWs.includes(enc.base64))) return { leaked: true, encoding: "base64" };
  if (text.includes(enc.base64url) || (noWs && noWs.includes(enc.base64url))) return { leaked: true, encoding: "base64url" };
  if (b64Needles.some((n) => text.includes(n) || (noWs && noWs.includes(n)))) return { leaked: true, encoding: "base64" };
  if (b64uNeedles.some((n) => text.includes(n) || (noWs && noWs.includes(n)))) return { leaked: true, encoding: "base64url" };
  if (lower.includes(enc.hex) || compactHex.includes(enc.hex)) return { leaked: true, encoding: "hex" };

  if (compactToken.length >= 8) {
    if (compactText.includes(compactToken)) return { leaked: true, encoding: "spaced" };
    if (compactText.includes(compactRev)) return { leaked: true, encoding: "reversed" };
    if (compactText.includes(compactRot13)) return { leaked: true, encoding: "rot13" };
  }
  return null;
}

function collectLeafStrings(value, out = [], seen = new Set()) {
  if (typeof value === "string") {
    if (value) out.push(value);
    return out;
  }
  if (!value || typeof value !== "object" || seen.has(value)) return out;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) collectLeafStrings(item, out, seen);
    return out;
  }
  for (const v of Object.values(value)) collectLeafStrings(v, out, seen);
  return out;
}

function matchTargets(value, checks, depth = 0) {
  if (!checks.length || value === null || value === undefined || depth > 2) return null;
  if (typeof value !== "string") {
    for (const leaf of collectLeafStrings(value)) {
      const hit = matchTargets(leaf, checks, depth);
      if (hit) return hit;
    }
  }
  const serialized = typeof value === "string" ? value : JSON.stringify(value ?? "");
  if (!serialized) return null;

  const variants = [serialized];
  if (/%[0-9a-f]{2}|\+/i.test(serialized)) {
    try {
      const decoded = decodeURIComponent(serialized.replace(/\+/g, " "));
      if (decoded !== serialized) variants.push(decoded);
    } catch { /* malformed percent-escapes stay as serialized */ }
  }

  // Test full-token checks across all variants first so URL-encoded ac%5Fcnr%5F... reports
  // "url" before falling back to standalone random suffix matches.
  for (const c of checks) {
    for (let i = 0; i < variants.length; i += 1) {
      const hit = matchSinglePass(variants[i], i > 0, c);
      if (hit) return hit;
    }
  }

  if (depth < 2) {
    for (let i = 0; i < variants.length; i += 1) {
      const text = variants[i];
      const noWs = /(?:\\[nrt]|\s)/.test(text) ? text.replace(/(?:\\[nrt]|\s)+/g, "") : "";
      const b64Sources = noWs ? [text, noWs] : [text];
      for (const src of b64Sources) {
        const b64Runs = src.match(/(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])/g) || [];
        for (const chunk of b64Runs) {
          const decoded = fromBase64Chunk(chunk);
          if (!decoded) continue;
          const inner = matchTargets(decoded, checks, depth + 1);
          if (inner) return { leaked: true, encoding: inner.encoding === "raw" ? "base64" : inner.encoding };
        }
      }

      const hexByteRuns = text.match(/(?:0x)?[0-9a-f]{2}(?:[\s,:;-]+(?:0x)?[0-9a-f]{2}){5,}/gi) || [];
      for (const run of hexByteRuns) {
        const cleanHex = run.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
        const decoded = fromHexBytes(cleanHex);
        if (!decoded) continue;
        const inner = matchTargets(decoded, checks, depth + 1);
        if (inner) return { leaked: true, encoding: inner.encoding === "raw" ? "hex" : inner.encoding };
      }

      const codeRuns = text.match(/(?<!\d)(?:(?:1[01]\d|12[0-6]|[3-9]\d)(?:\s*,\s*|\s+)){7,}(?:1[01]\d|12[0-6]|[3-9]\d)(?!\d)/g) || [];
      for (const run of codeRuns) {
        const nums = run.trim().split(/[\s,]+/).map((n) => Number(n));
        if (!nums.every((n) => n >= 32 && n <= 126)) continue;
        const decoded = String.fromCharCode(...nums);
        const inner = matchTargets(decoded, checks, depth + 1);
        if (inner) return { leaked: true, encoding: inner.encoding === "raw" ? "charcodes" : inner.encoding };
      }
    }
  }
  return null;
}

/**
 * Check a string or JSON-serializable value for a canary token across common encodings.
 *
 * :param value: Text, URL, or tool/action arguments object.
 * :param token: Active canary token.
 * :param depth: Internal recursion depth when inspecting Base64/hex/charcode chunks.
 * :return: { leaked: true, encoding } when detected, or null otherwise.
 */
export function detectCanaryLeak(value, token, depth = 0) {
  const targets = canaryTargets(token);
  if (!targets.length || targets[0].length < 6) return null;
  const checks = targets.map(buildTargetCheck);
  return matchTargets(value, checks, depth);
}
