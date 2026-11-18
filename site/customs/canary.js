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
    reversed: [...raw].reverse().join(""),
    base64: b64,
    base64url: b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    hex: toHex(raw),
    rot13: rot13(raw),
  };
}

/**
 * Check a string or JSON-serializable value for a canary token across common encodings.
 *
 * :param value: Text, URL, or tool/action arguments object.
 * :param token: Active canary token.
 * :param depth: Internal recursion depth when inspecting Base64 chunks.
 * :return: { leaked: true, encoding } when detected, or null otherwise.
 */
export function detectCanaryLeak(value, token, depth = 0) {
  if (!token || value === null || value === undefined || depth > 2) return null;
  const enc = canaryEncodings(token);
  if (!enc || enc.raw.length < 6) return null;

  const serialized = typeof value === "string" ? value : JSON.stringify(value ?? "");
  if (!serialized) return null;

  const { b64Needles, b64uNeedles } = depth === 0
    ? base64OffsetNeedles(enc.raw)
    : { b64Needles: [], b64uNeedles: [] };

  const compactToken = enc.raw.replace(/[^a-z0-9]/gi, "").toLowerCase();
  const compactRev = enc.reversed.replace(/[^a-z0-9]/gi, "").toLowerCase();
  const compactRot13 = enc.rot13.replace(/[^a-z0-9]/gi, "").toLowerCase();

  const variants = [serialized];
  if (/%[0-9a-f]{2}|\+/i.test(serialized)) {
    try {
      const decoded = decodeURIComponent(serialized.replace(/\+/g, " "));
      if (decoded !== serialized) variants.push(decoded);
    } catch { /* malformed percent-escapes stay as serialized */ }
  }

  for (let i = 0; i < variants.length; i += 1) {
    const text = variants[i];
    const lower = text.toLowerCase();
    if (text.includes(enc.raw) || lower.includes(enc.raw.toLowerCase())) {
      return { leaked: true, encoding: i > 0 ? "url" : "raw" };
    }
    if (text.includes(enc.reversed) || lower.includes(enc.reversed.toLowerCase())) {
      return { leaked: true, encoding: "reversed" };
    }
    if (text.includes(enc.rot13) || lower.includes(enc.rot13.toLowerCase())) {
      return { leaked: true, encoding: "rot13" };
    }
    if (text.includes(enc.base64)) return { leaked: true, encoding: "base64" };
    if (text.includes(enc.base64url)) return { leaked: true, encoding: "base64url" };
    if (b64Needles.some((n) => text.includes(n))) return { leaked: true, encoding: "base64" };
    if (b64uNeedles.some((n) => text.includes(n))) return { leaked: true, encoding: "base64url" };
    if (lower.includes(enc.hex)) return { leaked: true, encoding: "hex" };

    // Strip whitespace and separators ("a c _ c n r ...") uniformly across both token and text.
    if (compactToken.length >= 8) {
      const compactText = text.replace(/[^a-z0-9]/gi, "").toLowerCase();
      if (compactText.includes(compactToken)) return { leaked: true, encoding: "spaced" };
      if (compactText.includes(compactRev)) return { leaked: true, encoding: "reversed" };
      if (compactText.includes(compactRot13)) return { leaked: true, encoding: "rot13" };
    }

    if (depth < 2) {
      const b64Runs = text.match(/(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])/g) || [];
      for (const chunk of b64Runs) {
        const decoded = fromBase64Chunk(chunk);
        if (!decoded) continue;
        const inner = detectCanaryLeak(decoded, token, depth + 1);
        if (inner) return { leaked: true, encoding: inner.encoding === "raw" ? "base64" : inner.encoding };
      }
    }
  }
  return null;
}
