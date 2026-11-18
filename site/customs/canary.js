// canary.js: synthetic canary tokens and multi-encoding exfiltration detection.
//
// A canary token sits in protected host context that outside partners should never see or
// echo back. If a partner or compromised turn tries to exfiltrate the token in raw,
// URL-encoded, Base64, hex, or reversed form, detectCanaryLeak() flags the channel.

function randomHex(bytes = 6) {
  const buf = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < bytes; i += 1) buf[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function toBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function toHex(text) {
  const bytes = new TextEncoder().encode(text);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
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
  };
}

/**
 * Check a string or JSON-serializable value for a canary token across common encodings.
 *
 * :param value: Text, URL, or tool/action arguments object.
 * :param token: Active canary token.
 * :return: { leaked: true, encoding } when detected, or null otherwise.
 */
export function detectCanaryLeak(value, token) {
  if (!token || value === null || value === undefined) return null;
  const enc = canaryEncodings(token);
  if (!enc || enc.raw.length < 6) return null;

  const serialized = typeof value === "string" ? value : JSON.stringify(value ?? "");
  if (!serialized) return null;

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
    if (text.includes(enc.base64)) return { leaked: true, encoding: "base64" };
    if (text.includes(enc.base64url)) return { leaked: true, encoding: "base64url" };
    if (lower.includes(enc.hex)) return { leaked: true, encoding: "hex" };
  }
  return null;
}
