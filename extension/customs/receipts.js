// receipts.js: signed inspection receipts, Agent Customs' stamp in a form anyone can check.
//
// A receipt says: Agent Customs inspected this network on this date, its fingerprint was
// this, and the verdict was this. It is signed with Agent Customs' private key (ECDSA P-256,
// "ES256"), so nobody can change the verdict, the date or the fingerprint without the
// signature failing. The public key is published at .well-known/agent-customs-key.json.
//
// A receipt covers one exact version. If the network changes, its fingerprint no longer
// matches, and the stamp no longer applies to it. Receipts expire after RECEIPT_DAYS, so an
// old stamp can't stand in for a fresh check.
//
// Every word in a receipt is Agent Customs' own: verdicts, rule titles and counts. Nothing
// written by the inspected network is copied into it.

import { canonicalJson } from "./canonical.js";

export const RECEIPT_TYPE = "agent-customs-receipt";
export const RECEIPT_DAYS = 35;

const KEY_ALGORITHM = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_ALGORITHM = { name: "ECDSA", hash: "SHA-256" };

function subtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("This browser cannot check signatures (Web Crypto is missing).");
  return s;
}

const utf8 = (text) => new TextEncoder().encode(text);

function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text) {
  const base64 = String(text).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * A short, stable name for a public key: the start of the SHA-256 of its JWK.
 *
 * :param publicJwk: The public key as a JWK.
 * :return: The key id.
 */
export async function keyIdOf(publicJwk) {
  const { crv, kty, x, y } = publicJwk;
  const digest = await subtle().digest("SHA-256", utf8(canonicalJson({ crv, kty, x, y })));
  return toBase64Url(new Uint8Array(digest).slice(0, 12));
}

/**
 * Make a new signing key pair.
 *
 * :return: {privateJwk, publicJwk, keyId}
 */
export async function makeSigningKey() {
  const pair = await subtle().generateKey(KEY_ALGORITHM, true, ["sign", "verify"]);
  const privateJwk = await subtle().exportKey("jwk", pair.privateKey);
  const { crv, kty, x, y } = await subtle().exportKey("jwk", pair.publicKey);
  const publicJwk = { crv, kty, x, y };
  return { privateJwk, publicJwk, keyId: await keyIdOf(publicJwk) };
}

/**
 * The receipt for one inspection report, before it is signed.
 *
 * :param report: A report from analyzeNetwork or inspectNetworkUrl.
 * :param options.keyId: The id of the key that will sign it.
 * :param options.site: The Agent Customs site that publishes it.
 * :param options.now: The time of signing.
 * :return: The receipt.
 */
export function receiptFromReport(report, { keyId, site, now = new Date() } = {}) {
  const expires = new Date(now.getTime() + RECEIPT_DAYS * 86400000);
  return {
    type: RECEIPT_TYPE,
    version: 1,
    network: report.target.url,
    fingerprint: report.identity?.hash || null,
    verdict: report.verdict.code,
    stamp: report.verdict.stamp,
    summary: report.verdict.summary,
    counts: report.counts || {},
    findings: (report.findings || []).map((f) => ({ rule: f.rule, severity: f.severity, title: f.title })),
    conformance: { passed: report.conformance?.passed ?? 0, total: report.conformance?.total ?? 0 },
    inspectedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    inspector: { name: "Agent Customs", version: report.version || "", site: site || "", keyId: keyId || "" },
  };
}

/**
 * Sign a receipt.
 *
 * :param receipt: From receiptFromReport.
 * :param privateJwk: The private key as a JWK.
 * :return: {receipt, signature: {alg, keyId, value}}
 */
export async function signReceipt(receipt, privateJwk) {
  const key = await subtle().importKey("jwk", privateJwk, KEY_ALGORITHM, false, ["sign"]);
  const signature = await subtle().sign(SIGN_ALGORITHM, key, utf8(canonicalJson(receipt)));
  return { receipt, signature: { alg: "ES256", keyId: receipt.inspector.keyId, value: toBase64Url(new Uint8Array(signature)) } };
}

/**
 * Check a signed receipt.
 *
 * :param signed: {receipt, signature}.
 * :param publicJwk: Agent Customs' public key as a JWK.
 * :param options.now: The time to check expiry against.
 * :param options.fingerprint: The network's fingerprint now, to see whether the stamp applies.
 * :return: {valid, reason, expired, matches, receipt}. valid means the signature is right;
 *   matches is true, false, or null when no fingerprint was given.
 */
export async function verifyReceipt(signed, publicJwk, { now = new Date(), fingerprint = null } = {}) {
  const receipt = signed?.receipt;
  const fail = (reason) => ({ valid: false, reason, expired: false, matches: null, receipt: receipt || null });
  if (!receipt || receipt.type !== RECEIPT_TYPE || receipt.version !== 1) return fail("This is not an Agent Customs receipt.");
  if (signed.signature?.alg !== "ES256" || typeof signed.signature.value !== "string") return fail("The receipt has no signature.");
  const keyId = await keyIdOf(publicJwk);
  if (signed.signature.keyId !== keyId || receipt.inspector?.keyId !== keyId) return fail("The receipt was signed with another key.");
  let ok = false;
  try {
    const key = await subtle().importKey("jwk", { ...publicJwk, ext: true }, KEY_ALGORITHM, false, ["verify"]);
    ok = await subtle().verify(SIGN_ALGORITHM, key, fromBase64Url(signed.signature.value), utf8(canonicalJson(receipt)));
  } catch {
    ok = false;
  }
  if (!ok) return fail("The signature does not match: the receipt was changed after it was signed.");
  return {
    valid: true,
    reason: "",
    expired: now.getTime() > Date.parse(receipt.expiresAt),
    matches: fingerprint ? receipt.fingerprint === fingerprint : null,
    receipt,
  };
}

/**
 * Where a network's receipt is published, relative to the receipts folder:
 * https://shop.example/agents/bakery becomes shop.example/agents/bakery.json.
 *
 * :param networkUrl: The network's address.
 * :return: The relative path.
 */
export function receiptPath(networkUrl) {
  const u = new URL(networkUrl);
  const parts = u.pathname.split("/").filter(Boolean).map((p) => p.replace(/[^\w.-]/g, "_"));
  return `${u.host.replace(/[^\w.-]/g, "_")}/${parts.join("/") || "index"}.json`;
}
