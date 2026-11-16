// receipts.mjs: Agent Customs' signed stamps (receipts) from the command line.
//
//   npm run receipts -- key       make the signing key (once)
//   npm run receipts -- sign      inspect every network in tools/receipt-sites.json and sign a stamp
//   npm run receipts -- verify <receipt file or address> [--live]
//
// The private key is read from the AGENT_CUSTOMS_SIGNING_KEY environment variable (as on
// GitHub), or else from a file outside the repository, ../agent-customs-signing-key.json.
// It is never printed. The public key goes to site/.well-known/agent-customs-key.json and
// the stamps to site/receipts/, with an index at site/receipts/index.json.

import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { makeSigningKey, receiptFromReport, receiptPath, signReceipt, verifyReceipt } from "../site/customs/receipts.js";
import { inspectWeb } from "./inspect-local.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE_URL = "https://montbaga.github.io/agent-customs/";
const PUBLIC_KEY_FILE = path.join(ROOT, "site", ".well-known", "agent-customs-key.json");
const RECEIPTS_DIR = path.join(ROOT, "site", "receipts");
const SITES_FILE = path.join(ROOT, "tools", "receipt-sites.json");
const DEFAULT_PRIVATE_KEY = path.resolve(ROOT, "..", "agent-customs-signing-key.json");

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const option = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};

async function readJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

async function makeKey() {
  const privateFile = path.resolve(option("--private", DEFAULT_PRIVATE_KEY));
  if (existsSync(privateFile) && !flag("--force")) {
    console.error(`A signing key already exists at ${privateFile}. Use --force to replace it (old stamps will then fail to verify).`);
    process.exit(1);
  }
  const { privateJwk, publicJwk, keyId } = await makeSigningKey();
  await writeFile(privateFile, JSON.stringify(privateJwk), { mode: 0o600 });
  await mkdir(path.dirname(PUBLIC_KEY_FILE), { recursive: true });
  await writeFile(PUBLIC_KEY_FILE, JSON.stringify({
    about: "Agent Customs' public key. Use it to check signed stamps (receipts).",
    issuer: "Agent Customs", site: SITE_URL, alg: "ES256", keyId, publicKey: publicJwk,
  }, null, 2) + "\n");
  console.log(`Made signing key ${keyId}.`);
  console.log(`  private key (keep secret, never commit): ${privateFile}`);
  console.log(`  public key: ${path.relative(ROOT, PUBLIC_KEY_FILE)}`);
}

async function privateKey() {
  if (process.env.AGENT_CUSTOMS_SIGNING_KEY) return JSON.parse(process.env.AGENT_CUSTOMS_SIGNING_KEY);
  const file = path.resolve(option("--key", DEFAULT_PRIVATE_KEY));
  if (!existsSync(file)) return null;
  return readJson(file);
}

async function sign() {
  const secret = await privateKey();
  if (!secret) {
    console.log("No signing key (AGENT_CUSTOMS_SIGNING_KEY or ../agent-customs-signing-key.json), so no stamps were signed.");
    return;
  }
  const published = await readJson(PUBLIC_KEY_FILE);
  const { networks } = await readJson(SITES_FILE);
  const now = new Date();
  const index = [];
  const previous = existsSync(path.join(RECEIPTS_DIR, "index.json")) ? (await readJson(path.join(RECEIPTS_DIR, "index.json"))).receipts : [];
  for (const network of networks) {
    let report;
    try {
      report = await inspectWeb(network);
    } catch (error) {
      // Keep the last stamp: a network that is down for a moment loses nothing.
      const kept = previous.find((e) => e.network === network);
      if (kept) index.push(kept);
      console.log(`  skipped ${network}${kept ? " (kept its last stamp)" : ""}: ${error.message}`);
      continue;
    }
    const signed = await signReceipt(receiptFromReport(report, { keyId: published.keyId, site: SITE_URL, now }), secret);
    const check = await verifyReceipt(signed, published.publicKey);
    if (!check.valid) throw new Error(`The signing key does not match the published public key (${check.reason}).`);
    const rel = receiptPath(network);
    await mkdir(path.dirname(path.join(RECEIPTS_DIR, rel)), { recursive: true });
    await writeFile(path.join(RECEIPTS_DIR, rel), JSON.stringify(signed, null, 2) + "\n");
    index.push({ network, path: rel, stamp: signed.receipt.stamp, verdict: signed.receipt.verdict,
      fingerprint: signed.receipt.fingerprint, inspectedAt: signed.receipt.inspectedAt, expiresAt: signed.receipt.expiresAt });
    console.log(`  ${signed.receipt.stamp.padEnd(24)} ${network}`);
  }
  await writeFile(path.join(RECEIPTS_DIR, "index.json"), JSON.stringify({
    about: "Signed Agent Customs stamps. Check them with the public key at .well-known/agent-customs-key.json.",
    issuer: "Agent Customs", site: SITE_URL, keyId: published.keyId, signedAt: now.toISOString(), receipts: index,
  }, null, 2) + "\n");
  console.log(`Signed ${index.length} stamp(s) into ${path.relative(ROOT, RECEIPTS_DIR)}/`);
}

async function load(where) {
  if (/^https?:\/\//i.test(where)) {
    const response = await fetch(where);
    if (!response.ok) throw new Error(`${where} answered ${response.status}.`);
    return response.json();
  }
  return readJson(path.resolve(where));
}

async function verify() {
  const where = args[1];
  if (!where) {
    console.error("Give a receipt file or address: npm run receipts -- verify <receipt> [--live]");
    process.exit(1);
  }
  const signed = await load(where);
  // Always Agent Customs' own key, never one the receipt points to: a forger can name any site.
  const published = existsSync(PUBLIC_KEY_FILE) ? await readJson(PUBLIC_KEY_FILE) : await load(new URL(".well-known/agent-customs-key.json", SITE_URL).href);
  let fingerprint = null;
  if (flag("--live")) fingerprint = (await inspectWeb(signed.receipt.network)).identity.hash;
  const check = await verifyReceipt(signed, published.publicKey, { fingerprint });
  if (!check.valid) {
    console.log(`NOT VALID: ${check.reason}`);
    process.exit(2);
  }
  const r = check.receipt;
  console.log(`Valid signature from Agent Customs (key ${published.keyId}).`);
  console.log(`  ${r.network}`);
  console.log(`  ${r.stamp} on ${r.inspectedAt.slice(0, 10)}, ${check.expired ? "EXPIRED on" : "valid until"} ${r.expiresAt.slice(0, 10)}`);
  if (check.matches === true) console.log("  The network today is the same version that was stamped.");
  if (check.matches === false) console.log("  The network has CHANGED since it was stamped, so the stamp no longer applies.");
}

const commands = { key: makeKey, sign, verify };
const run = commands[args[0]];
if (!run) {
  console.error("Use: npm run receipts -- key | sign | verify <receipt> [--live]");
  process.exit(1);
}
await run();
