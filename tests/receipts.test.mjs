// Tests for signed stamps (receipts): signing, checking, and the stamps this site publishes.
// Run from the project folder: node --test tests/receipts.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { inspectNetworkUrl } from "../site/customs/inspect.js";
import { makeSigningKey, receiptFromReport, receiptPath, signReceipt, verifyReceipt } from "../site/customs/receipts.js";
import { RANGE_ORIGIN } from "../site/desk.js";
import { fsFetch } from "../tools/fs-fetch.mjs";
import { stampStillApplies } from "../tools/stamp-renewal.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fetchImpl = fsFetch({ [RANGE_ORIGIN]: path.join(ROOT, "range") });
const shady = await inspectNetworkUrl(`${RANGE_ORIGIN}/shady_pizza/shady_pizza`, { fetchImpl, pageOrigin: "http://127.0.0.1:8080" });
const readJson = async (rel) => JSON.parse(await readFile(path.join(ROOT, rel), "utf8"));

test("a signed stamp checks out, with its verdict, date and fingerprint", async () => {
  const key = await makeSigningKey();
  const signed = await signReceipt(receiptFromReport(shady, { keyId: key.keyId, site: "https://customs.example/" }), key.privateJwk);
  const check = await verifyReceipt(signed, key.publicJwk, { fingerprint: shady.identity.hash });
  assert.equal(check.valid, true, check.reason);
  assert.equal(check.expired, false);
  assert.equal(check.matches, true);
  assert.equal(check.receipt.verdict, "DENIED");
  assert.equal(check.receipt.stamp, "Entry denied");
  // Our own words only: rule titles, never the network's text or its hidden sentence.
  assert.doesNotMatch(JSON.stringify(signed), /card number and CVV|website_place_order/);
});

test("a changed stamp, another key, an old stamp and a changed network are all caught", async () => {
  const key = await makeSigningKey();
  const signed = await signReceipt(receiptFromReport(shady, { keyId: key.keyId }), key.privateJwk);

  const forged = structuredClone(signed);
  forged.receipt.verdict = "CLEARED";
  forged.receipt.stamp = "Cleared";
  assert.match((await verifyReceipt(forged, key.publicJwk)).reason, /changed after it was signed/);

  const other = await makeSigningKey();
  assert.match((await verifyReceipt(signed, other.publicJwk)).reason, /another key/);

  const later = new Date(Date.parse(signed.receipt.expiresAt) + 86400000);
  const old = await verifyReceipt(signed, key.publicJwk, { now: later });
  assert.equal(old.valid, true);
  assert.equal(old.expired, true);

  const changed = await verifyReceipt(signed, key.publicJwk, { fingerprint: "sha256:0000" });
  assert.equal(changed.matches, false);

  assert.match((await verifyReceipt({ receipt: { type: "other" } }, key.publicJwk)).reason, /not an Agent Customs receipt/);
});

test("stamps are published at one address per network", () => {
  assert.equal(receiptPath("https://shop.example/agents/bakery"), "shop.example/agents/bakery.json");
  assert.equal(receiptPath("http://127.0.0.1:8081/loop_maze/loop_maze"), "127.0.0.1_8081/loop_maze/loop_maze.json");
});

test("every stamp this site publishes verifies with the published key", async () => {
  const published = await readJson("site/.well-known/agent-customs-key.json");
  const index = await readJson("site/receipts/index.json");
  const sites = await readJson("tools/receipt-sites.json");
  assert.equal(index.keyId, published.keyId);
  assert.deepEqual(index.receipts.map((e) => e.network).sort(), [...sites.networks].sort());
  for (const entry of index.receipts) {
    const signed = await readJson(path.join("site", "receipts", entry.path));
    const check = await verifyReceipt(signed, published.publicKey);
    assert.equal(check.valid, true, `${entry.network}: ${check.reason}`);
    assert.equal(signed.receipt.network, entry.network);
    assert.equal(signed.receipt.stamp, entry.stamp);
  }
});

test("after a publish, a stamp is kept only while it still describes the network", () => {
  const now = new Date("2026-11-21T12:00:00Z");
  const previous = { network: "https://a.example/n", fingerprint: "abc", verdict: "CLEARED", expiresAt: "2026-12-23T00:00:00Z" };
  const report = (hash, code) => ({ identity: { hash }, verdict: { code } });
  assert.equal(stampStillApplies(previous, report("abc", "CLEARED"), { now }), true, "same version, same verdict, weeks left");
  assert.equal(stampStillApplies(previous, report("xyz", "CLEARED"), { now }), false, "the network changed");
  assert.equal(stampStillApplies(previous, report("abc", "HOLD"), { now }), false, "the verdict changed");
  assert.equal(stampStillApplies(previous, report("abc", "CLEARED"), { now: new Date("2026-12-15T00:00:00Z") }), false, "less than 10 days left");
  assert.equal(stampStillApplies(undefined, report("abc", "CLEARED"), { now }), false, "no stamp yet");
});

test("the stamps follow every publish, and a stamps-only publish ends the chain", async () => {
  const workflow = await readFile(path.join(ROOT, ".github", "workflows", "receipts.yml"), "utf8");
  const pages = await readFile(path.join(ROOT, ".github", "workflows", "pages.yml"), "utf8");
  const publishName = pages.match(/^name:\s*(.+)$/m)[1].trim();
  assert.match(workflow, /workflow_run:\s*\n\s*workflows:\s*\["([^"]+)"\]/);
  assert.equal(workflow.match(/workflows:\s*\["([^"]+)"\]/)[1], publishName, "it follows the publishing workflow by its name");
  assert.match(workflow, /--if-changed/);
  assert.match(workflow, /if git diff --cached --quiet; then echo "No new stamps."; exit 0; fi/);
});
