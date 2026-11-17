// Tests for the downloadable Border Clearance Certificate & Advisory SVG generator.
// Run from the project folder: node --test tests/certificate.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { certificateFilename, certificateMeta, certificateSvg, escapeXml } from "../site/certificate.js";
import { inspectNetworkUrl } from "../site/customs/inspect.js";
import { makeSigningKey, receiptFromReport, signReceipt, verifyReceipt } from "../site/customs/receipts.js";
import { RANGE_ORIGIN } from "../site/desk.js";
import { fsFetch } from "../tools/fs-fetch.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fetchImpl = fsFetch({ [RANGE_ORIGIN]: path.join(ROOT, "range") });
const sunny = await inspectNetworkUrl(`${RANGE_ORIGIN}/sunny_bakery/sunny_bakery`, { fetchImpl, pageOrigin: "http://127.0.0.1:8080" });
const shady = await inspectNetworkUrl(`${RANGE_ORIGIN}/shady_pizza/shady_pizza`, { fetchImpl, pageOrigin: "http://127.0.0.1:8080" });
const maze = await inspectNetworkUrl(`${RANGE_ORIGIN}/loop_maze/loop_maze`, { fetchImpl, pageOrigin: "http://127.0.0.1:8080" });

test("a cleared network with a valid signed receipt produces a verified Clearance Certificate", async () => {
  const key = await makeSigningKey();
  const signed = await signReceipt(receiptFromReport(sunny, { keyId: key.keyId, site: "https://montbaga.github.io/agent-customs/" }), key.privateJwk);
  const check = await verifyReceipt(signed, key.publicJwk, { fingerprint: sunny.identity.hash });

  const meta = certificateMeta(sunny, check);
  assert.equal(meta.clearanceAllowed, true);
  assert.equal(meta.documentTitle, "Border Clearance Certificate");
  assert.equal(meta.signedStatus, "VERIFIED ES256 SIGNATURE");

  const svg = certificateSvg(sunny, { receiptCheck: check, verifyUrl: "https://montbaga.github.io/agent-customs/?inspect=sunny" });
  assert.match(svg, /<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, /Border Clearance Certificate/);
  assert.match(svg, /VERIFIED ES256 SIGNATURE/);
  assert.match(svg, new RegExp(sunny.identity.hash));
  assert.match(svg, /P&lt;AGTCUSTOMS&lt;&lt;CLEARED&lt;&lt;SUNNY&lt;BAKERY/);
});

test("a cleared network without a signed receipt is labeled as an unsigned browser snapshot", () => {
  const meta = certificateMeta(sunny, null);
  assert.equal(meta.clearanceAllowed, true);
  assert.equal(meta.signedStatus, "UNSIGNED BROWSER SNAPSHOT");
  const svg = certificateSvg(sunny);
  assert.match(svg, /UNSIGNED BROWSER SNAPSHOT/);
  assert.doesNotMatch(svg, /VERIFIED ES256 SIGNATURE/);
});

test("changed-fingerprint and expired receipts show honest warnings instead of green verification", async () => {
  const key = await makeSigningKey();
  const signed = await signReceipt(receiptFromReport(sunny, { keyId: key.keyId }), key.privateJwk);
  const changed = await verifyReceipt(signed, key.publicJwk, { fingerprint: "sha256:0000" });
  assert.equal(certificateMeta(sunny, changed).signedStatus, "CHANGED SINCE SIGNED");

  const future = new Date(Date.parse(signed.receipt.expiresAt) + 86400000);
  const expired = await verifyReceipt(signed, key.publicJwk, { now: future, fingerprint: sunny.identity.hash });
  assert.equal(certificateMeta(sunny, expired).signedStatus, "SIGNED STAMP EXPIRED");
});

test("denied and held networks never receive a Clearance Certificate", () => {
  const deniedMeta = certificateMeta(shady, null);
  assert.equal(deniedMeta.clearanceAllowed, false);
  assert.equal(deniedMeta.documentTitle, "Entry Refusal Notice");
  const deniedSvg = certificateSvg(shady);
  assert.match(deniedSvg, /Entry Refusal Notice/);
  assert.doesNotMatch(deniedSvg, /Border Clearance Certificate/);

  const holdMeta = certificateMeta(maze, null);
  assert.equal(holdMeta.clearanceAllowed, false);
  assert.equal(holdMeta.documentTitle, "Border Inspection Advisory");
  assert.match(certificateSvg(maze), /Border Inspection Advisory/);
});

test("certificateSvg escapes untrusted strings so hostile networks cannot inject markup", () => {
  const hostile = structuredClone(sunny);
  hostile.identity.brand = `<script>alert("xss")</script>&BadCo`;
  hostile.target.url = `https://evil.example/?x="><img src=x onerror=1>`;
  const svg = certificateSvg(hostile, { verifyUrl: "javascript:alert(1)" });
  assert.doesNotMatch(svg, /<script>/);
  assert.doesNotMatch(svg, /<img /);
  assert.doesNotMatch(svg, /href="javascript:/i);
  assert.match(svg, new RegExp(escapeXml("<script>")));
});

test("certificateSvg preserves exact untruncated clickable verifyUrl inside <a>", () => {
  const longVerifyUrl = "https://montbaga.github.io/agent-customs/?inspect=https%3A%2F%2Fagent-customs-range.github.io%2Fsunny_bakery%2Fsunny_bakery";
  const svg = certificateSvg(sunny, { verifyUrl: longVerifyUrl });
  assert.match(svg, new RegExp(`<a href="${escapeXml(longVerifyUrl).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}" target="_blank">`));
  assert.ok(svg.includes(`>${escapeXml(longVerifyUrl)}<`), "exact verifyUrl text must not be ellipsis-truncated");
});

test("certificateFilename creates clean slugs with verdict and date", () => {
  const png = certificateFilename(sunny, "png");
  const svg = certificateFilename(shady, "svg");
  assert.match(png, /^agent-customs-sunny-bakery-cleared-\d{4}-\d{2}-\d{2}\.png$/);
  assert.match(svg, /^agent-customs-shady-pizza-denied-\d{4}-\d{2}-\d{2}\.svg$/);
});

test("every published receipt in site/receipts verifies directly into certificateSvg", async () => {
  const published = JSON.parse(await readFile(path.join(ROOT, "site/.well-known/agent-customs-key.json"), "utf8"));
  const sunnySigned = JSON.parse(await readFile(path.join(ROOT, "site/receipts/agent-customs-range.github.io/sunny_bakery/sunny_bakery.json"), "utf8"));
  const check = await verifyReceipt(sunnySigned, published.publicKey, { fingerprint: sunny.identity.hash });
  const svg = certificateSvg(sunny, { receiptCheck: check });
  assert.match(svg, new RegExp(published.keyId));
});
