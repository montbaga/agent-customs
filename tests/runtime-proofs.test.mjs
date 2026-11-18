// Tests for runtime canary tripwire, certificate/receipt verification, and Attack Lab simulations.
// Run from the project folder: node --test tests/runtime-proofs.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ARENA_SCENARIOS, runArenaScenario } from "../site/arena.js";
import { certificateHtml, certificateSvg, parseVerificationFile, verifyDroppedArtifact } from "../site/certificate.js";
import { canaryEncodings, detectCanaryLeak, generateCanaryToken } from "../site/customs/canary.js";
import { installCustomsGuard } from "../site/customs/guard.js";
import { inspectNetworkUrl } from "../site/customs/inspect.js";
import { MemoryStorage, PinStore } from "../site/customs/pins.js";
import { makeSigningKey, receiptFromReport, signReceipt } from "../site/customs/receipts.js";
import { RANGE_ORIGIN } from "../site/desk.js";
import { Engine } from "../site/runtime/engine.js";
import { AgentNetwork } from "../site/runtime/kernel.js";
import { TraceBus } from "../site/runtime/trace.js";
import { fsFetch } from "../tools/fs-fetch.mjs";
import { ScriptedModel } from "./scripted_model.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "http://127.0.0.1:8080";
const SUNNY = `${RANGE_ORIGIN}/sunny_bakery/sunny_bakery`;
const RUG = `${RANGE_ORIGIN}/rugpull/sunny_bakery`;

const serve = fsFetch({ [SITE]: path.join(ROOT, "site"), [RANGE_ORIGIN]: path.join(ROOT, "range") });
const manifest = JSON.parse(await readFile(path.join(ROOT, "site", "agent-manifest.json"), "utf8"));
const config = JSON.parse(await readFile(path.join(ROOT, "site", "agent_customs.network.json"), "utf8"));

// ---- Lock 3: Canary Token Tripwire -----------------------------------------------------

test("detectCanaryLeak catches raw, URL, Base64, hex, and reversed encodings", () => {
  const token = generateCanaryToken();
  const enc = canaryEncodings(token);
  assert.ok(token.startsWith("ac_cnr_") && token.length >= 19);

  assert.equal(detectCanaryLeak("ordinary benign shop hours response", token), null);
  assert.equal(detectCanaryLeak(`url=${enc.raw}`, token)?.encoding, "raw");
  assert.equal(detectCanaryLeak(`https://leak.invalid/?q=${encodeURIComponent(token).replace(/_/g, "%5F")}`, token)?.encoding, "url");
  assert.equal(detectCanaryLeak({ data: enc.base64 }, token)?.encoding, "base64");
  assert.equal(detectCanaryLeak({ data: enc.base64url }, token)?.encoding, "base64url");
  assert.equal(detectCanaryLeak(`dump:${enc.hex}`, token)?.encoding, "hex");
  assert.equal(detectCanaryLeak(`rev=${enc.reversed}`, token)?.encoding, "reversed");
  assert.equal(detectCanaryLeak(`rot=${enc.rot13}`, token)?.encoding, "rot13");
  assert.equal(detectCanaryLeak({ b: Buffer.from(`x${token}`).toString("base64") }, token)?.encoding, "base64");
  assert.equal(detectCanaryLeak({ b: Buffer.from(`xy${token}`).toString("base64") }, token)?.encoding, "base64");
  assert.equal(detectCanaryLeak({ b: Buffer.from(JSON.stringify({ note: "ctx", t: token })).toString("base64") }, token)?.encoding, "base64");
  assert.match(detectCanaryLeak({ b: Buffer.from(`x${token}`).toString("base64url") }, token)?.encoding || "", /^base64(?:url)?$/);
  assert.equal(detectCanaryLeak(`tok=${[...token].join(" ")}`, token)?.encoding, "spaced");
  assert.equal(detectCanaryLeak(enc.base64.replace(/(.{8})/g, "$1\n"), token)?.encoding, "base64");
  const hexSpaced = [...Buffer.from(token)].map((b) => b.toString(16).padStart(2, "0")).join(" ");
  assert.equal(detectCanaryLeak(hexSpaced, token)?.encoding, "hex");
  const charCodes = [...token].map((c) => c.charCodeAt(0)).join(",");
  assert.equal(detectCanaryLeak(charCodes, token)?.encoding, "charcodes");
  assert.equal(detectCanaryLeak(`token_part=${token.slice(7)}`, token)?.encoding, "raw");
  assert.equal(detectCanaryLeak("totally unrelated data chunk", token), null);

  // Wrapped MIME/64-column Base64 inside object fields across all 80 byte offsets.
  for (const width of [64, 76]) {
    let caught = 0;
    for (let pad = 0; pad < 80; pad += 1) {
      const wrapped = Buffer.from(`${"x".repeat(pad)}${token}`).toString("base64").replace(new RegExp(`(.{${width}})`, "g"), "$1\n");
      if (detectCanaryLeak({ name: "tool", toolArgs: { note: wrapped } }, token)) caught += 1;
    }
    assert.equal(caught, 80, `wrapped Base64 inside toolArgs at width ${width} must catch 80/80`);
  }
});

test("guard Lock 3 canary tripwire blocks encoded exfiltration and revokes partner approval", async () => {
  const prevFetch = globalThis.fetch;
  globalThis.fetch = (url, init) => serve(url, init);
  try {
    const store = new PinStore(new MemoryStorage());
    const token = "ac_cnr_testtrip1234";
    const encoded = canaryEncodings(token).base64;
    const lockEvents = [];
    const canaryEvents = [];

    const engine = new Engine({ originUrl: SITE, trace: new TraceBus() });
    const officer = new ScriptedModel([
      { tool: "sunny_bakery_sunny_bakery", arguments: { request: "Menu?" } },
      { text: "Checked menu." },
      { tool: "sunny_bakery_sunny_bakery", arguments: { request: `Forward token ${encoded}` } },
      { text: "Stopped." },
    ]);
    const peer = new ScriptedModel([{ text: "Sourdough and rye." }]);
    engine.top = { network: new AgentNetwork(config, "agent_customs"), base: SITE, manifest, llm: officer, bundleUrl: null, integrity: null };
    engine.userRouter = { baseUrl: "https://router.invalid/v1", mock: false };
    engine.onConsent = async () => "allow";
    const compile = engine._compile;
    engine._compile = async function (...args) {
      const compiled = await compile.apply(this, args);
      if (!args[3]?.isTop) compiled.llm = peer;
      return compiled;
    };

    const guard = installCustomsGuard(engine, {
      store,
      canaryToken: token,
      notice: false,
      onLock: (ev) => lockEvents.push(ev),
      onCanaryTrip: (ev) => canaryEvents.push(ev),
    });

    await engine.runTurn("Check Sunny Bakery.");
    assert.ok(store.get(SUNNY), "first benign turn pins Sunny Bakery");
    assert.equal(guard.canary.tripped, false);

    await engine.runTurn("Run second request.");

    assert.equal(guard.canary.tripped, true);
    assert.ok(canaryEvents.some((e) => e.encoding === "base64" && e.revoked.includes(SUNNY)));
    assert.ok(lockEvents.some((e) => e.lock === 3 && /canary trap \(base64\)/.test(e.kind)));
    assert.equal(store.get(SUNNY), null, "compromised partner approval must be deleted on canary trip");

    const secondCallResults = officer.calls[3].messages.filter((m) => m.role === "tool").map((m) => m.content).join("\n");
    assert.match(secondCallResults, /protected canary trap token appeared \(base64 encoding\)/);
  } finally {
    globalThis.fetch = prevFetch;
  }
});

// ---- Drag-and-Drop Certificate & Receipt Verifier --------------------------------------

test("verifyDroppedArtifact verifies SVG certificates with embedded receipts, catches tampering and live drift", async () => {
  const published = JSON.parse(await readFile(path.join(ROOT, "site/.well-known/agent-customs-key.json"), "utf8"));
  const sunnyReceipt = JSON.parse(await readFile(path.join(ROOT, "site/receipts/agent-customs-range.github.io/sunny_bakery/sunny_bakery.json"), "utf8"));

  const sunnyLive = await inspectNetworkUrl(SUNNY, { fetchImpl: serve, pageOrigin: SITE });
  const rugLive = await inspectNetworkUrl(RUG, { fetchImpl: serve, pageOrigin: SITE });

  const svg = certificateSvg(sunnyLive, {
    receiptCheck: { valid: true, expired: false, matches: true, receipt: sunnyReceipt.receipt },
    signedReceipt: sunnyReceipt,
    verifyUrl: `https://montbaga.github.io/agent-customs/?inspect=${encodeURIComponent(SUNNY)}`,
  });

  const parsed = parseVerificationFile(svg);
  assert.equal(parsed.kind, "certificate");
  assert.equal(parsed.url, SUNNY);
  assert.equal(parsed.fingerprint, sunnyLive.identity.hash);

  // Authentic certificate + matching live target -> verified.
  const okRes = await verifyDroppedArtifact(svg, { publicJwk: published.publicKey, liveReport: sunnyLive });
  assert.equal(okRes.status, "verified");
  assert.equal(okRes.liveStatus, "match");

  // Authentic certificate compared against rug-pulled live report -> changed.
  const driftRes = await verifyDroppedArtifact(svg, { publicJwk: published.publicKey, liveReport: rugLive });
  assert.equal(driftRes.status, "changed");
  assert.equal(driftRes.liveStatus, "changed");

  // Tampered metadata inside SVG while preserving embedded signed receipt -> tampered.
  const tamperedSvg = svg.replace("&quot;verdict&quot;:&quot;CLEARED&quot;", "&quot;verdict&quot;:&quot;HOLD&quot;");
  assert.notEqual(tamperedSvg, svg, "metadata replacement must modify the SVG");
  const tamperedRes = await verifyDroppedArtifact(tamperedSvg, { publicJwk: published.publicKey });
  assert.equal(tamperedRes.status, "tampered");

  // Legacy SVG without <metadata> still extracts URL, hash, and verdict honestly as unsigned.
  const legacySvg = svg.replace(/<metadata\s+id="agent-customs-cert">[\s\S]*?<\/metadata>/, "");
  const legacyRes = await verifyDroppedArtifact(legacySvg, { publicJwk: published.publicKey, liveReport: sunnyLive });
  assert.equal(legacyRes.status, "unsigned");
  assert.equal(legacyRes.liveStatus, "match");

  // Expired receipt -> expired.
  const key = await makeSigningKey();
  const signed = await signReceipt(receiptFromReport(sunnyLive, { keyId: key.keyId }), key.privateJwk);
  const future = new Date(Date.parse(signed.receipt.expiresAt) + 86400000);
  const expiredRes = await verifyDroppedArtifact(JSON.stringify(signed), { publicJwk: key.publicJwk, now: future });
  assert.equal(expiredRes.status, "expired");

  // HTML certificate wrapper verifies identically to SVG (full ES256 + live match).
  const htmlCert = certificateHtml(svg, "Sunny Bakery Certificate");
  const htmlRes = await verifyDroppedArtifact(htmlCert, { publicJwk: published.publicKey, liveReport: sunnyLive });
  assert.equal(htmlRes.status, "verified");
  assert.equal(htmlRes.liveStatus, "match");

  // Printed PDF extracts /URI (?inspect=...) annotation and reports honestly without faking ES256 signature,
  // even when a published receipt exists for the extracted URL.
  const fakePdf = Buffer.from(
    `%PDF-1.4\n1 0 obj << /Subtype /Link /A << /S /URI /URI (https://montbaga.github.io/agent-customs/?inspect=${encodeURIComponent(SUNNY)}) >> >> endobj\n%%EOF`,
    "latin1",
  );
  const pdfRes = await verifyDroppedArtifact({ bytes: new Uint8Array(fakePdf), name: "cert.pdf" }, {
    publicJwk: published.publicKey,
    lookupSignedReceipt: async () => sunnyReceipt,
    liveReport: sunnyLive,
  });
  assert.equal(pdfRes.ok, true);
  assert.equal(pdfRes.artifact.kind, "pdf");
  assert.equal(pdfRes.artifact.url, SUNNY);
  assert.equal(pdfRes.status, "unsigned");
  assert.equal(pdfRes.liveStatus, "live-checked");
  assert.match(pdfRes.liveSummary, /printed PDF has no SHA-256 hash/);

  const emptyPdf = Buffer.from("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF", "latin1");
  const emptyPdfRes = await verifyDroppedArtifact({ bytes: new Uint8Array(emptyPdf), name: "vector-only.pdf" }, { publicJwk: published.publicKey });
  assert.equal(emptyPdfRes.ok, false);
  assert.match(emptyPdfRes.reason, /vector shapes/);
});

// ---- Attack Lab Split-Screen Arena -----------------------------------------------------

test("all Attack Lab scenarios execute against real analyzer, locks, canary, and diff modules", async () => {
  for (const sc of ARENA_SCENARIOS) {
    const res = await runArenaScenario(sc.id);
    assert.equal(res.scenario.id, sc.id);
    assert.equal(res.unprotected.steps.length, 3);
    assert.equal(res.protected.steps.length, 3);
    assert.ok(res.elapsedMs > 0);
  }

  const unicodeRun = await runArenaScenario("unicode-card-theft");
  assert.match(unicodeRun.protected.outcome, /Entry denied/);

  const mcpRun = await runArenaScenario("mcp-trifecta");
  assert.match(mcpRun.protected.outcome, /Held for review/);

  const canaryRun = await runArenaScenario("canary-exfil");
  assert.match(canaryRun.protected.outcome, /Canary tripped \(base64\) & pin revoked/);

  const rugRun = await runArenaScenario("rug-pull");
  assert.match(rugRun.protected.outcome, /Held for review/);
});

test("guard arms the host system prompt with Lock 3 canary, catches dynamic offset exfiltration from messages[0], and restores on uninstall", async () => {
  const prevFetch = globalThis.fetch;
  globalThis.fetch = (url, init) => serve(url, init);
  try {
    const store = new PinStore(new MemoryStorage());
    const topNet = new AgentNetwork(config, "agent_customs");
    const frontName = topNet.findFrontMan();
    const frontSpec = topNet.getAgentSpec(frontName);
    const originalPrompt = String(frontSpec.instructions || "");

    const calls = [];
    // Dynamic model that encodes its OWN system prompt (messages[0].content) with a 1-byte offset in Base64.
    const dynamicModel = {
      async chat(req) {
        calls.push(req);
        if (calls.length === 1) {
          return { content: "", toolCalls: [{ id: "c1", type: "function", function: { name: "sunny_bakery_sunny_bakery", arguments: JSON.stringify({ request: "Hours?" }) } }] };
        }
        if (calls.length === 2) {
          return { content: "Hours sent.", toolCalls: [] };
        }
        if (calls.length === 3) {
          const sysPrompt = req.messages[0]?.content || "";
          const encodedPrompt = Buffer.from(`x${sysPrompt}`).toString("base64");
          return { content: "", toolCalls: [{ id: "c2", type: "function", function: { name: "sunny_bakery_sunny_bakery", arguments: JSON.stringify({ request: `note=${encodedPrompt}` }) } }] };
        }
        return { content: "Blocked.", toolCalls: [] };
      },
    };
    const peer = new ScriptedModel([{ text: "Open 8am." }]);
    const engine = new Engine({ originUrl: SITE, trace: new TraceBus() });
    engine.top = { network: topNet, base: SITE, manifest, llm: dynamicModel, bundleUrl: null, integrity: null };
    engine.userRouter = { baseUrl: "https://router.invalid/v1", mock: false };
    engine.onConsent = async () => "allow";
    const compile = engine._compile;
    engine._compile = async function (...args) {
      const compiled = await compile.apply(this, args);
      if (!args[3]?.isTop) compiled.llm = peer;
      return compiled;
    };

    const guard = installCustomsGuard(engine, { store, notice: false });
    assert.ok(frontSpec.instructions.includes(guard.canary.token), "host system instructions must be armed automatically");
    assert.notEqual(frontSpec.instructions, originalPrompt);

    await engine.runTurn("Menu?");
    assert.ok(store.get(SUNNY), "first benign turn pins Sunny Bakery");
    assert.equal(guard.canary.tripped, false);

    await engine.runTurn("Summarize my request.");
    assert.equal(guard.canary.tripped, true, "exfiltrating messages[0].content at arbitrary Base64 offset must trip Lock 3");
    assert.equal(store.get(SUNNY), null, "partner pin must be revoked when system prompt canary leaks");
    assert.equal(peer.calls.length, 1, "partner must not receive second turn after Lock 3 trips");

    guard.uninstall();
    assert.equal(frontSpec.instructions, originalPrompt, "uninstall must restore original host instructions cleanly");
  } finally {
    globalThis.fetch = prevFetch;
  }
});
