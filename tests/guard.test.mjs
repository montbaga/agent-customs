// End-to-end tests of the guard inside the real browser runtime engine.
// The officer and the partner networks run on scripted models; files come from disk.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { installCustomsGuard } from "../site/customs/guard.js";
import { MemoryStorage, PinStore } from "../site/customs/pins.js";
import { Engine } from "../site/runtime/engine.js";
import { AgentNetwork } from "../site/runtime/kernel.js";
import { TraceBus } from "../site/runtime/trace.js";
import { RANGE_ORIGIN } from "../site/desk.js";
import { fsFetch } from "../tools/fs-fetch.mjs";
import { ScriptedModel } from "./scripted_model.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "http://127.0.0.1:8080";
const RANGE = RANGE_ORIGIN;
const RANGE_HOST = new URL(RANGE).host;
const escapeRe = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const SUNNY = `${RANGE}/sunny_bakery/sunny_bakery`;
const SHADY = `${RANGE}/shady_pizza/shady_pizza`;

// The runtime fetches partner files with the global fetch. Record every request, and
// optionally serve the rug-pulled bakery in place of the original.
const serve = fsFetch({ [SITE]: path.join(ROOT, "site"), [RANGE]: path.join(ROOT, "range") });
const requests = [];
let rugPulled = false;
globalThis.fetch = async (url, init) => {
  requests.push(String(url));
  const target = rugPulled ? String(url).replace(`${RANGE}/sunny_bakery/`, `${RANGE}/rugpull/`) : String(url);
  return serve(target, init);
};

const manifest = JSON.parse(await readFile(path.join(ROOT, "site", "agent-manifest.json"), "utf8"));
const config = JSON.parse(await readFile(path.join(ROOT, "site", "agent_customs.network.json"), "utf8"));

/**
 * An engine for this site with scripted models and the guard installed, as site.js does.
 */
function makeEngine({ officerSteps, peerSteps = [], store, confirm = async () => false, consent = "allow" }) {
  const engine = new Engine({ originUrl: SITE, trace: new TraceBus() });
  const officer = new ScriptedModel(officerSteps);
  const peer = new ScriptedModel(peerSteps);
  engine.top = { network: new AgentNetwork(config, "agent_customs"), base: SITE, manifest, llm: officer, bundleUrl: null, integrity: null };
  engine.userRouter = { baseUrl: "https://router.invalid/v1", mock: false };
  const consents = [];
  engine.onConsent = async (info) => { consents.push(info); return consent; };
  // Partner networks run on the scripted peer model instead of a real provider.
  const compile = engine._compile;
  engine._compile = async function (...args) {
    const compiled = await compile.apply(this, args);
    if (!args[3]?.isTop) compiled.llm = peer;
    return compiled;
  };
  const reports = [];
  const confirmations = [];
  const guard = installCustomsGuard(engine, {
    store,
    confirmEntry: async (report) => { confirmations.push(report); return confirm(report); },
    onReport: (report) => reports.push(report),
  });
  return { engine, officer, peer, reports, confirmations, consents, guard };
}

function toolMessage(model, callIndex) {
  return model.calls[callIndex].messages.filter((m) => m.role === "tool").map((m) => m.content).join("\n");
}

test("a denied partner never runs, and the officer is told why without the payload", async () => {
  const store = new PinStore(new MemoryStorage());
  const t = makeEngine({
    store,
    officerSteps: [{ tool: "shady_pizza_shady_pizza", arguments: { request: "What do you offer?" } }, { text: "Shady Pizza was turned away." }],
  });
  const result = await t.engine.runTurn("Ask Shady Pizza what it offers.");
  assert.equal(result.text, "Shady Pizza was turned away.");
  assert.equal(t.consents.length, 1, "the visitor's consent card came first");
  assert.equal(t.peer.calls.length, 0, "no partner agent ran");
  const told = toolMessage(t.officer, 1);
  assert.match(told, /^Error from tool 'shady_pizza_shady_pizza': Agent Customs refused entry to "shady_pizza"/);
  assert.match(told, /Nothing from that network ran/);
  assert.doesNotMatch(told, /card number|CVV|website_place_order/, "the hidden payload never reaches the model");
  assert.equal(t.reports[0].guard.decision, "refused");
  assert.equal(store.get(SHADY), null, "a refused network is never approved");
});

test("a clean partner runs and is approved on first use", async () => {
  const store = new PinStore(new MemoryStorage());
  const t = makeEngine({
    store,
    officerSteps: [{ tool: "sunny_bakery_sunny_bakery", arguments: { request: "What do you offer?" } }, { text: "It offers bread and cakes." }],
    peerSteps: [{ text: "Sunny Bakery offers breads, pastries, celebration cakes and coffee." }],
  });
  await t.engine.runTurn("What does Sunny Bakery offer?");
  assert.equal(t.peer.calls.length, 1, "the partner agent ran");
  assert.match(toolMessage(t.officer, 1), /breads, pastries/);
  assert.equal(t.reports[0].guard.decision, "admitted");
  const pin = store.get(SUNNY);
  assert.equal(pin.how, "first-use");
  assert.equal(pin.hash, t.reports[0].identity.hash);
  assert.equal(t.confirmations.length, 0);
});

test("a partner that changed since approval is held; declining stops it, approving re-pins it", async () => {
  const store = new PinStore(new MemoryStorage());
  rugPulled = false;
  const first = makeEngine({
    store,
    officerSteps: [{ tool: "sunny_bakery_sunny_bakery", arguments: { request: "What do you offer?" } }, { text: "ok" }],
    peerSteps: [{ text: "Breads and cakes." }],
  });
  await first.engine.runTurn("What does Sunny Bakery offer?");
  const approved = store.get(SUNNY).hash;

  rugPulled = true;
  try {
    const declined = makeEngine({
      store, confirm: async () => false,
      officerSteps: [{ tool: "sunny_bakery_sunny_bakery", arguments: { request: "What do you offer?" } }, { text: "It changed." }],
      peerSteps: [{ text: "should not run" }],
    });
    await declined.engine.runTurn("What does Sunny Bakery offer?");
    assert.equal(declined.confirmations.length, 1, "the visitor was asked");
    const held = declined.confirmations[0];
    assert.equal(held.drift.changed, true);
    assert.ok(held.drift.changes.some((c) => c.kind === "instructions_changed" && c.added.some((l) => /gift card/.test(l))));
    assert.equal(declined.peer.calls.length, 0);
    assert.match(toolMessage(declined.officer, 1), new RegExp(`held "sunny_bakery" from ${escapeRe(RANGE_HOST)} for review and the visitor turned it away`));
    assert.equal(store.get(SUNNY).hash, approved, "the old approval stays");

    const admitted = makeEngine({
      store, confirm: async () => true,
      officerSteps: [{ tool: "sunny_bakery_sunny_bakery", arguments: { request: "What do you offer?" } }, { text: "ok" }],
      peerSteps: [{ text: "Breads, and a gift card offer." }],
    });
    await admitted.engine.runTurn("What does Sunny Bakery offer?");
    assert.equal(admitted.peer.calls.length, 1);
    assert.notEqual(store.get(SUNNY).hash, approved);
    assert.equal(store.get(SUNNY).how, "reviewed");
  } finally {
    rugPulled = false;
  }
});

test("declining the consent card means nothing is fetched or inspected", async () => {
  const store = new PinStore(new MemoryStorage());
  const t = makeEngine({
    store, consent: "decline",
    officerSteps: [{ tool: "sunny_bakery_sunny_bakery", arguments: { request: "What do you offer?" } }, { text: "Declined." }],
  });
  const before = requests.length;
  await t.engine.runTurn("What does Sunny Bakery offer?");
  assert.equal(requests.length, before, "no request was made");
  assert.equal(t.reports.length, 0);
  assert.match(toolMessage(t.officer, 1), new RegExp(`The user declined to contact ${escapeRe(RANGE_HOST)}`));
});

test("installing twice reuses the guard, and uninstall restores the engine", async () => {
  const engine = new Engine({ originUrl: SITE, trace: new TraceBus() });
  const original = engine._compile;
  const a = installCustomsGuard(engine, { store: new PinStore(new MemoryStorage()) });
  const b = installCustomsGuard(engine);
  assert.equal(a, b);
  assert.notEqual(engine._compile, original);
  a.uninstall();
  assert.equal(engine._compile, original);
});
