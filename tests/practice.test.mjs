// Tests for the practice site, Main Street Guide (practice/): an ordinary agentic site made
// with the agentify-website kit, which adds the Agent Customs guard with one folder and two
// lines. The end-to-end tests install the guard exactly as practice/site.js does, with no
// options, inside the practice site's own copy of the runtime.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { installCustomsGuard } from "../practice/customs/guard.js";
import { Engine } from "../practice/runtime/engine.js";
import { AgentNetwork } from "../practice/runtime/kernel.js";
import { TraceBus } from "../practice/runtime/trace.js";
import { inspectNetworkUrl } from "../site/customs/inspect.js";
import { RANGE_ORIGIN } from "../site/desk.js";
import { fsFetch } from "../tools/fs-fetch.mjs";
import { COPIED_FOLDERS, FONTS } from "../tools/make-practice.mjs";
import { ScriptedModel } from "./scripted_model.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PRACTICE = "https://practice.test";
const RANGE = RANGE_ORIGIN;
const fetchImpl = fsFetch({ [PRACTICE]: path.join(ROOT, "practice"), [RANGE]: path.join(ROOT, "range") });
const read = (rel) => readFile(path.join(ROOT, rel), "utf8");

/** Every file under a folder, as sorted paths relative to it. */
async function filesUnder(dir, prefix = "") {
  const out = [];
  for (const entry of await readdir(path.join(dir, prefix), { withFileTypes: true })) {
    const rel = path.join(prefix, entry.name);
    if (entry.isDirectory()) out.push(...await filesUnder(dir, rel));
    else out.push(rel);
  }
  return out.sort();
}

test("the practice site's customs/ and runtime/ folders are exact copies of their sources", async () => {
  for (const [from, to] of COPIED_FOLDERS) {
    const source = await filesUnder(path.join(ROOT, from));
    const copy = await filesUnder(path.join(ROOT, to));
    assert.deepEqual(copy, source, `${to} has other files than ${from}: run npm run practice`);
    for (const file of source) {
      const a = await readFile(path.join(ROOT, from, file));
      const b = await readFile(path.join(ROOT, to, file));
      assert.ok(a.equals(b), `${to}/${file} differs from ${from}/${file}: run npm run practice`);
    }
  }
  for (const font of FONTS) {
    const a = await readFile(path.join(ROOT, "site", "fonts", font));
    const b = await readFile(path.join(ROOT, "practice", "fonts", font));
    assert.ok(a.equals(b), `practice/fonts/${font} differs from site/fonts/${font}`);
  }
});

test("site.js adds exactly two lines for the guard: the import, and one call right after boot()", async () => {
  const lines = (await read("practice/site.js")).split(/\r?\n/);
  const code = lines.map((line) => line.replace(/\/\/.*$/, "").trim());
  const guardLines = code.map((line, i) => [line, i]).filter(([line]) => /installCustomsGuard|customs\//.test(line));
  assert.deepEqual(guardLines.map(([line]) => line), [
    'import { installCustomsGuard } from "./customs/guard.js";',
    "installCustomsGuard(booted.engine);",
  ]);
  const call = guardLines[1][1];
  const boot = code.findIndex((line) => line.startsWith("const booted = await boot("));
  const bootEnd = code.findIndex((line, i) => i > boot && line === "});");
  assert.equal(call, bootEnd + 1, "the call comes on the line after the boot() call ends");
  assert.ok(code.indexOf("AssistantMount.engine = booted.engine;") > call, "the guard is in place before the page uses the engine");
});

test("the practice network passes the agentify-website kit's build check", () => {
  const output = execFileSync(process.execPath, [
    "vendor/agentify-website/scripts/build_network.mjs", "practice/main_street_guide.hocon",
    "--manifest", "practice/agent-manifest.json", "--check",
  ], { cwd: ROOT, encoding: "utf8" });
  assert.match(output, /OK: these files are up to date/);
  assert.doesNotMatch(output, /WARNING/);
});

test("Agent Customs clears the practice site's own network", async () => {
  const report = await inspectNetworkUrl(`${PRACTICE}/main_street_guide`, { fetchImpl, pageOrigin: "http://127.0.0.1:8080" });
  assert.equal(report.verdict.code, "CLEARED", report.verdict.summary);
});

test("the shop list on the page matches the partners the network calls", async () => {
  const html = await read("practice/index.html");
  const config = JSON.parse(await read("practice/main_street_guide.network.json"));
  const shops = [...html.matchAll(/data-shop="([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(shops, Object.values(config.link_labels));
  for (const url of config.tools[0].tools) assert.ok(url.startsWith(`${RANGE}/`), url);
});

// ---- The guard, installed with no options, as practice/site.js does ---------------------------

const manifest = JSON.parse(await read("practice/agent-manifest.json"));
const config = JSON.parse(await read("practice/main_street_guide.network.json"));

/**
 * An engine for the practice site with scripted models, and the guard installed with no
 * options. The runtime fetches partner files with the global fetch.
 */
function practiceEngine({ guideSteps, shopSteps = [] }) {
  globalThis.fetch = fetchImpl;
  const engine = new Engine({ originUrl: PRACTICE, trace: new TraceBus() });
  const guide = new ScriptedModel(guideSteps);
  const shop = new ScriptedModel(shopSteps);
  engine.top = { network: new AgentNetwork(config, "main_street_guide"), base: PRACTICE, manifest, llm: guide, bundleUrl: null, integrity: null };
  engine.userRouter = { baseUrl: "https://router.invalid/v1", mock: false };
  engine.onConsent = async () => "allow";
  // Partner networks run on the scripted shop model instead of a real provider.
  const compile = engine._compile;
  engine._compile = async function (...args) {
    const compiled = await compile.apply(this, args);
    if (!args[3]?.isTop) compiled.llm = shop;
    return compiled;
  };
  const guard = installCustomsGuard(engine);
  return { engine, guide, shop, guard };
}
const toolText = (model) => model.calls[1].messages.filter((m) => m.role === "tool").map((m) => m.content).join("\n");

test("practice site: Shady Pizza is refused, and none of its agents run", async () => {
  const t = practiceEngine({
    guideSteps: [{ tool: "shady_pizza_shady_pizza", arguments: { request: "What do you offer?" } }, { text: "It was turned away." }],
  });
  await t.engine.runTurn("Ask Shady Pizza what it offers.");
  assert.equal(t.shop.calls.length, 0, "no Shady Pizza agent ran");
  assert.match(toolText(t.guide), /Agent Customs refused entry to "shady_pizza"/);
  assert.doesNotMatch(toolText(t.guide), /card number|CVV/, "the hidden payload never reaches the model");
  assert.deepEqual(t.guard.log.map((r) => [r.target.network, r.verdict.code, r.guard.decision]), [["shady_pizza", "DENIED", "refused"]]);
});

test("practice site: Sunny Bakery runs, and its version is approved on first use", async () => {
  const t = practiceEngine({
    guideSteps: [{ tool: "sunny_bakery_sunny_bakery", arguments: { request: "What do you offer?" } }, { text: "Bread and cakes." }],
    shopSteps: [{ text: "Sunny Bakery offers breads, pastries, celebration cakes and coffee." }],
  });
  await t.engine.runTurn("Ask Sunny Bakery what it offers.");
  assert.equal(t.shop.calls.length, 1, "the bakery's agent ran");
  assert.match(toolText(t.guide), /breads, pastries/);
  assert.equal(t.guard.log[0].guard.decision, "admitted");
  assert.equal(t.guard.store.get(`${RANGE}/sunny_bakery/sunny_bakery`).how, "first-use");
});

test("practice site: Loop Maze is held, and with no one to ask it is turned away", async () => {
  // In a browser the guard asks the visitor in a dialog. Without a page there is no one to
  // ask, so the default answer is no.
  const t = practiceEngine({
    guideSteps: [{ tool: "loop_maze_loop_maze", arguments: { request: "Do you have a maze puzzle?" } }, { text: "It was held." }],
  });
  await t.engine.runTurn("Ask Loop Maze for a puzzle.");
  assert.equal(t.shop.calls.length, 0, "no Loop Maze agent ran");
  assert.match(toolText(t.guide), /Agent Customs held "loop_maze" .* turned it away/);
  assert.deepEqual(t.guard.log.map((r) => [r.verdict.code, r.guard.decision]), [["HOLD", "declined"]]);
});
