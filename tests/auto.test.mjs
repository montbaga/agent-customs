// The one-line install: site/customs/auto.js holds the runtime until the guard is on.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import test from "node:test";
import { guardWhenReady } from "../site/customs/auto.js";

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
};
const fakeEngine = (order) => ({
  runTurn: async function (text) { order.push(`turn:${text}`); return { text: "answer" }; },
  _compile: async function (base) { order.push(`compile:${base}`); return {}; },
});
// Like the real guard: it wraps the runtime's partner step and checks every partner first.
const fakeGuard = (order) => ({
  installCustomsGuard: (engine) => {
    order.push("guard");
    const step = engine._compile;
    engine._compile = async function (...args) { order.push("checked"); return step.apply(this, args); };
    engine.__agentCustoms = { on: true };
  },
});

test("a chat sent before the guard has loaded waits for it, then runs guarded", async () => {
  const order = [];
  const guardFiles = deferred();
  const page = {};
  guardWhenReady(page, () => guardFiles.promise);
  const engine = fakeEngine(order);
  page.__nsweb = { engine, trace: {} };
  assert.equal(page.__nsweb.engine, engine, "the runtime still reads back what it set");
  const turn = engine.runTurn("hello");
  const partner = engine._compile("https://partner.example");
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(order, [], "nothing runs while the guard is still loading");
  guardFiles.resolve(fakeGuard(order));
  assert.deepEqual(await turn, { text: "answer" });
  await partner;
  assert.deepEqual(order, ["guard", "turn:hello", "checked", "compile:https://partner.example"],
    "a partner held while the guard loaded goes through the guard, not around it");
  assert.ok(engine.__agentCustoms, "the guard is on");
});

test("if the guard cannot load, chats and partners fail instead of running unchecked", async () => {
  const order = [];
  const page = {};
  const errors = [];
  const original = console.error;
  console.error = (...args) => errors.push(args.join(" "));
  try {
    guardWhenReady(page, () => Promise.reject(new Error("offline")));
    const engine = fakeEngine(order);
    page.__nsweb = { engine };
    await assert.rejects(engine.runTurn("hello"), /Agent Customs could not load/);
    await assert.rejects(engine._compile("https://partner.example"), /Agent Customs could not load/);
  } finally {
    console.error = original;
  }
  assert.deepEqual(order, [], "nothing ran");
  assert.match(errors.join(), /Agent Customs could not start/);
});

test("a runtime that started before the script loaded is held and guarded too", async () => {
  const order = [];
  const engine = fakeEngine(order);
  const page = { __nsweb: { engine } };
  guardWhenReady(page, async () => fakeGuard(order));
  await engine.runTurn("hi");
  assert.deepEqual(order, ["guard", "turn:hi"]);
});

test("a value without an engine is ignored, and an engine is held only once", async () => {
  const page = {};
  let loads = 0;
  guardWhenReady(page, async () => { loads += 1; return fakeGuard([]); });
  page.__nsweb = { trace: {} };
  const engine = fakeEngine([]);
  page.__nsweb = { engine };
  const held = engine.runTurn;
  page.__nsweb = { engine };
  assert.equal(engine.runTurn, held, "the second publish does not wrap it again");
  await engine.runTurn("x");
  assert.equal(loads, 1, "the guard's files load once");
});

test("with the real guard, and a site that also installs it by hand, nothing runs unguarded or loops", async () => {
  const { installCustomsGuard } = await import("../site/customs/guard.js");
  const calls = [];
  const engine = { runTurn: async () => "turn done", _compile: async (base) => { calls.push(base); return {}; }, top: null };
  const page = {};
  guardWhenReady(page, async () => ({ installCustomsGuard: (e) => installCustomsGuard(e, { notice: false, locks: false, canary: false }) }));
  page.__nsweb = { engine };
  const byHand = installCustomsGuard(engine, { notice: false, locks: false, canary: false });
  assert.equal(await engine.runTurn("hi"), "turn done");
  assert.equal(engine.__agentCustoms, byHand, "one guard, the one installed by hand");
  await engine._compile("https://partner.example", {}, {}, { isTop: true });
  assert.deepEqual(calls, ["https://partner.example"], "the runtime's own step ran exactly once");
  byHand.uninstall();
});
