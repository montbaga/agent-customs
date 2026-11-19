// The one-line install: site/customs/auto.js attaches the guard when the runtime starts.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import test from "node:test";
import { guardWhenReady } from "../site/customs/auto.js";

test("the guard attaches when the runtime publishes its engine, once", () => {
  const page = {};
  const installed = [];
  guardWhenReady(page, (engine) => installed.push(engine));
  assert.deepEqual(installed, [], "nothing to guard before the runtime starts");
  const engine = { name: "engine" };
  page.__nsweb = { engine, trace: {} };
  assert.deepEqual(installed, [engine]);
  assert.equal(page.__nsweb.engine, engine, "the runtime still reads back what it set");
  page.__nsweb = { trace: {} };
  assert.equal(installed.length, 1, "a value without an engine is ignored");
});

test("a runtime that started before the script loaded is guarded straight away", () => {
  const engine = { name: "engine" };
  const page = { __nsweb: { engine } };
  const installed = [];
  guardWhenReady(page, (e) => installed.push(e));
  assert.deepEqual(installed, [engine]);
});

test("a guard that cannot start never breaks the page's own start-up", () => {
  const page = {};
  const errors = [];
  const original = console.error;
  console.error = (...args) => errors.push(args.join(" "));
  try {
    guardWhenReady(page, () => { throw new Error("no _compile step"); });
    assert.doesNotThrow(() => { page.__nsweb = { engine: {} }; });
  } finally {
    console.error = original;
  }
  assert.match(errors.join(), /Agent Customs could not start/);
});

test("with the real installer, the engine ends up guarded, and installing twice is harmless", async () => {
  const { installCustomsGuard } = await import("../site/customs/guard.js");
  const engine = { _compile: async () => ({}), top: null };
  const page = {};
  guardWhenReady(page, (e) => installCustomsGuard(e, { notice: false, locks: false, canary: false }));
  page.__nsweb = { engine };
  const guard = engine.__agentCustoms;
  assert.ok(guard, "the guard is installed");
  assert.equal(installCustomsGuard(engine), guard, "a site that also installs it by hand gets the same guard");
  guard.uninstall();
});
