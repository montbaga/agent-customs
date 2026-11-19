// auto.js: Agent Customs in one line. Added to a page made with Cognizant's
// agentify-website kit, above the page's own script tags, it starts the guard with its default
// settings. The published one-line file is dist/agent-customs.js: this file and the guard,
// joined by tools/make-bundle.mjs so one integrity hash covers them (see the README).
//
// Above the other tags, the browser runs it before the page's own code starts the assistant.
// The kit's runtime publishes its engine as window.__nsweb once boot() is done. This file
// imports nothing up front, so it runs as soon as it arrives, and the guard's own files load
// in the background. Until they have loaded and the guard is on, every chat turn and every
// partner waits. If the guard cannot load, they fail instead of running unchecked.
// For other settings, import guard.js instead.

/**
 * Hold the runtime's engine until the guard is installed on it.
 *
 * :param target: The page's window.
 * :param load: Loads guard.js (tests pass their own).
 */
export function guardWhenReady(target = globalThis, load = () => import("./guard.js")) {
  let loading = null;
  const guardModule = () => (loading ||= Promise.resolve().then(load));
  // Start loading at once; a failure is reported when an engine waits on it.
  guardModule().catch(() => {});

  const attach = (value) => {
    const engine = value?.engine;
    if (!engine || engine.__agentCustoms || engine.__agentCustomsAuto) return;
    engine.__agentCustomsAuto = true;
    const turn = engine.runTurn;
    const compile = engine._compile;
    let held;
    // A guard installed by hand meanwhile wraps the held step, so its calls already passed it.
    let byHand = false;
    const ready = guardModule().then(({ installCustomsGuard }) => {
      byHand = Boolean(engine.__agentCustoms);
      if (engine.runTurn === held.turn) engine.runTurn = turn;
      if (!byHand) {
        engine._compile = compile;
        installCustomsGuard(engine);
      }
    });
    ready.catch((error) => console.error("Agent Customs could not start, so the assistant is paused:", error));
    const wait = async () => {
      try {
        await ready;
      } catch {
        throw new Error("Agent Customs could not load, so this was not run. Reload the page to try again.");
      }
    };
    const heldTurn = async function (...args) {
      await wait();
      return turn.apply(this, args);
    };
    // A partner held here goes through the guard once it is on, never around it.
    const heldCompile = async function (...args) {
      await wait();
      return (byHand ? compile : engine._compile).apply(this, args);
    };
    held = { turn: typeof turn === "function" ? heldTurn : turn, compile: heldCompile };
    engine.runTurn = held.turn;
    engine._compile = held.compile;
  };

  const existing = Object.getOwnPropertyDescriptor(target, "__nsweb");
  if (existing && "value" in existing) {
    attach(existing.value);
    return;
  }
  if (existing) return;
  let current;
  Object.defineProperty(target, "__nsweb", {
    configurable: true,
    enumerable: true,
    get: () => current,
    set: (value) => {
      current = value;
      attach(value);
    },
  });
}

if (typeof window !== "undefined") guardWhenReady(window);
