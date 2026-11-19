// auto.js: Agent Customs in one line. Add this to a page made with Cognizant's
// agentify-website kit, and the guard starts with its default settings:
//
//   <script type="module" src="https://cdn.jsdelivr.net/gh/montbaga/agent-customs@v1.0.0/site/customs/auto.js"></script>
//
// The kit's runtime publishes its engine as window.__nsweb once boot() is done. This file waits
// for that moment and installs the guard. For other settings, import guard.js instead.
import { installCustomsGuard } from "./guard.js";

/**
 * Install the guard on the runtime's engine as soon as the runtime publishes it.
 *
 * :param target: The page's window.
 * :param install: The installer (installCustomsGuard; tests pass their own).
 */
export function guardWhenReady(target = globalThis, install = installCustomsGuard) {
  const attach = (value) => {
    if (!value?.engine) return;
    try {
      install(value.engine);
    } catch (error) {
      // Never break the page's own start-up.
      console.error("Agent Customs could not start:", error);
    }
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
