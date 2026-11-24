// Mounts the Customs Officer assistant inside the page and installs the guard.
// Loaded with <script type="module" src="site.js"></script>; the page needs the mount
// markup in index.html (#assistant-status and #agent-app).
//
// Three connections to the runtime:
//  1. Inspections and comparisons the assistant starts ask the visitor first, on the
//     runtime's own consent card, before any other origin is contacted.
//  2. installCustomsGuard() inspects every partner network after its consent card and
//     before it runs, using the same rules as the page.
//  3. Each guard decision appears in the page's border log, and as a notice in the chat
//     whose "See the full report" opens the report on this page.
//  4. The desk's AI double-check switch uses the visitor's own key, for inspections on the
//     page and for partners the guard lets in.
// Before the runtime mounts, OpenRouter joins its AI providers (providers.js).
//
// The visitor's key lives in the key vault (vault-bridge.js), a separate site in a frame. The
// runtime starts with a stand-in key and address, and every AI request it makes goes through
// the vault, which adds the real key. This page never reads or stores the key.
import { desk } from "./desk.js";
import { installCustomsGuard } from "./customs/guard.js";
import { confirmChoice, confirmEntryDialog } from "./customs/guard-ui.js";
import { createEngineJudge, engineJudgeModel } from "./customs/judge.js";
import { addProviders } from "./providers.js";
import { legacyKeys, mountModelPicker, readModelSetup } from "./model-picker.js";
import { KeyVault, VAULT_KEY, VAULT_ROUTER, pageTheme, routeVaultFetch } from "./vault-bridge.js";

/**
 * Limit which website actions named sub-agents can see and execute.
 *
 * :param engine: The runtime engine, or an object with actions, trace and top.
 * :param allowByAgent: Map of agent name to allowed website action names.
 * :return: {uninstall()}
 */
export function scopeAgentActions(engine, allowByAgent = {}) {
  const actions = engine?.actions;
  const trace = engine?.trace;
  if (!actions || !trace || typeof actions.catalog !== "function" || typeof actions.execute !== "function") {
    return { uninstall() {} };
  }
  const allow = new Map(
    Object.entries(allowByAgent).map(([agent, names]) => [agent, new Set(names || [])]),
  );
  if (!allow.size) return { uninstall() {} };

  const agentStack = [];
  const websiteToolStack = [];
  const removeById = (stack, id) => {
    for (let i = stack.length - 1; i >= 0; i -= 1) {
      if (stack[i].id === id) { stack.splice(i, 1); return; }
    }
  };
  const onEvent = (event) => {
    const ev = event?.detail;
    if (!ev) return;
    if (ev.phase === "start") {
      if (ev.kind === "agent") {
        agentStack.push({ id: ev.id, agent: ev.agent, network: ev.network || "" });
      } else if (ev.kind === "tool" && ev.toolKind === "agent") {
        const parent = trace.spans?.get(ev.parent);
        agentStack.push({ id: ev.id, agent: ev.tool, network: parent?.network || "" });
      } else if (ev.kind === "tool" && ev.toolKind === "website") {
        websiteToolStack.push({ id: ev.id, parent: ev.parent });
      }
    } else if (ev.phase === "end") {
      removeById(agentStack, ev.id);
      removeById(websiteToolStack, ev.id);
    }
  };
  trace.addEventListener("event", onEvent);

  const originalCatalog = actions.catalog;
  actions.catalog = function scopedCatalog(scope) {
    const list = originalCatalog.call(this, scope);
    const active = agentStack[agentStack.length - 1];
    if (!active) return list;
    const topNetwork = engine.top?.network?.name || "";
    if (topNetwork && active.network && active.network !== topNetwork) return list;
    if (scope?.network && active.network && scope.network !== active.network) return list;
    const allowed = allow.get(active.agent);
    return allowed ? list.filter((action) => allowed.has(action.name)) : list;
  };

  const originalExecute = actions.execute;
  actions.execute = async function scopedExecute(plan, confirm, invocationId) {
    const toolSpan = websiteToolStack[websiteToolStack.length - 1];
    if (toolSpan) {
      const parent = trace.spans?.get(toolSpan.parent);
      const topNetwork = engine.top?.network?.name || "";
      if (parent?.kind === "agent" && (!topNetwork || !parent.network || parent.network === topNetwork)) {
        const allowed = allow.get(parent.agent);
        if (allowed) {
          for (const item of plan || []) {
            const name = item?.entry?.name;
            if (!allowed.has(name)) {
              throw new Error(`${parent.agent} is not allowed to call ${name}.`);
            }
          }
        }
      }
    }
    return originalExecute.call(this, plan, confirm, invocationId);
  };

  return {
    uninstall() {
      trace.removeEventListener("event", onEvent);
      actions.catalog = originalCatalog;
      actions.execute = originalExecute;
    },
  };
}

/**
 * Boots the browser runtime in the page's assistant section.
 */
export class AssistantMount {
  /**
   * The first chat message once the visitor has a key: what the assistant can do here.
   */
  static GREETING = "I'm the Customs Officer. Give me an agent network URL and I'll inspect it, explain the findings, or compare two versions. I can also ask the test-range networks a question, once they pass inspection.";

  /**
   * Boot the runtime and report the result in the status line.
   *
   * :return: The runtime engine, or null when boot failed.
   */
  static async start() {
    const status = document.querySelector("#assistant-status");
    const siteBase = new URL("./", import.meta.url).href;
    const { promise: aiConnected, resolve: connectAi } = Promise.withResolvers();
    desk.connectAi(aiConnected);
    const vault = AssistantMount.openVault();
    try {
      const [{ boot }, { API_KEY_PROVIDERS }, byok] = await Promise.all([
        import("./runtime/index.js"), import("./runtime/ui.js"), import("./runtime/byok.js"),
        vault?.ready,
      ]);
      addProviders(API_KEY_PROVIDERS);
      let setup = readModelSetup();
      if (setup && vault?.status) await vault.ask("use", setup);
      // Never a saved key: the practice site, on this same address, saves keys the old way.
      const booted = await boot("#agent-app", {
        originUrl: siteBase,
        sandboxWorkerUrl: new URL("runtime/sandbox-worker.js", siteBase).href,
        byokKey: VAULT_KEY,
        router: VAULT_ROUTER,
        model: setup?.model || "",
      });
      const engine = booted.engine;
      AssistantMount.engine = engine;
      AssistantMount.defaultReview = engine.onActionConfirm;
      engine.onActionConfirm = AssistantMount.review;
      AssistantMount.defaultConsent = engine.onConsent;
      engine.onConsent = AssistantMount.consent;

      // 1. Contact with another origin, started by the assistant, needs the visitor's OK,
      //    and so does any approval the assistant asks to give or forget.
      desk.askContact = AssistantMount.askContact;
      desk.confirmApproval = AssistantMount.confirmApproval;
      // 2 and 3. Inspect every partner network before it runs, and log the decision.
      AssistantMount.guard = installCustomsGuard(engine, {
        // These change only this page (a report, a comparison) or ask the visitor
        // themselves (approvals), so the action lock lets them run.
        trustedActions: ["inspect_agent_network", "compare_networks", "pin_network", "unpin_network"],
        store: desk.pins,
        confirmEntry: confirmEntryDialog,
        onReport: (report) => desk.recordBorderEvent(report),
        // The notice's "See the full report" shows the report here, on the Report tab.
        reportPage: siteBase,
        openReport: (url) => document.dispatchEvent(new CustomEvent("customs:inspect", { detail: { url } })),
        // 4. The same switch turns the AI double-check on for partners.
        semanticJudge: () => desk.aiCheckOn,
      });
      AssistantMount.actionScope = scopeAgentActions(engine, {
        instruction_analyst: ["get_inspection_details"],
      });

      // The AI is ready once the vault holds the key the setup uses; a saved key may be locked.
      const judge = createEngineJudge(engine);
      const model = engineJudgeModel(engine);
      const aiState = () => {
        const active = vault?.status?.active;
        const ready = !!setup && !!active && active.router === setup.router;
        return { ready, locked: ready && vault.status.state === "locked" };
      };
      connectAi({ judge, model, ...aiState() });
      vault?.on((event) => { if (event === "status") desk.connectAi({ judge, model, ...aiState() }); });
      document.addEventListener("customs:focus-key", () => vault?.focus());
      // Without a key, the model picker below says what to do, so the status line rests.
      const needsKey = !aiState().ready;
      status.textContent = "Officer on duty. Every partner network is inspected before it runs.";
      status.hidden = needsKey;
      const picker = document.querySelector("#model-picker");
      if (picker) {
        mountModelPicker(picker, {
          engine, providers: API_KEY_PROVIDERS, app: document.querySelector("#agent-app"), vault, setup, legacy: legacyKeys(byok),
          onSetup: (next) => { setup = next; desk.connectAi({ judge, model, ...aiState() }); },
        });
      }
      if (!needsKey) AssistantMount.greet();
      return engine;
    } catch (error) {
      // The page must keep working without the assistant.
      connectAi(null);
      status.textContent = "The officer couldn't load. You can still inspect networks with the form above.";
      const current = document.querySelector("#mp-current");
      if (current) current.textContent = "The officer couldn't load, so no model can be set. The inspection tools above still work.";
      console.error("Assistant startup failed", error);
      return null;
    }
  }

  /**
   * Ask the visitor, on the runtime's consent card, before an inspection contacts
   * another origin. The card shows the full address the officer chose. The runtime
   * remembers "Always allow" under the value in peerOrigin; giving it the full address
   * keeps that memory to this one address, apart from the host-wide memory that partner
   * calls use, so a different path (which could carry chat text) is asked about again.
   *
   * :param request.host: The host to contact.
   * :param request.address: The address to inspect, without query or fragment.
   * :param request.purpose: What will be read, shown on the card.
   * :return: True when the visitor allows it.
   */
  static async askContact({ host, address, purpose }) {
    const engine = AssistantMount.engine;
    if (!engine) return false;
    const decision = await engine.requestConsent({
      kind: "inspect", phase: "call", peerLabel: host, peerOrigin: address, requestText: purpose,
      est: { totalTokens: 0, costText: "no AI calls" },
    });
    return decision !== "decline";
  }

  /** Put the vault's frame into the model settings and route the runtime's AI requests through it. */
  static openVault() {
    const slot = document.querySelector("#mp-vault");
    if (!slot) return null;
    const vault = KeyVault.mount(slot, { theme: pageTheme() });
    routeVaultFetch(vault, window);
    // The palette switch changes the page's colours; the vault's box follows.
    new MutationObserver(() => vault.ask("theme", { theme: pageTheme() }))
      .observe(document.documentElement, { attributes: true, attributeFilter: ["data-palette"] });
    return vault;
  }

  static greet() {
    const first = document.querySelector("#ns-msgs .ns-msg.bot");
    if (first) first.textContent = AssistantMount.GREETING;
  }

  /**
   * Confirm actions before they run. This site has no irreversible actions of its own,
   * so anything that reaches here (such as a partner's action) gets the runtime's dialog.
   */
  static async review(items) {
    const confirmed = await AssistantMount.defaultReview(items);
    AssistantMount.keepFocusInChat();
    return confirmed;
  }

  /**
   * Ask the visitor before the officer approves a network or forgets an approval. The desk
   * calls this only after its own rules allow the request (desk.pin and desk.unpin).
   *
   * :param request.action: "approve" or "forget".
   * :param request.url: The network URL.
   * :param request.report: The inspection report, when there is one.
   * :return: True when the visitor agrees.
   */
  static async confirmApproval({ action, url, report }) {
    const name = report ? `"${report.target.network}" from ${report.target.host}` : url;
    const question = action === "approve"
      ? {
        title: `Approve ${name}?`,
        paragraphs: [
          `The Customs Officer asks to approve the version you inspected (${report.verdict.stamp}, fingerprint ${report.identity.short}).`,
          "This exact version will then run without asking again. If it changes, it will be held for your review.",
        ],
        confirmLabel: "Approve",
        cancelLabel: "Not now",
      }
      : {
        title: `Forget your approval of ${name}?`,
        paragraphs: ["The Customs Officer asks to forget it. Its next use will be inspected as new."],
        confirmLabel: "Forget approval",
        cancelLabel: "Keep it",
      };
    const agreed = await confirmChoice({ kicker: "Agent Customs · approval", ...question });
    AssistantMount.keepFocusInChat();
    return agreed;
  }

  /**
   * Show the runtime's consent card, focus it while it waits, then return focus to the chat.
   */
  static async consent(info) {
    const answer = AssistantMount.defaultConsent(info);
    AssistantMount.focusConsentCard();
    const decision = await answer;
    AssistantMount.keepFocusInChat();
    return decision;
  }

  static focusConsentCard() {
    const cards = document.querySelectorAll("#ns-msgs .ns-consent");
    const card = cards[cards.length - 1];
    const title = card ? card.querySelector(".ns-consent-title") : null;
    if (!title) return;
    card.setAttribute("role", "group");
    card.setAttribute("aria-label", title.textContent);
    const active = document.activeElement;
    if (active && active !== document.body && !active.closest("#agent-app")) return;
    title.tabIndex = -1;
    title.focus();
  }

  static keepFocusInChat() {
    if (document.activeElement === document.body || document.activeElement === null) {
      document.querySelector("#ns-input")?.focus();
    }
  }
}

// Boot only in a browser. Node tests import this file without booting. No top-level await:
// start() reports its own failures, and older browsers can run this file.
if (typeof window !== "undefined") {
  AssistantMount.start();
}
