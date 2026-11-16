// locks.js: two locks that hold whatever a scam says, in any wording and any language.
//
//   Lock 1, secrets: a real card number or IBAN is never sent to a partner's assistant.
//           Once a partner (or an outside tool) has answered in a turn, none goes to an
//           outside tool or into a website action either. And the page never follows a
//           link that carries one.
//   Lock 2, actions: once a partner has answered in a turn, a website action that changes
//           something waits for the visitor's own click, in the runtime's confirmation box.
//
// The rules in rules.js try to spot a scam by its words. These locks don't read words:
// they check the secret itself (card numbers pass the Luhn check, IBANs their check
// digits) and who prompted an action. Like the guard, they wrap this engine instance
// only, and uninstall() undoes them. Lock 3, no remote images, is the page's own policy.

// ---- Real card numbers and IBANs ---------------------------------------------------

// 13 to 19 digits, maybe in groups ("4242 4242 4242 4242", "4242-4242-...").
const CARD_CANDIDATE = /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g;
// The first digits card networks use: Visa, Mastercard, American Express, Diners, JCB,
// Discover, UnionPay and Maestro. Other long numbers (orders, parcels) mostly start elsewhere.
const CARD_PREFIX = /^(?:4|5[0-9]|2[2-7]|3[0-9]|6)/;
// Two letters, two check digits, then 11 to 30 letters and digits, written in one piece
// or in groups of four, so a word after it ("... 0130 00 please") is not taken in.
const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)\b/gi;

function luhn(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i += 1) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

function ibanValid(raw) {
  const s = raw.replace(/\s+/g, "").toUpperCase();
  if (s.length < 15 || s.length > 34) return false;
  let rest = 0;
  for (const ch of s.slice(4) + s.slice(0, 4)) {
    const v = ch >= "A" && ch <= "Z" ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48;
    rest = (rest * (v > 9 ? 100 : 10) + v) % 97;
  }
  return rest === 1;
}

const mask = (value) => `${value.slice(0, 4)}…${value.slice(-2)}`;

/**
 * Real card numbers and IBANs in a text. A number counts only when its check digit is
 * right, so most other long numbers do not.
 *
 * :param text: Any text, or an object (its JSON is checked).
 * :return: [{kind: "card number" | "IBAN", sample}], with each number shortened.
 */
export function findSecrets(text) {
  const s = typeof text === "string" ? text : JSON.stringify(text ?? "");
  const found = [];
  for (const m of s.matchAll(CARD_CANDIDATE)) {
    const digits = m[0].replace(/[ -]/g, "");
    if (digits.length >= 13 && CARD_PREFIX.test(digits) && luhn(digits)) found.push({ kind: "card number", sample: mask(digits) });
  }
  for (const m of s.matchAll(IBAN_CANDIDATE)) {
    if (ibanValid(m[0])) found.push({ kind: "IBAN", sample: mask(m[0].replace(/\s+/g, "").toUpperCase()) });
  }
  return found;
}

/**
 * What the calling assistant is told when a lock keeps a secret back. Our own words only.
 */
export function keptOut(kind, where) {
  return `Agent Customs kept a ${kind} out of ${where}. Nothing was sent. Card numbers and bank account numbers never go to a partner's assistant, an outside tool or a website action after a partner has answered. Tell the visitor so, and do not try again.`;
}

function hostOf(url) {
  try { return new URL(url).host; } catch { return String(url || "another site"); }
}

// ---- Installing the locks ------------------------------------------------------------

/**
 * Put both locks on a runtime engine.
 *
 * :param engine: The Engine from the runtime's boot().
 * :param options.trustedActions: Names of website actions that change only harmless things
 *   on the page (or ask the visitor themselves), so Lock 2 lets them run without a click.
 * :param options.notify: (event) => void, with {lock, kind, where}, whenever a lock keeps a
 *   secret back.
 * :return: {state, uninstall()}
 */
export function installLocks(engine, { trustedActions = [], notify = () => {} } = {}) {
  const state = { active: true, inTurn: false, outsideAnswered: false };
  const trusted = new Set(trustedActions);
  const undo = [];
  const swap = (target, key, make) => {
    if (!target || typeof target[key] !== "function") return;
    const original = target[key];
    target[key] = make(original);
    undo.push(() => { target[key] = original; });
  };
  const after = () => state.active && state.inTurn && state.outsideAnswered;
  const block = (kind, where) => {
    try { notify({ lock: 1, kind, where }); } catch { /* a notice never changes a decision */ }
    return keptOut(kind, where);
  };

  // A turn starts with no outside answer yet.
  swap(engine, "runTurn", (original) => async function lockedTurn(...args) {
    state.inTurn = true;
    state.outsideAnswered = false;
    try { return await original.apply(this, args); } finally {
      state.inTurn = false;
      state.outsideAnswered = false;
    }
  });

  // Lock 1 at the partner: a request never carries a card number or IBAN. The partner's
  // answer arms the other checks for the rest of the turn.
  swap(engine, "resolveRemote", (original) => async function lockedRemote(...args) {
    const session = await original.apply(this, args);
    if (session && !session.__customsLocks) {
      const invoke = session.invoke;
      session.invoke = async function lockedInvoke(request, opts) {
        if (state.active) {
          const found = findSecrets(request?.user_message?.text || "");
          if (found.length) return block(found[0].kind, `this request to ${hostOf(session.base)}`);
        }
        try { return await invoke.call(this, request, opts); } finally { if (state.inTurn) state.outsideAnswered = true; }
      };
      session.__customsLocks = true;
    }
    return session;
  });

  // An outside tool (MCP) is checked the same way once an outside answer is in, and its own
  // answer counts as one.
  swap(engine, "resolveMcp", (original) => async function lockedMcp(...args) {
    const client = await original.apply(this, args);
    if (client && !client.__customsLocks) {
      const callTool = client.callTool;
      client.callTool = async function lockedCall(name, toolArgs, parentSpan) {
        if (after()) {
          const found = findSecrets(toolArgs ?? {});
          if (found.length) throw new Error(block(found[0].kind, `a call to ${hostOf(client.url)}`));
        }
        try { return await callTool.call(this, name, toolArgs, parentSpan); } finally { if (state.inTurn) state.outsideAnswered = true; }
      };
      client.__customsLocks = true;
    }
    return client;
  });

  // Lock 2, and Lock 1 for website actions, once an outside answer is in.
  swap(engine.actions, "execute", (original) => async function lockedExecute(plan, confirm, invocationId) {
    if (!after()) return original.call(this, plan, confirm, invocationId);
    const found = findSecrets((plan || []).map(({ args }) => args));
    if (found.length) throw new Error(block(found[0].kind, "a website action"));
    const changes = (plan || []).some(({ entry }) => entry.effect !== "read" && !trusted.has(entry.name));
    if (!changes) return original.call(this, plan, confirm, invocationId);
    const askVisitor = async (items) => {
      try { return Boolean(await engine.onActionConfirm(items)); } catch { return false; }
    };
    return original.call(this, plan, askVisitor, invocationId);
  });

  // Lock 1 for links: the page never follows a link that carries a card number or IBAN.
  if (typeof document !== "undefined" && document.addEventListener) {
    const onClick = (event) => {
      if (!state.active) return;
      const link = event.target?.closest?.("a[href]");
      if (!link) return;
      let href = link.href;
      try { href = decodeURIComponent(href); } catch { /* keep it as it is */ }
      const found = findSecrets(href);
      if (!found.length) return;
      event.preventDefault();
      event.stopPropagation();
      block(found[0].kind, `a link to ${hostOf(link.href)}`);
    };
    for (const type of ["click", "auxclick"]) {
      document.addEventListener(type, onClick, true);
      undo.push(() => document.removeEventListener(type, onClick, true));
    }
  }

  return {
    state,
    uninstall() {
      state.active = false;
      while (undo.length) undo.pop()();
    },
  };
}
