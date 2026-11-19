// vault-bridge.js: the page's side of the key vault (vault/, a separate site in a frame).
//
// The page never holds the key. The runtime starts with a stand-in key and address, and
// routeVaultFetch() sends every request for that address to the vault, which adds the key and
// streams the answer back. The page says hello to the vault's exact origin with one end of a
// MessageChannel, and everything else goes over that channel.

export const VAULT_ROUTER = "https://key-vault.invalid/v1";
export const VAULT_KEY = "kept-in-the-key-vault";
// A service the vault does not know by name; its address is typed into the vault.
export const CUSTOM_SERVICE = "custom";
const STAND_IN = new URL(VAULT_ROUTER);
const HELLO = "agent-customs-vault:hello";
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);
const NO_BODY = new Set([101, 204, 205, 304]);

/** A page on this computer uses the local vault (npm run serve:vault); a published page, the published one. */
export function vaultAddress(loc = globalThis.location) {
  const host = loc?.hostname || "";
  if (LOOPBACK.has(host)) return `http://${host}:8090/`;
  return "https://agent-customs-vault.github.io/";
}

/** The page's palette, so the vault's box matches it. */
export function pageTheme(root = globalThis.document?.documentElement) {
  if (!root) return {};
  const style = getComputedStyle(root);
  const read = (name) => style.getPropertyValue(name).trim();
  return { c1: read("--c1"), c2: read("--c2"), c3: read("--c3"), onC3: read("--on-c3") };
}

export class KeyVault {
  /** Put the vault's frame into a slot. `ready` gives the first status, or null on timeout. */
  static mount(slot, { url = vaultAddress(), theme = pageTheme(), timeoutMs = 10_000 } = {}) {
    const frame = document.createElement("iframe");
    frame.className = "vault-frame";
    frame.title = "Key vault";
    frame.allow = "publickey-credentials-get; publickey-credentials-create";
    const vault = new KeyVault(frame, new URL(url).origin, { theme, timeoutMs });
    frame.addEventListener("load", () => vault.hello(frame.contentWindow), { once: true });
    frame.src = url;
    slot.append(frame);
    return vault;
  }

  constructor(frame, origin, { theme = {}, timeoutMs = 10_000 } = {}) {
    this.frame = frame;
    this.origin = origin;
    this.theme = theme;
    this.status = null;
    this.port = null;
    this.next = 1;
    this.pending = new Map();
    this.listeners = new Set();
    ({ promise: this.connected, resolve: this.onConnected } = Promise.withResolvers());
    this.ready = Promise.race([this.connected, new Promise((resolve) => setTimeout(() => resolve(null), timeoutMs))]);
  }

  // The browser delivers the hello only if the frame still shows the vault's own origin.
  hello(target) {
    const channel = new MessageChannel();
    this.port = channel.port1;
    this.port.onmessage = (event) => this.receive(event.data);
    target.postMessage({ type: HELLO, theme: this.theme }, this.origin, [channel.port2]);
  }

  receive(message) {
    if (!message || typeof message !== "object") return;
    if (message.id && this.pending.has(message.id)) {
      const resolve = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.reply?.status) this.update(message.reply.status);
      resolve(message.reply);
      return;
    }
    if (message.event === "status") this.update(message.status);
    else if (message.event === "height" && this.frame) this.frame.style.height = `${Math.ceil(Number(message.px) || 0)}px`;
    else this.emit(message.event, message);
  }

  update(status) {
    const first = !this.status;
    this.status = status;
    if (first) this.onConnected(status);
    this.emit("status", status);
  }

  emit(event, data) {
    for (const listener of this.listeners) listener(event, data);
  }

  /** Events: status, detected (a key for another provider), draft (a key typed), submit (Enter). */
  on(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  ask(type, data = {}) {
    if (!this.port) return Promise.resolve({ ok: false, reason: "unavailable" });
    const id = this.next++;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.port.postMessage({ ...data, id, type });
    });
  }

  focus() {
    this.frame?.focus();
    return this.ask("focus");
  }

  // fetch() for the stand-in address. Paths outside it are answered here and never leave the page.
  fetch(url, init = {}) {
    const target = new URL(url);
    if (!target.pathname.startsWith(`${STAND_IN.pathname}/`)) return Promise.resolve(new Response("Not found", { status: 404 }));
    const path = target.pathname.slice(STAND_IN.pathname.length);
    const signal = init.signal;
    if (signal?.aborted) return Promise.reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
    if (!this.port) return Promise.resolve(refusal(503, "The key vault could not load, so no AI request can be sent. Reload the page to try again."));
    return new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const port = channel.port1;
      let stream = null;
      let answered = false;
      const finish = () => { signal?.removeEventListener("abort", abort); port.close(); };
      const fail = (error) => {
        if (!answered) { answered = true; reject(error); } else stream?.error(error);
        finish();
      };
      const abort = () => {
        port.postMessage({ abort: true });
        fail(signal.reason ?? new DOMException("Aborted", "AbortError"));
      };
      signal?.addEventListener("abort", abort, { once: true });
      const body = new ReadableStream({
        start(controller) { stream = controller; },
        cancel() { port.postMessage({ abort: true }); finish(); },
      });
      port.onmessage = ({ data }) => {
        if (data?.head) {
          answered = true;
          const { status, statusText = "", type = "" } = data.head;
          const empty = NO_BODY.has(status);
          resolve(new Response(empty ? null : body, { status, statusText, headers: type ? { "Content-Type": type } : {} }));
          if (empty) finish();
        } else if (data?.chunk) {
          stream?.enqueue(new Uint8Array(data.chunk));
        } else if (data?.end) {
          stream?.close();
          finish();
        } else if (data?.error) {
          fail(new TypeError("The key vault could not reach the AI provider."));
        }
      };
      this.port.postMessage({ type: "fetch", path, method: String(init.method || "GET").toUpperCase(), body: typeof init.body === "string" ? init.body : null }, [channel.port2]);
    });
  }
}

function refusal(status, message) {
  return new Response(JSON.stringify({ error: { message } }), { status, headers: { "Content-Type": "application/json" } });
}

/** Send requests for the stand-in address to the vault. Returns a function that undoes it. */
export function routeVaultFetch(vault, target = globalThis) {
  const original = target.fetch;
  target.fetch = function fetch(input, init) {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input?.url;
    let parsed = null;
    try { parsed = new URL(url, target.location?.href); } catch { /* not an address */ }
    if (parsed?.origin !== STAND_IN.origin) return original.call(target, input, init);
    if (input instanceof Request) {
      return input.text().then((text) => vault.fetch(parsed.href, { method: input.method, body: text || null, signal: init?.signal ?? input.signal }));
    }
    return vault.fetch(parsed.href, init);
  };
  return () => { target.fetch = original; };
}
