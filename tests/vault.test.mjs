// The key vault: where a key may go, what the page may ask for, how a remembered key is
// locked, and the page's side of the private channel.
// Run from the project folder: node --test "tests/*.test.mjs"
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  PASSWORD_ROUNDS, PROVIDERS, RateLimit, allowedPage, checkRequest, cleanTheme, fromBase64, lockKeys, openKeys,
  passkeyLock, passwordLock, providerForKey, providerHeaders, relockKeys, serviceAddress, toBase64, unlockKeys,
} from "../vault/vault-core.js";
import { CUSTOM_SERVICE, KeyVault, VAULT_KEY, VAULT_ROUTER, routeVaultFetch, vaultAddress } from "../site/vault-bridge.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FAST = 1000; // PBKDF2 rounds for tests only; the vault uses PASSWORD_ROUNDS

test("the vault sends each company's keys only to that company's own address, the one the runtime uses", async () => {
  const { API_KEY_PROVIDERS } = await import("../site/runtime/ui.js");
  const { addProviders } = await import("../site/providers.js");
  addProviders(API_KEY_PROVIDERS);
  for (const p of PROVIDERS) {
    const runtime = API_KEY_PROVIDERS.find((r) => r.name === p.name);
    assert.ok(runtime, p.name);
    assert.equal(p.router, runtime.router, p.name);
    assert.deepEqual(p.prefixes, runtime.keyPrefixes, p.name);
  }
  assert.equal(providerForKey(" gsk_123 ")?.name, "Groq");
  assert.equal(providerForKey("sk-or-v1-abc")?.name, "OpenRouter");
  assert.equal(providerForKey("sk-ant-api03")?.name, "Anthropic");
  // Each Otari region refuses the other's keys (HTTP 421), so an EU key goes to the EU gateway.
  assert.equal(providerForKey("otk_v1_eu_abc")?.router, "https://eu.api.otari.ai/api/v1");
  assert.equal(providerForKey("otk_v1_abc")?.router, "https://api.otari.ai/api/v1");
  assert.equal(providerForKey("mystery-key"), null);
});

test("an address typed into the vault must be https, or http on this computer", () => {
  assert.equal(serviceAddress(" https://llm.example.invalid/v1/ "), "https://llm.example.invalid/v1");
  assert.equal(serviceAddress("https://llm.example.invalid/v1/chat/completions"), "https://llm.example.invalid/v1");
  assert.equal(serviceAddress("https://llm.example.invalid/v1/models"), "https://llm.example.invalid/v1");
  assert.equal(serviceAddress("https://api.otari.ai/v1"), "https://api.otari.ai/api/v1");
  assert.equal(serviceAddress("https://eu.api.otari.ai"), "https://eu.api.otari.ai/api/v1");
  assert.equal(serviceAddress("https://otari.ai"), "https://api.otari.ai/api/v1");
  assert.equal(serviceAddress("http://localhost:11434/v1"), "http://localhost:11434/v1");
  assert.equal(serviceAddress("http://127.0.0.1:8099/v1"), "http://127.0.0.1:8099/v1");
  for (const bad of ["", "llm.example.invalid", "http://llm.example.invalid/v1", "javascript:alert(1)", "ftp://x.invalid",
    "https://user:pass@llm.example.invalid/v1", "https://llm.example.invalid/v1?to=evil", "https://llm.example.invalid/v1#x"]) {
    assert.equal(serviceAddress(bad), "", bad);
  }
});

test("only Agent Customs may use the published vault; pages on this computer may use a local one", () => {
  assert.equal(allowedPage("https://montbaga.github.io", "agent-customs-vault.github.io"), true);
  for (const other of ["https://evil.example", "https://montbaga.github.io.evil.example", "http://montbaga.github.io", "http://127.0.0.1:8080", "null"]) {
    assert.equal(allowedPage(other, "agent-customs-vault.github.io"), false, other);
  }
  assert.equal(allowedPage("http://127.0.0.1:8080", "127.0.0.1"), true);
  assert.equal(allowedPage("http://localhost:8080", "localhost"), true);
  assert.equal(allowedPage("https://evil.example", "127.0.0.1"), false);
});

test("the page may ask for a model list and chats, nothing else, and not too many", () => {
  assert.deepEqual(checkRequest({ path: "/models", method: "GET" }), { ok: true });
  assert.deepEqual(checkRequest({ path: "/chat/completions", method: "post", body: '{"model":"m"}' }), { ok: true });
  for (const [request, status] of [
    [{ path: "/files", method: "GET" }, 403],
    [{ path: "/chat/completions", method: "GET" }, 403],
    [{ path: "/../files", method: "POST", body: "{}" }, 403],
    [{ path: "/organization/api_keys", method: "GET" }, 403],
    [{ path: "/chat/completions", method: "POST", body: "not json" }, 400],
    [{ path: "/chat/completions", method: "POST" }, 400],
    [{ path: "/chat/completions", method: "POST", body: JSON.stringify("x".repeat(5 * 1024 * 1024)) }, 413],
  ]) assert.equal(checkRequest(request).status, status, JSON.stringify(request).slice(0, 80));
  let now = 0;
  const limit = new RateLimit(2, 1000, () => now);
  assert.equal(limit.take(), true);
  assert.equal(limit.take(), true);
  assert.equal(limit.take(), false, "a third request in the same second waits");
  now = 1001;
  assert.equal(limit.take(), true);
});

test("the vault adds the key itself, and the header Anthropic needs from browsers", () => {
  assert.deepEqual(providerHeaders("https://api.groq.com/openai/v1", "gsk_1", true), { Authorization: "Bearer gsk_1", "Content-Type": "application/json" });
  assert.equal(providerHeaders("https://api.anthropic.com/v1", "sk-ant-1", false)["anthropic-dangerous-direct-browser-access"], "true");
  assert.equal(providerHeaders("https://api.openai.com/v1", "k", false)["anthropic-dangerous-direct-browser-access"], undefined);
});

test("the page's colours reach the vault only as plain hex values", () => {
  assert.deepEqual(cleanTheme({ c1: "#0c1d18", c2: " #ECE4D3 ", c3: "red; background: url(https://evil.example/x)", onC3: "#000" }),
    { c1: "#0c1d18", c2: "#ECE4D3", onC3: "#000" });
  assert.deepEqual(cleanTheme(null), {});
});

test("a remembered key is stored only encrypted, and only the right password opens it", async () => {
  assert.ok(PASSWORD_ROUNDS >= 600_000, "the vault makes each password guess cost 600,000 rounds");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keys = { "https://api.groq.com/openai/v1": { name: "Groq", key: "gsk_secret_value_1" } };
  const { box, raw } = await lockKeys({ kind: "password", key: await passwordLock("correct horse", salt, FAST), salt: toBase64(salt), rounds: FAST }, keys);
  const stored = JSON.stringify(box);
  assert.doesNotMatch(stored, /gsk_secret_value_1/, "the key itself is never in the stored record");
  assert.deepEqual(box.saved, [{ name: "Groq", router: "https://api.groq.com/openai/v1" }]);
  const opened = await unlockKeys(box, await passwordLock("correct horse", fromBase64(box.salt), box.rounds));
  assert.deepEqual(opened.keys, keys);
  assert.deepEqual([...opened.raw], [...raw]);
  await assert.rejects(unlockKeys(box, await passwordLock("wrong horse", fromBase64(box.salt), box.rounds)));
  // A changed record does not open either.
  const changed = { ...box, keys: { ...box.keys, data: toBase64(fromBase64(box.keys.data).map((b, i) => (i === 0 ? b ^ 1 : b))) } };
  await assert.rejects(openKeys(changed, raw));
  // A key saved later in the same visit joins the box without the password.
  const more = { ...keys, "https://api.openai.com/v1": { name: "OpenAI", key: "sk-proj-2" } };
  const grown = await relockKeys(box, raw, more);
  assert.deepEqual(await openKeys(grown, raw), more);
  assert.deepEqual(grown.saved.map((s) => s.name), ["Groq", "OpenAI"]);
});

test("a passkey's secret bytes open the box; other bytes do not", async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const { box } = await lockKeys({ kind: "passkey", key: await passkeyLock(secret), credential: "id", prfSalt: "salt" }, { r: { name: "n", key: "k" } });
  assert.deepEqual((await unlockKeys(box, await passkeyLock(secret))).keys, { r: { name: "n", key: "k" } });
  await assert.rejects(unlockKeys(box, await passkeyLock(crypto.getRandomValues(new Uint8Array(32)))));
});

test("a published page uses the published vault; a page on this computer uses a local one", () => {
  assert.equal(vaultAddress({ hostname: "montbaga.github.io" }), "https://agent-customs-vault.github.io/");
  assert.equal(vaultAddress({ hostname: "127.0.0.1" }), "http://127.0.0.1:8090/");
  assert.equal(vaultAddress({ hostname: "localhost" }), "http://localhost:8090/");
  assert.equal(CUSTOM_SERVICE, "custom");
  assert.notEqual(VAULT_KEY, "demo", "the runtime treats 'demo' as no key at all");
  assert.match(new URL(VAULT_ROUTER).hostname, /\.invalid$/, "the stand-in address can never reach a real server");
});

// A vault on the other end of a real MessageChannel, answering like vault.js does.
function connectedVault(answer) {
  const frame = { style: {} };
  const vault = new KeyVault(frame, "http://127.0.0.1:8090", { timeoutMs: 1000 });
  const seen = [];
  const target = {
    postMessage(message, origin, [port]) {
      seen.push({ hello: message, origin });
      port.onmessage = ({ data, ports }) => { seen.push(data); answer(data, ports?.[0], port); };
      port.postMessage({ event: "status", status: { state: "ready", active: { name: "Groq", router: "https://api.groq.com/openai/v1" }, saved: [] } });
    },
  };
  vault.hello(target);
  return { vault, seen, frame };
}

test("the page says hello only to the vault's own origin, and learns what it holds, never a key", async () => {
  const { vault, seen } = connectedVault((data, _port, main) => {
    if (data.type === "status") main.postMessage({ id: data.id, reply: { ok: true, status: { state: "locked", active: null, saved: [] } } });
  });
  const first = await vault.ready;
  assert.equal(seen[0].origin, "http://127.0.0.1:8090");
  assert.equal(seen[0].hello.type, "agent-customs-vault:hello");
  assert.equal(first.state, "ready");
  const events = [];
  vault.on((event, data) => events.push([event, data?.state]));
  const reply = await vault.ask("status");
  assert.equal(reply.ok, true);
  assert.equal(vault.status.state, "locked", "a reply's status updates the page's copy");
  assert.deepEqual(events, [["status", "locked"]]);
  vault.port.close();
});

test("a chat for the stand-in address goes to the vault without any key, and streams back", async () => {
  const { vault, seen } = connectedVault((data, port) => {
    if (data.type !== "fetch") return;
    port.postMessage({ head: { status: 200, statusText: "OK", type: "text/event-stream" } });
    for (const part of ['data: {"choices":[{"delta":{"content":"Hel"}}]}\n', 'data: {"choices":[{"delta":{"content":"lo"}}]}\n', "data: [DONE]\n"]) {
      const bytes = new TextEncoder().encode(part);
      port.postMessage({ chunk: bytes.buffer }, [bytes.buffer]);
    }
    port.postMessage({ end: true });
  });
  await vault.ready;
  const response = await vault.fetch(`${VAULT_ROUTER}/chat/completions`, {
    method: "post", headers: { Authorization: `Bearer ${VAULT_KEY}` }, body: '{"model":"m","stream":true}',
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/event-stream");
  assert.match(await response.text(), /Hel[\s\S]*lo[\s\S]*\[DONE\]/);
  const sent = seen.find((m) => m.type === "fetch");
  assert.deepEqual(sent, { type: "fetch", path: "/chat/completions", method: "POST", body: '{"model":"m","stream":true}' });
  assert.doesNotMatch(JSON.stringify(seen), /Authorization|Bearer/, "the page's headers, stand-in key included, are not passed on");
  vault.port.close();
});

test("a stopped chat stops in the vault too, and odd addresses never leave the page", async () => {
  let aborted = false;
  const { vault } = connectedVault((data, port) => {
    if (data.type !== "fetch") return;
    port.onmessage = ({ data: m }) => { if (m.abort) aborted = true; };
    port.postMessage({ head: { status: 200, type: "text/event-stream" } });
  });
  await vault.ready;
  const controller = new AbortController();
  const response = await vault.fetch(`${VAULT_ROUTER}/chat/completions`, { method: "POST", body: "{}", signal: controller.signal });
  const reading = response.text();
  controller.abort();
  await assert.rejects(reading, (e) => e.name === "AbortError");
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(aborted, true);
  // The runtime also asks the stand-in address for a manifest; the page answers that itself.
  assert.equal((await vault.fetch("https://key-vault.invalid/agent-manifest.json")).status, 404);
  vault.port.close();
});

test("without a vault, the runtime's AI requests get a plain refusal", async () => {
  const vault = new KeyVault({ style: {} }, "http://127.0.0.1:8090", { timeoutMs: 10 });
  assert.equal(await vault.ready, null);
  const response = await vault.fetch(`${VAULT_ROUTER}/chat/completions`, { method: "POST", body: "{}" });
  assert.equal(response.status, 503);
  assert.match((await response.json()).error.message, /key vault could not load/);
  assert.deepEqual(await vault.ask("models"), { ok: false, reason: "unavailable" });
});

test("only requests for the stand-in address are routed to the vault", async () => {
  const calls = [];
  const target = { fetch: async (input) => { calls.push(["page", String(input)]); return new Response("ok"); }, location: { href: "http://127.0.0.1:8080/" } };
  const vault = { fetch: async (url, init) => { calls.push(["vault", url, init?.method]); return new Response("{}"); } };
  const restore = routeVaultFetch(vault, target);
  await target.fetch("https://api.groq.com/openai/v1/models");
  await target.fetch("agent-manifest.json");
  await target.fetch(`${VAULT_ROUTER}/chat/completions`, { method: "POST", body: "{}" });
  await target.fetch(new Request(`${VAULT_ROUTER}/models`));
  assert.deepEqual(calls, [
    ["page", "https://api.groq.com/openai/v1/models"],
    ["page", "agent-manifest.json"],
    ["vault", `${VAULT_ROUTER}/chat/completions`, "POST"],
    ["vault", `${VAULT_ROUTER}/models`, "GET"],
  ]);
  restore();
  await target.fetch(`${VAULT_ROUTER}/models`);
  assert.equal(calls.at(-1)[0], "page");
});

test("both pages allow only their own scripts, and all HTML the site writes goes through one cleaner", async () => {
  const site = await readFile(path.join(ROOT, "site", "index.html"), "utf8");
  const policy = site.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  assert.match(policy, /script-src 'self';/);
  assert.match(policy, /object-src 'none'/);
  assert.match(policy, /form-action 'self'/);
  assert.match(policy, /frame-src https: /, "frames: the key vault, and partners' action bridges");
  assert.match(policy, /require-trusted-types-for 'script'; trusted-types default agent-customs-html/);
  assert.ok(site.indexOf('src="trusted-types.js"') < site.indexOf('type="module"'), "the cleaner loads before any module");
  assert.equal([...site.matchAll(/<script(?![^>]*\bsrc=)[^>]*>/g)].length, 0, "no inline scripts, which the policy would block");
  assert.doesNotMatch(site, /\son[a-z]+="/, "no inline event handlers");
  const vault = await readFile(path.join(ROOT, "vault", "index.html"), "utf8");
  const vaultPolicy = vault.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  assert.match(vaultPolicy, /default-src 'none'; script-src 'self'; style-src 'self'/);
  assert.match(vaultPolicy, /base-uri 'none'/);
  assert.match(vaultPolicy, /require-trusted-types-for 'script'; trusted-types 'none'/, "the vault writes no HTML at all");
});

test("model-list errors keep their HTTP code separately from the vault status", async () => {
  const { vault } = connectedVault((data, _port, main) => {
    if (data.type === "models") {
      main.postMessage({ id: data.id, reply: { ok: false, code: 401, status: { state: "empty", active: null, saved: [] } } });
    } else if (data.type === "flush") {
      main.postMessage({ id: data.id, reply: { ok: true, status: { state: "empty", active: null, saved: [], selection: { provider: "Otari", draft: true } } } });
    }
  });
  await vault.ready;
  const flushed = await vault.ask("flush");
  assert.equal(flushed.ok, true);
  assert.equal(flushed.status.selection.provider, "Otari");
  const models = await vault.ask("models");
  assert.equal(models.ok, false);
  assert.equal(models.code, 401);
  assert.equal(models.status.state, "empty");
  vault.port.close();
});
