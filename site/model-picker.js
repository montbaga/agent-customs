// model-picker.js: the officer's model picker, in plain steps.
//
//   1. Choose a model: Claude, GPT, Gemini, an open model, or any model through OpenRouter,
//      then the exact model from its list.
//   2. Open that provider's key page and create a key.
//   3. Paste the key into the key vault's box and press Save and start.
//
// The key goes into the key vault (vault-bridge.js), never into this page. The vault says
// which providers hold a key and whether it is locked, and lists the models a key can use. The
// picker saves the provider's own listed name (Google lists "models/gemini-2.5-pro"), and Save
// waits for that list. Save and start keeps the key in the vault, saves the provider and model
// here (neither is secret), and reloads.
import { CUSTOM_SERVICE } from "./vault-bridge.js";

// Suggested models per provider, best known first. Ids are each provider's own. The
// OpenRouter ids come from openrouter.ai/api/v1/models (November 2026), and each can call
// tools, which the officer needs. A pasted key replaces a provider's suggestions with the
// models that key can use.
const CLAUDE = [
  { id: "claude-sonnet-5-5", name: "Claude Sonnet 5.5" },
  { id: "claude-opus-5-5", name: "Claude Opus 5.5" },
  { id: "claude-haiku-5-5", name: "Claude Haiku 5.5" },
  { id: "claude-fable-5-2", name: "Claude Fable 5.2" },
];
const GPT = [
  { id: "gpt-5.5", name: "GPT-5.5" },
  { id: "gpt-6.1-sol", name: "GPT-6.1 Sol" },
  { id: "gpt-6.1-terra", name: "GPT-6.1 Terra" },
];
const GEMINI = [
  { id: "gemini-3.8-flash", name: "Gemini 3.8 Flash" },
  { id: "gemini-4-argon", name: "Gemini 4 Argon (paid tier)" },
  { id: "gemini-4-carbon", name: "Gemini 4 Carbon" },
  { id: "gemini-4-hydrogen", name: "Gemini 4 Hydrogen" },
];
const GROQ = [
  // An open model that OpenAI released for anyone to run; Groq runs it, and the key goes only to Groq.
  { id: "openai/gpt-oss-120b", name: "GPT-OSS 120B, an open model" },
];
export const OPENROUTER_MODELS = [
  { id: "google/gemini-3.8-flash", name: "Gemini 3.8 Flash" },
  { id: "google/gemini-4-argon", name: "Gemini 4 Argon" },
  { id: "google/gemini-4-carbon", name: "Gemini 4 Carbon" },
  { id: "anthropic/claude-sonnet-5.5", name: "Claude Sonnet 5.5" },
  { id: "anthropic/claude-opus-5.5", name: "Claude Opus 5.5" },
  { id: "openai/gpt-6.1-sol", name: "GPT-6.1 Sol" },
  { id: "openai/gpt-5.5", name: "GPT-5.5" },
  { id: "deepseek/deepseek-v4.1-flash", name: "DeepSeek V4.1 Flash" },
  { id: "meta-llama/llama-4-maverick", name: "Llama 4 Maverick" },
  { id: "mistralai/mistral-large-4-0", name: "Mistral Large 4" },
  { id: "x-ai/grok-4.7", name: "Grok 4.7" },
  { id: "qwen/qwen3.8-flash", name: "Qwen3.8 Flash" },
  { id: "moonshotai/kimi-k3", name: "Kimi K3" },
];

/**
 * The choices, one per card. `provider` names an entry of the runtime's provider list
 * (runtime/ui.js API_KEY_PROVIDERS, plus providers.js), which holds its key page.
 * `live: false` keeps the curated list instead of the provider's full catalogue. `custom`
 * marks the last card, where the visitor types any other service's address into the vault.
 * `safety` and `limitUrl` say how to keep a lost key from costing much.
 */
export const MODEL_CHOICES = [
  { id: "claude", title: "Claude", by: "Anthropic", provider: "Anthropic", cost: "Paid", models: CLAUDE,
    safety: "Safest: give your Anthropic account a monthly spending limit.", limitUrl: "https://console.anthropic.com/settings/limits" },
  { id: "gpt", title: "GPT", by: "OpenAI", provider: "OpenAI", cost: "Paid", models: GPT,
    safety: "Safest: give your OpenAI project a monthly budget.", limitUrl: "https://platform.openai.com/settings/organization/limits" },
  { id: "gemini", title: "Gemini", by: "Google", provider: "Google AI Studio", cost: "Free tier", models: GEMINI,
    safety: "Safest: a free-tier key, with billing off, cannot run up a bill." },
  { id: "open", title: "Open model", by: "Groq", provider: "Groq", cost: "Free tier", models: GROQ,
    safety: "Safest: Groq's free tier needs no card, so its key cannot run up a bill." },
  { id: "any", title: "Any model", by: "OpenRouter", provider: "OpenRouter", cost: "One key for all", models: OPENROUTER_MODELS, live: false,
    safety: "Safest: give the key a credit limit when you create it." },
  { id: "other", title: "Other", by: "Any AI service", provider: "", cost: "For developers", models: [], custom: true,
    safety: "Safest: if the service bills by use, give the key a spending limit there." },
];
const OTHER = MODEL_CHOICES.find((c) => c.custom);

// Catalogue entries that cannot chat: embeddings, images, video, speech, live audio, music.
const NOT_CHAT = /embed|imagen|image|banana|veo|tts|aqa|whisper|dall-e|moderation|transcribe|realtime|audio|live|robotics|computer-use|lyria/i;

/**
 * The choice for a provider name.
 *
 * :param name: A provider name, like "Anthropic".
 * :return: The choice, or null.
 */
export function choiceForProvider(name) {
  return MODEL_CHOICES.find((c) => c.provider === name) || null;
}

/**
 * The choice whose provider serves this address.
 *
 * :param router: A provider address, like https://api.anthropic.com/v1.
 * :param providers: The runtime's provider list.
 * :return: The choice, or null.
 */
export function choiceForRouter(router, providers) {
  const clean = String(router || "").trim().replace(/\/+$/, "");
  const provider = providers.find((p) => p.router.replace(/\/+$/, "") === clean);
  return provider ? choiceForProvider(provider.name) : null;
}

// Google lists its models as "models/<id>"; the rest of a name is what people know.
const bare = (id) => String(id || "").trim().replace(/^models\//, "");

/**
 * A readable name for a model id nobody listed: "gemini-2.5-pro" reads "Gemini 2.5 Pro".
 *
 * :param id: A model id.
 * :return: The readable name.
 */
export function prettyModelName(id) {
  return bare(id).split("/").pop().split("-").filter(Boolean).map((part) => {
    if (/^\d+(\.\d+)?b$/i.test(part) || /^(it|gpt|oss)$/i.test(part)) return part.toUpperCase();
    return /^\d/.test(part) ? part : part[0].toUpperCase() + part.slice(1);
  }).join(" ");
}

/**
 * A readable name for a model id.
 *
 * :param id: A model id, like anthropic/claude-sonnet-5.5 or models/gemini-4-argon.
 * :return: Its known name, or a readable form of the id.
 */
export function modelLabel(id) {
  if (!String(id || "").trim()) return "";
  for (const choice of MODEL_CHOICES) {
    const known = choice.models.find((m) => m.id === id || m.id === bare(id));
    if (known) return known.name;
  }
  return prettyModelName(id);
}

/**
 * The chat models in a provider's catalogue, without duplicates.
 *
 * :param ids: Model ids as the provider lists them.
 * :return: The ids that look like chat models.
 */
export function chatModels(ids) {
  return [...new Set((ids || []).map((id) => String(id || "").trim()).filter((id) => id && !NOT_CHAT.test(id)))];
}

/**
 * The provider's own id for a model name, from its catalogue: exact, or the same name
 * without Google's "models/" prefix.
 *
 * :param name: A model name, like gemini-2.5-pro.
 * :param live: The catalogue's ids.
 * :return: The listed id, or null.
 */
export function listedId(name, live) {
  if (!name || !live?.length) return null;
  return live.find((id) => id === name) || live.find((id) => bare(id) === bare(name)) || null;
}

// Newest first: the main families (Gemini, Claude, GPT), then by version number.
const family = (id) => (/^(gemini|claude|gpt|o\d)/.test(bare(id).split("/").pop()) ? 0 : 1);
const version = (id) => {
  const m = bare(id).match(/(\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : 0;
};

/**
 * The list to offer: the suggestions the key can use first (under the provider's own ids),
 * then the rest of the key's chat models, newest first. Without a catalogue, the suggestions.
 *
 * :param suggested: [{id, name}] for the provider.
 * :param live: The key's chat model ids, or null.
 * :return: [{id, name}].
 */
export function mergeModels(suggested, live) {
  if (!live?.length) return suggested;
  const used = new Set();
  const first = [];
  for (const s of suggested) {
    const match = listedId(s.id, live);
    if (match && !used.has(match)) { first.push({ id: match, name: s.name }); used.add(match); }
  }
  const rest = live.filter((id) => !used.has(id))
    .sort((a, b) => family(a) - family(b) || version(b) - version(a) || bare(a).localeCompare(bare(b)))
    .map((id) => ({ id, name: modelLabel(id) }));
  return [...first, ...rest];
}

/**
 * Plain words for a provider's refusal. The runtime reports one as
 * "LLM HTTP <status>: <the provider's reply>", which says little to most people. The key
 * vault's own refusals are plain already.
 *
 * :param text: The runtime's error text.
 * :param provider: The provider's name, like "Google AI Studio".
 * :param model: The model's readable name.
 * :return: {status, advice, detail}, or null when the text is not a provider's refusal.
 */
export function explainProviderError(text, provider = "The AI provider", model = "this model") {
  const found = String(text || "").match(/LLM HTTP (\d{3}):?\s*([\s\S]*)$/);
  if (!found) return null;
  const status = Number(found[1]);
  const raw = found[2].trim();
  const quoted = raw.match(/"message"\s*:\s*"((?:[^"\\]|\\.)*)"/)?.[1];
  const detail = (quoted ? quoted.replace(/\\n/g, " ").replace(/\\"/g, '"') : raw).slice(0, 300);
  const says = (pattern) => pattern.test(raw);
  let advice;
  if (says(/key vault/i)) {
    advice = detail;
  } else if (status === 401 || says(/API_KEY_INVALID|api key not valid|invalid api key|incorrect api key/i)) {
    advice = `${provider} did not accept the key. Paste it again under AI model settings.`;
  } else if (says(/free[_ ]?tier|limit:\s*0\b|paid tier/i)) {
    // Google answers this way when a model is not part of a free-tier key at all.
    advice = `${model} is not part of this key's free tier. Turn on billing for the key with ${provider}, or choose a model the free tier includes, such as a Flash one.`;
  } else if (status === 429 || says(/RESOURCE_EXHAUSTED|quota|rate limit/i)) {
    advice = `${model} has reached its limit for this key. Free tiers allow only a few requests a minute, and larger models may need billing. Wait a minute, or choose a lighter model, such as a Flash one.`;
  } else if (status === 403 || says(/PERMISSION_DENIED|billing/i)) {
    advice = `This key may not use ${model}; it may need billing turned on with ${provider}. Choose another model, or turn on billing.`;
  } else if (status === 404 || says(/not found|does not exist|not supported|unsupported model|invalid model/i)) {
    advice = `${provider} does not offer ${model} for chat with this key. Choose another model under AI model settings.`;
  } else if (status >= 500) {
    advice = `${provider} had a problem answering. Try again in a minute.`;
  } else {
    advice = `${provider} turned the request down (error ${status}). The technical details say why.`;
  }
  return { status, advice, detail };
}

const SETUP_KEY = "agent-customs-model";
const ROUTER_MODELS_KEY = "agent-customs-router-models";

/** {provider, router, model} saved with Save and start, or null. provider may be "custom". */
export function readModelSetup(storage = globalThis.localStorage) {
  try {
    const setup = JSON.parse(storage?.getItem(SETUP_KEY) || "null");
    if (setup && typeof setup.provider === "string" && typeof setup.model === "string") {
      return { provider: setup.provider, router: String(setup.router || ""), model: setup.model };
    }
  } catch { /* storage blocked or damaged */ }
  return null;
}

export function saveModelSetup({ provider, router, model }, storage = globalThis.localStorage) {
  try { storage?.setItem(SETUP_KEY, JSON.stringify({ provider, router, model })); } catch { /* storage blocked */ }
}

export function clearModelSetup(storage = globalThis.localStorage) {
  try { storage?.removeItem(SETUP_KEY); } catch { /* storage blocked */ }
}

function readRouterModel(router, storage = globalThis.localStorage) {
  if (!router) return "";
  try {
    const map = JSON.parse(storage?.getItem(ROUTER_MODELS_KEY) || "null");
    return typeof map?.[router] === "string" ? map[router] : "";
  } catch {
    return "";
  }
}

function saveRouterModel(router, model, storage = globalThis.localStorage) {
  if (!router || !model) return;
  try {
    const map = JSON.parse(storage?.getItem(ROUTER_MODELS_KEY) || "{}") || {};
    map[router] = model;
    storage?.setItem(ROUTER_MODELS_KEY, JSON.stringify(map));
  } catch { /* storage blocked */ }
}

/**
 * Keys saved in this site's own storage, outside the vault: by an older version of this page,
 * or by the practice site on the same address. {count, clear}; nothing is deleted until clear().
 */
export function legacyKeys(byok) {
  try {
    const real = (key) => !!key && key !== "demo";
    const ids = byok.loadByokStore().profiles.filter((p) => real(p.key)).map((p) => p.id);
    const tab = real(byok.loadTabByokSetup(null).key);
    return {
      count: ids.length + (tab && !ids.length ? 1 : 0),
      clear() {
        for (const id of ids) byok.deleteByokProfile(id);
        if (tab) byok.saveTabByokSetup(null);
      },
    };
  } catch {
    return { count: 0, clear() {} };
  }
}

// After Save and start the page reloads; this note brings the visitor back here.
// view.js reads it too, to reopen the Officer tab before anything else draws.
const RETURN_KEY = "agent-customs-after-save";

const hostOf = (url) => { try { return new URL(url).host; } catch { return ""; } };

/**
 * Wire the picker to its markup.
 *
 * :param root: The #model-picker element.
 * :param options: {engine, providers, app, vault, setup, legacy}. engine is null when the
 *   runtime failed to load; vault.status is null when the vault did not load.
 */
export function mountModelPicker(root, { engine, providers, app, vault, setup = null, legacy = null, onSetup = null }) {
  const $ = (selector) => root.querySelector(selector);
  const cards = $("#mp-cards");
  const current = $("#mp-current");
  const change = $("#mp-change");
  const forgetBtn = $("#mp-forget");
  const body = $("#mp-body");
  const modelSelect = $("#mp-model");
  const modelOther = $("#mp-model-other");
  const keyLink = $("#mp-key-link");
  const keyOther = $("#mp-key-other");
  const start = $("#mp-start");
  const status = $("#mp-status");
  const safety = $("#mp-safety");
  const legacyNote = $("#mp-legacy");

  let currentSetup = setup;
  if (currentSetup?.router && currentSetup?.model) saveRouterModel(currentSetup.router, currentSetup.model);
  const held = () => vault?.status || null;
  const selection = () => held()?.selection || null;
  // A key with no card of its own (Otari's) goes under "Other", by its provider's name.
  let otherProvider = "";
  let wasSelectionLocked = false;
  const vaultName = (choice) => (choice.custom ? otherProvider || CUSTOM_SERVICE : choice.provider);
  const nameOf = (choice) => {
    if (!choice.custom) return choice.provider;
    const sel = selection();
    return sel && (sel.provider !== CUSTOM_SERVICE || sel.router) ? sel.name : "that service";
  };
  const choiceOf = (entry) => (entry && !entry.custom && choiceForProvider(entry.name)) || OTHER;
  let setupChoice = currentSetup ? choiceOf({ name: currentSetup.provider, custom: currentSetup.provider === CUSTOM_SERVICE }) : null;
  let hadSavedKeys = !!(held()?.saved?.length);
  const savedEntryForChoice = (choice) => {
    const saved = held()?.saved || [];
    const active = held()?.active;
    if (active && choiceOf(active).id === choice.id) return active;
    return saved.find((s) => choiceOf(s).id === choice.id) || null;
  };
  const fallbackModelFor = (entry) => {
    if (!entry) return "";
    const remembered = readRouterModel(entry.router);
    if (remembered) return remembered;
    const known = providers.find((p) => p.router === entry.router);
    if (known?.model) return known.model;
    return choiceOf(entry)?.models?.[0]?.id || "";
  };
  const savedModelFor = (choice) => {
    if (setupChoice?.id === choice.id && (!choice.custom || (otherProvider || CUSTOM_SERVICE) === currentSetup.provider)) {
      return currentSetup.model;
    }
    return fallbackModelFor(savedEntryForChoice(choice));
  };
  const savedOtherProvider = (preferred = "") => {
    const saved = held()?.saved || [];
    if (preferred) return saved.some((s) => s.name === preferred) ? preferred : "";
    const active = held()?.active;
    const underOther = (entry) => entry && choiceOf(entry).id === OTHER.id;
    const match = underOther(active) ? active : saved.find(underOther);
    return match && !match.custom ? match.name : "";
  };

  // Cards: native radio buttons, so arrow keys and screen readers work as usual.
  for (const choice of MODEL_CHOICES) {
    const label = document.createElement("label");
    label.className = "mp-card";
    label.innerHTML = `<input type="radio" name="mp-model" value="${choice.id}">`
      + `<span class="mp-title">${choice.title}</span><span class="mp-by">${choice.by}</span><span class="mp-cost">${choice.cost}</span>`
      + `<span class="mp-saved" hidden>In use</span>`;
    cards.append(label);
  }
  const refreshCards = () => {
    const statusNow = held();
    const active = statusNow?.active;
    const saved = statusNow?.saved || [];
    for (const choice of MODEL_CHOICES) {
      const tag = root.querySelector(`input[name="mp-model"][value="${choice.id}"]`)?.closest(".mp-card")?.querySelector(".mp-saved");
      if (!tag) continue;
      const entry = saved.find((s) => choiceOf(s).id === choice.id);
      if (active && choiceOf(active).id === choice.id) {
        tag.textContent = active.locked || statusNow.state === "locked" ? "Locked" : "In use";
        tag.hidden = false;
        continue;
      }
      tag.textContent = entry?.locked ? "Locked" : "Saved";
      tag.hidden = !entry;
    }
  };

  const say = (text, tone = "") => {
    status.textContent = text;
    status.dataset.tone = tone;
  };
  const selected = () => MODEL_CHOICES.find((c) => c.id === root.querySelector('input[name="mp-model"]:checked')?.value) || choiceForProvider("Google AI Studio");
  const chosenModel = () => modelSelect.value || modelOther.value.trim();

  // The model list: options, then "Other" for any name. Keeps the wanted model when listed.
  const renderModels = (models, want) => {
    modelSelect.replaceChildren();
    for (const m of models) modelSelect.append(new Option(m.name, m.id));
    modelSelect.append(new Option(models.length ? "Other: type a model name" : "Paste your AI model key below to load models, or type a model name", ""));
    const match = models.find((m) => m.id === want || bare(m.id) === bare(want));
    modelSelect.value = match ? match.id : (models[0]?.id || "");
    modelOther.hidden = !!modelSelect.value;
    return !!match;
  };

  // {models}, {rejected}, {unreachable} or {reason}.
  const modelsFor = async (choice) => {
    if (choice.live === false || !vault) return { models: null };
    const result = await vault.ask("models");
    if (result?.ok) return { models: chatModels(result.ids) };
    const code = result?.code ?? (typeof result?.status === "number" ? result.status : undefined);
    if (result?.rejected || code === 401 || code === 403) return { rejected: true };
    if (code === 0) return { models: null, unreachable: true };
    return { models: null, reason: result?.reason || "", provider: result?.provider || "", status: code || 0 };
  };
  const rejectedNote = (choice) => `${nameOf(choice)} did not accept this key. Check that you copied all of it.`;
  const mismatchNote = (providerName) => {
    if (!providerName) return `That key does not match ${nameOf(selected())}.`;
    const a = (n) => (/^[aeiou]/i.test(n) ? "an" : "a");
    if (providerName.startsWith("Otari")) {
      return `That key does not belong to ${nameOf(selected())}. Select the Other card to use a third-party key.`;
    }
    const target = choiceForProvider(providerName);
    if (selected().custom) {
      return target
        ? `That is ${a(providerName)} ${providerName} key. Select the ${target.title} card — Other is only for keys not from the cards above.`
        : `That key belongs to ${providerName}.`;
    }
    return target
      ? `That is ${a(providerName)} ${providerName} key, not ${nameOf(selected())}. Select the ${target.title} card to use it.`
      : `That key belongs to ${providerName}, not ${nameOf(selected())}.`;
  };
  const unreachableNote = (choice) => choice.custom && !otherProvider
    ? `Could not reach ${nameOf(choice)} at that address. Check the service address (for example https://api.example.com/v1) and that it allows browser requests.`
    : `Could not reach ${nameOf(choice)}. Check the service address or your connection, then try again.`;

  const saveActionWords = () => (change.hidden ? "Save and start" : "Keep this model or Save and start");
  // Show the key's models in the list, keeping the chosen one when the key can use it.
  let request = 0;
  const listForKey = async (choice) => {
    const sel = selection();
    const savedEntry = savedEntryForChoice(choice);
    const inactiveSaved = !!(sel?.saved && !sel.locked && !sel.draft && held()?.active?.router !== sel.router);
    if (choice.live === false || !sel || !(sel.draft || (sel.saved && !sel.locked))) {
      if (choice.live === false && sel?.draft) {
        say(`Your ${nameOf(choice)} key is ready in the vault. Pick a model above, then press Save and start.`);
      } else if (inactiveSaved) {
        const modelText = chosenModel() ? ` (${modelLabel(chosenModel())})` : "";
        say(`Saved ${nameOf(choice)} key${modelText}. Press ${saveActionWords()} to use it.`);
      } else if (savedEntry && sel?.locked && !sel.draft) {
        const modelText = chosenModel() ? ` (${modelLabel(chosenModel())})` : "";
        say(`Locked ${nameOf(choice)} key${modelText}. Unlock below to use it.`);
      }
      return;
    }
    const mine = ++request;
    const wanted = chosenModel();
    say(`Asking ${nameOf(choice)} which models your key can use…`);
    const result = await modelsFor(choice);
    if (mine !== request || selected().id !== choice.id) return;
    if (result.reason === "mismatch") { say(mismatchNote(result.provider), "warn"); return; }
    if (result.rejected) { say(rejectedNote(choice), "warn"); return; }
    if (result.unreachable) { say(unreachableNote(choice), "warn"); return; }
    if (!result.models?.length) {
      say(inactiveSaved && wanted ? `Saved ${nameOf(choice)} key (${modelLabel(wanted)}). Press ${saveActionWords()} to use it.` : "");
      return;
    }
    const kept = renderModels(mergeModels(choice.models, result.models), wanted);
    const count = `${result.models.length} model${result.models.length === 1 ? "" : "s"}`;
    say(kept || !wanted
      ? `Your key can use ${count}. Pick one, then press ${saveActionWords()}.`
      : `Your key cannot use ${modelLabel(wanted)}. It can use the ${count} in the list; ${modelLabel(chosenModel())} is selected.`);
  };

  const showSafety = (choice) => {
    if (!safety) return;
    const parts = [choice.safety];
    if (choice.limitUrl) {
      const link = document.createElement("a");
      link.href = choice.limitUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Set a limit";
      parts.push(" ", link);
    }
    safety.replaceChildren(...parts);
  };

  const syncKeyLink = (providerName) => {
    const known = providers.find((p) => p.name === providerName);
    keyLink.hidden = !known?.keyUrl;
    if (keyOther) keyOther.hidden = !!known?.keyUrl;
    keyLink.href = known?.keyUrl || "#";
    keyLink.querySelector("[data-mp-provider]").textContent = providerName;
  };
  const renderSavedModels = (choice, want = savedModelFor(choice)) => {
    const inUse = want && !listedId(want, choice.models.map((m) => m.id)) ? [{ id: want, name: modelLabel(want) }] : [];
    renderModels([...inUse, ...choice.models], want);
  };

  const show = (choice, { fromKey = false, note = "", model = "", provider = "" } = {}) => {
    otherProvider = provider || (fromKey ? otherProvider : "");
    const radio = root.querySelector(`input[name="mp-model"][value="${choice.id}"]`);
    if (radio) radio.checked = true;
    syncKeyLink(choice.provider || otherProvider);
    showSafety(choice);
    modelOther.value = "";
    // The model saved with this provider leads the list, even when it is not a suggestion.
    renderSavedModels(choice, model || savedModelFor(choice));
    say(note);
    // A key typed for another provider is cleared, unless that key chose this card.
    const asked = vault ? vault.ask("select", { provider: vaultName(choice), keepDraft: fromKey }) : Promise.resolve();
    const seq = request;
    // Ask the provider only while the steps are open, never on a plain page load.
    asked.then(() => {
      wasSelectionLocked = !!selection()?.locked;
      refreshCards();
      syncActions();
      if (seq === request && !body.hidden) listForKey(choice);
    });
  };

  cards.addEventListener("change", () => {
    const choice = selected();
    show(choice, choice.custom ? { provider: savedOtherProvider() } : {});
  });
  modelSelect.addEventListener("change", () => {
    modelOther.hidden = !!modelSelect.value;
    if (!modelSelect.value) modelOther.focus();
    syncActions();
  });

  // What the officer uses now, and whether the steps need to be open.
  const refreshCurrent = () => {
    current.dataset.tone = "";
    if (!engine) {
      current.textContent = "The assistant could not load. Report, Compare and Verify still work.";
      return "closed";
    }
    const s = held();
    if (!s) {
      current.textContent = "The key vault could not load, so no AI model can be set. Report, Compare and Verify still work.";
      return "closed";
    }
    const active = s.active;
    const model = modelLabel(currentSetup?.model) || "the site's model";
    const sel = selection();
    const selLabel = nameOf(selected());
    const needPhrase = selected().custom && !sel?.router && selLabel === "that service"
      ? "Other needs a service address and key below."
      : `${selected().title} (${selLabel}) needs a key below.`;
    if (currentSetup && active && active.router === currentSetup.router) {
      const via = active.custom ? hostOf(active.router) : active.name;
      const mode = s.state === "locked" ? "open" : "in-use";
      if (body.hidden || sel?.router === active.router) {
        if (s.state === "locked") {
          current.dataset.tone = "warn";
          current.textContent = `Chosen: ${model}, through ${via}. Its saved key is locked; unlock it below.`;
          return "open";
        }
        current.textContent = `In use: ${model}, through ${via}. Your key is in the key vault.`;
        return "in-use";
      }
      const nowNote = `Current model: ${model}, through ${via}${s.state === "locked" ? " (locked)" : ""}.`;
      if (sel?.locked) {
        current.dataset.tone = "warn";
        current.textContent = `Your saved ${selLabel} key is locked; unlock it below. (${nowNote})`;
      } else if (sel?.saved && !sel.draft) {
        const action = mode === "in-use" ? "Keep this model or Save and start" : "Save and start";
        current.textContent = `Your saved ${selLabel} key is unlocked; press ${action} below to use it. (${nowNote})`;
      } else {
        current.textContent = `${needPhrase} (${nowNote})`;
      }
      return mode;
    }
    if (currentSetup) {
      const via = currentSetup.provider === CUSTOM_SERVICE ? hostOf(currentSetup.router) : currentSetup.provider;
      current.textContent = `The key vault has no ${via} key in this tab. Paste it below to use ${model} again.`;
      return "open";
    }
    if (!body.hidden && sel?.locked) {
      current.dataset.tone = "warn";
      current.textContent = `Your saved ${selLabel} key is locked; unlock it below.`;
    } else if (!body.hidden && sel?.saved && !sel.draft) {
      current.textContent = `Your saved ${selLabel} key is unlocked; press Save and start below to use it.`;
    } else {
      current.textContent = "No model chosen yet. Report, Compare and Verify work without one.";
    }
    return "open";
  };
  let forgetArmed = 0;
  const activeVia = (active) => (active ? (active.custom ? hostOf(active.router) : active.name) : "");
  const headerForgetLabel = (active) => (active ? `Forget ${activeVia(active)} key` : "Forget key");
  const syncForget = () => {
    if (!forgetBtn) return;
    const active = held()?.active;
    const showHeader = !!active && body.hidden;
    forgetBtn.hidden = !showHeader;
    if (!showHeader && forgetArmed) {
      clearTimeout(forgetArmed);
      forgetArmed = 0;
    }
    if (!forgetArmed) forgetBtn.textContent = headerForgetLabel(active);
  };
  const syncActions = () => {
    const sel = selection();
    const readySaved = !!(sel?.saved && !sel.locked && !sel.draft);
    change.setAttribute("aria-expanded", String(!body.hidden));
    change.textContent = body.hidden ? "Change model" : (readySaved ? "Keep this model" : "Cancel");
    syncForget();
  };
  const layout = (mode) => {
    change.hidden = mode !== "in-use";
    if (mode === "closed") body.hidden = true;
    else if (mode === "open" && body.hidden) {
      body.hidden = false;
      listForKey(selected());
    }
    syncActions();
  };

  const applyRuntimeModel = (model) => {
    if (engine) engine.modelOverride = model;
    const input = app?.querySelector("#ns-model");
    if (input) input.value = model;
  };
  const reconcileSetup = () => {
    const saved = held()?.saved || [];
    if (saved.length) hadSavedKeys = true;
    const active = held()?.active || null;
    if (!currentSetup || saved.some((s) => s.router === currentSetup.router)) return null;
    if (hadSavedKeys || !active) {
      clearModelSetup();
      currentSetup = null;
      setupChoice = null;
      if (!saved.length && !active) hadSavedKeys = false;
      applyRuntimeModel("");
      onSetup?.(null);
      return { kind: "cleared" };
    }
    return null;
  };

  vault?.on((event, data) => {
    if (event === "status") {
      reconcileSetup();
      let otherRestored = false;
      const selProvider = data?.selection?.provider || "";
      if (selected().custom && otherProvider && selProvider === CUSTOM_SERVICE) {
        otherProvider = "";
        syncKeyLink("");
        renderModels([], "");
        say("");
      } else if (selected().custom && selProvider && selProvider !== CUSTOM_SERVICE && otherProvider !== selProvider) {
        otherProvider = selProvider;
        syncKeyLink(selProvider);
        renderSavedModels(selected());
        otherRestored = true;
      }
      const unlockedNow = wasSelectionLocked && !selection()?.locked && !!selection()?.saved;
      wasSelectionLocked = !!selection()?.locked;
      refreshCards();
      layout(refreshCurrent());
      if ((unlockedNow || otherRestored) && !body.hidden) listForKey(selected());
    } else if (event === "detected") {
      const match = choiceForProvider(data.provider);
      if (!match && selected().custom) {
        const known = providers.find((p) => p.name === data.provider);
        const savedModel = readRouterModel(known?.router);
        show(OTHER, { fromKey: true, provider: data.provider, model: savedModel || known?.model || "",
          note: `Key detected for ${data.provider}; address filled automatically.` });
      }
    } else if (event === "mismatch") {
      say(mismatchNote(data.provider), "warn");
    } else if (event === "draft") {
      listForKey(selected());
    } else if (event === "draft-cleared") {
      renderSavedModels(selected());
      say("");
      const sel = selection();
      if (!body.hidden && sel?.saved && !sel.draft) listForKey(selected());
    } else if (event === "submit") {
      start.click();
    }
  });

  // A provider's refusal in the chat: plain advice first, the provider's own words folded away.
  const msgs = app?.querySelector("#ns-msgs");
  if (msgs) {
    new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (!(node instanceof HTMLElement) || !node.classList.contains("ns-msg") || node.dataset.explained) continue;
          const via = held()?.active?.name;
          const info = explainProviderError(node.textContent, via, modelLabel(currentSetup?.model) || undefined);
          if (!info) continue;
          node.dataset.explained = "true";
          const advice = document.createElement("p");
          advice.textContent = info.advice;
          const more = document.createElement("details");
          const label = document.createElement("summary");
          label.textContent = "Technical details";
          const code = document.createElement("code");
          code.textContent = `Error ${info.status}: ${info.detail}`;
          more.append(label, code);
          node.replaceChildren(advice, more);
          current.dataset.tone = "warn";
          current.textContent = `In use: ${modelLabel(currentSetup?.model) || "the site's model"}. Its last request failed; see the chat, or choose another model.`;
        }
      }
    }).observe(msgs, { childList: true });
  }

  // The runtime's developer view (its execution trace), switched from below the chat.
  const tech = document.querySelector("#tech-toggle");
  const devToggle = app?.querySelector("#ns-devtoggle");
  if (tech && devToggle) {
    const sync = () => {
      const on = devToggle.classList.contains("on");
      tech.textContent = on ? "Hide technical details" : "Show technical details";
      tech.setAttribute("aria-pressed", String(on));
    };
    sync();
    tech.addEventListener("click", () => { devToggle.click(); sync(); });
  } else if (tech) {
    tech.hidden = true;
  }

  // Keys an older version saved outside the vault: say so once, and offer to delete them.
  if (legacyNote && legacy?.count) {
    const text = legacyNote.querySelector("[data-mp-legacy]");
    if (text) text.textContent = `${legacy.count === 1 ? "1 key is" : `${legacy.count} keys are`} still saved the old way, in this site's own storage outside the vault.`;
    legacyNote.hidden = false;
    legacyNote.querySelector("button")?.addEventListener("click", () => {
      legacy.clear();
      legacyNote.hidden = true;
      say("The old copies are deleted. From now on, keys live only in the key vault.");
    });
  }

  const commitProblem = (reason, choice) => ({
    address: "Type the service's address in the vault box first. It starts with https://.",
    locked: `Your saved ${nameOf(choice)} key is locked. Unlock it in the vault box first.`,
    empty: choice.custom ? "Paste your AI model key first." : `Paste your ${nameOf(choice)} key first.`,
  }[reason] || "The key vault did not take the key. Reload the page and try again.");

  const activateSavedChoice = async (choice) => {
    const sel = selection();
    let model = chosenModel();
    if (!sel || !sel.saved || sel.locked || sel.draft) return false;
    if (!model) { say("Choose a model, or type its name.", "warn"); modelOther.hidden = false; modelOther.focus(); return false; }
    if (choice.live !== false) {
      say(`Checking ${modelLabel(model)} with ${nameOf(choice)}…`);
      const result = await modelsFor(choice);
      if (result.reason === "mismatch") { say(mismatchNote(result.provider), "warn"); return false; }
      if (result.rejected) { say(rejectedNote(choice), "warn"); return false; }
      if (result.unreachable) { say(unreachableNote(choice), "warn"); return false; }
      if (result.models?.length) {
        const listed = listedId(model, result.models);
        if (!listed) {
          renderModels(mergeModels(choice.models, result.models), "");
          say(`Your key cannot use ${modelLabel(model)}. Pick one of the ${result.models.length} models in the list, then press Keep this model or Save and start.`, "warn");
          modelSelect.focus();
          return false;
        }
        model = listed;
      }
    }
    const done = await vault.ask("commit");
    if (!done?.ok || !done.status?.active) {
      say(done?.reason === "mismatch" ? mismatchNote(done.provider) : commitProblem(done?.reason, choice), "warn");
      return false;
    }
    request += 1;
    const active = done.status.active;
    currentSetup = { provider: active.custom ? CUSTOM_SERVICE : active.name, router: active.router, model };
    setupChoice = choiceOf(active);
    saveModelSetup(currentSetup);
    saveRouterModel(active.router, model);
    applyRuntimeModel(model);
    onSetup?.(currentSetup);
    const assistantStatus = document.querySelector("#assistant-status");
    if (assistantStatus) assistantStatus.hidden = false;
    say("");
    body.hidden = true;
    refreshCards();
    layout(refreshCurrent());
    return true;
  };

  start.addEventListener("click", async () => {
    // Save speaks for itself: a list still loading must not talk over it.
    request += 1;
    if (!engine) { say("The assistant could not load, so a model cannot be set here. Reload the page to try again.", "warn"); return; }
    if (!selection()) { say("The key vault could not load, so a key cannot be saved. Reload the page to try again.", "warn"); return; }
    start.disabled = true;
    try {
      await vault.ask("flush", { draft: false });
      request += 1;
      const choice = selected();
      const sel = selection();
      if (!sel) { say("The key vault could not load, so a key cannot be saved. Reload the page to try again.", "warn"); return; }
      if (!sel.draft && !sel.saved) {
        say(choice.custom && !otherProvider && !sel.router
          ? "Paste your AI model key first, then type its https:// service address below (unless your key fills it automatically)."
          : commitProblem("empty", choice), "warn");
        vault.focus();
        return;
      }
      if (choice.custom && !otherProvider && !sel.router) { say(commitProblem("address", choice), "warn"); vault.focus(); return; }
      if (!sel.draft && sel.locked) { say(commitProblem("locked", choice), "warn"); vault.focus(); return; }
      let model = chosenModel();
      // Save under the name the provider lists, which is the only name it accepts.
      say(model ? `Checking ${modelLabel(model)} with ${nameOf(choice)}…` : `Asking ${nameOf(choice)} which models your key can use…`);
      const result = await modelsFor(choice);
      if (result.reason === "mismatch") { say(mismatchNote(result.provider), "warn"); return; }
      if (result.rejected) { say(rejectedNote(choice), "warn"); return; }
      if (result.unreachable) { say(unreachableNote(choice), "warn"); if (choice.custom) vault.focus(); return; }
      if (result.models?.length) {
        if (!model) {
          renderModels(mergeModels(choice.models, result.models), "");
          model = chosenModel();
        }
        const listed = listedId(model, result.models);
        if (!listed) {
          renderModels(mergeModels(choice.models, result.models), "");
          say(`Your key cannot use ${modelLabel(model)}. Pick one of the ${result.models.length} models in the list, then press Save and start.`, "warn");
          modelSelect.focus();
          return;
        }
        model = listed;
      }
      if (!model) { say("Choose a model, or type its name.", "warn"); modelOther.hidden = false; modelOther.focus(); return; }
      const done = await vault.ask("commit");
      if (!done?.ok || !done.status?.active) {
        say(done?.reason === "mismatch" ? mismatchNote(done.provider) : commitProblem(done?.reason, choice), "warn");
        if (done?.reason !== "mismatch") vault.focus();
        return;
      }
      const active = done.status.active;
      saveModelSetup({ provider: active.custom ? CUSTOM_SERVICE : active.name, router: active.router, model });
      saveRouterModel(active.router, model);
      // Come back here after the reload, without the browser restoring the old position.
      try {
        sessionStorage.setItem(RETURN_KEY, String(Date.now()));
        history.scrollRestoration = "manual";
      } catch { /* storage blocked */ }
      say(`Saved. Starting ${modelLabel(model)}…`);
      location.reload();
    } finally {
      start.disabled = false;
    }
  });

  forgetBtn?.addEventListener("click", async () => {
    const active = held()?.active;
    if (!active) return;
    if (!forgetArmed) {
      forgetArmed = setTimeout(() => {
        forgetArmed = 0;
        forgetBtn.textContent = headerForgetLabel(held()?.active);
      }, 4000);
      forgetBtn.textContent = `Click again to forget ${activeVia(active)}`;
      return;
    }
    clearTimeout(forgetArmed);
    forgetArmed = 0;
    forgetBtn.textContent = headerForgetLabel(held()?.active);
    forgetBtn.disabled = true;
    try {
      await vault?.ask("forget", { router: active.router });
    } finally {
      forgetBtn.disabled = false;
    }
  });

  change.addEventListener("click", async () => {
    if (body.hidden) {
      body.hidden = false;
      syncActions();
      listForKey(selected());
      return;
    }
    const sel = selection();
    const readySaved = !!(sel?.saved && !sel.locked && !sel.draft);
    if (!readySaved) {
      body.hidden = true;
      if (setupChoice) show(setupChoice, setupChoice.custom ? { provider: savedOtherProvider(currentSetup?.provider) } : {});
      syncActions();
      return;
    }
    const sameRouter = sel.router === currentSetup?.router;
    const sameModel = chosenModel() === currentSetup?.model;
    if (sameRouter && sameModel && held()?.active?.router === currentSetup?.router) {
      body.hidden = true;
      syncActions();
      return;
    }
    change.disabled = true;
    try {
      await activateSavedChoice(selected());
    } finally {
      change.disabled = false;
    }
  });

  const switchedOnLoad = reconcileSetup();
  const mode = refreshCurrent();
  body.hidden = mode !== "open";
  layout(mode);
  refreshCards();
  // A key under "Other" that belongs to a service the vault knows by name (Otari) keeps that name
  // while that key is still saved in the vault.
  const initialOther = setupChoice === OTHER && currentSetup?.provider !== CUSTOM_SERVICE
    ? savedOtherProvider(currentSetup?.provider)
    : "";
  if (app && currentSetup?.model && currentSetup.model !== engine?.modelOverride) applyRuntimeModel(currentSetup.model);
  show(setupChoice || choiceForProvider("Google AI Studio"), {
    provider: initialOther,
    ...(switchedOnLoad?.kind === "switched" ? { model: switchedOnLoad.model, note: `Switched back to ${switchedOnLoad.active.name}.` } : {}),
  });

  // Back from Save and start's reload. view.js reopened the Officer tab before anything drew;
  // the status line above the picker may have changed height since, so settle once more.
  let returning = 0;
  try {
    returning = Number(sessionStorage.getItem(RETURN_KEY) || 0);
    sessionStorage.removeItem(RETURN_KEY);
  } catch { /* storage blocked */ }
  if (returning && Date.now() - returning < 60_000) {
    const tab = document.querySelector('[data-tab="officer"]');
    if (tab && tab.getAttribute("aria-selected") !== "true") tab.click();
    window.scrollTo({ top: root.getBoundingClientRect().top + window.scrollY - 110, behavior: "instant" });
  }
  // Later reloads restore the scroll position as usual.
  try { history.scrollRestoration = "auto"; } catch { /* not supported */ }
}
