// model-picker.js: the officer's model picker, in plain steps.
//
//   1. Choose a model: Claude, GPT, Gemini, an open model, or any model through OpenRouter,
//      then the exact model from its list.
//   2. Open that provider's key page and create a key.
//   3. Paste the key and press Save and start.
//
// Once a key is pasted, the picker asks that provider which models the key can use (the same
// request the runtime makes before saving) and lists them under the provider's own names.
// Google, for one, lists "models/gemini-2.5-pro" where people write "gemini-2.5-pro", and the
// runtime accepts only a name from that list, so the picker always saves the listed name.
// Save waits for the list, so a quick click cannot send a name the provider does not know.
//
// Switching to another provider clears the key field, since a key works only with its own
// provider. Keeping the provider and changing only the model reuses the key already saved in
// this browser.
//
// The picker fills in the runtime's own settings form and presses its Save and start, so the
// runtime still checks the model with the provider, saves the setup in this browser and
// reloads. The runtime's full form stays available under "Another provider (advanced)".

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
 * (runtime/ui.js API_KEY_PROVIDERS, plus providers.js), which holds its address and key page.
 * `live: false` keeps the curated list instead of the provider's full catalogue.
 */
export const MODEL_CHOICES = [
  { id: "claude", title: "Claude", by: "Anthropic", provider: "Anthropic", cost: "Paid", models: CLAUDE },
  { id: "gpt", title: "GPT", by: "OpenAI", provider: "OpenAI", cost: "Paid", models: GPT },
  { id: "gemini", title: "Gemini", by: "Google", provider: "Google AI Studio", cost: "Free tier", models: GEMINI },
  { id: "open", title: "Open model", by: "Groq", provider: "Groq", cost: "Free tier", models: GROQ },
  { id: "any", title: "Any model", by: "OpenRouter", provider: "OpenRouter", cost: "One key for all", models: OPENROUTER_MODELS, live: false },
];

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
 * Ask a provider which models a key can use: the request the runtime makes before saving.
 *
 * :param router: The provider's address.
 * :param key: The API key.
 * :return: {ok: true, ids} or {ok: false, status}; status 0 when the browser could not ask.
 */
export async function listModels(router, key, fetchImpl = globalThis.fetch) {
  try {
    const response = await fetchImpl(`${String(router).replace(/\/$/, "")}/models`, {
      cache: "no-store",
      headers: { Authorization: `Bearer ${key}` },
    });
    if (!response.ok) return { ok: false, status: response.status };
    const body = await response.json();
    return { ok: true, ids: (Array.isArray(body?.data) ? body.data : []).map((m) => String(m?.id || "").trim()).filter(Boolean) };
  } catch {
    return { ok: false, status: 0 };
  }
}

/**
 * Plain words for a provider's refusal. The runtime reports one as
 * "LLM HTTP <status>: <the provider's reply>", which says little to most people.
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
  if (status === 401 || says(/API_KEY_INVALID|api key not valid|invalid api key|incorrect api key/i)) {
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

// After Save and start the runtime reloads the page; this note brings the visitor back here.
// view.js reads it too, to reopen the Officer tab before anything else draws.
const RETURN_KEY = "agent-customs-after-save";

/**
 * The newest setup saved in this browser for a provider: one that goes to the provider's
 * address, or holds a key that is recognisably the provider's.
 *
 * :param profiles: The runtime's saved setups ({id, name, router, model, key, updatedAt}).
 * :param provider: The provider ({name, router}).
 * :param providerForApiKey: The runtime's key recogniser.
 * :return: The setup, or null.
 */
export function savedSetupFor(profiles, provider, providerForApiKey) {
  if (!provider) return null;
  const clean = (url) => String(url || "").trim().replace(/\/+$/, "");
  return (profiles || [])
    .filter((p) => p?.key && (clean(p.router) === clean(provider.router) || providerForApiKey?.(p.key)?.name === provider.name))
    .sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")))[0] || null;
}

/**
 * Fill in the runtime's settings form and press its Save and start.
 *
 * A saved setup is updated in place, not copied: it is selected first (the runtime fills the
 * form from it) and stays selected after a new key, which would otherwise start a new one. A
 * new key goes in next: the runtime recognises the provider and fills in its defaults, which
 * the chosen address and model then replace. Without a key, the one the form holds stays.
 *
 * :param app: The #agent-app element.
 * :param setup: {key, router, model, name, profileId}; key may be "" to keep the form's key,
 *   and profileId names the saved setup to update.
 * :return: True when the form was found, held a key, and was submitted.
 */
export function applyToRuntime(app, { key, router, model, name, profileId = "" }) {
  const field = (selector) => app?.querySelector(selector);
  const keyEl = field("#ns-key");
  const apply = field("#ns-apply");
  if (!keyEl || !apply) return false;
  const set = (el, value) => {
    if (!el) return;
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const profileEl = field("#ns-profile");
  const known = !!profileId && !!profileEl && [...(profileEl.options || [])].some((o) => o.value === profileId);
  if (known) {
    profileEl.value = profileId;
    profileEl.dispatchEvent(new Event("change", { bubbles: true }));
  }
  if (key) set(keyEl, key);
  if (!String(keyEl.value || "").trim()) return false;
  set(field("#ns-router"), router);
  set(field("#ns-model"), model);
  const nameEl = field("#ns-profile-name");
  if (nameEl) nameEl.value = name;
  if (known) profileEl.value = profileId;
  apply.click();
  return true;
}

/**
 * Wire the picker to its markup.
 *
 * :param root: The #model-picker element.
 * :param options: {engine, providers, providerForApiKey, app, byok}. engine may be null when
 *   the runtime failed to load. byok is the runtime's byok.js: the setups saved in this
 *   browser, so a provider whose key was saved before needs no key pasted again.
 */
export function mountModelPicker(root, { engine, providers, providerForApiKey, app, byok }) {
  const $ = (selector) => root.querySelector(selector);
  const cards = $("#mp-cards");
  const current = $("#mp-current");
  const change = $("#mp-change");
  const body = $("#mp-body");
  const modelSelect = $("#mp-model");
  const modelOther = $("#mp-model-other");
  const keyLink = $("#mp-key-link");
  const keyInput = $("#mp-key");
  const start = $("#mp-start");
  const status = $("#mp-status");
  const advanced = $("#mp-advanced");
  const forget = $("#mp-forget");
  const providerOf = (choice) => providers.find((p) => p.name === choice.provider);

  // What is in use now: the active setup's provider, key and model.
  const hasKey = !!engine && !engine.mockLLM && !!engine.byokKey && engine.byokKey !== "demo";
  const router = engine?.userRouter?.baseUrl || engine?.routerOverride || "";
  const saved = hasKey ? choiceForRouter(router, providers) : null;
  const savedKey = hasKey ? engine.byokKey : "";
  const savedModel = hasKey ? (engine.modelOverride || "") : "";
  const usesActive = (choice) => !!saved && saved.provider === choice.provider;

  // Every setup saved in this browser, so each provider's key is asked for once: the newest
  // saved setup for a provider brings its key and its model back.
  const savedSetups = () => {
    try { return byok?.loadByokStore?.().profiles || []; } catch { return []; }
  };
  const savedSetup = (choice) => savedSetupFor(savedSetups(), providerOf(choice), providerForApiKey);
  const savedKeyFor = (choice) => savedSetup(choice)?.key || (usesActive(choice) ? savedKey : "");
  const usesSavedKey = (choice) => !!savedKeyFor(choice);
  const savedModelFor = (choice) => (usesActive(choice) ? savedModel : (savedSetup(choice)?.model || ""));
  const keyFor = (choice) => keyInput.value.trim() || savedKeyFor(choice);

  // Cards: native radio buttons, so arrow keys and screen readers work as usual. A card whose
  // provider has a saved key says so.
  for (const choice of MODEL_CHOICES) {
    const label = document.createElement("label");
    label.className = "mp-card";
    label.innerHTML = `<input type="radio" name="mp-model" value="${choice.id}">`
      + `<span class="mp-title">${choice.title}</span><span class="mp-by">${choice.by}</span><span class="mp-cost">${choice.cost}</span>`
      + `<span class="mp-saved" hidden>Key saved</span>`;
    cards.append(label);
  }
  const refreshCards = () => {
    for (const choice of MODEL_CHOICES) {
      const tag = root.querySelector(`input[name="mp-model"][value="${choice.id}"]`)?.closest(".mp-card")?.querySelector(".mp-saved");
      if (tag) tag.hidden = !usesSavedKey(choice);
    }
  };
  refreshCards();

  const say = (text, tone = "") => {
    status.textContent = text;
    status.dataset.tone = tone;
  };
  const selected = () => MODEL_CHOICES.find((c) => c.id === root.querySelector('input[name="mp-model"]:checked')?.value) || choiceForProvider("Google AI Studio");
  const chosenModel = () => modelSelect.value || modelOther.value.trim();
  const keyNote = (choice) => (usesSavedKey(choice)
    ? `Your saved ${choice.provider} key will be used. Paste a new key only to replace it.`
    : `Your key stays in this browser and goes only to ${choice.provider}.`);

  // The model list: options, then "Other" for any name. Keeps the wanted model when listed.
  const renderModels = (models, want) => {
    modelSelect.innerHTML = "";
    for (const m of models) modelSelect.append(new Option(m.name, m.id));
    modelSelect.append(new Option("Other: type a model name", ""));
    const match = models.find((m) => m.id === want || bare(m.id) === bare(want));
    modelSelect.value = match ? match.id : (models[0]?.id || "");
    modelOther.hidden = !!modelSelect.value;
    return !!match;
  };

  // The models a key can use, asked once per provider and key: {models} or {rejected}.
  const catalogue = new Map();
  const modelsFor = async (choice, key) => {
    if (choice.live === false || !key) return { models: null };
    const keyProvider = providerForApiKey(key);
    if (keyProvider && keyProvider.name !== choice.provider) return { models: null };
    const tag = `${choice.provider}\n${key}`;
    if (!catalogue.has(tag)) {
      catalogue.set(tag, listModels(providerOf(choice).router, key).then((result) => {
        if (result.ok) return { models: chatModels(result.ids) };
        if (result.status === 401 || result.status === 403) { catalogue.delete(tag); return { rejected: true }; }
        return { models: null };
      }));
    }
    return catalogue.get(tag);
  };
  const rejectedNote = (choice) => `${choice.provider} did not accept this key. Check that you copied all of it.`;

  // Show the key's models in the list, keeping the chosen one when the key can use it.
  let request = 0;
  const listForKey = async (choice) => {
    const key = keyFor(choice);
    if (choice.live === false || !key) return;
    const mine = ++request;
    const wanted = chosenModel();
    say(`Asking ${choice.provider} which models your key can use…`);
    const result = await modelsFor(choice, key);
    if (mine !== request || selected().id !== choice.id) return;
    if (result.rejected) { say(rejectedNote(choice), "warn"); return; }
    if (!result.models?.length) { say(keyNote(choice)); return; }
    const kept = renderModels(mergeModels(choice.models, result.models), wanted);
    say(kept
      ? `Your key can use ${result.models.length} models. Pick one, then press Save and start.`
      : `Your key cannot use ${modelLabel(wanted)}. It can use the ${result.models.length} models in the list; ${modelLabel(chosenModel())} is selected.`);
  };

  let shownProvider = "";
  const show = (choice, { fromKey = false, note = "" } = {}) => {
    // A key works only with its own provider: a new provider starts with an empty key field.
    if (!fromKey && shownProvider && shownProvider !== choice.provider) keyInput.value = "";
    shownProvider = choice.provider;
    const radio = root.querySelector(`input[name="mp-model"][value="${choice.id}"]`);
    if (radio) radio.checked = true;
    const provider = providerOf(choice);
    keyLink.href = provider?.keyUrl || "#";
    keyLink.querySelector("[data-mp-provider]").textContent = choice.provider;
    keyInput.placeholder = usesSavedKey(choice) ? `Saved ${choice.provider} key will be used` : `Paste your ${choice.provider} key`;
    if (forget) {
      forget.hidden = !savedSetup(choice);
      forget.textContent = `Forget the saved ${choice.provider} key`;
    }
    modelOther.value = "";
    // The model saved with this provider leads the list, even when it is not a suggestion.
    const want = savedModelFor(choice);
    const inUse = want && !listedId(want, choice.models.map((m) => m.id)) ? [{ id: want, name: modelLabel(want) }] : [];
    renderModels([...inUse, ...choice.models], want);
    say(note || keyNote(choice));
    // Ask the provider only while the steps are open, never on a plain page load.
    if (!body.hidden) listForKey(choice);
  };

  cards.addEventListener("change", () => show(selected()));
  modelSelect.addEventListener("change", () => {
    modelOther.hidden = !!modelSelect.value;
    if (!modelSelect.value) modelOther.focus();
  });

  // A pasted key that belongs to another provider selects that provider's card; a key for
  // this provider lists the models it can use.
  let typing = 0;
  keyInput.addEventListener("input", () => {
    clearTimeout(typing);
    typing = setTimeout(() => {
      const key = keyInput.value.trim();
      const provider = providerForApiKey(key);
      const match = provider && choiceForProvider(provider.name);
      if (match && match.id !== selected().id) {
        show(match, { fromKey: true, note: `That is ${/^[aeiou]/i.test(provider.name) ? "an" : "a"} ${provider.name} key, so ${match.title} is selected.` });
      } else if (key) {
        listForKey(selected());
      }
    }, 400);
  });

  // The runtime's own hints (a model the provider does not publish, the reload) show here
  // while a setup from this picker is being saved.
  let saving = false;
  const hint = app?.querySelector("#ns-profile-hint");
  if (hint) {
    new MutationObserver(() => {
      if (!saving || !hint.textContent.trim()) return;
      const warn = hint.classList.contains("warn");
      say(hint.textContent.trim(), warn ? "warn" : "");
      // The runtime stopped short of saving, so no reload is coming.
      if (warn) { try { sessionStorage.removeItem(RETURN_KEY); } catch { /* storage blocked */ } }
    }).observe(hint, { childList: true, characterData: true, subtree: true, attributes: true });
  }

  // A provider's refusal in the chat: plain advice first, the provider's own words folded away.
  const msgs = app?.querySelector("#ns-msgs");
  if (msgs) {
    new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (!(node instanceof HTMLElement) || !node.classList.contains("ns-msg") || node.dataset.explained) continue;
          const info = explainProviderError(node.textContent, saved?.provider, modelLabel(savedModel) || undefined);
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
          current.textContent = `In use: ${modelLabel(savedModel) || "the site's model"}. Its last request failed; see the chat, or choose another model.`;
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

  start.addEventListener("click", async () => {
    // Save speaks for itself: a list still loading from typing must not talk over it.
    clearTimeout(typing);
    request += 1;
    const choice = selected();
    const provider = providerOf(choice);
    const setup = savedSetup(choice);
    const key = keyFor(choice);
    if (!engine) { say("The assistant could not load, so a model cannot be set here. Reload the page to try again.", "warn"); return; }
    if (!key) { say(`Paste your ${choice.provider} key first.`, "warn"); keyInput.focus(); return; }
    let model = chosenModel();
    if (!model) { say("Choose a model, or type its name.", "warn"); modelOther.hidden = false; modelOther.focus(); return; }
    start.disabled = true;
    try {
      // Save under the name the provider lists, which is the only name the runtime accepts.
      say(`Checking ${modelLabel(model)} with ${choice.provider}…`);
      const result = await modelsFor(choice, key);
      if (result.rejected) { say(rejectedNote(choice), "warn"); return; }
      if (result.models?.length) {
        const listed = listedId(model, result.models);
        if (!listed) {
          renderModels(mergeModels(choice.models, result.models), "");
          say(`Your key cannot use ${modelLabel(model)}. Pick one of the ${result.models.length} models in the list, then press Save and start.`, "warn");
          modelSelect.focus();
          return;
        }
        model = listed;
      }
      saving = true;
      // Come back here after the reload, without the browser restoring the old position.
      try {
        sessionStorage.setItem(RETURN_KEY, String(Date.now()));
        history.scrollRestoration = "manual";
      } catch { /* storage blocked */ }
      const sent = applyToRuntime(app, { key, profileId: setup?.id || "", router: provider.router, model, name: `${modelLabel(model)} (${choice.provider})` });
      if (!sent) {
        saving = false;
        try { sessionStorage.removeItem(RETURN_KEY); } catch { /* storage blocked */ }
        say("The settings form is not ready yet. Reload the page and try again.", "warn");
      }
    } finally {
      start.disabled = false;
    }
  });

  // Forget a saved key: two clicks, since it cannot be undone. When the officer is using that
  // key right now, the page reloads without it.
  let armed = 0;
  forget?.addEventListener("click", () => {
    const choice = selected();
    if (!armed) {
      forget.textContent = `Click again to forget the saved ${choice.provider} key`;
      armed = setTimeout(() => { armed = 0; forget.textContent = `Forget the saved ${choice.provider} key`; }, 4000);
      return;
    }
    clearTimeout(armed);
    armed = 0;
    const provider = providerOf(choice);
    for (const p of savedSetups()) {
      if (savedSetupFor([p], provider, providerForApiKey)) byok?.deleteByokProfile?.(p.id);
    }
    keyInput.value = "";
    if (usesActive(choice)) {
      byok?.saveTabByokSetup?.(null);
      try {
        sessionStorage.setItem(RETURN_KEY, String(Date.now()));
        history.scrollRestoration = "manual";
      } catch { /* storage blocked */ }
      location.reload();
      return;
    }
    refreshCards();
    show(choice, { note: `The saved ${choice.provider} key is forgotten. This browser no longer holds it.` });
  });

  advanced.addEventListener("click", () => {
    const open = !app.classList.contains("show-advanced");
    app.classList.toggle("show-advanced", open);
    advanced.setAttribute("aria-expanded", String(open));
    if (open) {
      const details = app.querySelector(".ns-settings");
      if (details) details.open = true;
      details?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  });

  change.addEventListener("click", () => {
    body.hidden = !body.hidden;
    change.setAttribute("aria-expanded", String(!body.hidden));
    change.textContent = body.hidden ? "Change model" : "Keep this model";
    if (!body.hidden) listForKey(selected());
  });

  if (hasKey) {
    let host = "";
    try { host = new URL(router).host; } catch { /* no usable address */ }
    current.textContent = `In use: ${modelLabel(savedModel) || "the site's model"}, through ${saved ? saved.provider : (host || "your provider")}.`;
    change.hidden = false;
    body.hidden = true;
  } else {
    current.textContent = engine
      ? "No model chosen yet. The inspection tools above work without one."
      : "The assistant could not load. The inspection tools above still work.";
    body.hidden = !engine;
  }
  show(saved || choiceForProvider("Google AI Studio"));

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
