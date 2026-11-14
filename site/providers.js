// providers.js: AI providers the officer's settings offer beyond the runtime's own four
// (Google AI Studio, Groq, OpenAI, Anthropic).
//
// The runtime keeps its provider list in an exported array (runtime/ui.js, API_KEY_PROVIDERS).
// Adding an entry before the runtime mounts shows the provider under AI model settings, fills
// in its address and model when it is picked, and recognises its keys by their prefix. The
// runtime's files stay unchanged.
//
// OpenRouter: one key reaches hundreds of models (Claude, Gemini, GPT, Llama, Mistral,
// DeepSeek, Qwen and more), and it allows calls from the browser. Its default model is
// Gemini 3.8 Flash, a fast and inexpensive model that can call tools; any other model name
// from openrouter.ai/models can be typed under Advanced settings.

export const EXTRA_PROVIDERS = [
  {
    name: "OpenRouter",
    keyUrl: "https://openrouter.ai/settings/keys",
    router: "https://openrouter.ai/api/v1",
    model: "google/gemini-3.8-flash",
    keyPrefixes: ["sk-or-"],
    accessNote: "One key, hundreds of models",
  },
];

/**
 * Add the extra providers to the runtime's list, once each.
 *
 * :param list: The runtime's API_KEY_PROVIDERS array.
 * :param extra: The providers to add.
 * :return: The same list.
 */
export function addProviders(list, extra = EXTRA_PROVIDERS) {
  for (const provider of extra) {
    if (!list.some((p) => p.name === provider.name)) list.push(provider);
  }
  return list;
}
