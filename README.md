# Agent Customs

Border control for the Open Agentic Web. Agent Customs checks another site's agent network before that network runs in your browser, and one line adds the same check to your own agentic site.

On the [Open Agentic Web](https://github.com/cognizant-ai-labs/agentic-web), one site's agent can call another site's agent network. The partner's agents then run in the visitor's browser and use the visitor's AI key. The spec says partner instructions are untrusted input (section 5): they can try to override the caller's rules, ask the visitor for secrets, or leak the conversation. Today the only protection is a consent card that shows a label the partner picked for itself and the first 140 characters of the request.

Agent Customs adds the missing checkpoint. It runs five groups of checks:

| Check | What it looks at |
| --- | --- |
| Papers | Conformance with the MVP spec (profile 0.2), one check at a time, each citing its section and giving the publisher a fix. It uses the runtime's own parser and validator, and flags keys or passwords left in the public files (shown shortened). |
| Contraband | Hidden Unicode tag characters (decoded and shown), zero-width and right-to-left tricks, prompt injection, requests for passwords, codes and card details, image links that leak the conversation, orders aimed at the calling site's assistant, text written to fool reviewers, and encoded blobs. |
| Itinerary | Every other site, MCP server and code bundle the network can reach, and whether its own policy allows that. |
| Privacy | Which private context (`sly_data`) it lets cross a site boundary. |
| Identity | A SHA-256 fingerprint of the version you approved, look-alike letters from other alphabets, authority claims its host does not back up, and a line-by-line diff when a publisher changes a network or its manifest after approval (a "rug pull"). |

Each network gets one verdict: Cleared, Cleared with conditions, Held for review, Entry denied, Papers not in order, or Could not inspect.

## Three ways to use it

1. On the website. Paste a network URL and read the report. You can approve (pin) a version, or compare two versions.
2. Through the Customs Officer, an agent network on the same site that runs in your browser on your own key. It inspects networks, explains findings in plain words, compares versions, asks an instruction analyst for a second opinion, and talks to the test-range networks. Every partner it calls goes through the guard first. It can approve a version, or forget an approval, only after you confirm in a dialog.
3. As a guard in any agentic site. Copy `site/customs/` next to your `runtime/` folder and add one line after `boot()`:

   ```js
   import { installCustomsGuard } from "./customs/guard.js";
   installCustomsGuard(engine);
   ```

   Each partner network is inspected after the visitor's consent card and before any of its agents run. The guard checks the exact objects the runtime compiled, so a partner cannot show the inspector one file and run another. A denied partner fails closed, and the calling agent gets a plain reason. Held partners, and partners that changed since approval, wait for the visitor. No runtime file is edited.

## Design principles

No verdict comes from a model. The officer reads text written by strangers, so fixed rules decide, and they give the same verdict on the page, in the chat and in the guard. The officer gets a compact report without quoted payloads, and any quoted text is marked as data.

Nothing leaves the browser. Inspections read public files without cookies, keys or a referrer, approvals stay in the browser's own storage, and there is no Agent Customs server.

The visitor is asked before any contact. Inspections the officer starts use the runtime's own consent card, which shows the full address, and the guard runs after the partner's consent card, never before. Approvals belong to the visitor too: the officer reads text written by strangers, so it cannot approve a network or forget an approval without the visitor's click.

The checks read what the model reads. An agent's instructions and its `command` text, which the runtime adds to the system prompt, are both checked, and so are descriptions and the whole input schema a calling model sees.

Honest sites should not be flagged. The challenge's official examples (a pizza restaurant, a guesthouse and harbor tours) all come out Cleared, and Agent Customs passes its own inspection. "Never ask for passwords" is not read as asking for passwords.

## The test range

`range/` is a second website of small networks for demos and tests, written by `tools/make-range.mjs`. None is a real business, and every attacker address uses the reserved `.invalid` domain, which never resolves.

| Network | What it shows | Verdict |
| --- | --- | --- |
| `sunny_bakery` | An honest network, for comparison | Cleared |
| `shady_pizza` | Hidden instructions in invisible tag characters ask for the card number and tell the calling assistant to place an order; a "logo" image leaks the conversation; a note tries to talk reviewers into a pass | Entry denied |
| `bank_helper` | A made-up bank, "Marrow Point Sаvings Bank" with a Cyrillic а, plus pressure language, password and one-time-code phishing, an open policy, an outside MCP server, unpinned code, and all private context forwarded | Entry denied |
| `loop_maze` | Agents that call each other, a call to its own URL, 500 steps, an hour-long limit, and invisible and reversed text | Held for review |
| `rugpull/sunny_bakery` | The bakery after a quiet update: it asks for contact details, tells the caller to add a gift card, and adds a new partner | Held for review |

The range also serves Cognizant's three official example sites under `official/`, copied unchanged (Apache 2.0).

## Run it locally

You need Node.js 22 or newer. There is nothing to install, because there are no dependencies.

```shell
npm test                 # 59 tests: engine, guard inside the real runtime, website tools, local server
npm run serve            # the site at http://127.0.0.1:8080/
npm run serve:range      # the test range at http://localhost:8081/ (a second origin), with a request log
npm run smoke            # optional: drives headless Edge or Chrome and saves screenshots
npm run inspect -- https://site.example/agent_network   # inspect a real site from this computer, including whether other sites may read it (CORS)
```

Open http://127.0.0.1:8080/ and press a test-range button. Inspections need no key. To use the officer, open the Officer tab, pick a model under AI model settings, and paste a key from that provider (Google AI Studio and Groq have free tiers). Then try questions such as "What does the Sunny Bakery test network offer? Ask it." and "Ask Shady Pizza what it offers."

To watch the guard catch a rug pull, the site has to use your local range, because the switch changes local files only. Run `node tools/set-origins.mjs --range http://localhost:8081`, start both servers, and ask the officer about Sunny Bakery (the guard approves it on first use). Then run `node tools/rugpull.mjs on` and ask again: the guard holds it and shows the changed lines. `node tools/rugpull.mjs off` puts the original back. Before you publish, point the site at the hosted range again with `set-origins.mjs`. On the hosted site, the Compare tab shows the same change.

`range-requests.jsonl` logs every request the range receives, including whether an `Authorization` header or cookies came with it. It shows that the partner site never receives the visitor's key.

## Host it

The site and the range must be on two different origins, so that partner calls cross a real site boundary.

On GitHub Pages, every site of one account shares one origin (`<account>.github.io`), so the range needs a second owner, such as a free GitHub organization:

1. Create the organization (for example `agent-customs-range`) and, in it, an empty public repository named `<organization>.github.io`.
2. Run `node tools/set-origins.mjs --range https://<organization>.github.io`. It points the site at that address, regenerates `range/` for it, and rebuilds the network with the official build script.
3. Push the contents of `range/`, plus an empty `.nojekyll` file, to that repository. GitHub Pages serves it at `https://<organization>.github.io/`.
4. In this repository, open Settings, then Pages, and set Source to GitHub Actions. `.github/workflows/pages.yml` then publishes `site/` at `https://<account>.github.io/agent-customs/` on every push to `main`, once the tests and the network check pass.

Visitors' keys are stored per origin, and every Pages site of one account shares that origin. So a script on any other Pages site of the same account could read keys saved here. Publish Agent Customs from an account or organization whose other Pages sites load no third-party scripts, or give it a custom domain.

GitHub Pages sends `Access-Control-Allow-Origin: *` on every file, which is what other sites' browsers need. It does not read `_headers`, so the runtime's sandbox policy (a Content-Security-Policy header on `runtime/sandbox-worker.js`) is not sent there. Netlify and Cloudflare Pages do apply `_headers`: drag `range/` and `site/` into [Netlify Drop](https://app.netlify.com/drop) as two sites after step 2.

The network URL is then `https://<site host>/agent_customs`, for example `https://<account>.github.io/agent-customs/agent_customs`.

## Spec MVP interoperability checks (section 6)

| Check | Here |
| --- | --- |
| Two-agent network and manifest on an HTTPS host | `customs_officer` and `instruction_analyst`; `site/agent-manifest.json` |
| Run with the site's default router, and with BYOK | Otari default router; the officer's AI model settings |
| Internal agent plus a grounded capability | `instruction_analyst`, plus six registered site actions (`website_inspect_agent_network` and others) |
| Load an exact named network from a second origin after approval | The officer calls `sunny_bakery` and `shady_pizza` on the range origin; covered end to end in `tests/guard.test.mjs` |
| The second site never receives the key | `range-requests.jsonl`: `"authorization": false` on every request |
| Private context absent at the peer unless allowed | The network allows none; the Privacy check reports any `allow` rule |
| Invalid network, cycle, over-budget and denied origin stop with visible errors | The runtime's checks, plus the guard's refusals, which reach the agent as plain errors |

## Files

| Path | What |
| --- | --- |
| `site/customs/` | The inspection engine and guard: `analyze.js` (all checks and the verdict), `rules.js` (text rules), `unicode.js` (hidden characters), `canonical.js` (fingerprints), `diff.js` (snapshots and diffs), `pins.js` (approvals), `inspect.js` (fetching like a caller), `guard.js` and `guard-ui.js` |
| `site/agent_customs.hocon` | Network source; the build writes `agent_customs.network.json`, `agent-mcp.json`, `.well-known/` and `bridge/` |
| `site/desk.js`, `site-actions.js`, `view.js`, `site.js` | The page object, the six website tools, the page view, and the runtime mount with the guard |
| `site/model-picker.js`, `providers.js` | The officer's model picker. It adds OpenRouter to the runtime's providers (Google AI Studio, Groq, OpenAI and Anthropic), lists the models a pasted key can use, remembers each provider's key in this browser, and rewrites provider errors in plain words. It fills in the runtime's own settings form, so the runtime still checks the model before saving |
| `site/index.html`, `styles.css`, `assistant.css`, `effects.js`, `scene-gl.js`, `hero-demo.js`, `hero-data.js`, `fonts/` | The page. `DESIGN.md` describes the design. The fonts are Geist and Instrument Serif (SIL Open Font License). The page loads no third-party scripts, because any script on it could read the visitor's AI key. `tests/hero-data.test.mjs` checks every value the hero replay shows against the engine |
| `site/runtime/` | The agentic-web browser runtime, unchanged (Apache 2.0) |
| `range/` | The test range (generated) |
| `tests/` | Node tests, with the official examples as fixtures |
| `tools/` | Range generator, origin switcher, rug-pull switch, local server with `_headers`, smoke test, command-line inspector |
| `vendor/agentify-website/` | The official agentify-website files, unchanged, used for their build and check scripts |

## Limits

- Pattern rules catch known techniques, not every possible manipulation. The instruction analyst gives a model's second opinion, labeled as an opinion. A network that passes is not certified safe, and the site says so.
- Approvals are per browser. There is no shared registry of verdicts yet; a later version could publish signed inspection receipts to a registry such as the NANDA Index.
- A site that sends no CORS header cannot be inspected from a browser, and no caller's browser can run its network either. Agent Customs reports this as Could not inspect.
- From the runtime: the LLM provider must allow browser calls, and the network file, instructions included, is public.

## License

Apache License 2.0. Copyright 2026 Monty Bagati. The runtime and the agentify-website files come from [cognizant-ai-labs/agentic-web](https://github.com/cognizant-ai-labs/agentic-web) (Apache 2.0).
