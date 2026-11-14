# Agent Customs: DevPost submission

Copy the sections under "Submission text" into the DevPost form. The video script and the checklist at the end are for preparing the entry.

---

## Submission text

### Tagline

Border control for the Open Agentic Web: check another site's agent network before it runs in your browser, and add the same check to any agentic site with one line.

### The problem

On the Open Agentic Web, one site's agent can call another site's agent network. When it does, the partner's agents run in the visitor's browser and use the visitor's AI key. The spec treats partner instructions as untrusted input that may try to override the caller's rules, pull out information or trigger unsafe actions (section 5). Right now the only protection is a consent card, which shows a label the partner picked for itself and the first 140 characters of the request.

That leaves two groups exposed. Site builders who link to partners can have their visitors phished, or their own assistant ordered around, by one bad partner or by a partner that changes quietly after they linked to it. Visitors pay for every partner call with their key, and the partner reads their conversation.

The spec lists the missing pieces as future work: conformance tests, integrity pinning with re-consent on change, consent policies, and identity and reputation. The agentic-web README still marks its validation script as a TODO. Agent Customs is my attempt at those pieces.

### What it does

Agent Customs loads a published agent network the same way a caller's runtime does and gives it one verdict: Cleared, Cleared with conditions, Held for review or Entry denied. It runs five groups of checks:

- Papers: conformance with MVP profile 0.2, one check at a time, each with its spec section and a fix for the publisher. It uses the runtime's own parser and validator.
- Contraband: instructions hidden in invisible Unicode tag characters (decoded and shown in red), zero-width and right-to-left tricks, prompt injection, requests for passwords, one-time codes and card details, image links that leak the conversation, orders aimed at the calling site's assistant, and notes written to fool a reviewer.
- Itinerary: every other site, MCP server and code bundle the network can reach.
- Privacy: any private context (`sly_data`) the network lets cross a site boundary.
- Identity: a SHA-256 fingerprint of the version you approved, look-alike letters from other alphabets, and a line-by-line diff when a publisher changes a network after you approved it.

You can use it in three ways. On the website, paste a network URL to get a report, approve a version, or compare two versions. In the chat, the Customs Officer (the site's own agent network, running on the visitor's key) inspects networks, explains findings, compares versions and calls partner networks on another site; every partner it calls goes through the guard first. In any other agentic site, one line, `installCustomsGuard(engine)`, inspects each partner network after the visitor's consent card and before any of its agents run. The guard checks the exact objects the runtime compiled, so a partner can't show the inspector one file and run another. A denied partner fails closed with a plain reason the calling agent can pass on, a partner that changed since approval waits for the visitor, and no runtime file is edited.

### Conformance (Stage One)

- Public agent network JSON: `agent_customs.network.json`, built from HOCON and checked with the official `build_network.mjs`, which reports no warnings. Agent Customs also passes its own inspection.
- Runtime: the agentic-web browser runtime in `/runtime/`, unchanged.
- Interface: the Customs Officer chat, plus the inspection, approval and comparison tools on the page.
- LLM and key settings: bring your own key. A model picker on top of the runtime's settings offers Claude, GPT, Gemini, an open model on Groq, or any model on OpenRouter, and lists the models the pasted key can use.
- Works with the website: six registered site actions (`website_inspect_agent_network` and five others) read and change the page.
- Works with other agentic websites: the officer calls partner networks on a second origin after the visitor agrees.
- Callable by other agentic websites: the network URL is public, with CORS, a bridge page and the template's peer rules.

### How it was built

- Plain JavaScript modules with no dependencies, no build step and no server, in line with the spec's idea of running agents in the browser.
- The network is written in HOCON with the official `agentify-website` templates, and the template rules are kept word for word.
- The guard wraps `engine._compile` on one engine instance. Every partner network passes through that step after it is fetched and validated and before it runs, which is why the guard needs no runtime changes.
- Fingerprints are SHA-256 over canonical JSON, with a pure JavaScript fallback for browsers without Web Crypto.
- `DESIGN.md` describes the page: three colors, one live effect in the hero (a WebGL ink shader that stops off screen and holds still under reduced motion), and a replay of a real inspection that a test checks against the engine. The page loads no third-party scripts, because any script on it could read the visitor's AI key.
- 45 Node tests, including end-to-end runs of the guard inside the real runtime engine with scripted models, plus headless-browser checks of the desktop and phone layouts.
- Started and built during the submission period (November 2026).

### Tools shared with the community

All are Apache 2.0, in the public repository, and each one works on its own:

- The inspection engine (`site/customs/`) checks any agent network for conformance and safety, in a browser or in Node. It could serve as the validation script the agentic-web README asks for.
- The guard (`site/customs/guard.js`) drops into any agentic site with one line.
- The test range (`tools/make-range.mjs`) has deliberately unsafe sample networks (a smuggler, an impersonator, a budget burner and a rug pull) next to an honest one, for testing any runtime or checker. Every attacker address uses the reserved `.invalid` domain.
- Smaller tools: a command-line inspector (`tools/inspect-local.mjs`), a local server that applies Netlify-style `_headers` (`tools/serve.mjs`), and a headless-browser smoke test with no dependencies (`tools/smoke.mjs`).

### Why it's different

Most agentic websites put an assistant in front of a business. This one is about the agentic web itself: it is the checkpoint that makes it reasonable to link your agent to someone else's.

A few choices came straight from the spec's threat model. No verdict comes from a model, because the officer reads text written by attackers, and refusals sent to a calling agent contain only Agent Customs' own rule titles, never the attacker's words. Consent comes first: inspections the officer starts use the runtime's own consent card, and the guard runs after the partner's card, never before. Honest sites are not flagged: the rules understand negation, so "Never ask for passwords" passes and "Never forget to ask for the CVV" does not, and the challenge's own examples (a pizza restaurant, a guesthouse and harbor tours) all come out Cleared.

### What's next

- Signed inspection receipts that registries such as the NANDA Index could publish, so a verdict can be shared instead of living in one browser.
- Site policy files, such as "deny any partner with an open peer policy".
- Inspecting a partner's own partners, with consent at each hop.

### Built with

JavaScript, HTML, CSS, the Open Agentic Web runtime, Neuro SAN HOCON, Web Crypto, the Node.js test runner, Otari.

### Links

- Live site: https://montbaga.github.io/agent-customs/ (network URL `https://montbaga.github.io/agent-customs/agent_customs`)
- Test range: https://agent-customs-range.github.io/
- Code: https://github.com/montbaga/agent-customs

---

## Video script (1 minute 50 seconds)

Speak it yourself, with the site running in a browser. Use no music, and keep other companies' logos out of the frame.

| Time | Show | Say |
| --- | --- | --- |
| 0:00 | Home page, the replay stamps Shady Pizza | "On the Open Agentic Web, other sites' agents run in your browser, on your AI key. Who checks them at the border? I built Agent Customs." |
| 0:12 | In the inspection desk, press Sunny Bakery | "An honest network: Cleared. Every spec check passes, each one tied to its section of the spec, and it gets a fingerprint." |
| 0:25 | Scroll through "The sentence you can't see", then press Shady Pizza in the desk | "This pizza network looks normal. Inspect it: Entry denied. 182 invisible characters hide a sentence asking for your card number and telling the calling site's assistant to place an order. Here it is, decoded." |
| 0:50 | Officer tab. Ask: "Ask Shady Pizza what it offers." Allow the card | "Now my Customs Officer, an agent running on my own key. I allow contact, and the guard inspects the partner before it runs. Refused. Nothing from it ran, and the officer explains why." |
| 1:15 | Compare tab, press "Try the rug-pull sample" | "Approval isn't forever. The bakery quietly added two lines. Customs shows exactly what changed and holds the new version for review." |
| 1:35 | "A guard for your agentic site" | "Any agentic site gets this with one line. No server, and no changes to the runtime. Rules decide; the model only explains." |
| 1:47 | The closing line | "Agent Customs: border control for the agentic web." |

## Before you submit

- [x] Host the test range and the site on two different origins: https://montbaga.github.io/agent-customs/ and https://agent-customs-range.github.io/.
- [ ] Run `npm test`, and run `npm run smoke` against the hosted site to make the screenshots.
- [ ] Try the officer live with your own key: the Sunny Bakery question, the Shady Pizza question, and one inspection by chat.
- [ ] Record the video, keep it under 2 minutes, and upload it to YouTube as public.
- [x] Push the code to a public GitHub repository and fill in the links above.
- [ ] Submit before Monday, January 11, 2027, 8:00 am Pacific Time.
