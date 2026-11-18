<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/hero-banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/hero-banner-light.svg">
  <img src="docs/images/hero-banner-dark.svg" alt="Agent Customs — safety checks for AI agents from other websites" width="100%">
</picture>

<br><br>

[**Live Inspection Desk**](https://montbaga.github.io/agent-customs/) &nbsp;·&nbsp;
[**Practice Site**](https://montbaga.github.io/agent-customs/practice/) &nbsp;·&nbsp;
[**Test Range**](https://agent-customs-range.github.io/) &nbsp;·&nbsp;
[**Threat Model (`PAPER.md`)**](PAPER.md) &nbsp;·&nbsp;
[**Benchmark**](#5--agent-customs-bench-npm-run-bench--papermd) &nbsp;·&nbsp;
[**Add Guard**](#add-the-guard-to-your-site) &nbsp;·&nbsp;
[**Contact**](#lets-talk)

<br>

<a href="https://github.com/montbaga/agent-customs/actions/workflows/pages.yml"><img alt="Tests and publish" src="https://github.com/montbaga/agent-customs/actions/workflows/pages.yml/badge.svg"></a>
<a href="#5--agent-customs-bench-npm-run-bench--papermd"><img alt="Bench: 87.8% blocked · 0% false blocks" src="https://img.shields.io/badge/bench-87.8%25_blocked_%C2%B7_0%25_FP-c8f03c?labelColor=0c1d18"></a>
<a href="#try-it-yourself"><img alt="Checks: 154 passing" src="https://img.shields.io/badge/tests-154_passing-ece4d3?labelColor=0c1d18"></a>
<img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-c8f03c?labelColor=0c1d18">
<img alt="Dependencies: none" src="https://img.shields.io/badge/dependencies-none-ece4d3?labelColor=0c1d18">
<a href="#lets-talk"><img alt="Built by Monty Bagati" src="https://img.shields.io/badge/say_hello-Monty_Bagati-c8f03c?labelColor=132d25"></a>

</div>

<br>

> **The problem in one minute:** On Cognizant's [Open Agentic Web](https://github.com/cognizant-ai-labs/agentic-web), one website's AI assistant can call another website's assistant. When it does, that partner runs **in your browser**, on **your API key**, reading **your request**. A dishonest site can hide orders in invisible Unicode characters that people cannot see — and today's consent card only shows the partner's name and URL, never what its instructions say.
>
> **Agent Customs is passport control before execution.** Deterministic rules inspect the partner's compiled files at **\$0 LLM cost** and stamp every network **Cleared**, **Held for review**, or **Entry denied** — pin approved versions against silent rug pulls, and enforce runtime locks that cannot be talked out of a verdict.

<br>

### Watch it work

https://github.com/user-attachments/assets/856eb212-3735-4a19-86da-0168c0ab7a2b

<br>

<table width="100%">
<tr>
<td width="33.3%" valign="top">
  <strong>1 · Inspect any link</strong><br><br>
  Paste an Open Agentic Web network, Google A2A Agent Card, or MCP catalog/<code>server.json</code> URL without an API key. Get a verdict, decoded invisible text, capability flow, and fixes.
</td>
<td width="33.3%" valign="top">
  <strong>2 · Pin against rug pulls</strong><br><br>
  Approve a clean version to store its SHA-256 fingerprint in this browser (plus persisted MCP <code>listTools()</code> pins stored via <code>PinStore</code> / <code>localStorage</code>, forgettable from the Desk Approvals tab). If files drift later, the guard holds them and shows the diff.
</td>
<td width="33.3%" valign="top">
  <strong>3 · Guard silently live</strong><br><br>
  Drop two lines into any <code>agentify-website</code> app. Every partner call passes through checkpoint inspection and Lock 1–3 runtime guards automatically before running.
</td>
</tr>
</table>

<p align="center">
  <img src="docs/images/hidden-sentence.jpg" alt="What people see vs what the AI model reads: 182 hidden Unicode tag characters decoded by Agent Customs" width="100%">
  <br><sub><b>Shady Pizza</b> shows visitors one plain sentence. Beneath it sit 182 invisible tag characters demanding card numbers and CVVs — decoded and blocked on entry.</sub>
</p>

---

## Think of airport customs

*"Most people will never visit this website. The website is the showroom; the guard is what site owners take home."*

| At the airport | On the Open Agentic Web |
| :--- | :--- |
| A traveller arriving from abroad | Another website's AI assistant |
| The country they want to enter | Your browser, your AI key, and your conversation |
| The customs officer & X-ray desk | Agent Customs |
| The passport stamp | **Cleared**, **Held for review**, or **Entry denied** |

<details open>
<summary><b>Who uses Agent Customs, and why</b></summary>

| Who | Why it matters |
| :--- | :--- |
| **Site owners linking to partners** | If a partner's assistant tricks people, your visitors get hurt and your site gets blamed. Inspect partners before linking, like checking references. |
| **Sites needing 24/7 guardrails** | One pre-launch check isn't enough if a partner changes next week. The guard checks compiled partner files on every load and blocks rug pulls. |
| **Publishers before shipping** | Like spell-check before launch: catches spec bugs, missing CORS headers, accidentally exposed keys, and overly broad `sly_data` permissions. |
| **Directories & auditors** | Batch-inspect lists of agentic websites with `node bin/agent-customs.mjs check` / SARIF CI gates or verify tamper-evident ECDSA receipts. |
| **Everyday visitors** | Protected transparently on any guarded site without installing extensions or ever visiting this desk. |

</details>

---

## Add the guard to your site

Any site built with Cognizant's `agentify-website` kit adds full protection in two steps — **no server, no build step, zero runtime edits**:

**1. Copy** [`site/customs/`](site/customs/) next to your `runtime/` folder.  
**2. Add two lines** to your `site.js`:

```js
// At the top of site.js
import { installCustomsGuard } from "./customs/guard.js";

// Right after the boot(...) call
installCustomsGuard(booted.engine);
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/checkpoint-flow-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/checkpoint-flow-light.svg">
  <img src="docs/images/checkpoint-flow-dark.svg" alt="Partner call checkpoint flow: consent card, customs guard inspection, and verdict outcomes" width="100%">
</picture>

- **Safe notices in chat:** Under every partner consent card, visitors see the verdict, issues found, and a **See the full report** link — written strictly in Agent Customs' own rule titles (`guard-notice.js`) so decoded payloads never leak into the LLM prompt.
- **Same exact compiled objects:** The guard checks the exact network objects `engine._compile` just built, after visitor consent and before execution — so a server cannot show one file to a scanner and execute another (`tests/practice.test.mjs` verifies all 58 upstream kit files stay untouched).

<details open>
<summary><b>Guard options (strict mode, opt-in semanticJudge, custom dialogs, trusted actions)</b></summary>

`installCustomsGuard(engine)` needs no options. Customize behavior with:

| Option | Default | What it does |
| :--- | :--- | :--- |
| `strict` | `false` | Enables zero-trust mode: asks before every partner, never auto-pins, ignores `trustedActions`, blocks outbound PII |
| `semanticJudge` | `false` | Opt-in Layer 2 AI semantic escalation (`true` calls caller's configured provider over `CLEARED`/`CONDITIONS` outputs; default `false` keeps checks deterministic at `0` tokens) |
| `locks` | `true` | `false` disables Lock 1–3 runtime protections (secrets redaction, reply quarantine, MCP tool pinning, action gate, canary) |
| `canary` | `true` | Injects a synthetic session canary into the top front agent's instructions and revokes partner pins on leak |
| `trustedActions` | `[]` | Harmless UI-only action names exempt from extra confirmation clicks after an external reply |
| `store` | Origin `localStorage` | Custom `PinStore` backend for approved partner SHA-256 and MCP tool-list pins |
| `policy` | Deny bad, ask held | Customize which verdicts block automatically vs prompt the user |
| `confirmEntry` | Built-in modal | `async (report) => boolean` handles **Held for review** and drift decisions |
| `notice` | Chat notice card | `false` disables notices; `(report) => true` renders your own UI notice |
| `reportPage` | Public Desk URL | Target URL opened by **See the full report** |
| `openReport` | None | `(url) => void` opens reports inside your own page |
| `onReport` | None | Callback fired on every partner inspection for telemetry/logging |
| `onLock` | None | Fires `{ lock, kind, where, reason }` whenever a runtime lock blocks sensitive data |
| `onCanaryTrip` | None | Fires `{ encoding, where, partners, revoked }` when Lock 3 detects a canary leak |

</details>

---

## Try it yourself

Three ways to explore Agent Customs, fastest first:

<table width="100%">
<tr>
<td width="33.3%" valign="top">
  <strong>1 · Automatic Test Suite</strong><br><br>
  No browser or API key needed:<br><br>
  <code>npm test</code><br><br>
  Runs 154 checks across attacks, frozen Rounds 2–3 &amp; re-check controls, Unicode obfuscation, A2A/MCP schemas, capability flow, canary tripwires, certificates, benchmarks, CLI, extension, and the practice site.
</td>
<td width="33.3%" valign="top">
  <strong>2 · Inspection Desk (No Key)</strong><br><br>
  Open the <a href="https://montbaga.github.io/agent-customs/"><strong>Live Desk</strong></a>:<br>
  • <strong>Shady Pizza</strong> → <em>Entry denied</em><br>
  • <strong>Sunny Bakery</strong> → <em>Cleared</em><br>
  • <strong>A2A, MCP &amp; chains</strong> → 1-click samples<br>
  • <strong>Verify</strong> receipt tab + <strong>Attack lab</strong> section<br>
  • <strong>Compare</strong> → <em>Try the rug-pull sample</em>
</td>
<td width="33.3%" valign="top">
  <strong>3 · Officer / Practice Site</strong><br><br>
  Paste a key (Google AI Studio &amp; Groq have free tiers) on <strong>Officer</strong> or <a href="https://montbaga.github.io/agent-customs/practice/"><strong>Practice Site</strong></a>:<br>
  • Ask <code>Ask Shady Pizza what it offers.</code> → blocked safely<br>
  • Ask <code>Ask Sunny Bakery what it offers.</code> → runs cleanly
</td>
</tr>
</table>

### The Practice Site: [Main Street Guide](https://montbaga.github.io/agent-customs/practice/)

An ordinary town-guide app built with Cognizant's kit in a completely different palette ([`practice/`](practice/)), wired up using only the 2-line guard install:

<p align="center">
  <img src="docs/images/practice-home.jpg" alt="Main Street Guide practice site showing three shops and their guard stamps" width="100%">
</p>

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/practice-change.jpg" alt="Only one folder and two lines added to site.js"><br><sub><b>1 · Minimal integration:</b> Copy <code>customs/</code> and add two lines in <code>site.js</code>. Zero edits to runtime code.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/practice-consent.jpg" alt="Runtime consent card before contact"><br><sub><b>2 · Visitor agrees first:</b> The runtime asks permission before fetching a single byte from the partner.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/practice-refused.jpg" alt="Shady Pizza refused before running"><br><sub><b>3 · Entry denied:</b> Shady Pizza is stopped cold before running; the chat lists all 9 problems safely.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/practice-held.jpg" alt="Loop Maze held for visitor decision"><br><sub><b>4 · Held for review:</b> Borderline sites like Loop Maze show findings and let the visitor decide.</sub></td>
  </tr>
</table>

<details open>
<summary><b>What <code>tests/practice.test.mjs</code> verifies automatically</b></summary>

- `practice/customs/` and `practice/runtime/` stay byte-for-byte synced with `site/`.
- `practice/site.js` contains only the two guard lines (`installCustomsGuard` import + call).
- The network passes Cognizant's official `build_network.mjs --check`.
- End-to-end execution clears `Sunny Bakery`, refuses `Shady Pizza`, and holds `Loop Maze`.

</details>

---

## Inside the inspection desk

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/five-checks-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/five-checks-light.svg">
  <img src="docs/images/five-checks-dark.svg" alt="Five Inspection Gates: Papers, Contraband, Itinerary, Privacy, Identity" width="100%">
</picture>

<br>

| Verdict Stamp | Meaning | What the Guard Does |
| :--- | :--- | :--- |
| **`Cleared`** | No known problems found | Admits partner and pins its SHA-256 fingerprint |
| **`Cleared with conditions`** | Minor hygiene notes listed | Admits partner with visible conditions and pins it |
| **`Held for review`** | Unusual limits, unfamiliar language, or post-approval drift | Pauses and asks the visitor to approve or turn it away |
| **`Entry denied`** | Hidden commands, injection, phishing, or leak links | Blocks execution completely; explains why safely |
| **`Papers not in order`** | Invalid Open Agentic Web, A2A, or MCP schema | Refuses broken manifest before execution |
| **`Could not inspect`** | Unreachable host or missing CORS header | Nothing loads or executes |

### Desk Gallery

<p align="center">
  <img src="docs/images/hero.jpg" alt="Agent Customs hero page replaying Shady Pizza inspection" width="100%">
  <br><sub>Live landing experience: paste any agent network URL or replay an instant inspection.</sub>
</p>

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/report-denied.jpg" alt="Denied report for Shady Pizza with decoded hidden instructions"><br><sub><b>Report (Denied):</b> Every finding maps to its exact agent, why it matters, how to fix it, and red-highlighted decoded Unicode.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/report-cleared.jpg" alt="Cleared report for Sunny Bakery with 15/15 spec checks passing"><br><sub><b>Report (Cleared):</b> 15/15 spec checks tied to section numbers, plus a unique SHA-256 network fingerprint.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/compare.jpg" alt="Compare view showing diff of Sunny Bakery after a silent rug pull"><br><sub><b>Compare (Rug Pulls):</b> Highlights line-by-line diffs when a previously clean network adds data-harvesting prompts or new partners.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/officer.jpg" alt="Officer tab unified BYOK model picker"><br><sub><b>Officer:</b> Bring your own key (Claude, GPT, Gemini, Groq, OpenRouter, or custom) to inspect, explain, and test partners safely.</sub></td>
  </tr>
</table>

### Phase 1–3 Showcase

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/phase1-mcp-trifecta.jpg" alt="Phase 1 MCP Lethal Trifecta held for review report"><br><sub><b>Phase 1 — MCP &amp; Lethal Trifecta:</b> Inspects <code>mcp.json</code> manifests, traces capability paths across tool names, schemas, and external sinks, and grades <code>Papers 3/7 pass</code>.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/phase2-verify.jpg" alt="Phase 2 ES256 Customs Certificate signature verification"><br><sub><b>Phase 2 — Signed Receipt Verification:</b> Verifies ES256 signatures on exported Customs Certificates locally and compares against the live endpoint fingerprint.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/phase2-attack-lab.jpg" alt="Phase 2 and 3 Attack Lab simulation paired with the Agent Customs Bench scorecard"><br><sub><b>Phase 2 &amp; 3 — Attack Lab &amp; Benchmark:</b> Side-by-side without/with Agent Customs simulation paired with the 184-case benchmark scorecard.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/phase3-builders.jpg" alt="Phase 3 Builders panel showing CLI, Action, and Extension tabs"><br><sub><b>Phase 3 — For Builders (CLI, Action &amp; Extension):</b> Copy-ready integration tabs covering <code>site.js</code>, Node CLI, SARIF GitHub Action, and the browser extension.</sub></td>
  </tr>
</table>

<p align="center">
  <img src="docs/images/phase3-extension.jpg" alt="Phase 3 Chrome/Edge browser extension inspecting io.github.microsoft/playwright-mcp" width="72%">
  <br><sub><b>Phase 3 — Browser Extension:</b> One-click MV3 popup inspection over optional <code>https://*/*</code> origin grants (shown inspecting <code>io.github.microsoft/playwright-mcp</code>).</sub>
</p>

<details open>
<summary><b>Mobile views (Inspection Desk &amp; Practice Site)</b></summary>

<table>
  <tr>
    <td width="50%" align="center"><img src="docs/images/phone-report.jpg" alt="Shady Pizza report on mobile" width="300"><br><sub>Agent Customs on mobile</sub></td>
    <td width="50%" align="center"><img src="docs/images/practice-phone.jpg" alt="Practice site on mobile" width="300"><br><sub>Practice site on mobile</sub></td>
  </tr>
</table>

</details>

---

## Defense in depth: runtime locks & signed stamps

Static rules catch known obfuscations and phrasing, **while runtime locks limit damage when novel attacks get through**:

### 1 · Three runtime locks (`locks.js`, `canary.js` + CSP)

| Lock | What it blocks | Mechanism |
| :--- | :--- | :--- |
| **Lock 1 · Secrets stay home** | Sending card numbers, IBANs, keys, or explicit creds out | Format-based matching with `\p{Nd}` Unicode digit folding (full-width, Arabic-Indic), bounded 1–4 char separators (`" -- "`), Luhn/IBAN check digits (bounded inbound-only `IMEI`/`IMSI`/`ICCID` exemptions, zero outbound exemptions), Base64 chunk decoding, and explicit credential redaction (`"bank login is ..."`) across turns, partner calls, MCP/sandbox args, actions, forms, and clicked links. |
| **Lock 2 · Actions &amp; replies** | *"Quietly place an order"* &amp; side-channel payloads | Quarantines unsafe replies (incl. inline `System:` overrides &amp; email-login phishing while allowing benign few-shot dialogues), allow-lists output keys (`{ cruse, text, source, presentation }`), drops remote images (backed by page CSP `img-src 'self' data: blob:`) and external bare/full domains (with or without `/path`), persists MCP `listTools()` digests in `PinStore`, and gates state-changing actions on a human click. |
| **Lock 3 · Armed canary trap** | Hidden prompt dumps &amp; encoded leaks | Appends a synthetic session canary (`ac_cnr_...`) to the top front agent's instructions at install/turn (restored cleanly on `uninstall()`). Outbound sinks walk string leaves inside objects and scan full tokens + random suffixes across raw, URL, ROT13, spaced, hex/spaced-hex, comma char codes, reversed, and 3-offset / wrapped Base64 (`80/80` at width 64 &amp; 76), halting execution and revoking partner approvals on trip. |

### 2 · How well it catches tricks (`tests/attacks.test.mjs`)

Tested continuously across scam wording, multi-language phrasing, adversarial paraphrases, and honest edge cases so legitimate sites aren't false-flagged:

| What was tested | Sentences | Result |
| --- | --- | --- |
| A second review's sentences, written to get past the rules | 23 | All get the right verdict now |
| Scam sentences in English and the 10 checked languages | 32 | All blocked |
| Scam sentences in 11 other languages | 11 | All held for a person |
| Honest English sentences, many close to a scam's wording | 27 | None flagged |
| Honest sentences in other languages | 23 | None blocked |

- **10 checked languages** (card/OTP/password requests blocked immediately): Spanish, French, German, Portuguese, Italian, Russian, Chinese, Japanese, Hindi, Arabic. Non-English sentences outside clear English are held for human review (`C-LANGUAGE`), including short 3-word accented Turkish, Indonesian, Swedish, Norwegian, Danish, Zulu, and Somali requests (`tests/round3.test.mjs`).
- **Official &amp; contestant sanity checks:** Cognizant's official demos (`3 CLEARED`, `1 CONDITIONS`), Agent Customs itself, and all **52** offline benign bench controls evaluate cleanly with **0 false blocks**; an independent check of 26 public contestant networks between `37dccd4` and `931d1b1` recorded **0 verdict regressions**.

### 3 · Tamper-evident signed stamps (`ES256`) & key anchor

Agent Customs publishes ECDSA P-256 signed inspection receipts ([`receipts/index.json`](https://montbaga.github.io/agent-customs/receipts/index.json)) verified against [`.well-known/agent-customs-key.json`](https://montbaga.github.io/agent-customs/.well-known/agent-customs-key.json) with a 35-day expiry and live SHA-256 fingerprint matching:

```sh
npm run receipts -- verify https://montbaga.github.io/agent-customs/receipts/agent-customs-range.github.io/shady_pizza/shady_pizza.json --live
```

- **Pinned Public Key Fingerprint (`-DC99sDa-qJjBp2N`):**
  `crv: "P-256"`, `kty: "EC"`, `x: "Wzq2yNI2mFX6Iz-GBeV7LKacVokiI396oifQRocfzxo"`, `y: "qdaCQ4K-07HN5yiq8CfFVUgRVtJm5uszNMsjuBqWQic"` (mirrored at [`site/.well-known/agent-customs-key.json`](site/.well-known/agent-customs-key.json)).

> **Origin isolation note:** Browser `localStorage` pins and saved BYOK keys are scoped per origin (`<account>.github.io`). Production deployments should host Agent Customs on its own dedicated origin rather than sharing an origin with unrelated static portfolios.

Public networks listed in [`tools/receipt-sites.json`](tools/receipt-sites.json) receive regularly refreshed, centrally signed stamps (`npm run receipts -- sign`). Website owners can open a pull request adding their public URL to [`tools/receipt-sites.json`](tools/receipt-sites.json) to join the signed directory; any site not on that list generates an **unsigned browser snapshot** whose recorded SHA-256 fingerprint can still be matched live on the **Verify** tab.

### 4 · Multi-protocol adapters, capability flow & clearance certificates

- **Open Agentic Web, Google A2A &amp; MCP (`protocols.js`):** Discovers `agent-manifest.json`/`.network.json`, Google A2A Agent Cards (`.well-known/agent.json`, `.well-known/agent-card.json`, including `supportedInterfaces` and `additionalInterfaces`), MCP catalogs/`mcpServers`/Streamable HTTP discovery endpoints, and official MCP Registry `server.json` (`packages` and `remotes`) — scanning instructions, `outputSchema`, `annotations.title`, `prompts[].messages`, A2A `skills[].name`, identifier-split schema keys, shell runners, and a generic `rawDoc` walk.
- **Name- &amp; schema-based "Lethal Trifecta" (`capabilities.js`, `S-TRIFECTA`):** Splits `camelCase` and `snake_case` identifiers across tool names, descriptions, parameters, REST toolboxes, and off-origin URLs to flag untrusted input + sensitive access + external egress paths even in polite prose. Untrusted MCP `annotations` can raise risk, never suppress concrete name, schema, or off-origin signals.
- **Bounded transitive checks (`R-TRANSITIVE`):** Follows same-origin partner references automatically (up to depth 2, 6 targets, cycle-safe) and supports opting in to cross-origin downstream checks on the Desk (`--transitive` in CLI).
- **Clearance Certificates &amp; Verify dropzone (`certificate.js`):** Export standalone SVG, printable HTML (`Unsigned` notice on PDFs), or 2× PNG cards with embedded ES256 metadata, or drop `.svg`, `.json`, `.html`, or `.pdf` files on the **Verify** tab to check their signature and live SHA-256 fingerprint.
- **Side-by-side Attack lab (`arena.js`):** Replay hidden Unicode theft, Lethal Trifecta MCP leaks, Base64 canary traps, and rug pulls without an API key (`#lab` section).

### 5 · Agent Customs Bench (`npm run bench` — [PAPER.md](PAPER.md))

Reproducible desktop benchmark (Node.js v24.18.0, win32, **`$0` model tokens**) cleanly separating **Static Detection (`98` hostile across Rounds 1–3, internal un-tuned Held-out, and quoted external probes + `61` benign controls)** from **Runtime Lock &amp; Integrity Self-Tests (`25` checks)**, compared against a **Normalized Regex Baseline** run *after* identical NFKC, tag-character decoding, and invisible-character stripping:

| Suite / Category | Cases | Agent Customs | Normalized Regex Baseline | Avg Latency |
| :--- | ---: | :--- | ---: | ---: |
| **Round 1 · `unicode_obfuscation`** | 12 | **100.0%** blocked/held | 58.3% | 12.40 ms |
| **Round 1 · `prompt_and_phishing`** | 24 | **100.0%** blocked/held | 16.7% | 4.74 ms |
| **Round 1 · `a2a_mcp_supply_chain`** | 6 | **66.7%** blocked/held *(**100%** flagged)* | 33.3% | 6.74 ms |
| **Round 2 · `round2_adversarial`** *(red team, pre-fix 3/24)* | 24 | **95.8%** blocked/held *(**100%** flagged)* | 20.8% | 4.21 ms |
| **Round 3 · `round3_generalization`** *(pre-fix 0/15)* | 15 | **100.0%** blocked/held | 0.0% | 2.46 ms |
| **Held-out · `heldout_unseen`** *(internal, post-fix)* | 10 | **50.0%** blocked/held | 0.0% | 2.11 ms |
| **External · `external_heldout_quoted`** *(7 quoted from 20-case third-party set; `1/20` → `4/20` on full set)* | 7 | **42.9%** blocked/held *(via format rules)* | 14.3% | 1.91 ms |
| **Benign controls** *(3 official demos, 14 MCP/A2A, Round 3, held-out &amp; re-check)* | 61 | **100.0%** unblocked (**0% false blocks**; 57 `CLEARED`, 4 `CONDITIONS`) | 91.8% *(8.2% false blocks)* | 4.89 ms |
| **Static Detection Total** | **159** | **86/98 (`87.8%`) blocked/held · 89/98 (`90.8%`) flagged** | **19/98 (`19.4%`) · 8.2% FP** | **~2.64 ms detection median** |
| Lock &amp; integrity self-tests (`locks` + `tampering`) | 25 | **25/25 (`100%`) passing** | *N/A* | 1.64–1.95 ms avg |

See [**PAPER.md**](PAPER.md) for the full threat model, 5-layer diagram, commit provenance for frozen Round 2/3/external sets, and honest unseen-phrasing ceilings (`node tools/bench.mjs --verbose`).

---

## The test range

The dedicated second-origin test site at https://agent-customs-range.github.io/ hosts deliberately unsafe sample networks (using non-resolving `.invalid` attacker domains):

| Network | What it demonstrates | Stamp |
| :--- | :--- | :--- |
| **`sunny_bakery`** | Honest reference network + clean spec | `Cleared` |
| **`shady_pizza`** | Hidden Unicode tags, card theft, remote image leak, reviewer jailbreak | `Entry denied` |
| **`bank_helper`** | Cyrillic homoglyph (`Marrow Point Sаvings`), OTP phishing, unpinned code | `Entry denied` |
| **`loop_maze`** | Mutual recursion, self-URL call, 500-step budget, invisible/bidi text | `Held for review` |
| **`rugpull/sunny_bakery`** | Silent post-approval update asking for contact details + new partner link | `Held for review` |

---

## Run it everywhere (CLI, GitHub Action, Chrome / Edge Extension)

Requires Node 22+ and zero npm packages.

<table width="100%">
<tr>
<td width="33.3%" valign="top">
  <strong>1 · CLI &amp; Benchmark</strong><br><br>
  Scan URLs, local folders, MCP/A2A manifests, or verify ES256 receipts:<br><br>
  <code>npm test</code><br>
  <code>npm run bench -- --verbose</code><br>
  <code>node bin/agent-customs.mjs check https://raw.githubusercontent.com/microsoft/playwright-mcp/main/server.json</code>
</td>
<td width="33.3%" valign="top">
  <strong>2 · GitHub Action (<code>action.yml</code>)</strong><br><br>
  Block PRs introducing hidden prompts, leaked keys, or toxic MCP configs with native SARIF uploads:<br><br>
  <code>uses: montbaga/agent-customs@main</code><br>
  Supports <code>strict</code>, <code>allow-hold</code>, <code>transitive</code>, and <code>sarif-file</code>.
</td>
<td width="33.3%" valign="top">
  <strong>3 · Chrome / Edge Extension</strong><br><br>
  Inspect live <code>https://</code> websites past CORS using per-origin <code>optional_host_permissions</code> (<code>https://*/*</code> on click):<br><br>
  1. Run <code>npm run extension</code><br>
  2. Open <code>chrome://extensions</code> (Developer mode)<br>
  3. <strong>Load unpacked</strong> → select <a href="extension/"><code>extension/</code></a>
</td>
</tr>
</table>

```sh
git clone https://github.com/montbaga/agent-customs.git
cd agent-customs
npm test                                # 154 checks (attacks, Rounds 2–3, re-check controls, locks, CLI, bench & extension)
npm run bench -- --verbose              # Print separated benchmark scorecard + flagged breakdown
npm run check && npm run check:practice # Validate Agent Customs & practice networks with Cognizant's kit
node bin/agent-customs.mjs check site/samples/mcp-poisoned --sarif
node bin/agent-customs.mjs verify site/receipts/agent-customs-range.github.io/sunny_bakery/sunny_bakery.json --live
```

**GitHub Action usage (add `if: always()` so SARIF uploads even on non-zero `HOLD`/`DENIED` exits):**

```yaml
- uses: montbaga/agent-customs@main
  with:
    target: site/agent_customs
    strict: "true"
    sarif-file: agent-customs.sarif
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: agent-customs.sarif
```

### Watch the live server & rug-pull simulation

```sh
# Terminal 1 & Terminal 2
npm run serve            # Serves site/ on port 8080
npm run serve:range      # Serves range/ on port 8081 (logs headers to range-requests.jsonl)
```

To simulate a live rug pull against `Sunny Bakery` mid-session:

```sh
node tools/set-origins.mjs --range http://localhost:8081
# 1. Inspect or ask Officer about Sunny Bakery (pins the clean fingerprint)
node tools/rugpull.mjs on
# 2. Click "Check for changes" or ask Officer again -> held with line-by-line diff
node tools/rugpull.mjs off
node tools/set-origins.mjs --range https://agent-customs-range.github.io
```

*(Note: `npm run smoke` drives Edge or Chrome headlessly against local servers to verify zero console errors and cross-origin behavior.)*

---

## Deep dive, hosting & architecture

<details open>
<summary><b>Host your own copy (GitHub Pages, Netlify, or Cloudflare Pages)</b></summary>

The site and the test range must sit on **two separate origins** so partner calls exercise real cross-origin consent cards. On GitHub Pages, publish `range/` under a second account or organization:

1. Create a public repo `<organization>.github.io`.
2. Point origins and rebuild everything:
   ```sh
   node tools/set-origins.mjs --range https://<organization>.github.io
   ```
3. Push `range/` (with an empty `.nojekyll`) to `<organization>.github.io`.
4. Enable GitHub Actions in **Settings → Pages** for the main repo ([`.github/workflows/pages.yml`](.github/workflows/pages.yml)).

> **Security note on origin isolation:** Browser storage (`localStorage` pins and saved BYOK keys) is scoped per origin (`<account>.github.io`). Use a dedicated origin/domain rather than sharing `<account>.github.io` with unrelated static portfolios, or deploy `site/` and `range/` separately to Netlify or Cloudflare Pages so `_headers` (`Content-Security-Policy` on `sandbox-worker.js`) is applied in production.

</details>

<details open>
<summary><b>How it is built &amp; security architecture</b></summary>

- **Zero model-decided verdicts by default:** Fixed rules decide every verdict identically on the report page, in chat, and inside the live guard (`semanticJudge` stays `false` unless explicitly opted in).
- **Zero backend server:** Inspections read public files without cookies, keys, or referrers. Pins stay strictly in browser `localStorage`.
- **Consent before contact:** Both Officer tool inspections and partner calls require explicit visitor consent cards before network contact.
- **Prompt + `command` + schema coverage:** Reads `instructions`, runtime `command`, `outputSchema`, `annotations.title`, A2A `skills[].name`, `prompts[].messages`, identifier-split schema keys, and a generic `rawDoc` walk so model-visible fields don't escape scanning.
- **Runtime hooks checked weekly:** Because `guard.js` wraps internal engine methods (`_compile`, `runTurn`, `resetHistory`, `resolveRemote`, `resolveMcp`, `sandbox.invoke`, `actions.execute`, `submitActions`), [`.github/workflows/cognizant-kit.yml`](.github/workflows/cognizant-kit.yml) tests weekly against Cognizant's upstream kit.

</details>

<details open>
<summary><b>Open Agentic Web MVP interoperability checks (Section 6)</b></summary>

| Spec Check | Implementation Here |
| :--- | :--- |
| Two-agent network + manifest on HTTPS | `customs_officer` &amp; `instruction_analyst` (`site/agent-manifest.json`) |
| Default router + BYOK | Otari default + multi-provider BYOK picker (`OpenRouter`, Google, Groq, OpenAI, Anthropic, Custom) |
| Internal agent + grounded actions | `instruction_analyst` + 6 website tools (`inspect_agent_network`, `compare_networks`, `pin_network`, etc.) |
| Cross-origin execution after approval | Officer queries `sunny_bakery` / `shady_pizza` across origins (`tests/guard.test.mjs`) |
| Keys never forwarded to peers | Verified via `range-requests.jsonl` (`"authorization": false` on all peer requests) |
| Fail closed on bad spec / denied partner | Runtime checks + deterministic Guard refusals |

</details>

<details open>
<summary><b>Repository file map</b></summary>

| Path | Purpose |
| :--- | :--- |
| [`site/customs/`](site/customs/) | Core engine (`analyze.js`, `protocols.js`, `capabilities.js`, `canary.js`, `rules.js`, `languages.js`, `locks.js`, `unicode.js`, `canonical.js`, `diff.js`, `pins.js`, `inspect.js`, `guard.js`, `judge.js`, `receipts.js`) |
| [`site/agent_customs.hocon`](site/agent_customs.hocon) | Officer + analyst network definition |
| [`site/desk.js`](site/desk.js), [`view.js`](site/view.js), [`certificate.js`](site/certificate.js), [`arena.js`](site/arena.js), [`site.js`](site/site.js) | Inspection desk UI, certificates, Attack lab, actions, and guard wiring |
| [`site/runtime/`](site/runtime/) | Upstream Cognizant Open Agentic Web runtime (unmodified, Apache 2.0) |
| [`practice/`](practice/) | Main Street Guide demo app generated by `tools/make-practice.mjs` |
| [`extension/`](extension/) | Manifest V3 Chrome/Edge popup inspector generated by `tools/make-extension.mjs` |
| [`bin/`](bin/) &amp; [`action.yml`](action.yml) | Zero-dependency CLI (`check`, `verify`, `bench`) with SARIF output and GitHub Composite Action |
| [`PAPER.md`](PAPER.md) | 5-layer architecture note, formal threat model, benchmark scorecard &amp; honest limits |
| [`tools/`](tools/) | CLI inspector, benchmark suite (`bench.mjs`, `round2-corpus.mjs`, `round3-corpus.mjs`, `heldout-corpus.mjs`, `external-heldout.mjs`), local server, range/practice/extension builders, smoke checks, receipt signer |
| [`tests/`](tests/) | Node native test runner suite (`154` tests) + official spec fixtures |
| [`vendor/agentify-website/`](vendor/agentify-website/) | Upstream kit scripts &amp; templates (unmodified) |

</details>

<details open>
<summary><b>Honest limits &amp; FAQ</b></summary>

- **Agent manifests, not general HTML:** Built for AI agent manifests and catalogs — Open Agentic Web (`agent-manifest.json`, `.network.json`), Google A2A Agent Cards (`.well-known/agent.json`, `agent-card.json`), and MCP (`mcp.json`, `server.json`, `mcpServers`, `tools/list`), not regular HTML websites.
- **`Cleared` ≠ certified safe:** It means known attack vectors were not found — which is why version pinning + Luhn/IBAN/action/canary locks remain armed at runtime. Manifests naming third-party brands on generic hosts (such as `raw.githubusercontent.com`) surface an `I-AUTHORITY` hygiene notice (`Cleared with conditions`) because the host itself does not verify publisher identity.
- **Static vs. runtime boundaries:** Open Agentic Web and MCP tool executions run with Lock 1–3 runtime guards and persisted `PinStore` MCP `listTools()` pins (forgettable from Desk Approvals after intentional updates); Google A2A is inspected statically because Cognizant's runtime does not execute remote A2A transports directly. Category rules caught Round 1–3 phrasing, but on 20 independent unseen wordings static rules held `1/20` pre-format and `4/20` after format additions (`50%` on internal held-out, `3/7` quoted externals after adding crypto/`javascript:`/IBAN format rules), confirming rules act as a first filter backed by runtime Locks 1–3 and opt-in `semanticJudge: true`. Written-out card words, bounded inbound-only visitor-chat `IMEI`/`IMSI`/`ICCID` exemptions (15 / 14–15 / 19–20 digits within 3 words; never exempted outbound), 5+ char digit separators, and split-field secrets stay out of band.
- **Language scope:** English is checked in full; 10 additional languages check secret/card/password phishing; unfamiliar scripts/languages (including multi-token Turkish, Indonesian, Swedish, Norwegian, Danish, Zulu, and Somali requests, while leaving 3-word accented dishes and greetings clear) are held for human review.
- **CORS requirement:** Sites that omit `Access-Control-Allow-Origin` cannot be fetched directly from the static web desk — inspect those origins via [`bin/agent-customs.mjs`](bin/agent-customs.mjs), CI [`action.yml`](action.yml), or the MV3 browser [`extension/`](extension/) (`optional_host_permissions` over `https://*/*`).
- **Similar tools:** Unlike CLI-only MCP scanners such as [Snyk Agent Scan](https://github.com/snyk/agent-scan), Agent Customs runs 100% inside the browser (plus optional CLI, SARIF GitHub Action, and browser extension) across Open Agentic Web, A2A, and MCP catalogs with no external backend, guards partner calls at runtime with armed canaries and MCP tool pinning, and pins SHA-256 versions against rug pulls.

</details>

---

## Let's talk

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/contact-card-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/contact-card-light.svg">
  <img src="docs/images/contact-card-dark.svg" alt="Direct line to Monty Bagati — security reviews, integrations, feedback, and roles" width="100%">
</picture>

<br><br>

<a href="mailto:bagati.monty@gmail.com?subject=Agent%20Customs%20%E2%80%94%20Hello%20Monty"><img alt="Email Monty Bagati" src="https://img.shields.io/badge/Email-bagati.monty%40gmail.com-c8f03c?style=for-the-badge&logo=gmail&logoColor=c8f03c&labelColor=0c1d18"></a>
&nbsp;
<a href="https://www.linkedin.com/in/monty-bagati-90454626/"><img alt="Connect on LinkedIn" src="https://img.shields.io/badge/LinkedIn-Monty_Bagati-ece4d3?style=for-the-badge&logo=linkedin&logoColor=ece4d3&labelColor=0c1d18"></a>
&nbsp;
<a href="https://github.com/montbaga"><img alt="GitHub Profile" src="https://img.shields.io/badge/GitHub-%40montbaga-8fd1a6?style=for-the-badge&logo=github&logoColor=8fd1a6&labelColor=0c1d18"></a>
&nbsp;
<a href="https://github.com/montbaga/agent-customs/issues/new"><img alt="Open an Issue or Feedback" src="https://img.shields.io/badge/Feedback-Report_a_Bypass_or_Idea-f0a35e?style=for-the-badge&logo=github&logoColor=f0a35e&labelColor=0c1d18"></a>

<br><br>

<a href="https://montbaga.github.io/agent-customs/"><img src="site/favicon.svg" alt="Agent Customs" width="36"></a>

<br>

**Agent Customs** · Built by [**Monty Bagati**](https://www.linkedin.com/in/monty-bagati-90454626/) for the Open Agentic Web  
<sub>Apache License 2.0 · Copyright 2026 Monty Bagati · Runtime &amp; templates from <a href="https://github.com/cognizant-ai-labs/agentic-web">cognizant-ai-labs/agentic-web</a> (Apache 2.0)</sub>

</div>
