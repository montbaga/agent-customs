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
[**Benchmark**](#agent-customs-bench-npm-run-bench--papermd) &nbsp;·&nbsp;
[**Add Guard**](#add-the-guard-in-two-lines) &nbsp;·&nbsp;
[**Contact**](#lets-talk)

<br>

<a href="https://github.com/montbaga/agent-customs/actions/workflows/pages.yml"><img alt="Tests and publish" src="https://github.com/montbaga/agent-customs/actions/workflows/pages.yml/badge.svg"></a>
<a href="#try-it-yourself"><img alt="Checks: 147 passing" src="https://img.shields.io/badge/tests-147_passing-ece4d3?labelColor=0c1d18"></a>
<a href="#agent-customs-bench-npm-run-bench--papermd"><img alt="Bench: 95.5% detection · 0% FP" src="https://img.shields.io/badge/bench-95.5%25_blocked_%C2%B7_0%25_FP-c8f03c?labelColor=0c1d18"></a>
<img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-c8f03c?labelColor=0c1d18">

</div>

<br>

> **Cognizant's consent card asks "may I call Shady Pizza?" — but never shows what Shady Pizza's agent was told to do.**
>
> **Agent Customs reads it first, with two lines of code, and keeps checking after you say yes.** Fixed rules inspect the partner's compiled files in the browser at **\$0 LLM cost** (`Cleared`, `Held for review`, or `Entry denied`), pin approved SHA-256 versions against silent rug pulls, and enforce runtime locks that cannot be talked out of a verdict.

<p align="center">
  <img src="docs/images/practice-refused.jpg" alt="Agent Customs blocking Shady Pizza inside Cognizant's runtime before execution" width="84%">
  <br><sub><b>Live runtime defense on <a href="https://montbaga.github.io/agent-customs/practice/">Main Street Guide</a>:</b> Shady Pizza passes Cognizant's URL consent prompt, then hits Agent Customs on the compiled network — blocked cold before any partner agent runs, with zero attacker text sent to the model.</sub>
</p>

---

## Add the guard in two lines

Any [Open Agentic Web](https://github.com/cognizant-ai-labs/agentic-web) app built with Cognizant's `agentify-website` kit adds full checkpoint inspection, version pinning, and runtime locks **without editing any runtime file or running a server**:

1. **Copy** [`site/customs/`](site/customs/) next to your `runtime/` folder.
2. **Add two lines** to `site.js`:

```js
import { installCustomsGuard } from "./customs/guard.js";

const { engine } = await boot("#agent-app", { /* ... */ });
installCustomsGuard(engine);
```

- **Inspects compiled objects, not a second fetch:** Wraps `engine._compile` directly on the host runtime so a server cannot serve one manifest to a scanner and execute another.
- **Model-free verdicts + isolated explanations:** Notices shown in chat (`guard-notice.js`) use Agent Customs' own rule titles only, never quoting attacker payloads back to your model.
- **Zero-dependency core:** Pure browser ESM + Node 22 (`tests/practice.test.mjs` verifies all 58 kit files remain unmodified).

<details>
<summary><b>Guard options (strict mode, opt-in semanticJudge, custom UI, trusted actions)</b></summary>

| Option | Default | What it does |
| :--- | :--- | :--- |
| `strict` | `false` | Asks before every partner, never auto-pins, ignores `trustedActions`, blocks outbound PII |
| `semanticJudge` | `false` | Opt-in Layer 2 AI semantic escalation (`true` calls caller's configured provider on `CLEARED`/`CONDITIONS`) |
| `locks` | `true` | Enables Lock 1 (secrets), Lock 2 (action gating + reply quarantine + MCP tool pinning), Lock 3 (canary trap) |
| `canary` | `true` | Injects a synthetic canary token into the top front agent's instructions and revokes partner pins on leak |
| `trustedActions` | `[]` | Harmless UI-only action names exempt from extra confirmation clicks after an external reply |
| `store` | `localStorage` | Custom `PinStore` backend for partner SHA-256 and MCP tool-list pins |
| `confirmEntry` | Built-in modal | `async (report) => boolean` prompt for **Held for review** networks and drift |
| `notice` | Chat notice card | `false` disables notices; `(report) => true` renders your own UI notice |
| `reportPage` / `openReport` | Public Desk | Configures where **See the full report** opens |
| `onReport` / `onLock` / `onCanaryTrip` | None | Telemetry hooks for inspection verdicts, lock blocks, and canary trips |

</details>

---

### Also included

- **Inspection Desk ([live](https://montbaga.github.io/agent-customs/)):** Paste any **Open Agentic Web**, **Google A2A** (`.well-known/agent.json` / `agent-card.json`), or **MCP** (`mcp.json`, `mcpServers`, `tools/list`, official Registry `server.json`) URL with no API key, compare rug pulls line-by-line, and export ECDSA P-256 Clearance Certificates (`.svg` / `.html` / `.png`).
- **CLI & GitHub Action ([`bin/agent-customs.mjs`](bin/agent-customs.mjs), [`action.yml`](action.yml)):** Fail PRs with native **SARIF v2.1.0** uploads on hidden prompts, secret harvesting, leaked keys, or Lethal Trifecta MCP tools (`npm run bench`, `node bin/agent-customs.mjs check ... --sarif`).
- **Chrome / Edge MV3 Extension ([`extension/`](extension/)):** Inspect external origins past browser CORS limits using per-origin `optional_host_permissions` (`https://*/*`, granted only when clicked).
- **Attack Lab (`#lab`) & ES256 Receipt Verifier (`#tab-verify`):** Interactive side-by-side without/with simulations and drag-and-drop certificate/receipt tampering checks.

<details>
<summary><b>Watch it work (video) &amp; visual gallery (Desk, Practice Site, Phase 1–3)</b></summary>

https://github.com/user-attachments/assets/856eb212-3735-4a19-86da-0168c0ab7a2b

<p align="center">
  <img src="docs/images/hidden-sentence.jpg" alt="182 invisible Unicode tag characters decoded by Agent Customs" width="100%">
  <br><sub><b>Shady Pizza:</b> 182 invisible Unicode tag characters decoded and blocked on entry.</sub>
</p>

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/hero.jpg" alt="Agent Customs inspection desk hero replay"><br><sub><b>Inspection Desk:</b> Five checks (Papers, Contraband, Itinerary, Privacy, Identity) with no API key.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/phase1-mcp-trifecta.jpg" alt="Phase 1 MCP Lethal Trifecta held for review report"><br><sub><b>MCP &amp; Lethal Trifecta:</b> Traces tool-name, schema, and external endpoint paths even in polite prose.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/compare.jpg" alt="Compare view showing diff after rug pull"><br><sub><b>Compare (Rug Pulls):</b> Highlights exact prompt and permission changes against a pinned snapshot.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/phase2-verify.jpg" alt="Phase 2 ES256 Customs Certificate signature verification"><br><sub><b>Verify Stamps:</b> Checks offline ES256 certificate signatures and matches live SHA-256 fingerprints.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/phase2-attack-lab.jpg" alt="Attack Lab simulation paired with Agent Customs Bench"><br><sub><b>Attack Lab &amp; Bench:</b> Replays Unicode theft, MCP trifecta, Base64 canary traps, and rug pulls live.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/phase3-builders.jpg" alt="For Builders card showing CLI, Action, and Extension tabs"><br><sub><b>CLI, CI &amp; Extension:</b> Drop-in guard snippet, Node CLI, SARIF Action, and MV3 popup inspector.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/report-cleared.jpg" alt="Cleared report for Sunny Bakery with 15/15 spec checks passing"><br><sub><b>Cleared Report:</b> 15/15 Open Agentic Web checks tied to spec sections + SHA-256 fingerprint.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/phase3-extension.jpg" alt="Browser extension inspecting io.github.microsoft/playwright-mcp"><br><sub><b>Browser Extension:</b> One-click MV3 inspection over optional <code>https://*/*</code> origin grants.</sub></td>
  </tr>
</table>

</details>

---

## Try it yourself

```sh
git clone https://github.com/montbaga/agent-customs.git
cd agent-customs
npm test                                # 147 automated tests (attacks, Round 2, protocols, locks, receipts, CLI, bench & extension)
npm run bench -- --verbose              # Separated static-detection vs. lock/integrity benchmark
npm run check && npm run check:practice # Validate Agent Customs & practice networks with Cognizant's kit
```

- **CLI & SARIF example:** `node bin/agent-customs.mjs check site/samples/mcp-poisoned --sarif`
- **Live MCP Registry check:** `node bin/agent-customs.mjs check https://raw.githubusercontent.com/microsoft/playwright-mcp/main/server.json`
- **GitHub Action (with `if: always()` so SARIF uploads even on HOLD/DENIED exit codes):**
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

---

## Defense in depth & verified security

### 1 · Three runtime locks (`locks.js`, `canary.js` + CSP)

| Lock | What it blocks | Mechanism |
| :--- | :--- | :--- |
| **Lock 1 · Secrets stay home** | Sending card numbers, IBANs, keys, or explicit creds out | Format-based matching with `\p{Nd}` Unicode digit folding (full-width, Arabic-Indic), bounded 1–3 char separators, Luhn/IBAN check digits, Base64 chunk decoding, and explicit credential redaction (`"bank login is ..."`) across turns, partner calls, MCP/sandbox args, actions, forms, and clicked links. |
| **Lock 2 · Actions & replies** | *"Quietly place an order"* & side-channel payloads | Quarantines unsafe replies, allow-lists output keys (`{ cruse, text, source, presentation: null }`), drops remote images (backed by page CSP) and foreign links, pins MCP `listTools()` digests against mid-session rug pulls, and requires human click confirmation for state-changing website actions once any external reply enters the chat. |
| **Lock 3 · Armed canary trap** | Hidden prompt dumps & encoded leaks | Appends a session canary (`ac_cnr_...`) to the top front agent's instructions at install/turn (restored cleanly on `uninstall()`). Outbound sinks scan for raw, URL, ROT13, spaced, hex, reversed, and 3-offset interior Base64/Base64url slices, halting execution and revoking partner approvals on trip. |

### 2 · How well it catches tricks (`tests/attacks.test.mjs`)

| What was tested | Sentences | Result |
| --- | --- | --- |
| A second review's sentences, written to get past the rules | 23 | All get the right verdict now |
| Scam sentences in English and the 10 checked languages | 32 | All blocked |
| Scam sentences in 11 other languages | 11 | All held for a person |
| Honest English sentences, many close to a scam's wording | 27 | None flagged |
| Honest sentences in other languages | 23 | None blocked |

- **10 checked secret languages:** Spanish, French, German, Portuguese, Italian, Russian, Chinese, Japanese, Hindi, Arabic. Non-English sentences outside clear English are held for human review (`C-LANGUAGE`), catching short Turkish and Indonesian lures cleanly (`tests/round2.test.mjs`).
- **Official & contestant sanity checks:** Cognizant's three official demos (`pizza_restaurant`, `guesthouse`, `harbor_tours`), Agent Customs itself, and all **31** offline benign bench controls evaluate cleanly with **0 false blocks**; an external Nov 2026 scan of 21 public contestant networks recorded **0 denied** (`14 CLEARED`, `2 CONDITIONS`, `4 HOLD` incl. 2 honest Indonesian sites, `1 INVALID`).

### 3 · Agent Customs Bench (`npm run bench` — [PAPER.md](PAPER.md))

Reproducible desktop benchmark (Node.js v24.18.0, win32, `$0` LLM cost) separating **Static Detection (`66` hostile + `31` benign controls)** from **Runtime Lock & Integrity Self-Tests (`16` checks)**, compared against a **Normalized Keyword Baseline** run *after* identical NFKC, tag-character decoding, and invisible-character stripping:

| Suite / Category | Cases | Agent Customs | Normalized Regex Baseline | Avg Latency |
| :--- | ---: | :--- | ---: | ---: |
| **Round 1 · `unicode_obfuscation`** | 12 | **100.0%** blocked/held | 58.3% | 5.61 ms |
| **Round 1 · `prompt_and_phishing`** | 24 | **100.0%** blocked/held | 16.7% | 2.07 ms |
| **Round 1 · `a2a_mcp_supply_chain`** | 6 | **66.7%** blocked/held *(**100%** flagged)* | 33.3% | 2.80 ms |
| **Round 2 · `round2_adversarial`** *(post-freeze)* | 24 | **95.8%** blocked/held *(**100%** flagged; pre-fix: **3/24**)* | 20.8% | 1.81 ms |
| **Benign controls** *(incl. 3 official demos, 10 MCP/A2A)* | 31 | **100.0%** clear (**0% false blocks**) | 90.3% *(9.7% false blocks)* | 3.43 ms |
| **Static Detection Total** | **97** | **63/66 (`95.5%`) blocked/held · 66/66 (`100%`) flagged** | **18/66 (`27.3%`) · 9.7% FP** | **1.48 ms detection median** |
| Lock & integrity self-tests (`locks` + `tampering`) | 16 | **16/16 (`100%`) passing** | *N/A* | 0.81–0.95 ms avg |

### 4 · Tamper-evident signed stamps (`ES256`) & key anchor

Signed stamps (`site/receipts/`) are 35-day ECDSA P-256 attestations bound to a partner's canonical SHA-256 fingerprint (`npm run receipts -- verify ... --live`).

- **Pinned Public Key Fingerprint (`-DC99sDa-qJjBp2N`):**
  `crv: "P-256"`, `kty: "EC"`, `x: "Wzq2yNI2mFX6Iz-GBeV7LKacVokiI396oifQRocfzxo"`, `y: "qdaCQ4K-07HN5yiq8CfFVUgRVtJm5uszNMsjuBqWQic"` (published at [`site/.well-known/agent-customs-key.json`](site/.well-known/agent-customs-key.json)).

> **Origin isolation note:** Browser `localStorage` pins and saved BYOK keys are scoped per origin (`<account>.github.io`). Production deployments should host Agent Customs on its own dedicated origin rather than sharing an origin with unrelated static portfolios.

---

<details>
<summary><b>The Practice Site, Test Range, Compatibility &amp; File Map</b></summary>

- **Practice Site ([`practice/`](practice/)):** Main Street Guide app wiring `Sunny Bakery` (`Cleared`), `Shady Pizza` (`Entry denied`), and `Loop Maze` (`Held for review`) using only the 2-line `guard.js` install (`npm run practice`).
- **Second-Origin Test Range (`range/`):** Deployed separately at https://agent-customs-range.github.io/ (`sunny_bakery`, `shady_pizza`, `bank_helper`, `loop_maze`, `rugpull/sunny_bakery`). Use `node tools/set-origins.mjs --range http://localhost:8081` + `node tools/rugpull.mjs on` to test drift locally.
- **Weekly Kit Compatibility:** [`.github/workflows/cognizant-kit.yml`](.github/workflows/cognizant-kit.yml) runs `npm test`, `npm run check`, and `npm run check:practice` weekly against `cognizant-ai-labs/agentic-web` `main`.
- **Files:** [`site/customs/`](site/customs/) (zero-dep engine) · [`bin/agent-customs.mjs`](bin/agent-customs.mjs) (CLI) · [`action.yml`](action.yml) (GitHub Action) · [`extension/`](extension/) (MV3 popup) · [`tools/`](tools/) (bench, receipts signer, range/practice builders) · [`PAPER.md`](PAPER.md) (threat model & limits) · [`tests/`](tests/) (`147` tests).

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
