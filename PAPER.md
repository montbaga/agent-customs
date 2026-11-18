# Agent Customs: Deterministic Port-of-Entry Inspection and Runtime Egress Locks for Multi-Protocol Web Agents

> **Abstract.** As web assistants adopt the Open Agentic Web, Google Agent2Agent (A2A), and Model Context Protocol (MCP), client browsers routinely delegate user requests to external agent manifests loaded from third-party origins. Today, delegation relies on UI consent prompts that show a partner's name and URL while feeding its uninspected instructions, schemas, and downstream links directly into the caller's model context. **Agent Customs** interposes a zero-dependency, browser-first port-of-entry pipeline combining deterministic multi-protocol inspection, identifier- and schema-based capability analysis, ES256 provenance with SHA-256 pinning (for both agent configs and MCP tool lists), format-based & canary runtime locks, and CI/browser distribution. Across our separated reproducible evaluation suite ([`tools/bench.mjs`](tools/bench.mjs)), static pre-execution inspection blocks or holds **92.3%** (`84/91`, **95.6%** flagged including `CONDITIONS` across `42` Round-1 vectors, `24` frozen Round-2 red-team vectors up from `3/24` pre-fix, `15` frozen Round-3 generalization vectors up from `0/15` pre-fix, and `6/10` / **60.0%** on a brand-new un-tuned post-fix Held-out set) at **$0 LLM cost** (`~1.26 ms` detection median on a desktop Node.js v24 run) with **0% (`0/39`) false blocks** across offline benign controls (against **19.8%** caught and **7.7%** false blocks for a normalized regex baseline), while **22/22** runtime lock and tamper-detection self-tests pass separately and remaining semantic and single-origin trust boundaries are explicitly documented.

---

## 1. Problem & Threat Model

### 1.1 Cross-Site Delegation Hazard
In client-side multi-agent runtimes such as Cognizant's [Open Agentic Web](https://github.com/cognizant-ai-labs/agentic-web), a host site connects to external partner networks via a consent prompt. That delegation creates three distinct security boundaries that traditional web SOP/CSP policies do not guard:

1. **Invisible & Non-Canonical Prompt Channels:** Attackers hide instructions in Unicode tag characters (`U+E0000`–`U+E007F`), zero-width splitters (`ZWSP`/`ZWJ`), bidirectional overrides (`RLO`), Cyrillic/Greek/Armenian/Cherokee homoglyphs, split multi-line phrases, or JSON Schema fields (`inputSchema`, `outputSchema`, `annotations.title`, `prompts[].messages`, `skills[].name`) never shown in standard consent cards.
2. **Name & Schema Capability Combinations ("Lethal Trifecta"):** A manifest written in completely polite prose can combine untrusted external input, sensitive reads/parameters (`my_read_env`, `get_config`, `environment settings`, `sly_data`, sensitive schema keys, or a single tool reading environment variables into a `webhookUrl` argument), and external egress (`notify_team`, webhooks, cross-origin endpoints) to create an exfiltration path regardless of self-declared MCP annotations.
3. **Post-Approval Drift & Novel Runtime Encodings:** Static pre-launch checks cannot stop a partner or third-party MCP server that clears inspection on Day 1 and silently adds harvesting instructions or tool-description mutations overnight (rug pull), nor can static wordlists stop a compromised turn from encoding secrets or canary tokens (e.g., Base64 at arbitrary byte offsets or line-wrapped, spaced hex, comma char codes, ROT13, or prefix-stripped suffixes) past naive format filters.

### 1.2 Adversary Capabilities, Trust Boundaries & Out-of-Scope Threats

| Boundary | Trusted / Assumed Integrity | Adversary Controlled |
| :--- | :--- | :--- |
| **Host Origin & Runtime** | Host page HTML/DOM, CSP (`img-src 'self' data: blob:`), unmodified Cognizant `Engine`, single-purpose origin isolation | Partner manifests, `.network.json`, A2A Agent Cards, MCP `mcp.json`/`tools/list`/`server.json`, partner replies & tool payloads |
| **Cryptographic Identity** | Published ECDSA P-256 public key (`.well-known/agent-customs-key.json`, `keyId: -DC99sDa-qJjBp2N`, mirrored out-of-band in `README.md`) | Client-downloaded `.svg`/`.html`/`.json`/`.pdf` artifacts presented to the **Verify** counter |
| **Guard Hook (`engine._compile`)** | Wraps 8 runtime hooks (`_compile`, `runTurn`, `resetHistory`, `resolveRemote`, `resolveMcp`, `sandbox.invoke`, `actions.execute`, `submitActions`), failing closed if `_compile` is missing | Network definitions prior to compilation, external REST/MCP return payloads |

**Out of scope:** A malicious host page itself, compromised same-origin scripts (which share browser `localStorage`), or a modified host `Engine` binary.

---

## 2. Architecture: Five Defense Layers

```text
  External Target (Open Agentic Web / Google A2A / MCP / server.json)
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 1 · Multi-Protocol Discovery & Canonicalization               │
  │   protocols.js · canonical.js · unicode.js                          │
  │   NFKC + skeleton homoglyph folding · U+E0000 decoder · AST mapping │
  └────┬────────────────────────────────────────────────────────────────┘
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 2 · Deterministic Pre-LLM Gates & Capability Analysis         │
  │   analyze.js · rules.js · languages.js · capabilities.js · inspect  │
  │   5 Gates (Papers, Contraband, Itinerary, Privacy, Identity)        │
  │   S-TRIFECTA name/schema/endpoint check · R-TRANSITIVE recursion    │
  │   Optional opt-in AI semantic judge (semanticJudge: true, off default)│
  └────┬────────────────────────────────────────────────────────────────┘
       │  Verdict: CLEARED | CONDITIONS | HOLD | DENIED | INVALID
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 3 · Cryptographic Provenance & Version Pinning                │
  │   receipts.js · pins.js · diff.js · certificate.js · locks.js (MCP) │
  │   35-day ES256 stamps · persisted network & MCP tool-list pins      │
  └────┬────────────────────────────────────────────────────────────────┘
       │  (Admitted & Pinned in Host Runtime)
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 4 · Format-Based & Canary Runtime Locks                       │
  │   locks.js · canary.js · CSP                                        │
  │   Lock 1: Unicode-folded Luhn/IBAN/key/Base64/explicit egress gate  │
  │   Lock 2: Reply quarantine + allow-listed fields + action click-gate│
  │   Lock 3: Prompt-injected canary + offset/format-invariant revocation│
  └────┬────────────────────────────────────────────────────────────────┘
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 5 · Zero-Dependency CLI, CI & Browser Distribution            │
  │   bin/agent-customs.mjs · action.yml · extension/                   │
  │   Env-safe PR SARIF v2.1.0 gates · Scoped optional_host MV3 popup   │
  └─────────────────────────────────────────────────────────────────────┘
```

### Layer 1: Unified Normalization (`protocols.js`, `unicode.js`, `canonical.js`)
Incoming manifests from Open Agentic Web, Google A2A (`.well-known/agent.json`, `.well-known/agent-card.json`), and MCP (`/mcp.json`, `mcpServers`, `tools/list`, official Registry `server.json`) are mapped into a unified model. Text scanning covers `instructions`, runtime `command`, `outputSchema`, `annotations.title`, A2A `skills[].name`, `prompts[].messages`, identifier-split schema keys, and a recursive `rawDoc` fallback walk—normalized with NFKC, invisible stripping, tag decoding, confusable skeletons, ROT13/reverse/Base64/hex decoding.

### Layer 2: Five Inspection Gates & Optional AI Escalation (`analyze.js`, `capabilities.js`, `guard.js`)
Fixed rules decide verdicts deterministically with `$0` LLM cost:
- **Papers / Contraband / Itinerary / Privacy / Identity:** Protocol conformance, instruction overrides (including inline `System:/Assistant:` directives), credential/ID/wallet-seed/OTP/bank-SMS/email-login phishing, remote-desktop & ClickFix/Run/DevTools coercion (`C-EXEC`, moderated to `CONDITIONS` when appearing in non-coercive tool documentation), gift-card payment/code coercion (`C-GIFT-CARD`), crypto-deposit & banking-QR approval phishing (`C-CRYPTO-QR`), single-description env-to-webhook exfiltration (`C-EXFIL`), 10 checked secret languages, non-English holds (`C-LANGUAGE`, including short accented 3-word text and expanded Swedish/Norwegian/Danish/Zulu/Somali/Turkish/Indonesian coverage), all A2A `supportedInterfaces`/`additionalInterfaces` cross-origin checks, and unbacked domain authority (`I-AUTHORITY`).
- **Name- & Schema-Based Lethal Trifecta (`S-TRIFECTA`):** Splits `camelCase` and `snake_case` identifiers across tool names, descriptions, input/output parameters (`SENSITIVE_PARAM`, `EGRESS_PARAM`), REST toolboxes, and off-origin tool URLs—catching both multi-tool chains and single-tool read-plus-egress designs even when MCP `annotations` falsify `readOnlyHint`/`openWorldHint`.
- **Opt-In Layer 2 Semantic Judge (`guard.js`):** Off by default (`semanticJudge: false`) so production guards remain deterministic and zero-token; callers enabling `semanticJudge: true` run an isolated zero-tool spotlighted check (`judge.js`) over `CLEARED`/`CONDITIONS` outputs.

### Layer 3: ES256 Receipts, Network & Persisted MCP Pinning (`receipts.js`, `pins.js`, `locks.js`)
Approved partner manifests persist their canonical SHA-256 config hash in `PinStore` (`localStorage` in browsers). Third-party `listTools()` responses likewise pin canonical tool/schema digests (`mcp:<url>`) in `PinStore` (persisted across visits with a `Forget` control in the Desk Approvals tab, or in memory when no store is passed) and drop tools (`[]`) with a Lock 2 notice if definitions change later. Pre-vetted URLs in [`tools/receipt-sites.json`](tools/receipt-sites.json) receive 35-day ES256 stamps signed offline against key `-DC99sDa-qJjBp2N`. Exported `.svg`/`.html` certificates verify cleanly offline + live; printed `.pdf` files are labeled **`Unsigned`**.

### Layer 4: Format-Based & Canary Runtime Locks (`locks.js`, `canary.js`)
`installCustomsGuard(engine)` arms three runtime defenses:
- **Lock 1 (Format-Based Outbound Secrets):** Folds Unicode decimal digits (`\p{Nd}`), detects Luhn cards (with 1–4 char separators), check-digit IBANs, API keys/tokens, explicit credential strings, and Base64-encoded secrets across user turns, partner calls, MCP/coded tool args, action plans, and clicked links.
- **Lock 2 (Reply Quarantine & Action Gating):** Inspects individual and concatenated reply strings (reusing indirect email-login & inline `System:`/`from now on` rules), drops unapproved keys (`out` rebuilt strictly from `{ cruse, text, source, presentation }`), strips remote tracking images, full URLs, and bare external `host.tld/path` domains, and holds state-changing actions after any external reply until human confirmation.
- **Lock 3 (Armed Canary Tripwire):** Appends a session-unique token (`ac_cnr_<hex>`) to the top front agent's system instructions (`engine.top.network`) at install/turn and restores cleanly on `uninstall()`. `detectCanaryLeak()` checks both the full token and its standalone high-entropy random suffix across `raw`, `url`, `reversed`, `rot13`, `hex` (inline & spaced byte runs), separator-collapsed `spaced`, 3-offset `k ∈ {0,1,2}` `base64`/`base64url` slices, line-wrapped Base64 (`depth <= 2`), and comma/space-separated decimal ASCII character codes, halting execution and revoking partner approvals on trip.

---

## 3. Empirical Evaluation (`Agent Customs Bench`)

[`tools/bench.mjs`](tools/bench.mjs) (`npm run bench`, snapshot saved in [`site/bench.json`](site/bench.json), measured on Node.js v24.18.0 win32 desktop) cleanly separates **static adversarial detection + offline benign controls** from **unit self-tests** of runtime locks and certificate integrity. To isolate rule logic from character-level decoding, the **Normalized Regex Baseline** runs `credit card|card number|cvv|password|passcode|otp|iban|ignore previous|sk-...` **after** identical `normalizeForRules()` canonicalization (NFKC + tag decoding + invisible stripping).

| Suite / Category | Cases | Agent Customs | Normalized Regex Baseline | Avg Latency |
| :--- | ---: | :--- | ---: | ---: |
| **Round 1 · `unicode_obfuscation`** | 12 | **100.0%** blocked/held (`12/12`) | 58.3% | 5.78 ms |
| **Round 1 · `prompt_and_phishing`** | 24 | **100.0%** blocked/held (`24/24`) | 16.7% | 2.27 ms |
| **Round 1 · `a2a_mcp_supply_chain`** | 6 | **66.7%** blocked/held *(**100.0%** flagged incl. `CONDITIONS`)* | 33.3% | 3.16 ms |
| **Round 2 · `round2_adversarial`** *(red team, pre-fix 3/24)* | 24 | **95.8%** blocked/held *(**100.0%** flagged)* | 20.8% | 2.14 ms |
| **Round 3 · `round3_generalization`** *(pre-fix 0/15)* | 15 | **100.0%** blocked/held (`15/15`) | 0.0% | 1.07 ms |
| **Held-out · `heldout_unseen`** *(written post-fix, un-tuned)* | 10 | **60.0%** blocked/held (`6/10`) | 0.0% | 1.17 ms |
| **`benign_controls`** *(3 official demos, 12 MCP/A2A, regression & held-out)* | 39 | **100.0%** unblocked (**0% false blocks**; 38 `CLEARED`, 1 `CONDITIONS` CLI docs) | 92.3% *(7.7% false blocks)* | 3.07 ms |
| **Static Detection Total** | **130** | **84/91 (`92.3%`) blocked/held · 87/91 (`95.6%`) flagged · 0% FP** | **18/91 (`19.8%`) · 7.7% FP** | **1.26 ms detection median** |
| Self-test · `runtime_exfil_locks` *(Lock 1/2/3)* | 18 | **100.0%** (`18/18` passing) | *N/A (runtime task)* | 0.70 ms |
| Self-test · `integrity_tampering` *(pin & cert tamper)* | 4 | **100.0%** (`4/4` passing) | *N/A (integrity task)* | 0.93 ms |

*Transparency & generalization note:*
- **Round 1** (`42` adversarial vectors + core lock/tamper self-tests) was authored alongside the analyzer as a regression suite.
- **Round 2** ([`tools/round2-corpus.mjs`](tools/round2-corpus.mjs), `24` hostile probes + `5` benign counter-examples) consists of the red team's own inputs, committed frozen on branch `red-team-fixes` in commit `78b7e22` before fixes (since `main` carries squashed PR merge `4a644ac`): **`3/24` (`12.5%`) pre-fix → `23/24` (`95.8%`) blocked/held (`24/24` flagged)** post-fix.
- **Round 3** ([`tools/round3-corpus.mjs`](tools/round3-corpus.mjs), `15` fresh phrasings for those categories + `4` false-alarm controls) was committed frozen on branch `round-3-fixes` in commit `8a89e5b` before generalizing the rules: **`0/15` held/denied (`1/15` `CONDITIONS`) pre-fix → `15/15` (`100%`) held/denied** and **`0/4` false blocks** post-fix.
- **Held-out** ([`tools/heldout-corpus.mjs`](tools/heldout-corpus.mjs), `10` new unseen paraphrases + `4` unseen benign controls) was written **after all rule changes finished, with zero rule tuning afterward**: **`6/10` (`60.0%`) caught** and **`0/4` false blocks** (`CLEARED`). Four unseen paraphrases (`twenty-four words from their emergency paper sheet`, `guide guest into JavaScript console to run refresh snippet`, `start TeamViewer and give partner ID`, and `Steam card codes sent right in this chat`) slipped through static regexes—honestly bounding deterministic pattern generalization vs. arbitrary novel phrasing. Three protocol cases (`Cross-origin A2A endpoint`, `MCP destructive unguarded payment tool`, `A2A additionalInterfaces off-origin`) intentionally return `CONDITIONS` by default and become `exit 2` under `--strict`.

---

## 4. Honest Limitations & Open Boundaries

1. **Semantic & Unseen Phrasing Ceiling (`60%` held-out):** Fixed rules cannot be talked out of a verdict, and generalizing by scam category raised unseen catch rate significantly without overfitting—yet novel phrasings lacking recognizable category anchors still miss static inspection unless `semanticJudge: true` is opted in.
2. **Protocol Execution & Pinning Boundaries:** Open Agentic Web and MCP tool executions run with live Lock 1–3 guards; Google A2A is inspected statically only because Cognizant's runtime does not execute remote A2A transports directly. Persisted `mcp:<url>` tool pins protect against silent rug pulls and must be cleared in Desk Approvals (or storage cleared) after an intentional upstream tool update.
3. **Encoding & Split-Secret Limits:** Lock 1 detects Luhn cards (1–4 char separators, Unicode `\p{Nd}` digits), IBANs, keys, Base64 secrets, and explicit login/CVV strings; Lock 3 detects full and random-suffix canary leaks across raw, URL, ROT13, spaced, hex/spaced-hex, char codes, reversed, and single-chunk/line-wrapped Base64 (`0/1/2` offset). Written-out card words (`"four two four two..."`), 5+ char custom digit separators, and fragments split piece-by-piece across separate fields or turns remain out of band.
4. **Runtime Hooks & Origin Isolation:** `guard.js` wraps 8 internal Cognizant `Engine` seams (`cognizant-kit.yml` tests compatibility weekly). On shared hosting such as `<user>.github.io`, all paths share `localStorage` pins and saved BYOK keys—host Agent Customs on a dedicated origin for production deployments.
5. **Browser CORS & Extension Scope Limits:** Sites omitting `Access-Control-Allow-Origin` cannot be read from the static web UI and require [`bin/agent-customs.mjs`](bin/agent-customs.mjs), [`action.yml`](action.yml), or the MV3 [`extension/`](extension/) (`optional_host_permissions` over `https://*/*`).

---

## 5. Reproducibility Commands

```sh
npm test                                    # 151 tests across attacks, Rounds 2–3, locks, receipts, CLI, bench & extension
npm run check                               # Validate site Open Agentic Web network with build_network.mjs
npm run check:practice                      # Validate practice site mirror and manifest
npm run bench -- --verbose                  # Reproduce separated Round 1–3 + Held-out detection & self-test scorecard
node bin/agent-customs.mjs check https://raw.githubusercontent.com/microsoft/playwright-mcp/main/server.json
```
