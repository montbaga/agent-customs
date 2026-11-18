# Agent Customs: Deterministic Port-of-Entry Inspection and Runtime Egress Locks for Multi-Protocol Web Agents

> **Abstract.** As web assistants adopt the Open Agentic Web, Google Agent2Agent (A2A), and Model Context Protocol (MCP), client browsers routinely delegate user requests to external agent manifests loaded from third-party origins. Today, delegation relies on UI consent prompts that show a partner's name and URL while feeding its uninspected instructions, schemas, and downstream links directly into the caller's model context. **Agent Customs** interposes a zero-dependency, browser-first port-of-entry pipeline combining deterministic multi-protocol inspection, identifier- and schema-based capability analysis, ES256 provenance with SHA-256 pinning (for both agent configs and MCP tool lists), format-based & canary runtime locks, and CI/browser distribution. Across our separated reproducible evaluation suite ([`tools/bench.mjs`](tools/bench.mjs)), static pre-execution inspection blocks or holds **87.8%** (`86/98`, **90.8%** flagged including `CONDITIONS` across `42` Round-1 vectors, `24` frozen Round-2 red-team vectors up from `3/24`, `15` frozen Round-3 vectors up from `0/15`, `5/10` / **50.0%** internal un-tuned held-out vectors, and `3/7` / **42.9%** frozen verbatim third-party probes via format detectors; across the full 20-case third-party unseen wording set, independent re-checks measured `1/20` pre-format and `4/20` after format additions) at **$0 LLM cost** (`~2.64 ms` detection median on a desktop Node.js v24 run) with **0% (`0/61`) false blocks** across offline benign controls (against **19.4%** caught and **8.2%** false blocks for a normalized regex baseline), while **25/25** runtime lock and tamper-detection self-tests pass separately and remaining semantic and single-origin trust boundaries are explicitly documented.

---

## 1. Problem & Threat Model

### 1.1 Cross-Site Delegation Hazard
In client-side multi-agent runtimes such as Cognizant's [Open Agentic Web](https://github.com/cognizant-ai-labs/agentic-web), a host site connects to external partner networks via a consent prompt. That delegation creates three distinct security boundaries that traditional web SOP/CSP policies do not guard:

1. **Invisible & Non-Canonical Prompt Channels:** Attackers hide instructions in Unicode tag characters (`U+E0000`–`U+E007F`), zero-width splitters (`ZWSP`/`ZWJ`), bidirectional overrides (`RLO`), Cyrillic/Greek/Armenian/Cherokee homoglyphs, split multi-line phrases, or JSON Schema fields (`inputSchema`, `outputSchema`, `annotations.title`, `prompts[].messages`, `skills[].name`) never shown in standard consent cards.
2. **Name & Schema Capability Combinations ("Lethal Trifecta"):** A manifest written in completely polite prose can combine untrusted external input, sensitive reads/parameters (`my_read_env`, `get_config`, `environment settings`, `sly_data`, sensitive schema keys, or a single tool reading environment variables into a `webhookUrl` argument), and external egress (`notify_team`, webhooks, cross-origin endpoints) to create an exfiltration path regardless of self-declared MCP annotations—while avoiding false alarms on benign typed parameters such as a travel tool's `destination` city string.
3. **Post-Approval Drift & Novel Runtime Encodings:** Static pre-launch checks cannot stop a partner or third-party MCP server that clears inspection on Day 1 and silently adds harvesting instructions or tool-description mutations overnight (rug pull), nor can static wordlists stop a compromised turn from encoding secrets or canary tokens (e.g., MIME/64-column line-wrapped Base64 inside JSON tool argument leaves, spaced hex, comma char codes, ROT13, or prefix-stripped suffixes) past naive format filters.

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
  │   S-TRIFECTA name/schema/endpoint check · format-based rules        │
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
  │   Lock 3: Prompt-injected canary + leaf-walked offset-invariant trip │
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
Fixed rules serve as a fast deterministic filter (`$0` LLM cost), prioritizing generalizable **format-based** checks alongside high-precision social-engineering gates:
- **Papers / Contraband / Itinerary / Privacy / Identity:** Protocol conformance, instruction overrides (excluding benign few-shot dialogues and non-data formatting instructions), credential/ID/wallet-seed/OTP/bank-SMS/email-login phishing (requiring copy/recipient context on card scans so kiosk loyalty scans clear), remote-desktop & ClickFix/Run/DevTools coercion (`C-EXEC`, excluding patch-notes links and benign developer debugging tips, moderated to `CONDITIONS` in CLI documentation), gift-card coercion (`C-GIFT-CARD`), crypto-transfer / redirected-IBAN / QR-approval scams (`C-CRYPTO-QR`, requiring a transfer verb in the same clause for `0x[40 hex]`/Bech32/Tron addresses, a transfer diversion signal for IBAN wires while surfacing unredirected business IBAN notices at `CONDITIONS` via `C-BANK-DETAILS`, and explicit banking-approval coercion on QR scans), scriptable link/data URLs (`C-EXFIL`, requiring link context and code/payload after `javascript:`/`data:text/html` so prose discussions clear), single-description env-to-configured-server tools (`CONDITIONS` unless targeting chat/cookies/webhooks/code URLs), 10 checked secret languages, non-English holds (`C-LANGUAGE`, keeping 3-word accented dishes/greetings clear while holding multi-token foreign requests), A2A `supportedInterfaces`/`additionalInterfaces`, and unbacked authority (`I-AUTHORITY`).
- **Name- & Schema-Based Lethal Trifecta (`S-TRIFECTA`):** Splits `camelCase` and `snake_case` identifiers across tool names, descriptions, schema parameters (`SENSITIVE_PARAM` and URL/description-qualified egress params so benign fields like `book_trip(destination)` stay `CLEARED`), REST toolboxes, and off-origin tool URLs—catching both multi-tool chains and single-tool read-plus-egress designs even when MCP `annotations` falsify `readOnlyHint`/`openWorldHint`.
- **Opt-In Layer 2 Semantic Judge (`guard.js`):** Off by default (`semanticJudge: false`) so production guards remain deterministic and zero-token; callers enabling `semanticJudge: true` run an isolated zero-tool spotlighted check (`judge.js`) over `CLEARED`/`CONDITIONS` outputs to cover unseen phrasing.

### Layer 3: ES256 Receipts, Network & Persisted MCP Pinning (`receipts.js`, `pins.js`, `locks.js`)
Approved partner manifests persist their canonical SHA-256 config hash in `PinStore` (`localStorage` in browsers). Third-party `listTools()` responses likewise pin canonical tool/schema digests (`mcp:<url>`) in `PinStore` (forgettable in the Desk Approvals tab, or session-scoped when no store is passed) and drop tools (`[]`) with a Lock 2 notice if definitions change later. Pre-vetted URLs in [`tools/receipt-sites.json`](tools/receipt-sites.json) receive 35-day ES256 stamps signed offline against key `-DC99sDa-qJjBp2N`. Exported `.svg`/`.html` certificates verify cleanly offline + live; printed `.pdf` files are labeled **`Unsigned`**.

### Layer 4: Format-Based & Canary Runtime Locks (`locks.js`, `canary.js`)
Because unseen wording can slip past any static filter, `installCustomsGuard(engine)` arms three wording-agnostic runtime defenses:
- **Lock 1 (Format-Based Outbound Secrets):** Folds Unicode decimal digits (`\p{Nd}`), detects Luhn cards (1–4 char separators; bounded `IMEI`/`IMSI`/`ICCID` keyword+length exemptions apply to visitor-typed chat input only, never outbound traffic or `order`/`invoice`/`receipt`/`tracking` prefixes), ISO 7064 check-digit IBANs, API keys/tokens, explicit credential strings, and Base64-encoded secrets across user turns, partner calls, MCP/coded tool args, action plans, and clicked links.
- **Lock 2 (Reply Quarantine & Action Gating):** Inspects individual and concatenated reply strings (reusing indirect email-login & targeted override rules), drops unapproved keys (`out` rebuilt strictly from `{ cruse, text, source, presentation }`), strips remote tracking images, full URLs, and bare external domains (with or without `/path`, e.g., `evil.invalid`), and holds state-changing actions after any external reply until human confirmation.
- **Lock 3 (Armed Canary Tripwire):** Appends a session-unique token (`ac_cnr_<hex>`) to the top front agent's system instructions (`engine.top.network`) at install/turn and restores cleanly on `uninstall()`. `detectCanaryLeak()` recursively walks individual string leaves inside structured objects (preserving real newlines before whitespace/`\\[nrt]` collapse) and checks both the full token and its standalone high-entropy random suffix across `raw`, `url`, `reversed`, `rot13`, inline/spaced `hex`, separator-collapsed `spaced`, 3-offset `k ∈ {0,1,2}` `base64`/`base64url` slices, MIME/64-column wrapped Base64 (`depth <= 2`, catching `80/80` padding offsets inside `toolArgs`), and comma ASCII character codes, halting execution and revoking partner approvals on trip.

---

## 3. Empirical Evaluation (`Agent Customs Bench`)

[`tools/bench.mjs`](tools/bench.mjs) (`npm run bench`, snapshot saved in [`site/bench.json`](site/bench.json), measured on Node.js v24.18.0 win32 desktop) separates **static adversarial detection + offline benign controls** from **unit self-tests** of runtime locks and certificate integrity. To isolate rule logic from character-level decoding, the **Normalized Regex Baseline** runs `credit card|card number|cvv|password|passcode|otp|iban|ignore previous|sk-...` **after** identical `normalizeForRules()` canonicalization (NFKC + tag decoding + invisible stripping).

| Suite / Category | Cases | Agent Customs | Normalized Regex Baseline | Avg Latency |
| :--- | ---: | :--- | ---: | ---: |
| **Round 1 · `unicode_obfuscation`** | 12 | **100.0%** blocked/held (`12/12`) | 58.3% | 12.40 ms |
| **Round 1 · `prompt_and_phishing`** | 24 | **100.0%** blocked/held (`24/24`) | 16.7% | 4.74 ms |
| **Round 1 · `a2a_mcp_supply_chain`** | 6 | **66.7%** blocked/held *(**100.0%** flagged incl. `CONDITIONS`)* | 33.3% | 6.74 ms |
| **Round 2 · `round2_adversarial`** *(red team, pre-fix 3/24)* | 24 | **95.8%** blocked/held *(**100.0%** flagged)* | 20.8% | 4.21 ms |
| **Round 3 · `round3_generalization`** *(pre-fix 0/15)* | 15 | **100.0%** blocked/held (`15/15`) | 0.0% | 2.46 ms |
| **Held-out · `heldout_unseen`** *(internal, written post-fix)* | 10 | **50.0%** blocked/held (`5/10`) | 0.0% | 2.11 ms |
| **External · `external_heldout_quoted`** *(7 quoted from 20-case third-party set; pre-format 0/7)* | 7 | **42.9%** blocked/held (`3/7` via format rules) | 14.3% | 1.91 ms |
| **`benign_controls`** *(3 official demos, 14 MCP/A2A, Round-3, held-out & 22 re-check controls; see below for live 135+57 MCP/A2A eval)* | 61 | **100.0%** unblocked (**0% false blocks on curated controls**; 57 `CLEARED`, 4 `CONDITIONS`) | 91.8% *(8.2% false blocks)* | 5.02 ms |
| **Static Detection Total** | **159** | **86/98 (`87.8%`) blocked/held · 89/98 (`90.8%`) flagged · 0% FP (curated)** | **19/98 (`19.4%`) · 8.2% FP** | **2.83 ms detection median** |
| Self-test · `runtime_exfil_locks` *(Lock 1/2/3)* | 21 | **100.0%** (`21/21` passing) | *N/A (runtime task)* | 1.67 ms |
| Self-test · `integrity_tampering` *(pin & cert tamper)* | 4 | **100.0%** (`4/4` passing) | *N/A (integrity task)* | 2.01 ms |

*Transparency & generalization note:*
- **Round 1** (`42` adversarial vectors + core lock/tamper self-tests) was authored alongside the analyzer as a regression suite.
- **Round 2** ([`tools/round2-corpus.mjs`](tools/round2-corpus.mjs), `24` hostile probes + `5` benign counter-examples) consists of the red team's own inputs, committed frozen on branch `red-team-fixes` in commit `a25e45a` before fixes (since `main` carries squashed PR merge `9675295`): **`3/24` (`12.5%`) pre-fix → `23/24` (`95.8%`) blocked/held (`24/24` flagged)** post-fix.
- **Round 3** ([`tools/round3-corpus.mjs`](tools/round3-corpus.mjs), `15` fresh phrasings for those categories + `4` false-alarm controls) was committed frozen on branch `round-3-fixes` in commit `4281300` before rule edits: **`0/15` held/denied (`1/15` `CONDITIONS`) pre-fix → `15/15` (`100%`) held/denied** and **`0/4` false blocks**.
- **Internal Held-out** ([`tools/heldout-corpus.mjs`](tools/heldout-corpus.mjs), `10` adversarial + `4` benign) was written after the Round-3 rule edits (committed alongside those changes in `66dbbf3`) with zero rule tuning afterward: **`5/10` (`50.0%`) caught** (`0/4` false blocks; tightening QR false-positive rules dropped one QR fee wording cleanly without re-tuning rules).
- **External Third-Party Held-out & Re-check Regressions:** Independent re-checks tested **20** third-party unseen scam wordings (recording `1/20` held before format additions, **`4/20` held** after `0x`/IBAN/`javascript:` format rules). The **7 verbatim quoted vectors** and **13 static controls** from the second re-check were committed frozen before fixes on `recheck-2-fixes` (`5a0210d`: **`0/7` → `3/7` (`42.9%`)** via general format rules with the remaining 13 unquoted probes left un-tuned); the **9 false-alarm controls** (bare `javascript:`/`data:text/html` mentions, bare `0x` contract queries including the live `mint_verifier_network` sample query, and business IBAN notices moved to `CONDITIONS`) and **6 Lock 1 prefix probes** from the third re-check were likewise frozen in [`tools/external-heldout.mjs`](tools/external-heldout.mjs) prior to edits (**`0/9` allowed → `9/9` unblocked**, **`0/6` → `6/6` Lock 1 checks passing**). Re-checking across `33` readable live contestant and Cognizant official networks showed **`0` verdict diffs vs `e4b345b`** (restoring `mint_verifier_network` to `CLEARED`). Three protocol cases (`Cross-origin A2A endpoint`, `MCP destructive unguarded payment tool`, `A2A additionalInterfaces off-origin`) intentionally return `CONDITIONS` by default and become `exit 2` under `--strict`.
- **Live MCP/A2A Real-World & Unseen Registry Evaluation ([`tests/realworld.test.mjs`](tests/realworld.test.mjs)):** Snapshotting **135** live public targets (17 well-known MCP servers, 83 anonymous MCP Registry servers, 35 Google A2A Agent Cards) prior to edits revealed **43/135 (`32%`)** false alarms on `17e8bc8` (and 6 debatable), driven by technical regexes, URIs, JSON, abbreviations, and identifiers firing `C-LANGUAGE` (37/43), base64/SVG icon data URIs (`C-ENCODED`/`C-EXFIL`), same-site referral/output links, own-server `Authorization: Bearer`/`Cookie` auth header docs, wording false hits (`before asking ... to`, `omit ... alerts`, `as an app in developer mode`, `complete kit`), `session_id`/`delete_token`/partner `apiKey` `S-TRIFECTA` handles, synthetic schema secret quotes, and `x402`/`0x` query-param misfires. Frozen in [`tests/fixtures/realworld/`](tests/fixtures/realworld/) first, root-cause fixes cut development-set false alarms from **`43/135` to `0/135`** (`0` missed among 10 keepers, `0` regressions on previously unblocked targets). Evaluated **once afterward with zero rule tuning** on **57** responsive unseen MCP Registry servers (`reg-urls.txt` lines 151–310; `160` queried, `103` HTTP 401/403/405 or unreachable anonymously): **32 `CLEARED`**, **11 `CONDITIONS`**, **9 `HOLD`**, **5 `DENIED`** (`5` justified holds/denials kept for Chinese/Korean prose, explicit `password` fields, and credential + egress capabilities; **`9/57` (`15.8%`: 7 clear + 2 borderline `S-TRIFECTA`)** unseen false alarms).

---

## 4. Honest Limitations & Open Boundaries

1. **Static Unseen-Phrasing Ceiling (`4/20` external, `50%` internal) & Live False Alarms:** Category rules caught every Round-3 case, but on 20 independent third-party wordings static rules held **`1/20`** pre-format (**`4/20`** after general format rules, **`3/7`** on the frozen quoted subset, leaving unquoted sentence phrasing un-tuned); static rules serve only as a fast `$0` first filter, while runtime Locks 1–3 and opt-in `semanticJudge: true` cover unseen phrasing at execution time. The **`0%` false-block rate** in Section 3 reflects the **61** offline curated controls (and **`0/135`** on the tuned real-world dev set); on **57** unseen live MCP Registry servers, un-tuned real-world phrasing and handle names still produced **`9/57` (`15.8%`)** false blocks (`7` clear + `2` borderline `S-TRIFECTA`).
2. **Protocol Execution & Pinning Boundaries:** Open Agentic Web and MCP tool executions run with live Lock 1–3 guards; Google A2A is inspected statically only because Cognizant's runtime does not execute remote A2A transports directly. Persisted `mcp:<url>` tool pins protect against silent rug pulls and must be cleared in Desk Approvals (or storage cleared) after an intentional upstream tool update.
3. **Encoding & Split-Secret Limits:** Lock 1 detects Luhn cards (1–4 char separators, Unicode `\p{Nd}` digits; bounded inbound-only visitor chat exemptions for `IMEI` 15-digit, `IMSI` 14–15-digit, and `ICCID` 19–20-digit identifiers within 3 words, with zero outbound exemptions in `findSensitiveData`), IBANs, keys, Base64 secrets, and explicit login/CVV strings; Lock 3 detects full and random-suffix canary leaks across raw, URL, ROT13, spaced, hex/spaced-hex, char codes, reversed, single-chunk Base64, and line-wrapped Base64 inside structured object leaves (`80/80` at columns 64 & 76). Written-out card words (`"four two four two..."`), 5+ char custom digit separators, and fragments split piece-by-piece across separate fields or turns remain out of band.
4. **Runtime Hooks & Origin Isolation:** `guard.js` wraps 8 internal Cognizant `Engine` seams (`cognizant-kit.yml` tests compatibility weekly). On shared hosting such as `<user>.github.io`, all paths share `localStorage` pins and saved BYOK keys—host Agent Customs on a dedicated origin for production deployments.
5. **Browser CORS, Auth-Gated Servers & Language Scope:** Sites omitting `Access-Control-Allow-Origin` cannot be read from the static web UI and require [`bin/agent-customs.mjs`](bin/agent-customs.mjs), [`action.yml`](action.yml), or the MV3 [`extension/`](extension/) (`optional_host_permissions` over `https://*/*`). Login-gated MCP/A2A servers (e.g., `HTTP 401/403` on OAuth-authenticated enterprise endpoints and ~103 of 160 registry URLs) cannot be inspected anonymously without credentials. Language heuristics skip non-prose metadata keys and common code/regex/URI tokens, which reduces false holds on English tech catalogs but can still flag terse non-English-looking technical fragments or OTP/refresh-token docs.

---

## 5. Reproducibility Commands

```sh
npm test                                    # 156 tests across attacks, Rounds 2–3, 135 real-world MCP/A2A targets, locks, receipts, CLI, bench & extension
npm run check                               # Validate site Open Agentic Web network with build_network.mjs
npm run check:practice                      # Validate practice site mirror and manifest
npm run bench -- --verbose                  # Reproduce separated Round 1–3, Held-out & quoted external detection + self-test scorecard
node bin/agent-customs.mjs check https://raw.githubusercontent.com/microsoft/playwright-mcp/main/server.json
```
