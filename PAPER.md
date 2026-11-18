# Agent Customs: Deterministic Port-of-Entry Inspection and Runtime Egress Locks for Multi-Protocol Web Agents

> **Abstract.** As web assistants adopt the Open Agentic Web, Google Agent2Agent (A2A), and Model Context Protocol (MCP), client browsers routinely delegate user requests to external agent manifests loaded from third-party origins. Today, delegation relies on UI consent prompts that show a partner's name and URL while feeding its uninspected instructions, schemas, and downstream links directly into the caller's model context. **Agent Customs** interposes a zero-dependency, browser-first port-of-entry pipeline combining deterministic multi-protocol inspection, identifier- and schema-based capability analysis, ES256 provenance with SHA-256 pinning (for both agent configs and MCP tool lists), format-based & canary runtime locks, and CI/browser distribution. Across our separated reproducible evaluation suite ([`tools/bench.mjs`](tools/bench.mjs)), static pre-execution inspection blocks or holds **95.5%** (`63/66`, **100%** flagged including `CONDITIONS` across `42` Round-1 vectors + `24` frozen Round-2 red-team vectors up from `3/24` pre-fix) at **$0 LLM cost** (`~1.48 ms` detection median on a desktop Node.js v24 run) with **0% (`0/31`) false blocks** across offline benign controls (against **27.3%** caught and **9.7%** false blocks for a normalized regex baseline), while **16/16** runtime lock and tamper-detection self-tests pass separately and remaining semantic and single-origin trust boundaries are explicitly documented.

---

## 1. Problem & Threat Model

### 1.1 Cross-Site Delegation Hazard
In client-side multi-agent runtimes such as Cognizant's [Open Agentic Web](https://github.com/cognizant-ai-labs/agentic-web), a host site connects to external partner networks via a consent prompt. That delegation creates three distinct security boundaries that traditional web SOP/CSP policies do not guard:

1. **Invisible & Non-Canonical Prompt Channels:** Attackers hide instructions in Unicode tag characters (`U+E0000`–`U+E007F`), zero-width splitters (`ZWSP`/`ZWJ`), bidirectional overrides (`RLO`), Cyrillic/Greek/Armenian/Cherokee homoglyphs, split multi-line phrases, or JSON Schema fields (`inputSchema`, `outputSchema`, `annotations.title`, `prompts[].messages`, `skills[].name`) never shown in standard consent cards.
2. **Name & Schema Capability Combinations ("Lethal Trifecta"):** A manifest written in completely polite prose can combine untrusted external input, sensitive reads/parameters (`my_read_env`, `get_config`, `environment settings`, `sly_data`, sensitive schema keys), and external egress (`notify_team`, webhooks, cross-origin endpoints) to create an exfiltration path regardless of self-declared MCP annotations.
3. **Post-Approval Drift & Novel Runtime Encodings:** Static pre-launch checks cannot stop a partner or third-party MCP server that clears inspection on Day 1 and silently adds harvesting instructions or tool-description mutations overnight (rug pull), nor can static wordlists stop a compromised turn from encoding secrets (e.g., Base64 at arbitrary byte offsets, hex, or ROT13) past naive format filters.

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
  │   35-day ES256 stamps · SHA-256 network & MCP tool-list pins        │
  └────┬────────────────────────────────────────────────────────────────┘
       │  (Admitted & Pinned in Host Runtime)
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 4 · Format-Based & Canary Runtime Locks                       │
  │   locks.js · canary.js · CSP                                        │
  │   Lock 1: Unicode-folded Luhn/IBAN/key/Base64/explicit egress gate  │
  │   Lock 2: Reply quarantine + allow-listed fields + action click-gate│
  │   Lock 3: Prompt-injected canary + offset-invariant leak revocation │
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
- **Papers / Contraband / Itinerary / Privacy / Identity:** Protocol conformance, instruction overrides, financial/ID/seed/credential/malware/remote-access/gift-card/bank-forwarding phishing, 10 checked secret languages, short non-English holds (`C-LANGUAGE`), all A2A `supportedInterfaces`/`additionalInterfaces` cross-origin checks, and unbacked domain authority (`I-AUTHORITY`).
- **Name- & Schema-Based Lethal Trifecta (`S-TRIFECTA`):** Splits `camelCase` and `snake_case` identifiers across tool names, descriptions, schema properties, REST toolboxes, and off-origin tool URLs. MCP `annotations` (`readOnlyHint`, `destructiveHint`, `openWorldHint`) can raise risk when present, never lower or suppress concrete name, schema, or external URL findings.
- **Opt-In Layer 2 Semantic Judge (`guard.js`):** Off by default (`semanticJudge: false`) so production guards remain deterministic and zero-token; callers enabling `semanticJudge: true` run an isolated zero-tool spotlighted check (`judge.js`) over `CLEARED`/`CONDITIONS` outputs.

### Layer 3: ES256 Receipts, SHA-256 Network & MCP Pinning (`receipts.js`, `pins.js`, `locks.js`)
Approved partner manifests pin their canonical SHA-256 config hash in `PinStore`, while third-party `listTools()` responses pin canonical tool/schema digests (`mcp:<url>`) on first use and drop the server's tools (`[]`) with a Lock 2 notice if definitions change later. Pre-vetted URLs in [`tools/receipt-sites.json`](tools/receipt-sites.json) receive 35-day ES256 stamps signed offline against key `-DC99sDa-qJjBp2N`. Exported `.svg`/`.html` certificates verify cleanly offline + live; printed `.pdf` files are labeled **`Unsigned`**.

### Layer 4: Format-Based & Canary Runtime Locks (`locks.js`, `canary.js`)
`installCustomsGuard(engine)` arms three runtime defenses:
- **Lock 1 (Format-Based Outbound Secrets):** Folds Unicode decimal digits (`\p{Nd}`, e.g. full-width and Arabic-Indic), detects Luhn cards (with 1–3 separators), check-digit IBANs, API keys/tokens, explicit credential strings (`"bank login is ..."`, `"3 digits on back are ..."`), and Base64-encoded secrets across user turns, partner calls, MCP/coded tool args, action plans, and clicked links.
- **Lock 2 (Reply Quarantine & Action Gating):** Inspects individual and concatenated reply strings, drops unapproved custom keys (`out` rebuilt from allow-listed `{ cruse, text, source, presentation: null }`), strips remote tracking images and foreign links, and holds state-changing actions after any external reply until human confirmation.
- **Lock 3 (Armed Canary Tripwire):** At guard install and each turn, appends a session-unique token (`ac_cnr_...`) to the top front agent's system instructions (`engine.top.network`) and restores original instructions cleanly on `uninstall()`. `detectCanaryLeak()` checks `raw`, `url`, `reversed`, `rot13`, `hex`, separator-collapsed `spaced`, 3-offset `k ∈ {0,1,2}` interior `base64`/`base64url` slices, and recursive Base64 chunk decodes (`depth <= 2`), halting execution and revoking partner approvals on leak.

---

## 3. Empirical Evaluation (`Agent Customs Bench`)

[`tools/bench.mjs`](tools/bench.mjs) (`npm run bench`, snapshot saved in [`site/bench.json`](site/bench.json), measured on Node.js v24.18.0 win32 desktop) cleanly separates **static adversarial detection + offline benign controls** from **unit self-tests** of runtime locks and certificate integrity. To isolate rule logic from character-level decoding, the **Normalized Regex Baseline** runs `credit card|card number|cvv|password|passcode|otp|iban|ignore previous|sk-...` **after** identical `normalizeForRules()` canonicalization (NFKC + tag decoding + invisible stripping).

| Suite / Category | Cases | Agent Customs | Normalized Regex Baseline | Avg Latency |
| :--- | ---: | :--- | ---: | ---: |
| **Round 1 · `unicode_obfuscation`** | 12 | **100.0%** blocked/held (`12/12`) | 58.3% | 5.61 ms |
| **Round 1 · `prompt_and_phishing`** | 24 | **100.0%** blocked/held (`24/24`) | 16.7% | 2.07 ms |
| **Round 1 · `a2a_mcp_supply_chain`** | 6 | **66.7%** blocked/held *(**100.0%** flagged incl. `CONDITIONS`)* | 33.3% | 2.80 ms |
| **Round 2 · `round2_adversarial`** *(post-freeze)* | 24 | **95.8%** blocked/held *(**100.0%** flagged; up from **3/24 / 12.5%** pre-fix)* | 20.8% | 1.81 ms |
| **`benign_controls`** *(incl. 3 official demos & 10 MCP/A2A schemas)* | 31 | **100.0%** clean (**0% false blocks**) | 90.3% *(9.7% false blocks)* | 3.43 ms |
| **Static Detection Total** | **97** | **63/66 (`95.5%`) blocked/held · 66/66 (`100%`) flagged · 0% FP** | **18/66 (`27.3%`) · 9.7% FP** | **1.48 ms detection median** |
| Self-test · `runtime_exfil_locks` *(Lock 1/2/3)* | 12 | **12/12 (`100%`) passing** | *N/A (runtime task)* | 0.81 ms |
| Self-test · `integrity_tampering` *(pin & cert tamper)* | 4 | **4/4 (`100%`) passing** | *N/A (integrity task)* | 0.95 ms |

*Transparency note:* Round-1 detection vectors (`42` adversarial cases) and self-tests (`16`) were authored alongside the analyzer as a regression benchmark. Round 2 (`tools/round2-corpus.mjs`, `24` hostile probes + `5` benign counter-examples from external red-team probing) was committed frozen in git **before** fixing the rules (`3/24` caught before fixes -> `23/24` blocked/held and `24/24` flagged after fixes). Three protocol cases (`Cross-origin A2A endpoint`, `MCP destructive unguarded payment tool`, `A2A additionalInterfaces off-origin`) intentionally return `CONDITIONS` by default and become `exit 2` under `--strict`.

---

## 4. Honest Limitations & Open Boundaries

1. **Semantic & Unseen Social Engineering Without Known Indicators:** Fixed rules can't be talked out of a verdict, and runtime locks limit damage when a novel wording gets past static checks—yet arbitrary polite persuasion lacking recognizable malware, credential, remote-access, payment, or capability patterns remains hard for static analyzers unless `semanticJudge: true` is opted in.
2. **Protocol Execution & Pinning Boundaries:** Open Agentic Web and MCP tool executions run with live Lock 1–3 guards; Google A2A is inspected statically only because Cognizant's runtime does not execute remote A2A transports directly. Static `PinStore` protects published specs and MCP tool lists (`listTools()`), whereas dynamic HTTP/MCP runtime replies rely on Lock 1–3 containment rather than pre-signed output hashes.
3. **Encoding & Split-Secret Limits:** Lock 1 catches standard/spaced/comma-separated/Unicode-digit cards, IBANs, keys, Base64 secrets, and explicit login/CVV strings, while Lock 3 catches raw, URL, ROT13, spaced, hex, reversed, and single-chunk Base64 (at any offset) canary leaks; however, numbers written entirely as prose words or secrets/canaries split fragment-by-fragment across independent fields or turns are not reassembled.
4. **Runtime Hooks & Origin Isolation:** `guard.js` wraps 8 internal Cognizant `Engine` seams (`cognizant-kit.yml` tests compatibility weekly). On shared hosting such as `<user>.github.io`, all paths on that origin share `localStorage` pins and saved BYOK keys—host Agent Customs on a dedicated origin for production deployments.
5. **Browser CORS Limits:** Sites omitting `Access-Control-Allow-Origin` cannot be read from the static web UI and require [`bin/agent-customs.mjs`](bin/agent-customs.mjs), [`action.yml`](action.yml), or the MV3 [`extension/`](extension/) (which requests per-origin `optional_host_permissions` for `https://*/*` on user click).

---

## 5. Reproducibility Commands

```sh
npm test                                    # Automated suite across attacks, Round 2, locks, receipts, CLI, bench & extension
npm run check                               # Validate site Open Agentic Web network with build_network.mjs
npm run check:practice                      # Validate practice site mirror and manifest
npm run bench -- --verbose                  # Reproduce separated detection + self-test benchmark scorecard
node bin/agent-customs.mjs check https://raw.githubusercontent.com/microsoft/playwright-mcp/main/server.json
```
