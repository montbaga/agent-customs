<div align="center">

<p align="center">
<a href="README.md"><img src="docs/images/tab-readme-on.svg" alt="README (this page)" height="46"></a><a href="ARCHITECTURE.md"><img src="docs/images/tab-architecture-off.svg" alt="Architecture" height="46"></a><a href="PAPER.md"><img src="docs/images/tab-paper-off.svg" alt="Paper" height="46"></a><a href="LICENSE.md"><img src="docs/images/tab-license-off.svg" alt="License" height="46"></a>
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/hero-banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/hero-banner-light.svg">
  <img src="docs/images/hero-banner-dark.svg" alt="Agent Customs, safety checks for AI agents from other websites" width="100%">
</picture>

<br><br>

[**Add it to your site**](#add-it-to-your-site) &nbsp;·&nbsp;
[**Live desk**](https://montbaga.github.io/agent-customs/) &nbsp;·&nbsp;
[**MCP server**](#use-it-as-an-mcp-server) &nbsp;·&nbsp;
[**Practice site**](https://montbaga.github.io/agent-customs/practice/) &nbsp;·&nbsp;
[**Test range**](https://agent-customs-range.github.io/) &nbsp;·&nbsp;
[**Contact**](#lets-talk)

<br>

<a href="https://github.com/montbaga/agent-customs/actions/workflows/pages.yml"><img alt="Tests and publish" src="https://github.com/montbaga/agent-customs/actions/workflows/pages.yml/badge.svg"></a>
<a href="#how-well-it-works"><img alt="Bench: 88.8% blocked, 0% false blocks" src="https://img.shields.io/badge/bench-88.8%25_blocked_%C2%B7_0%25_FP-c8f03c?labelColor=0c1d18"></a>
<a href="#try-it-yourself"><img alt="Tests: 219 passing" src="https://img.shields.io/badge/tests-219_passing-ece4d3?labelColor=0c1d18"></a>
<a href="LICENSE.md"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-c8f03c?labelColor=0c1d18"></a>
<img alt="Dependencies: none" src="https://img.shields.io/badge/dependencies-none-ece4d3?labelColor=0c1d18">
<a href="#lets-talk"><img alt="Built by Monty Bagati" src="https://img.shields.io/badge/say_hello-Monty_Bagati-c8f03c?labelColor=132d25"></a>

</div>

<br>

> **The problem in one minute.** On Cognizant's [Open Agentic Web](https://github.com/cognizant-ai-labs/agentic-web), one website's AI assistant can call another website's assistant. That partner then runs in your browser, on your API key, reading your request. A dishonest site can hide orders in characters people cannot see, and the consent card only shows the partner's name and address, never its instructions.
>
> **Agent Customs is passport control for those partners.** Fixed rules read the partner's files before they run, at no AI cost, and stamp them *Cleared*, *Held for review* or *Entry denied*. It remembers the version you approved, so a silent change gets caught, and it keeps runtime locks on that no clever wording can talk out of a verdict.

<br>

### Watch it work

https://github.com/user-attachments/assets/856eb212-3735-4a19-86da-0168c0ab7a2b

<br>

## Add it to your site

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/install-steps-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/install-steps-light.svg">
  <img src="docs/images/install-steps-dark.svg" alt="Add it to your site: copy the line, paste it above your scripts, and every partner is checked" width="100%">
</picture>

Pick one of four ways. Each works with any site made with Cognizant's `agentify-website` kit, and each code block below has a copy button.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/install-way-1-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/install-way-1-light.svg">
  <img src="docs/images/install-way-1-dark.svg" alt="Way 1, one line, easiest: paste it above your page's other scripts and the guard turns itself on" width="100%">
</picture>

```html
<script type="module"
  src="https://cdn.jsdelivr.net/gh/montbaga/agent-customs@v1.2.1/dist/agent-customs.js"
  integrity="sha384-YE70fIwlhYsCMabfI8QHUr/PX3ihOeP2pZz0r1rAtbi8Flp+y2m7I9uHIpaXaHrJ"
  crossorigin="anonymous"></script>
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/install-way-2-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/install-way-2-light.svg">
  <img src="docs/images/install-way-2-dark.svg" alt="Way 2, two lines, your settings: import the guard and pass your own settings" width="100%">
</picture>

```js
// At the top of site.js
import { installCustomsGuard }
  from "https://cdn.jsdelivr.net/gh/montbaga/agent-customs@v1.2.1/site/customs/guard.js";

// Right after boot()
installCustomsGuard(booted.engine, { strict: true });
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/install-way-3-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/install-way-3-light.svg">
  <img src="docs/images/install-way-3-dark.svg" alt="Way 3, npm, build tools: for projects with a build step" width="100%">
</picture>

```sh
npm install agent-customs
```

```js
import { installCustomsGuard } from "agent-customs";

installCustomsGuard(booted.engine);
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/install-way-4-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/install-way-4-light.svg">
  <img src="docs/images/install-way-4-dark.svg" alt="Way 4, copy the folder, self-hosted: nothing loads from outside" width="100%">
</picture>

```js
// After copying site/customs/ next to your runtime/ folder, in site.js:
import { installCustomsGuard } from "./customs/guard.js";

installCustomsGuard(booted.engine);
```

**See it live:** [Main Street Guide](https://montbaga.github.io/agent-customs/practice/) is an ordinary site with the guard added the fourth way. **Before you publish:** `npx agent-customs check <url>` or the [GitHub Action](#run-it-anywhere-command-line-mcp-server-github-action-browser-extension) checks your own network. **Inside your AI editor:** use the [MCP server](#run-it-anywhere-command-line-mcp-server-github-action-browser-extension). **As a visitor:** the [browser extension](#run-it-anywhere-command-line-mcp-server-github-action-browser-extension) checks agents on any site. Every setting and detail: [Install details](#install-details).

<br>

<table width="100%">
<tr>
<td width="33.3%" valign="top">
  <strong>Inspect any link</strong><br><br>
  Paste an Open Agentic Web network, a Google A2A agent card or an MCP server address. No API key needed. You get a stamp, the hidden text decoded, the data paths and how to fix each problem.
</td>
<td width="33.3%" valign="top">
  <strong>Catch silent changes</strong><br><br>
  Approving a clean version saves its fingerprint in your browser, for networks and for MCP tool lists. If the files change later, the guard holds them and shows what changed, line by line.
</td>
<td width="33.3%" valign="top">
  <strong>Guard every call</strong><br><br>
  Add one line to any <code>agentify-website</code> site. Every partner call is then checked before it runs, and three locks stay on while it runs.
</td>
</tr>
</table>

<p align="center">
  <img src="docs/images/hidden-sentence.jpg" alt="What people see and what the AI model reads: 182 hidden Unicode tag characters decoded by Agent Customs" width="100%">
  <br><sub><b>Shady Pizza</b> shows visitors one plain sentence. Behind it sit 182 invisible characters asking for card numbers and CVVs. Agent Customs decodes them and refuses entry.</sub>
</p>

---

## Think of airport customs

*"Most people will never visit this website. The website is the showroom; the guard is what site owners take home."*

| At the airport | On the Open Agentic Web |
| :--- | :--- |
| A traveller arriving from abroad | Another website's AI assistant |
| The country they want to enter | Your browser, your AI key and your conversation |
| The customs officer and the X-ray belt | Agent Customs |
| The passport stamp | *Cleared*, *Held for review* or *Entry denied* |

<details open>
<summary><b>Who uses it, and why</b></summary>

| Who | Why |
| :--- | :--- |
| **Sites that link to partners** | If a partner's assistant tricks people, your visitors get hurt and your site gets the blame. Check partners before you link to them, the way you would check references. |
| **Sites that need a guard all the time** | A check before launch is not enough if a partner changes next week. The guard checks the partner's files on every load. |
| **Publishers, before they ship** | Like a spell-check: it finds spec mistakes, missing CORS headers, keys left in files and `sly_data` permissions that are wider than needed. |
| **Directories and reviewers** | Check whole lists of agent sites from the command line or in CI, and verify signed stamps. |
| **Visitors** | Protected on any guarded site, without installing anything. |

</details>

---


## Install details

Each way to add the guard, step by step. All of them work with any site built with Cognizant's `agentify-website` kit, with no server, no build step and the runtime unchanged.

**1. One line (easiest).** Paste this into your page, above your other `<script>` tags. The guard switches itself on when your assistant starts.

```html
<script type="module" src="https://cdn.jsdelivr.net/gh/montbaga/agent-customs@v1.2.1/dist/agent-customs.js" integrity="sha384-YE70fIwlhYsCMabfI8QHUr/PX3ihOeP2pZz0r1rAtbi8Flp+y2m7I9uHIpaXaHrJ" crossorigin="anonymous"></script>
```

`integrity` is the file's fingerprint. If the file were ever changed, on the CDN or on the way, the browser would refuse to run it. The whole guard is in this one file ([`dist/agent-customs.js`](dist/agent-customs.js), built by `npm run bundle`), so the fingerprint covers all of it. `@v1.2.1` is a fixed version; to update, take the new line from the next release. Above the other tags, the browser runs it before your page starts the assistant, and chats wait until the guard is on. If your page has a `Content-Security-Policy` with `script-src`, add `https://cdn.jsdelivr.net` to it.

**2. Two lines, with your own settings.** Load the guard from the same release and pass any of the *Guard options* below. A browser cannot check a fingerprint on an `import`, so for that use option 3 or 4.

```js
// At the top of site.js
import { installCustomsGuard } from "https://cdn.jsdelivr.net/gh/montbaga/agent-customs@v1.2.1/site/customs/guard.js";

// Right after the boot(...) call
installCustomsGuard(booted.engine, { strict: true });
```

**3. npm.** For projects with a build step: `npm install agent-customs`, then `import { installCustomsGuard } from "agent-customs";`. The same package has the command line tool: `npx agent-customs check <url>`.

**4. Copy the folder.** To load nothing from outside, copy [`site/customs/`](site/customs/) next to your `runtime/` folder and use `import { installCustomsGuard } from "./customs/guard.js";`. The [practice site](practice/site.js) does this.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/checkpoint-flow-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/checkpoint-flow-light.svg">
  <img src="docs/images/checkpoint-flow-dark.svg" alt="Partner call checkpoint flow: consent card, customs guard inspection, and verdict outcomes" width="100%">
</picture>

- Notices in the chat. Under every partner consent card, visitors see the stamp, the problems found and a *See the full report* link. The notice uses Agent Customs' own wording only, so a partner's hidden text never reaches the model through it.
- It checks what will actually run. The guard inspects the network objects the runtime has just compiled, after the visitor agrees and before anything runs. A server cannot show one file to the scanner and run another. A weekly check runs every test against Cognizant's latest kit, and all 62 of its files are used unchanged.

New to the design? [**How it works**](ARCHITECTURE.md) explains every step with diagrams.

<details open>
<summary><b>Guard options</b></summary>

`installCustomsGuard(engine)` works with no options. These change its behaviour:

| Option | Default | What it does |
| :--- | :--- | :--- |
| `strict` | `false` | Asks before every partner, never pins on its own, ignores `trustedActions` and blocks personal details going out |
| `semanticJudge` | `false` | The AI double-check. The site's own AI also reads partners the rules cleared, their MCP tool lists and their replies, and it can only make a verdict stricter. `true` turns it on; a function `() => boolean` lets a switch on your page turn it on and off, as the desk does. Off means no tokens are used |
| `locks` | `true` | `false` turns off the three runtime locks and MCP tool pinning |
| `canary` | `true` | Plants a canary word in your assistant's instructions and withdraws a partner's approval if it leaks |
| `trustedActions` | `[]` | Harmless page actions that do not need an extra click after a partner reply |
| `store` | `localStorage` | Where approved fingerprints and MCP tool-list pins are kept |
| `policy` | Deny bad, ask on held | Which stamps block on their own and which ask the visitor |
| `confirmEntry` | Built-in dialog | `async (report) => boolean`, called for *Held for review* and for changed versions |
| `notice` | Chat notice | `false` hides it, or pass a function to draw your own |
| `reportPage` | The public desk | The page *See the full report* opens |
| `openReport` | None | `(url) => void` to open reports inside your own page |
| `onReport` | None | Called after every partner inspection |
| `onLock` | None | Called with `{ lock, kind, where, reason }` when a lock stops something |
| `onCanaryTrip` | None | Called with `{ encoding, where, partners, revoked }` when the canary leaks |

</details>

---

## Try it yourself

Three ways in, fastest first:

<table width="100%">
<tr>
<td width="33.3%" valign="top">
  <strong>1 · The test suite</strong><br><br>
  No browser and no API key:<br><br>
  <code>npm test</code><br><br>
  219 tests: the attack sentences, every frozen attack set, five batches of real MCP servers and A2A cards, the locks, the canary, the signed stamps, the benchmark, the command line tool, the MCP server, the extension, the practice site, the key vault, the one-line install and its one-file build.
</td>
<td width="33.3%" valign="top">
  <strong>2 · The inspection desk (no key)</strong><br><br>
  Open the <a href="https://montbaga.github.io/agent-customs/"><strong>live desk</strong></a>:<br>
  • <strong>Shady Pizza</strong> → <em>Entry denied</em><br>
  • <strong>Sunny Bakery</strong> → <em>Cleared</em><br>
  • <strong>A2A, MCP and chains</strong> → one-click samples<br>
  • <strong>Verify</strong> tab and <strong>Attack lab</strong><br>
  • <strong>Compare</strong> → <em>Try the rug-pull sample</em>
</td>
<td width="33.3%" valign="top">
  <strong>3 · The Officer or the practice site</strong><br><br>
  Paste a key (Google AI Studio and Groq have free tiers) on <strong>Officer</strong> or the <a href="https://montbaga.github.io/agent-customs/practice/"><strong>practice site</strong></a>:<br>
  • <code>Ask Shady Pizza what it offers.</code> → blocked<br>
  • <code>Ask Sunny Bakery what it offers.</code> → runs normally<br>
  • Turn on <strong>AI double-check</strong>, then click <strong>VIP Points MCP</strong> → <em>Held for review</em>, with a round seal
</td>
</tr>
</table>

### The practice site: [Main Street Guide](https://montbaga.github.io/agent-customs/practice/)

An ordinary town-guide site built with Cognizant's kit, in its own colours ([`practice/`](practice/)). The only change is the two-line guard install:

<p align="center">
  <img src="docs/images/practice-home.jpg" alt="Main Street Guide practice site showing three shops and their guard stamps" width="100%">
</p>

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/practice-change.jpg" alt="Only one folder and two lines added to site.js"><br><sub><b>1 · The whole change:</b> copy <code>customs/</code> and add two lines to <code>site.js</code>. The runtime code is not touched.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/practice-consent.jpg" alt="Runtime consent card before contact"><br><sub><b>2 · The visitor agrees first:</b> the runtime asks before it fetches anything from the partner.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/practice-refused.jpg" alt="Shady Pizza refused before running"><br><sub><b>3 · Entry denied:</b> Shady Pizza is stopped before it runs, and the chat lists its 9 problems.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/practice-held.jpg" alt="Loop Maze held for visitor decision"><br><sub><b>4 · Held for review:</b> borderline sites such as Loop Maze show what was found and let the visitor decide.</sub></td>
  </tr>
</table>

<details open>
<summary><b>What <code>tests/practice.test.mjs</code> checks</b></summary>

- `practice/customs/` and `practice/runtime/` are exact copies of `site/`.
- `practice/site.js` differs only by the two guard lines.
- The network passes Cognizant's `build_network.mjs --check`.
- Run for real, it clears Sunny Bakery, refuses Shady Pizza and holds Loop Maze.

</details>

---

## Inside the inspection desk

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/five-checks-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/five-checks-light.svg">
  <img src="docs/images/five-checks-dark.svg" alt="Five inspection gates: Papers, Contraband, Itinerary, Privacy, Identity" width="100%">
</picture>

<br>

| Stamp | Meaning | What the guard does |
| :--- | :--- | :--- |
| **Cleared** | No known problem found | Lets the partner in and remembers this version |
| **Cleared with conditions** | Only notes, nothing serious | Lets it in, shows the notes, remembers this version |
| **Held for review** | Something a person should look at, a language it cannot check, or a change since approval | Pauses and asks the visitor |
| **Entry denied** | Hidden orders, phishing or leak links | Blocks it and explains why |
| **Papers not in order** | Broken Open Agentic Web, A2A or MCP files | Refuses it before it runs |
| **Could not inspect** | The host cannot be reached or does not allow cross-site reads | Nothing loads |

### Screens

<p align="center">
  <img src="docs/images/hero.jpg" alt="Agent Customs home page replaying the Shady Pizza inspection" width="100%">
  <br><sub>The home page: paste any agent address, or watch a recorded inspection.</sub>
</p>

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/report-denied.jpg" alt="Denied report for Shady Pizza with decoded hidden instructions"><br><sub><b>A denied report:</b> every finding names its agent, why it matters and how to fix it, with the decoded hidden text in red.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/report-cleared.jpg" alt="Cleared report for Sunny Bakery with 15/15 spec checks passing"><br><sub><b>A cleared report:</b> 15 of 15 spec checks, each tied to its spec section, and the network's fingerprint.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/compare.jpg" alt="Compare view showing what changed in Sunny Bakery after a silent rug pull"><br><sub><b>Compare:</b> shows line by line what changed when a clean network later adds data-harvesting text or new partners.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/officer.jpg" alt="Officer tab with the bring-your-own-key model picker"><br><sub><b>Officer:</b> bring your own key (Claude, GPT, Gemini, Groq, OpenRouter or any compatible service) to have reports explained in plain words.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/ai-check-setup.jpg" alt="AI double-check switch waiting for a key, with a card that explains what an AI key is and offers to set up a free one"><br><sub><b>AI double-check, first visit:</b> with no key yet, the switch waits and a card explains what a key is, where to get a free one, and takes you there.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/ai-check-flagged.jpg" alt="VIP Points sample held for review by the AI double-check, with a round seal on the stamp and the flagged sentence as evidence"><br><sub><b>AI double-check, flagged:</b> the rules clear the VIP Points sample; the AI holds it and quotes the sentence. In this shot a stand-in plays the visitor's AI.</sub></td>
  </tr>
</table>

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/phase1-mcp-trifecta.jpg" alt="An MCP server held for a data path"><br><sub><b>MCP servers:</b> reads <code>mcp.json</code> and tool lists and follows the data paths across tool names, schemas and outside addresses.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/phase2-verify.jpg" alt="Verify tab checking a signed certificate"><br><sub><b>Verify:</b> checks the signature on an exported certificate in your browser and compares it with the live network.</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/phase2-attack-lab.jpg" alt="Attack lab and benchmark scorecard"><br><sub><b>Attack lab and benchmark:</b> the same attacks with and without Agent Customs, next to the benchmark scorecard.</sub></td>
    <td width="50%" valign="top"><img src="docs/images/phase3-builders.jpg" alt="Protect your assistant in one line: three steps, and the one-line install with its fingerprint"><br><sub><b>Add it to your site:</b> three steps and the one line to copy, with tabs for two lines, npm, the command line tool, the GitHub Action, the extension and the MCP server.</sub></td>
  </tr>
</table>

<p align="center">
  <img src="docs/images/phase3-extension.jpg" alt="Browser extension inspecting the Playwright MCP server" width="72%">
  <br><sub><b>Browser extension:</b> inspects the page you are on with one click, asking for access to that site only (shown on <code>io.github.microsoft/playwright-mcp</code>).</sub>
</p>

<details open>
<summary><b>On a phone</b></summary>

<table>
  <tr>
    <td width="50%" align="center"><img src="docs/images/phone-report.jpg" alt="Shady Pizza report on a phone" width="300"><br><sub>The desk on a phone</sub></td>
    <td width="50%" align="center"><img src="docs/images/practice-phone.jpg" alt="Practice site on a phone" width="300"><br><sub>The practice site on a phone</sub></td>
  </tr>
</table>

</details>

---

## How well it works

Rules catch known tricks. The runtime locks limit the damage when a new trick gets past the rules. Both are measured here, and the [paper](PAPER.md) has the method behind each number.

### 1 · The runtime locks

| Lock | What it stops | How |
| :--- | :--- | :--- |
| **Lock 1 · Secrets stay home** | Card numbers, IBANs, keys and typed-out logins leaving in partner requests, tool calls, actions, forms or links | It checks number formats and check digits (Luhn for cards, ISO 7064 for IBANs), also in other digit scripts and in Base64 |
| **Lock 2 · Replies and actions** | "Quietly place an order", and data hidden in reply fields | It keeps only the expected reply fields, drops remote images and unknown links, pins MCP tool lists, and makes page actions wait for the visitor's click |
| **Lock 3 · The canary** | Instructions leaking out, even encoded | It plants a canary word in your assistant's instructions and stops the call if the word shows up in anything going out, in any of ten encodings, then withdraws the partner's approval |

### 2 · Attack sentences (`tests/attacks.test.mjs`)

| What was tested | Sentences | Result |
| --- | --- | --- |
| A second review's sentences, written to get past the rules | 23 | All get the right verdict now |
| Scam sentences in English and the 12 checked languages | 34 | All blocked |
| Scam sentences in 9 other languages | 9 | All held for a person |
| Honest English sentences, many close to a scam's wording | 27 | None flagged |
| Honest sentences in other languages | 23 | None blocked |

The 12 checked languages are Spanish, French, German, Portuguese, Italian, Russian, Chinese, Japanese, Hindi, Arabic, Dutch and Indonesian. Text in any other language is held for a person to read, including short three-word requests in Turkish, Swedish, Norwegian, Danish, Zulu and Somali (`tests/round3.test.mjs`).

### 3 · Real MCP servers and A2A cards (`tests/realworld.test.mjs`)

Five batches of public tools, fetched read-only and saved, each one from hosts no earlier batch had used. A false alarm is a *Held* or *Denied* stamp on a tool a person judged harmless.

| Batch | Tools | First look (never seen before) | After fixing |
| :--- | ---: | :--- | :--- |
| 1 · well-known and Registry MCP servers, A2A cards | 135 | 43 (32%) | 0, with all 10 risky tools still held |
| 2 · Registry MCP and A2A | 124 | 23 (18.5%) | 5 |
| 3 · Registry MCP | 138 | 9 (6.5%) | 0 |
| 4 · Registry MCP and A2A | 236 | 26 (11%) | 3 |
| **5 · Registry MCP and A2A** | **237** | **13 (5.5%)** | 12, not tuned for it |

Five more batches were fetched the same way on 20 and 21 November 2026 (159, 185, 205, 160 and 92 tools; the snapshots are not in the repo). Batches 6 to 8 were used to find and fix general mistakes in the rules. Batch 8 was first measured once: 20 held without a good reason (9.8%) with the old rules, 14 (6.8%) with the 1.1.1 rules. Batches 9 and 10 were measured once for 1.1.2, before and after: 24 of 252 held without a good reason with 1.1.1, 23 (9.1%) with 1.1.2. The remaining ones are mostly wording rules reading honest text as hiding something ("without asking them again", "hide a work log entry") and look-alike letters in non-Latin text.

The attack sets that target the rules' own exceptions are now all held: probe6 22 of 22, probe7 19 of 19, probe8 27 of 27 (with 12 of 12 honest look-alikes cleared). The probe9 set, written after that round's changes, held 11 of 18 new attack wordings on its first run. probe12, written before the 1.1.1 rule changes: the old rules held 8 of its 20 tricks and the new ones hold 19, with none of its 15 honest lines held. The newest set, probe13, was written before the 1.1.2 changes and is about tool combinations, key wording, example addresses and quoted attacks: 1.1.1 held 7 of its 12 tricks and 2 of its 12 ordinary tools, 1.1.2 holds all 12 tricks and none of the ordinary tools. That is the honest measure of how the rules handle wording they were never written for.

### 4 · The benchmark (`npm run bench`)

Measured on a desktop with Node.js v24.18.0 and no AI model. The baseline is a plain word list run after the same Unicode cleaning, so the comparison is about the rules, not the decoding.

| Set | Cases | Agent Customs | Word-list baseline | Avg time |
| :--- | ---: | :--- | ---: | ---: |
| Round 1 · Unicode tricks | 12 | 12/12 blocked or held | 58.3% | 13.92 ms |
| Round 1 · injection and phishing | 24 | 24/24 | 16.7% | 3.15 ms |
| Round 1 · A2A and MCP | 6 | 4/6 (6/6 flagged with notes) | 33.3% | 5.02 ms |
| Round 2 · red team (3/24 before fixes) | 24 | 23/24 (24/24 flagged) | 20.8% | 3.05 ms |
| Round 3 · fresh wordings (0/15 before fixes) | 15 | 15/15 | 0.0% | 1.80 ms |
| Held-out, never tuned | 10 | 6/10 | 0.0% | 1.54 ms |
| Outside wordings, quoted (0/7 before format rules) | 7 | 3/7 | 14.3% | 1.57 ms |
| **Honest controls** | 61 | **0 blocked** (57 cleared, 4 with notes) | 8.2% blocked | 3.92 ms |
| **All detection** | 159 | **87/98 blocked or held, 90/98 flagged** | 19/98 | **1.81 ms median** |
| Lock and tamper self-tests | 25 | 25/25 pass | not applicable | about 1 ms |

### 5 · Signed stamps (ES256)

Agent Customs publishes signed inspection stamps ([`receipts/index.json`](https://montbaga.github.io/agent-customs/receipts/index.json)) for the public networks listed in [`tools/receipt-sites.json`](tools/receipt-sites.json). Each stamp is signed with an ECDSA P-256 key, lasts 35 days, and records the network's fingerprint, so anyone can check it is genuine and still matches the live network. A GitHub workflow signs fresh ones every month, and again after each publish for any network that changed, so the stamps on these networks never go out of date.

```sh
npm run receipts -- verify https://montbaga.github.io/agent-customs/receipts/agent-customs-range.github.io/shady_pizza/shady_pizza.json --live
```

- The public key (`-DC99sDa-qJjBp2N`): `crv: "P-256"`, `kty: "EC"`, `x: "Wzq2yNI2mFX6Iz-GBeV7LKacVokiI396oifQRocfzxo"`, `y: "qdaCQ4K-07HN5yiq8CfFVUgRVtJm5uszNMsjuBqWQic"`, also at [`site/.well-known/agent-customs-key.json`](site/.well-known/agent-customs-key.json).
- Joining the list: site owners can open a pull request that adds their public address to `tools/receipt-sites.json`. A network that is not on the list gets an unsigned browser snapshot instead, whose fingerprint can still be checked on the **Verify** tab.

### 6 · What else it reads

- Three protocols (`protocols.js`): Open Agentic Web networks, Google A2A cards (`agent.json`, `agent-card.json`, including other interfaces they list) and MCP (`mcp.json`, `mcpServers`, Streamable HTTP, Registry `server.json`). It reads every field a model sees, including output schemas, tool titles, prompt messages and A2A skill names.
- Data paths (`capabilities.js`): it splits `camelCase` and `snake_case` names, so `getUserFiles` and `get_user_files` read the same, and it follows tools, schemas, REST toolboxes and outside addresses. A server's own hints can raise the risk, never lower it.
- Partners of partners: it follows same-site partner links up to two levels deep, six targets at most, and can follow other sites too if you ask (`--transitive` on the command line).
- Certificates (`certificate.js`): export an SVG, a printable page or a PNG, or drop one on the **Verify** tab to check it.
- Attack lab (`arena.js`): replays hidden-text theft, an MCP data leak, the canary trap and a rug pull, without an API key.

---

## The test range

A second site, https://agent-customs-range.github.io/, hosts sample networks, some honest and some deliberately unsafe. The unsafe ones point at `.invalid` addresses that do not exist.

| Network | What it shows | Stamp |
| :--- | :--- | :--- |
| **`sunny_bakery`** | An honest reference network | *Cleared* |
| **`shady_pizza`** | Hidden Unicode text, card theft, a remote image leak, a note aimed at reviewers | *Entry denied* |
| **`bank_helper`** | A look-alike bank name (`Marrow Point Sаvings` with a Russian "а"), a request for a one-time code, unpinned code | *Entry denied* |
| **`loop_maze`** | Agents calling each other in a loop, a 500-step budget, invisible and right-to-left text | *Held for review* |
| **`rugpull/sunny_bakery`** | A later version of the bakery that asks for contact details and adds a new partner | *Held for review* |

---

## Run it anywhere: command line, MCP server, GitHub Action, browser extension

Needs Node 22 or newer and no npm packages.

<table width="100%">
<tr>
<td width="50%" valign="top">
  <strong>1 · Command line and benchmark</strong><br><br>
  Check addresses, folders, MCP and A2A files, or verify stamps:<br><br>
  <code>npm test</code><br>
  <code>npm run bench -- --verbose</code><br>
  <code>node bin/agent-customs.mjs check https://raw.githubusercontent.com/microsoft/playwright-mcp/main/server.json</code>
</td>
<td width="50%" valign="top">
  <strong>2 · MCP server (<code>agent-customs mcp</code>)</strong><br><br>
  Full inspection desk inside Claude Code, Cursor, Claude Desktop or Antigravity (all 11 tools and 4 resources):<br><br>
  <code>node bin/agent-customs.mjs mcp</code><br>
  <code>npx -y agent-customs mcp</code>
</td>
</tr>
<tr>
<td width="50%" valign="top">
  <strong>3 · GitHub Action (<code>action.yml</code>)</strong><br><br>
  Stops pull requests that add hidden prompts, leaked keys or risky MCP setups, with SARIF results in the Security tab:<br><br>
  <code>uses: montbaga/agent-customs@main</code><br>
  Options: <code>strict</code>, <code>allow-hold</code>, <code>transitive</code>, <code>sarif-file</code>.
</td>
<td width="50%" valign="top">
  <strong>4 · Chrome or Edge extension</strong><br><br>
  Inspects live <code>https://</code> sites that block cross-site reads, asking for access to one site at a time:<br><br>
  1. Run <code>npm run extension</code><br>
  2. Open <code>chrome://extensions</code> (Developer mode)<br>
  3. <strong>Load unpacked</strong> → pick <a href="extension/"><code>extension/</code></a>
</td>
</tr>
</table>

```sh
git clone https://github.com/montbaga/agent-customs.git
cd agent-customs
npm test                                # 219 tests
npm run bench -- --verbose              # the benchmark, with every flagged case
npm run check && npm run check:practice # both networks pass Cognizant's build check
node bin/agent-customs.mjs check site/samples/mcp-poisoned --sarif
node bin/agent-customs.mjs verify site/receipts/agent-customs-range.github.io/sunny_bakery/sunny_bakery.json --live
```

### Use it as an MCP server

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/mcp-steps-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/mcp-steps-light.svg">
  <img src="docs/images/mcp-steps-dark.svg" alt="Use Agent Customs as an MCP server inside Claude Code, Cursor, or Antigravity" width="100%">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/mcp-way-1-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/mcp-way-1-light.svg">
  <img src="docs/images/mcp-way-1-dark.svg" alt="Option 1: MCP config JSON. Paste into Claude Desktop, Cursor, or Antigravity via npx." width="100%">
</picture>

```json
{
  "mcpServers": {
    "agent-customs": {
      "command": "npx",
      "args": ["-y", "agent-customs", "mcp"]
    }
  }
}
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/mcp-way-2-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/mcp-way-2-light.svg">
  <img src="docs/images/mcp-way-2-dark.svg" alt="Option 2: Claude Code or local clone. Register with one CLI command, or run directly from a local clone." width="100%">
</picture>

```sh
# Claude Code (one command)
claude mcp add agent-customs -- npx -y agent-customs mcp

# Or run from a local clone (optional: set AGENT_CUSTOMS_AI_KEY for AI double-check)
node bin/agent-customs.mjs mcp
```

<details>
<summary><b>MCP tools included (11 tools and 4 resources — full website parity)</b></summary>

| What the website does | MCP tool | Notes |
| :--- | :--- | :--- |
| Inspect URL, folder, sample ID, or pasted config | `inspect_agent` | Supports Open Agentic Web, Google A2A, MCP, `deep` checks, drift & signed stamps |
| Read finding evidence & decoded hidden text | `get_inspection_details` | Reveals invisible Unicode/tag text quoted as untrusted data |
| Compare two versions (or against saved pin) | `compare_networks` | Pass `before: "pinned"` to diff any target against its stored approval |
| Save or forget version pins (`~/.agent-customs/pins.json`) | `approve_network`, `forget_approval` | Persistent across restarts; refuses `DENIED`, `INVALID`, and `UNREADABLE` |
| Read desk state, examples, log & AI double-check toggle | `get_desk_state`, `configure_ai_check` | Uses optional `AGENT_CUSTOMS_AI_KEY` when enabled |
| Generate or check SVG/HTML/JSON/PDF certificates | `issue_certificate`, `verify_certificate` | Checks ES256 signatures offline and optionally live |
| Replay Attack Lab & run runtime Locks 1–3 | `run_attack_lab`, `sanitize_exchange` | Live scenarios plus PII/canary redaction & reply beacon sanitization |

</details>

**In a GitHub workflow** (keep `if: always()` so the SARIF file uploads even when a check holds or denies):

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

### Try a rug pull on your own machine

```sh
# Two terminals
npm run serve            # the desk on port 8080
npm run serve:range      # the test range on port 8081 (request headers logged to range-requests.jsonl)
```

```sh
node tools/set-origins.mjs --range http://localhost:8081
# 1. Inspect Sunny Bakery, or ask the Officer about it (this pins the clean version)
node tools/rugpull.mjs on
# 2. Click "Check for changes", or ask the Officer again: it is held, with the changes listed
node tools/rugpull.mjs off
node tools/set-origins.mjs --range https://agent-customs-range.github.io
```

`npm run smoke` drives Edge or Chrome headlessly against the local servers and fails on any page error. It starts the key vault on port 8090 if it is not running (`npm run serve:vault`), since a page on this computer looks for the vault there.

`npm run vault:check` checks the key vault end to end in a headless browser, with a stand-in AI service on this computer: the page never holds the key, every AI request comes from the vault with the key, a remembered key is stored only encrypted, a new visit starts locked, a wrong password does not open it, and *Forget* removes it.

---

## What is new in this version

This round fixed a weakness in how the rules handled their own exceptions, and it was measured on 237 real tools the rules had never seen.

- An exception can only soften a warning, never remove it. Some honest tools sound like attacks: "we email you a 6-digit code", "the tracking link". Before, the rules removed the warning for such wording, and copied scams passed silently. Now the wording only turns a finding into a note, so the stamp becomes *Cleared with conditions* and the visitor still sees it.
- Signatures and data are recognised by what they are. Standard signatures on agent cards and Base64-encoded JSON are decoded and checked, wherever they appear, instead of being matched by field name.
- Two more languages. Dutch and Indonesian requests for passwords and card numbers are now read word by word. Takeover, chat-leak and "download and run" orders are caught in 14 languages.
- Honest numbers. False alarms on tools never seen before dropped from about 1 in 10 to about 1 in 18. New attack sets written after the changes were measured once before they were used. The details are in [How well it works](#how-well-it-works) and the [paper](PAPER.md#5--results).

The desk also has a new switch under the address box: **AI double-check**. When it is on, your own AI reads every network the rules clear, and every partner the Officer is about to call. It can only make a verdict stricter. If your AI flags something, *Cleared* becomes *Held for review*; if it finds nothing, the verdict stays as it was. Networks the rules already stopped are never sent to it, so they cost no tokens. The switch is off until you turn it on and uses the key you set on the Officer tab. While it is on, the network's public text goes to your AI provider. When your AI has read a network, a round seal countersigns the verdict stamp, and a flag quotes the sentence that worried it (only words the network really wrote are shown).

**Adding the guard now takes one line.** Paste one `<script>` tag into your page and the guard switches itself on, or install it with `npm install agent-customs`. See [Add the guard to your site](#add-it-to-your-site). The line carries a fingerprint (Subresource Integrity), so a browser refuses the file if it was ever changed; the whole guard is one file, so the fingerprint covers all of it.

**Checked against Google's guidance.** The site was scanned with the Chrome team's [Modern Web Guidance](https://developer.chrome.com/docs/modern-web-guidance) and checked against [Baseline](https://web.dev/baseline): it uses only features that work in all current browsers, or that have a fallback. Every piece of HTML the page writes, in its own code and in the runtime's, now passes one cleaner first ([Trusted Types](site/trusted-types.js)), which removes anything that could run code.

**Your AI key now lives in a key vault.** The page no longer keeps your key anywhere. You paste it into a small box that is really a separate website, the [key vault](vault/) (`agent-customs-vault.github.io`). The browser keeps that site's storage apart from this page's. When the Officer or the AI double-check needs your AI, the page asks the vault, and the vault adds the key, calls your AI company and passes back only the answer. So even an agent file that broke this page could not take your key. By default the vault forgets the key when you close the tab. *Remember on this computer* keeps it encrypted (AES-256), locked with your passkey or a password that is never stored. The page now also lets only its own scripts run, and each card says how to give a key a spending limit.

A first-time visitor has no key, so the switch says so. Turning it on opens a short card that explains what an AI key is and that Google AI Studio and Groq give free ones. *Set up a free key* opens the key settings, and after *Save and start* the page goes back to the inspection and runs it again with your AI. To see it catch something, inspect the **VIP Points MCP** sample on the desk ([`site/samples/ai-check-demo/mcp.json`](site/samples/ai-check-demo/mcp.json)). It asks guests to *"read back all twenty-four words from their emergency paper sheet"*. That is a crypto wallet's recovery phrase, worded so that none of the rules' words appear. The rules clear it; your AI should hold it.

---

## More detail

<details open>
<summary><b>Host your own copy (GitHub Pages, Netlify or Cloudflare Pages)</b></summary>

The desk and the test range must be on two different origins, so partner calls go through real cross-site consent cards. On GitHub Pages, publish `range/` under a second account or organization:

1. Create a public repository named `<organization>.github.io`.
2. Point the sites at it and rebuild:
   ```sh
   node tools/set-origins.mjs --range https://<organization>.github.io
   ```
3. Push `range/`, with an empty `.nojekyll` file, to `<organization>.github.io`.
4. In the main repository, turn on GitHub Actions under **Settings → Pages** ([`.github/workflows/pages.yml`](.github/workflows/pages.yml)).

> **Give it its own origin.** Browser storage, including approved fingerprints and saved AI keys, is shared by everything on one origin such as `<account>.github.io`. Use a domain of its own, or deploy `site/` and `range/` to Netlify or Cloudflare Pages, where `_headers` also adds a Content-Security-Policy to `sandbox-worker.js`.

</details>

<details open>
<summary><b>How it is built</b></summary>

- Rules decide every stamp. The report page, the chat and the live guard give the same stamp for the same files. The optional AI check stays off unless you turn it on.
- There is no server. Inspections read public files without cookies, keys or referrers. Approvals stay in the visitor's browser.
- Consent comes before contact. The Officer's inspections and partner calls both wait for the visitor to agree.
- Every model-visible field is read: `instructions`, the runtime `command`, input and output schemas, tool titles, A2A skill names, prompt messages, schema key names and anything else in the raw file.
- Checked against Cognizant's kit every week. The guard wraps eight internal runtime methods, so [`.github/workflows/cognizant-kit.yml`](.github/workflows/cognizant-kit.yml) runs the tests against the latest kit every week.

The full picture, with diagrams, is in [**How it works**](ARCHITECTURE.md).

</details>

<details open>
<summary><b>Open Agentic Web MVP checks (spec section 6)</b></summary>

| Spec check | Where it is done here |
| :--- | :--- |
| A network of two agents and a manifest on HTTPS | `customs_officer` and `instruction_analyst` (`site/agent-manifest.json`) |
| Default router and bring-your-own-key | Otari by default, plus a picker for OpenRouter, Google, Groq, OpenAI, Anthropic or any other service |
| An internal agent with grounded actions | `instruction_analyst`, plus 6 website tools (`inspect_agent_network`, `compare_networks`, `pin_network` and others) |
| Calls to other origins after approval | The Officer calls `sunny_bakery` and `shady_pizza` on the range (`tests/guard.test.mjs`) |
| Keys are never sent to partners | Shown in `range-requests.jsonl`: `"authorization": false` on every partner request |
| Fail closed on a bad spec or a denied partner | Runtime checks and the guard's refusals |

</details>

<details open>
<summary><b>Where things are</b></summary>

| Path | What it is |
| :--- | :--- |
| [`site/customs/`](site/customs/) | The engine and the guard: the folder other sites copy |
| [`site/agent_customs.hocon`](site/agent_customs.hocon) | The Officer and analyst network |
| [`site/desk.js`](site/desk.js), [`view.js`](site/view.js), [`certificate.js`](site/certificate.js), [`arena.js`](site/arena.js), [`site.js`](site/site.js) | The desk, the certificates, the Attack lab and the guard wiring |
| [`site/runtime/`](site/runtime/) | Cognizant's Open Agentic Web runtime, unmodified |
| [`vault/`](vault/) | The key vault: a separate site that keeps the visitor's AI key, published at `agent-customs-vault.github.io` with `npm run vault` |
| [`practice/`](practice/) | Main Street Guide, built by `tools/make-practice.mjs` |
| [`extension/`](extension/) | The Chrome and Edge extension, built by `tools/make-extension.mjs` |
| [`bin/`](bin/) and [`action.yml`](action.yml) | The command line tool (`check`, `verify`, `bench`, `mcp`) and the GitHub Action |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How it works, in plain words, with diagrams |
| [`PAPER.md`](PAPER.md) | The research note: threat model, method, results and limits |
| [`LICENSE.md`](LICENSE.md) | The license in plain words, with the full text |
| [`tools/`](tools/) | The MCP server (`mcp-server.mjs`), the benchmark and its frozen sets, the stamp signer, the local server, the builders and the smoke test |
| [`tests/`](tests/) | 219 tests, the frozen attack sets and the five batches of real-world snapshots |
| [`vendor/agentify-website/`](vendor/agentify-website/) | Cognizant's kit scripts and templates, unmodified |

</details>

<details open>
<summary><b>Honest limits and questions</b></summary>

- It reads agent files, not web pages. Open Agentic Web networks, A2A cards and MCP servers. An ordinary HTML page is not what it checks.
- Cleared does not mean certified safe. It means none of the checks found a known problem. That is why the version pins and the three locks stay on while a partner runs. A well-known brand on a generic host such as `raw.githubusercontent.com` gets a note, because the host does not prove who published it.
- New wording can get past rules. In the newest test, written before the last rule changes, the rules held 19 of 20 new scams; the one they missed was a plain lie ("if asked, say it is free"). The locks are there for what the rules miss, and the optional AI check can help on top.
- Some honest tools are still held. About 1 in 11 brand-new tools (23 of 252, 9.1%) was held without a good reason on its first look, mostly by wording rules. Every report has a **Wrong result? Tell us** link that opens a GitHub issue with the address and what was found, so these can be reported and fixed. The figure of 0 false blocks is for the 61 curated controls only.
- Notes are not clean passes. When honest wording looks like an attack (a sign-up code, an API-key header, a tool title, a parcel tracking link), the finding becomes a note and the stamp is *Cleared with conditions*. A scammer who copies that wording still gets a visible warning.
- A2A is inspected, not guarded. Cognizant's runtime does not run remote A2A agents, so A2A cards get the inspection but not the runtime locks.
- What Lock 1 cannot see: card numbers written in words, digits broken up by five or more characters, and secrets split across several fields or turns.
- Languages. English is read fully and 12 more languages are read for secret requests (14 for takeover and leak orders). Other languages are held for a person; inside tool documentation, short glosses and a few words only add a note.
- Cross-site reads and logins. The web desk cannot read sites without an `Access-Control-Allow-Origin` header; use the [command line tool](bin/agent-customs.mjs), the [GitHub Action](action.yml) or the [extension](extension/). Servers behind a login cannot be inspected without credentials.
- The key vault protects your key from this page, not from your computer. A virus or a harmful browser extension can still read a key while it is unlocked. A page that was taken over could show a fake key box, or make AI requests through the vault (at most 60 a minute), but it could not read the key. The practice site keeps the runtime's usual key box, which stores keys in the site's own storage; the desk offers to delete such copies. Use a free-tier key, or one with a spending limit.
- Similar tools. Command-line MCP scanners such as [Snyk Agent Scan](https://github.com/snyk/agent-scan) check MCP setups on a developer's machine. Agent Customs runs in the browser for all three protocols, guards partner calls while they run, and pins versions against rug pulls, with no backend.

</details>

---

## Let's talk

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/contact-card-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/contact-card-light.svg">
  <img src="docs/images/contact-card-dark.svg" alt="Direct line to Monty Bagati for security reviews, integrations, feedback and roles" width="100%">
</picture>

<br><br>

<a href="mailto:bagati.monty@gmail.com?subject=Agent%20Customs%3A%20Hello%20Monty"><img alt="Email Monty Bagati" src="https://img.shields.io/badge/Email-bagati.monty%40gmail.com-c8f03c?style=for-the-badge&logo=gmail&logoColor=c8f03c&labelColor=0c1d18"></a>
&nbsp;
<a href="https://www.linkedin.com/in/monty-bagati-90454626/"><img alt="Connect on LinkedIn" src="https://img.shields.io/badge/LinkedIn-Monty_Bagati-ece4d3?style=for-the-badge&logo=linkedin&logoColor=ece4d3&labelColor=0c1d18"></a>
&nbsp;
<a href="https://github.com/montbaga"><img alt="GitHub profile" src="https://img.shields.io/badge/GitHub-%40montbaga-8fd1a6?style=for-the-badge&logo=github&logoColor=8fd1a6&labelColor=0c1d18"></a>
&nbsp;
<a href="https://github.com/montbaga/agent-customs/issues/new"><img alt="Report a bypass or an idea" src="https://img.shields.io/badge/Feedback-Report_a_Bypass_or_Idea-f0a35e?style=for-the-badge&logo=github&logoColor=f0a35e&labelColor=0c1d18"></a>

<br><br>

<a href="https://montbaga.github.io/agent-customs/"><img src="site/favicon.svg" alt="Agent Customs" width="36"></a>

<br>

**Agent Customs** · Built by [**Monty Bagati**](https://www.linkedin.com/in/monty-bagati-90454626/) for the Open Agentic Web  
<sub>[Apache License 2.0](LICENSE.md) · Copyright 2026 Monty Bagati · Runtime &amp; templates from <a href="https://github.com/cognizant-ai-labs/agentic-web">cognizant-ai-labs/agentic-web</a> (Apache 2.0)</sub>

</div>
