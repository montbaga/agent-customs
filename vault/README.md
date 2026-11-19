# Agent Customs key vault

This is the small website that keeps your AI key for [Agent Customs](https://montbaga.github.io/agent-customs/).

Agent Customs reads agent files written by strangers. If one of them ever found a way to break that page, anything the page holds could be taken. So the page holds no key. Your key goes into this vault instead. The vault is a separate website, shown as a small box in Agent Customs' model settings. Because its address is different, the browser keeps its storage apart from the page's, and the page cannot read it.

## How it works

1. You paste your key into the vault's box. The page around it never sees it.
2. When Agent Customs needs the AI, it asks the vault. The vault adds the key, sends the request to your AI company, and passes back only the answer.
3. The vault sends a key only to the AI company it belongs to, or to the one address you typed into the vault yourself. The page cannot choose where a key goes.
4. The vault only answers Agent Customs (`montbaga.github.io`), and only two kinds of request: list the models, and chat. It sends at most 60 a minute.

## Where the key is kept

| Choice | Where | How long |
| :--- | :--- | :--- |
| Just this visit (the default) | This tab's storage, for this site only | Until you close the tab |
| Remember on this computer | This site's storage, **encrypted** with AES-256 | Until you click *Forget* |

A remembered key is locked with your **passkey** (fingerprint, face or device PIN, through the WebAuthn PRF extension) or a **password** (PBKDF2-SHA-256, 600,000 rounds per guess). Neither the passkey's secret nor the password is ever stored, so a copy of the browser's files holds only scrambled text. After you unlock it, it locks again after 15 minutes without use.

## What it cannot stop

- A virus on your computer, or a harmful browser extension, while the key is unlocked.
- If the Agent Customs page itself were taken over, it could show a fake key box that looks like this one, or make AI requests through the vault (up to 60 a minute). It still could not read a key already in the vault.
- Browsers that block all storage for embedded sites lose the key when the page reloads. Paste it again.

So use a free-tier key, or one with a spending limit. Then even a lost key costs little.

## Files

`index.html`, `vault.js` (the box and the private channel), `vault-core.js` (the rules and the encryption), `vault.css`, and the Geist fonts (SIL Open Font License). There are no outside scripts, and the page allows none.

The source lives in the Agent Customs repository, in [`vault/`](https://github.com/montbaga/agent-customs/tree/main/vault), with its tests. This repository only publishes it. Apache-2.0.
