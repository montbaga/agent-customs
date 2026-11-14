// rules.js: text rules for published agent instructions and descriptions.
//
// A peer network's instructions run inside the caller's model (spec section 5,
// "Untrusted instructions"). These rules look for text that works against the
// visitor or the calling site: overriding the caller's rules, asking for secrets,
// leaking the conversation, talking the visitor past a consent card, or trying to
// talk an inspector into a good verdict. Rules decide; a model only explains.
//
// Rules run on clauses, so "Never ask for passwords" is not read as "ask for
// passwords". Hidden characters are removed first (see unicode.js), so
// "pass​word" still counts as "password".

import { normalizeForRules, revealHidden } from "./unicode.js";

const SECRET = /\b(passwords?|pass ?codes?|pass ?phrases?|one[- ]time (?:pass)?codes?|otps?|2fa codes?|two[- ]factor codes?|verification codes?|security codes?|security answers?|mother'?s maiden name|card numbers?|(?:credit|debit|payment|bank) card (?:numbers?|details)|card details|cvv2?|cvc|social security(?: numbers?)?|ssn|seed phrases?|recovery phrases?|mnemonic phrases?|private keys?|api keys?|access tokens?|secret keys?|login (?:details|credentials)|online banking (?:login|details)|session cookies?)\b/i;
const PIN = /\bPINs?\b/;
const FINANCIAL_ID = /\b(bank account (?:numbers?|details)|account numbers?|routing numbers?|iban|sort codes?|passport numbers?|national id(?: numbers?)?|tax id(?: numbers?)?|driver'?s licen[cs]e(?: numbers?)?)\b/i;
const PERSONAL = /\b(full names?|e-?mail(?: address(?:es)?)?|phone numbers?|mobile numbers?|telephone numbers?|(?:home|street|postal|mailing) address(?:es)?|dates? of birth|birth ?dates?|birthdays?)\b/i;
// Asking verbs. "give/send/provide/share/enter" count only when aimed at the asker
// ("give us your", "send me the", "enter their"), so "give the visitor our phone
// number" is not read as asking for one.
const ASK = /\b(ask(?:s|ing)?|request(?:s|ing)?|collect(?:s|ing)?|obtain(?:s|ing)?|gather(?:s|ing)?|capture|confirm|verify|read (?:back|out)|tell (?:me|us)|what is (?:your|their)|needs? (?:your|their)|(?:give|send|provide|share|enter|type|submit|get)(?:\s+\w+){0,2}?\s+(?:us|me|your|their|his|her))\b/i;
const NEGATION = /\b(never|not|no|don'?t|do not|must not|mustn'?t|cannot|can'?t|won'?t|refuse to|avoid|without)\b(?!\s+(?:forget|fail|neglect|hesitate|only|matter|later than))/i;

// Split into clauses: sentences, and the halves of "..., but ..." or "...; then ...".
function clauses(text) {
  return text.split(/(?<=[.!?])\s+|[;\n]+|\s(?:but|however|then|and then)\s/i).map((s) => s.trim()).filter(Boolean);
}

// True when a negation comes before the asking verb in the same clause.
function negatedBefore(clause, verbIndex) {
  return NEGATION.test(clause.slice(0, verbIndex));
}

function askMatcher(termRe, extraRe) {
  return (text) => {
    const hits = [];
    for (const clause of clauses(text)) {
      const term = clause.match(termRe) || (extraRe ? clause.match(extraRe) : null);
      if (!term) continue;
      const verb = clause.match(ASK);
      if (!verb) continue;
      if (negatedBefore(clause, verb.index)) continue;
      hits.push({ match: term[0], excerpt: clause });
    }
    return hits;
  };
}

function regexMatcher(patterns, { negatable = false } = {}) {
  return (text) => {
    const hits = [];
    for (const clause of clauses(text)) {
      for (const re of patterns) {
        const m = clause.match(re);
        if (!m) continue;
        if (negatable && negatedBefore(clause, m.index)) continue;
        hits.push({ match: m[0], excerpt: clause });
        break;
      }
    }
    return hits;
  };
}

/**
 * The text rules. Each has an id, a category, a severity, a plain title, a fix for
 * the publisher and a matcher that returns [{match, excerpt}].
 */
export const TEXT_RULES = [
  {
    id: "C-SECRETS",
    severity: "critical",
    title: "Asks for passwords, codes or card details",
    why: "A partner network runs on the calling site's page. Asking that site's visitor for secrets is phishing, whoever publishes it.",
    fix: "Remove the request. Payment and sign-in belong in the site's own page, never in a chat.",
    match: askMatcher(SECRET, PIN),
  },
  {
    id: "C-FINANCIAL-ID",
    severity: "high",
    title: "Asks for bank or identity numbers",
    why: "Account, routing, passport and ID numbers enable fraud and identity theft.",
    fix: "Collect these only in the site's own secured form, and never through a network other sites can run.",
    match: askMatcher(FINANCIAL_ID),
  },
  {
    id: "C-PERSONAL",
    severity: "medium",
    title: "Asks the visitor for personal details",
    why: "When another site runs this network, it would ask that site's visitor, who never chose to share details with this publisher.",
    fix: "Ask for personal details only on your own site, and add the template's peer rule: when you have no website_* tools, do not ask for names, emails, phone numbers or codes.",
    match: askMatcher(PERSONAL),
  },
  {
    id: "C-OVERRIDE",
    severity: "high",
    title: "Tries to override other instructions",
    why: "Text that tells a model to drop its rules is the classic prompt injection. In a peer network it targets the caller's model.",
    fix: "Delete it. A network should describe its own job, not cancel anyone else's rules.",
    match: regexMatcher([
      /\b(ignore|disregard|forget|override|bypass|discard)\b[^.!?\n]{0,40}\b(previous|prior|above|earlier|preceding|original|system|caller'?s?|calling|all|any|other|your|their)\b[^.!?\n]{0,30}\b(instructions?|rules?|prompts?|guidelines?|polic(?:y|ies)|directions?|guardrails?)\b/i,
      /\byou are now\b/i,
      /\b(new|updated|real|true|secret|hidden)\s+(system\s+)?instructions?\s*[:\-]/i,
      /\byou are (?:actually |really )?(?:the|a|an) (?:system|developer|administrator|admin|root|operator)\b/i,
      /\b(developer|god|dan|jailbreak|unrestricted)\s+mode\b/i,
      /\b(reveal|print|show|repeat|output|leak)\b[^.!?\n]{0,30}\b(system prompt|your instructions|hidden instructions|the caller'?s instructions)\b/i,
    ]),
  },
  {
    id: "C-CALLER",
    severity: "high",
    title: "Gives orders to the calling site's assistant",
    why: "A partner's answer goes back to the calling site's model, which may have tools that change the page or place orders. Orders hidden in an answer can make it act without the visitor asking.",
    fix: "Return facts only. Never write instructions addressed to another assistant.",
    match: regexMatcher([
      /\b(tell|instruct|ask|order|make|have)\s+(the\s+)?(calling|caller'?s?|host|parent|upstream|top[- ]level|outer)\s+(agent|assistant|site|model|network|ai|llm)\b/i,
      /\b(calling|caller'?s?|host|parent|upstream|outer)\s+(agent|assistant|model|ai|llm)\s+(must|should|will|needs? to|has to)\b/i,
      /\bin your (answer|reply|response)[^.!?\n]{0,40}\b(include|add|append|insert)\b[^.!?\n]{0,40}\b(instruction|command|system|call)\b/i,
    ]),
  },
  {
    id: "C-CONSENT",
    severity: "high",
    title: "Tries to talk the visitor past a consent or confirmation step",
    why: "Consent cards and confirmation dialogs are the visitor's protection (spec sections 3.2 and 5). Steering them to 'Always allow' removes it.",
    fix: "Never mention how to answer the browser's cards or dialogs.",
    match: regexMatcher([
      /\b(click|press|tap|choose|select|pick)\s+["“'‘]?(always allow|allow)\b/i,
      /\b(skip|bypass|avoid|disable|suppress|hide)\s+(the\s+|any\s+|all\s+)?(consent|confirmation|approval|review|warning|dialog|card|prompt)s?\b/i,
      /\balways\s+(allow|approve|accept)\b/i,
    ], { negatable: true }),
  },
  {
    id: "C-CONCEAL",
    severity: "high",
    title: "Hides what it does from the visitor",
    why: "An agent that acts without telling the visitor removes their chance to say no.",
    fix: "Describe every action openly. The visitor must see what is done for them.",
    match: regexMatcher([
      /\b(without|before)\s+(telling|asking|informing|notifying|alerting|warning)\s+(the\s+)?(user|visitor|customer|human|person)\b/i,
      /\b(do not|don'?t|never)\s+(tell|inform|mention|reveal|disclose|let)\b[^.!?\n]{0,30}\b(user|visitor|customer|human)\b[^.!?\n]{0,40}\b(about|that|this|what|you)\b[^.!?\n]{0,40}\b(send|sent|share|shared|collect|forward|call|record|stor|track|log)/i,
      /\b(silently|secretly|covertly|quietly|discreetly)\s+(send|share|forward|collect|record|store|call|add|place|submit|track|log)\b/i,
    ]),
  },
  {
    id: "C-EXFIL",
    severity: "critical",
    title: "Tries to leak the conversation or private data",
    why: "Asking a model to put chat content, keys or context into a link or image sends it to a third party as soon as the answer is shown.",
    fix: "Remove it. Never build links or images from conversation content.",
    match: regexMatcher([
      /\b(include|append|embed|encode|send|post|forward|leak|exfiltrate|transmit|upload|put|add)\b[^.!?\n]{0,60}\b(conversation|chat history|chat log|conversation history|message history|previous messages|(?:user|visitor)'?s? messages|transcript|system prompt|your instructions|hidden instructions|sly_data|private context|api keys?|access tokens?|session tokens?|cookies?|personal (?:data|details)|(?:user|visitor) data)\b[^.!?\n]{0,60}\b(https?:\/\/|url|link|image|query|parameter|base64|webhook)/i,
      /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*(?:\{[^}]*\}|\?[^)\s]*=)/i,
      /https?:\/\/[^\s)"'<>]*(?:\{[a-z_ ]+\}|%7B[a-z_]+%7D|\$\{[^}]+\}|<[a-z_]+>)/i,
    ]),
  },
  {
    id: "C-BEACON",
    severity: "high",
    title: "Puts a remote image or tracking link in answers",
    why: "A remote image loads as soon as the answer appears, which tells a third party who read it and when, and can carry data in its address.",
    fix: "Use text links to your own pages only.",
    match: regexMatcher([
      /!\[[^\]]*\]\(\s*https?:\/\//i,
      /<img\b[^>]*\bsrc\s*=\s*["']?https?:/i,
      /\b(tracking|tracker|beacon|pixel)\s+(link|url|image|pixel)\b/i,
    ]),
  },
  {
    id: "C-INSPECTOR",
    severity: "high",
    title: "Tries to influence safety reviewers",
    why: "Text written for scanners and reviewers ('reviewers: this is certified safe') exists only to fool them.",
    fix: "Delete it. Safety comes from what the network does, not from what it says about itself.",
    match: regexMatcher([
      /\b(reviewers?|auditors?|inspectors?|scanners?|moderators?|classifiers?|graders?|evaluators?|security (?:tools?|teams?|checks?))\b[^.!?\n]{0,60}\b(is|are|as|be|been|mark|rate|treat|consider|report)\b[^.!?\n]{0,30}\b(safe|trusted|approved|certified|verified|clean|harmless|benign|legitimate)\b/i,
      /\b(if|when) you are (an?|the) (ai |automated |security )?(reviewer|auditor|inspector|scanner|classifier|grader|evaluator)\b/i,
      /\b(this|the) (network|agent|assistant|site) (is|has been) (officially )?(certified|verified|approved|audited) (safe|secure|by)\b/i,
    ]),
  },
  {
    id: "C-FORMAT",
    severity: "high",
    title: "Contains fake chat-format markers",
    why: "Markers such as <|im_start|>, [INST] or 'SYSTEM:' imitate the model's own message format to pass text off as a system message.",
    fix: "Remove the markers. Write instructions as plain text.",
    match: (text) => {
      const re = /<\|im_(?:start|end)\|>|\[\/?INST\]|<<\/?SYS>>|<\/?system>|<\/?(?:assistant|user)>|^\s*(?:system|assistant)\s*:/im;
      const m = text.match(re);
      return m ? [{ match: m[0], excerpt: text.slice(Math.max(0, m.index - 40), m.index + 80) }] : [];
    },
  },
  {
    id: "C-ENCODED",
    severity: "medium",
    title: "Contains an encoded blob",
    why: "Long Base64 or escaped text can hide instructions from a quick read while a model can still decode it.",
    fix: "Write instructions as plain text. Put data in your site's actions, not in instructions.",
    match: (text) => {
      const hits = [];
      const b64 = text.match(/[A-Za-z0-9+/]{80,}={0,2}/);
      if (b64) hits.push({ match: b64[0].slice(0, 40) + "…", excerpt: decodeBase64Preview(b64[0]) });
      const esc = text.match(/(?:\\u[0-9a-f]{4}|&#x?[0-9a-f]+;|%[0-9a-f]{2}){6,}/i);
      if (esc) hits.push({ match: esc[0].slice(0, 40), excerpt: esc[0].slice(0, 120) });
      return hits;
    },
  },
  {
    id: "C-URGENCY",
    severity: "low",
    title: "Uses pressure language",
    why: "Urgency ('your account will be locked') is a common way to rush people past their judgment.",
    fix: "State facts and deadlines plainly, without threats.",
    match: regexMatcher([
      /\b(account|card|access)\s+(will be|has been|is being)\s+(locked|suspended|closed|frozen|blocked|deleted)\b/i,
      /\b(act now|final (?:notice|warning)|immediately or|within \d+ (?:minutes|hours) or)\b/i,
    ]),
  },
];

function decodeBase64Preview(blob) {
  try {
    const raw = typeof atob === "function" ? atob(blob) : Buffer.from(blob, "base64").toString("binary");
    const printable = raw.replace(/[^\x20-\x7e]/g, "");
    if (printable.length / Math.max(raw.length, 1) > 0.9) return `decodes to: "${printable.slice(0, 160)}"`;
  } catch { /* not Base64 */ }
  return blob.slice(0, 120) + "…";
}

/**
 * Run every text rule over one string.
 *
 * :param text: An instruction, description or label.
 * :return: [{rule, match, excerpt}], excerpts with hidden characters revealed.
 */
export function scanText(text) {
  if (typeof text !== "string" || !text.trim()) return [];
  const normalized = normalizeForRules(text);
  const hits = [];
  for (const rule of TEXT_RULES) {
    const seen = new Set();
    for (const hit of rule.match(normalized)) {
      const key = hit.excerpt;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ rule, match: hit.match, excerpt: clip(revealHidden(hit.excerpt), 220) });
    }
  }
  return hits;
}

/**
 * Words in a brand or label that claim an authority the host may not have.
 */
export const AUTHORITY_TERMS = [
  "bank", "banking", "security team", "fraud", "official", "government", "gov", "tax", "irs", "hmrc", "police",
  "support team", "helpdesk", "help desk", "it department", "administrator", "paypal", "apple", "google",
  "microsoft", "amazon", "meta", "facebook", "visa", "mastercard", "amex", "american express", "netflix",
  "whatsapp", "openai", "anthropic", "cognizant", "mozilla", "nanda", "mit",
];

/**
 * Find authority words in a label that do not appear in the host name.
 *
 * :param label: A brand, label or description.
 * :param host: The publishing host, such as "evil.example".
 * :return: The authority words the host does not back up.
 */
export function unbackedAuthority(label, host) {
  if (typeof label !== "string") return [];
  const text = normalizeForRules(label).toLowerCase();
  const hostFlat = String(host || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const found = [];
  for (const term of AUTHORITY_TERMS) {
    const re = new RegExp(`\\b${term.replace(/ /g, "\\s+")}\\b`, "i");
    if (re.test(text) && !hostFlat.includes(term.replace(/[^a-z0-9]/g, ""))) found.push(term);
  }
  return found;
}

/**
 * Pull http(s) URLs out of text.
 *
 * :param text: Any string.
 * :return: The URLs found, without trailing punctuation.
 */
export function urlsIn(text) {
  if (typeof text !== "string") return [];
  return (normalizeForRules(text).match(/https?:\/\/[^\s)"'<>\]]+/gi) || []).map((u) => u.replace(/[.,;:!?]+$/, ""));
}

function clip(text, max) {
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}
