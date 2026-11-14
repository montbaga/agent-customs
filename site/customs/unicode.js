// unicode.js: find and reveal characters a person cannot see but a model can read.
//
// Published agent instructions are public, so anyone can read them before trusting
// a network. Invisible characters break that promise: Unicode "tag" characters
// (U+E0000-U+E007F) can carry a whole hidden sentence that most screens show as
// nothing, zero-width characters can hide or split words, and bidirectional controls
// can make text display in a different order than a model reads it ("Trojan Source").

const TAG_START = 0xe0000;
const TAG_END = 0xe007f;

// Zero-width and other invisible formatting characters.
const INVISIBLE = new Map([
  [0x00ad, "SOFT HYPHEN"],
  [0x034f, "COMBINING GRAPHEME JOINER"],
  [0x115f, "HANGUL CHOSEONG FILLER"],
  [0x1160, "HANGUL JUNGSEONG FILLER"],
  [0x180e, "MONGOLIAN VOWEL SEPARATOR"],
  [0x200b, "ZERO WIDTH SPACE"],
  [0x200c, "ZERO WIDTH NON-JOINER"],
  [0x200d, "ZERO WIDTH JOINER"],
  [0x2060, "WORD JOINER"],
  [0x2061, "FUNCTION APPLICATION"],
  [0x2062, "INVISIBLE TIMES"],
  [0x2063, "INVISIBLE SEPARATOR"],
  [0x2064, "INVISIBLE PLUS"],
  [0x3164, "HANGUL FILLER"],
  [0xfeff, "ZERO WIDTH NO-BREAK SPACE"],
  [0xffa0, "HALFWIDTH HANGUL FILLER"],
]);

// Bidirectional controls that reorder how text is displayed.
const BIDI = new Map([
  [0x200e, "LEFT-TO-RIGHT MARK"],
  [0x200f, "RIGHT-TO-LEFT MARK"],
  [0x202a, "LEFT-TO-RIGHT EMBEDDING"],
  [0x202b, "RIGHT-TO-LEFT EMBEDDING"],
  [0x202c, "POP DIRECTIONAL FORMATTING"],
  [0x202d, "LEFT-TO-RIGHT OVERRIDE"],
  [0x202e, "RIGHT-TO-LEFT OVERRIDE"],
  [0x2066, "LEFT-TO-RIGHT ISOLATE"],
  [0x2067, "RIGHT-TO-LEFT ISOLATE"],
  [0x2068, "FIRST STRONG ISOLATE"],
  [0x2069, "POP DIRECTIONAL ISOLATE"],
]);

const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;

function isVariationSelector(cp) {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}

function isPrivateUse(cp) {
  return (cp >= 0xe000 && cp <= 0xf8ff) || (cp >= 0xf0000 && cp <= 0xffffd) || (cp >= 0x100000 && cp <= 0x10fffd);
}

function isControl(cp) {
  return (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || (cp >= 0x7f && cp <= 0x9f);
}

function hex(cp) {
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}

/**
 * Scan one string for hidden characters.
 *
 * :param text: Any string from a published file.
 * :return: {tags, tagText, invisible, bidi, variation, privateUse, control, total},
 *   where tagText is the ASCII sentence hidden in tag characters, if any.
 */
export function scanHidden(text) {
  const out = { tags: 0, tagText: "", invisible: 0, invisibleNames: new Set(), bidi: 0, bidiNames: new Set(),
    variation: 0, variationSupplement: 0, privateUse: 0, control: 0, total: 0 };
  if (typeof text !== "string" || !text) return out;
  const chars = Array.from(text);
  for (let i = 0; i < chars.length; i += 1) {
    const cp = chars[i].codePointAt(0);
    if (cp >= TAG_START && cp <= TAG_END) {
      out.tags += 1;
      const ascii = cp - TAG_START;
      if (ascii >= 0x20 && ascii <= 0x7e) out.tagText += String.fromCharCode(ascii);
      else if (ascii === 0x7f || ascii === 0x01) out.tagText += " ";
      continue;
    }
    if (INVISIBLE.has(cp)) {
      // A zero-width joiner between two pictographs builds one emoji (a family, a flag).
      if (cp === 0x200d && PICTOGRAPHIC.test(chars[i - 1] || "") && PICTOGRAPHIC.test(chars[i + 1] || "")) continue;
      out.invisible += 1;
      out.invisibleNames.add(INVISIBLE.get(cp));
      continue;
    }
    if (BIDI.has(cp)) {
      out.bidi += 1;
      out.bidiNames.add(BIDI.get(cp));
      continue;
    }
    if (isVariationSelector(cp)) {
      // U+FE0F after a pictograph asks for emoji style: normal.
      const prev = chars[i - 1] || "";
      if (cp >= 0xfe00 && cp <= 0xfe0f && PICTOGRAPHIC.test(prev)) continue;
      if (cp >= 0xe0100) out.variationSupplement += 1;
      out.variation += 1;
      continue;
    }
    if (isPrivateUse(cp)) { out.privateUse += 1; continue; }
    if (isControl(cp)) { out.control += 1; continue; }
  }
  out.tagText = out.tagText.replace(/\s+/g, " ").trim();
  out.total = out.tags + out.invisible + out.bidi + out.variation + out.privateUse + out.control;
  return out;
}

/**
 * Make hidden characters visible, for a person reviewing the text.
 * Tag runs become ⟦hidden text: "..."⟧ and other characters ⟦U+XXXX⟧.
 *
 * :param text: Any string.
 * :return: The same text with every hidden character shown.
 */
export function revealHidden(text) {
  if (typeof text !== "string" || !text) return text;
  let out = "";
  let tagRun = "";
  const flush = () => {
    if (tagRun) {
      out += `⟦hidden text: "${tagRun}"⟧`;
      tagRun = "";
    }
  };
  const chars = Array.from(text);
  for (let i = 0; i < chars.length; i += 1) {
    const ch = chars[i];
    const cp = ch.codePointAt(0);
    if (cp >= TAG_START && cp <= TAG_END) {
      const ascii = cp - TAG_START;
      tagRun += ascii >= 0x20 && ascii <= 0x7e ? String.fromCharCode(ascii) : "";
      continue;
    }
    flush();
    const joinerInEmoji = cp === 0x200d && PICTOGRAPHIC.test(chars[i - 1] || "") && PICTOGRAPHIC.test(chars[i + 1] || "");
    const emojiStyle = cp >= 0xfe00 && cp <= 0xfe0f && PICTOGRAPHIC.test(chars[i - 1] || "");
    if (!joinerInEmoji && !emojiStyle
        && (INVISIBLE.has(cp) || BIDI.has(cp) || isVariationSelector(cp) || isPrivateUse(cp) || isControl(cp))) {
      out += `⟦${hex(cp)}⟧`;
    } else {
      out += ch;
    }
  }
  flush();
  return out;
}

/**
 * Remove every hidden character, so pattern rules see the words a model would read
 * once the hiding characters are skipped (for example "pass​word").
 *
 * :param text: Any string.
 * :return: The visible text plus any tag-hidden text, separated by a space.
 */
export function normalizeForRules(text) {
  if (typeof text !== "string") return "";
  const hidden = scanHidden(text).tagText;
  let visible = "";
  for (const ch of Array.from(text)) {
    const cp = ch.codePointAt(0);
    if ((cp >= TAG_START && cp <= TAG_END) || INVISIBLE.has(cp) || BIDI.has(cp) || isVariationSelector(cp)) continue;
    visible += ch;
  }
  return hidden ? `${visible}\n${hidden}` : visible;
}

// Letters from scripts that look like Latin letters.
const CONFUSABLE_SCRIPTS = [
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Armenian", /\p{Script=Armenian}/u],
  ["Cherokee", /\p{Script=Cherokee}/u],
];

/**
 * Find words that mix Latin letters with look-alike letters from another script,
 * such as "Sаvings" with a Cyrillic "а". These fool people, not models.
 *
 * :param text: A name, brand or label.
 * :return: A list of {word, scripts} for each mixed word.
 */
export function findMixedScriptWords(text) {
  if (typeof text !== "string" || !text) return [];
  const found = [];
  for (const word of text.split(/[\s_\-./:]+/u)) {
    if (!/\p{Script=Latin}/u.test(word)) continue;
    const scripts = CONFUSABLE_SCRIPTS.filter(([, re]) => re.test(word)).map(([name]) => name);
    if (scripts.length) found.push({ word, scripts });
  }
  // Fullwidth Latin letters (Ｐａｙ) look like ASCII but are different characters.
  if (/[Ａ-Ｚａ-ｚ]/u.test(text)) found.push({ word: text, scripts: ["Fullwidth Latin"] });
  return found;
}
