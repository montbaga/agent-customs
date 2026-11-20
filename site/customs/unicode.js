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
  [0x061c, "ARABIC LETTER MARK"],
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

// Every character Unicode says draws nothing ("default ignorable"). The lists above name
// the common ones; this catches the rest, such as U+206A-U+206F and unassigned ones.
const DEFAULT_IGNORABLE = /\p{Default_Ignorable_Code_Point}/u;

// Khmer and Mongolian writing use some of those characters (the Khmer inherent vowels and
// the Mongolian free variation selectors), so they do not count as hidden. The rules still
// skip them.
function isScriptIgnorable(cp) {
  return cp === 0x17b4 || cp === 0x17b5 || (cp >= 0x180b && cp <= 0x180d) || cp === 0x180f;
}

// The flags of England, Scotland and Wales are a black flag followed by tag characters
// ("gbeng", "gbsct", "gbwls"). Those exact sequences are emoji, not hidden text.
const FLAG_TAGS = /(?<=\u{1F3F4})\u{E0067}\u{E0062}(?:\u{E0065}\u{E006E}\u{E0067}|\u{E0073}\u{E0063}\u{E0074}|\u{E0077}\u{E006C}\u{E0073})\u{E007F}/gu;
const withoutFlagTags = (text) => text.replace(FLAG_TAGS, "");

// Characters that end a line. The rules read each as a newline, so clauses split there as
// they would at an ordinary line break, and the words around them stay apart.
const LINE_BREAKS = new Set([0x0b, 0x0c, 0x0d, 0x85, 0x2028, 0x2029]);

// Typographic quotes, which word processors and phones type for you, become plain ones, so
// "Don’t ask for passwords" reads as "Don't ask ...", a negation, not a request.
const QUOTES = new Map([
  [0x02bc, "'"], [0x2018, "'"], [0x2019, "'"], [0x201a, "'"], [0x201b, "'"], [0x2032, "'"],
  [0x201c, '"'], [0x201d, '"'], [0x201e, '"'], [0x201f, '"'], [0x2033, '"'],
]);

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

const isTag = (cp) => cp >= TAG_START && cp <= TAG_END;

// The ASCII character a tag character stands for. The tag markers themselves read as a space.
function tagChar(cp) {
  const ascii = cp - TAG_START;
  if (ascii >= 0x20 && ascii <= 0x7e) return String.fromCharCode(ascii);
  return ascii === 0x7f || ascii === 0x01 ? " " : "";
}

// A character that draws nothing, has no standard meaning, or is a control character. The
// lowest default-ignorable character is U+00AD, so plain ASCII skips the regex test.
function drawsNothing(cp, ch) {
  return (cp >= 0xad && DEFAULT_IGNORABLE.test(ch)) || isPrivateUse(cp) || isControl(cp);
}

/**
 * Whether chars[i] is hidden from a person reading the text: the one test that
 * scanHidden counts and revealHidden marks. Ordinary uses are not hidden: a joiner inside
 * an emoji, emoji style after a pictograph, and the characters Khmer and Mongolian need.
 * Tag characters are hidden too; callers decode them first.
 */
function isHiddenAt(chars, i) {
  const ch = chars[i];
  const cp = ch.codePointAt(0);
  if (!drawsNothing(cp, ch) || isScriptIgnorable(cp)) return false;
  // A zero-width joiner between two pictographs builds one emoji (a family, a flag).
  if (cp === 0x200d) return !(PICTOGRAPHIC.test(chars[i - 1] || "") && PICTOGRAPHIC.test(chars[i + 1] || ""));
  // U+FE00-U+FE0F after a pictograph asks for emoji style.
  if (cp >= 0xfe00 && cp <= 0xfe0f) return !PICTOGRAPHIC.test(chars[i - 1] || "");
  return true;
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
  const chars = Array.from(withoutFlagTags(text));
  for (let i = 0; i < chars.length; i += 1) {
    const cp = chars[i].codePointAt(0);
    if (isTag(cp)) {
      out.tags += 1;
      out.tagText += tagChar(cp);
    } else if (!isHiddenAt(chars, i)) {
      continue;
    } else if (INVISIBLE.has(cp)) {
      out.invisible += 1;
      out.invisibleNames.add(INVISIBLE.get(cp));
    } else if (BIDI.has(cp)) {
      out.bidi += 1;
      out.bidiNames.add(BIDI.get(cp));
    } else if (isVariationSelector(cp)) {
      out.variation += 1;
      if (cp >= 0xe0100) out.variationSupplement += 1;
    } else if (isPrivateUse(cp)) {
      out.privateUse += 1;
    } else if (isControl(cp)) {
      out.control += 1;
    } else {
      out.invisible += 1;
      out.invisibleNames.add(`INVISIBLE CHARACTER ${hex(cp)}`);
    }
  }
  out.tagText = out.tagText.replace(/\s+/g, " ").trim();
  const zalgo = text.match(/\p{M}{3,}/gu);
  if (zalgo) {
    out.invisible += zalgo.length;
    out.invisibleNames.add("EXCESSIVE COMBINING MARKS");
  }
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
  const chars = Array.from(withoutFlagTags(text));
  for (let i = 0; i < chars.length; i += 1) {
    const cp = chars[i].codePointAt(0);
    if (isTag(cp)) {
      tagRun += tagChar(cp);
      continue;
    }
    flush();
    out += isHiddenAt(chars, i) ? `⟦${hex(cp)}⟧` : chars[i];
  }
  flush();
  return out;
}

/**
 * Remove every hidden character, so pattern rules see the words a model would read
 * once the hiding characters are skipped (for example "pass​word").
 *
 * Then compatibility forms become their plain letters (NFKC): a no-break or ideographic
 * space is a space, and fullwidth or mathematical letters ("ｃａｒｄ", "𝐩𝐢𝐧") are ordinary
 * ones. Runs of spaces and tabs become one space, so "card  number" is "card number".
 *
 * :param text: Any string.
 * :return: The visible text plus any tag-hidden text, on a line of its own.
 */
export function normalizeForRules(text) {
  if (typeof text !== "string") return "";
  let visible = "";
  let hidden = "";
  // One pass: tag text is collected, and every character that draws nothing is dropped,
  // including the ordinary ones (an emoji joiner changes no word).
  for (const ch of withoutFlagTags(text)) {
    const cp = ch.codePointAt(0);
    if (isTag(cp)) hidden += tagChar(cp);
    else if (LINE_BREAKS.has(cp)) visible += "\n";
    else if (QUOTES.has(cp)) visible += QUOTES.get(cp);
    else if (!drawsNothing(cp, ch)) visible += ch;
  }
  hidden = hidden.replace(/\s+/g, " ").trim();
  // Keep newlines: the rules split clauses at them.
  visible = visible.normalize("NFKC").replace(/[^\S\n]+/g, " ");
  return hidden ? `${visible}\n${hidden}` : visible;
}

// Letters from scripts that look like Latin letters.
const CONFUSABLE_SCRIPTS = [
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Armenian", /\p{Script=Armenian}/u],
  ["Cherokee", /\p{Script=Cherokee}/u],
];

// Look-alike letters from Cyrillic, Greek, Armenian, Cherokee and IPA/Latin-extended
// mapped to their ASCII Latin skeleton.
const CONFUSABLE_CHARS = new Map([
  // Cyrillic
  ["а", "a"], ["А", "A"], ["В", "B"], ["е", "e"], ["Е", "E"], ["ё", "e"], ["Ё", "E"],
  ["і", "i"], ["І", "I"], ["ї", "i"], ["Ї", "I"], ["ј", "j"], ["Ј", "J"], ["К", "K"],
  ["М", "M"], ["Н", "H"], ["о", "o"], ["О", "O"], ["р", "p"], ["Р", "P"], ["с", "c"],
  ["С", "C"], ["Т", "T"], ["у", "y"], ["У", "Y"], ["х", "x"], ["Х", "X"], ["ѕ", "s"],
  ["Ѕ", "S"], ["һ", "h"], ["ԁ", "d"], ["ԍ", "g"], ["ԛ", "q"], ["Ԛ", "Q"], ["ԝ", "w"],
  ["Ԝ", "W"], ["ѵ", "v"], ["ӏ", "l"],
  // Greek
  ["α", "a"], ["Α", "A"], ["β", "b"], ["Β", "B"], ["ε", "e"], ["Ε", "E"], ["ζ", "z"],
  ["Ζ", "Z"], ["η", "n"], ["Η", "H"], ["ι", "i"], ["Ι", "I"], ["κ", "k"], ["Κ", "K"],
  ["μ", "u"], ["Μ", "M"], ["ν", "v"], ["Ν", "N"], ["ο", "o"], ["Ο", "O"], ["ρ", "p"],
  ["Ρ", "P"], ["ς", "s"], ["σ", "s"], ["τ", "t"], ["Τ", "T"], ["υ", "u"], ["Υ", "Y"],
  ["χ", "x"], ["Χ", "X"], ["γ", "y"], ["ω", "w"],
  // Armenian & Cherokee & Latin/IPA lookalikes
  ["օ", "o"], ["Օ", "O"], ["ս", "u"], ["հ", "h"], ["Տ", "S"], ["Ք", "P"],
  ["Ꭺ", "A"], ["Ꮀ", "F"], ["Ꮐ", "G"], ["Ꮋ", "H"], ["Ꭻ", "J"], ["Ꮮ", "L"], ["Ꮇ", "M"],
  ["Ꮲ", "P"], ["Ꭱ", "R"], ["Ꮪ", "S"], ["Ꮦ", "T"], ["Ꮩ", "V"], ["Ꮃ", "W"], ["Ꮓ", "Z"],
  ["Ꮟ", "b"], ["Ꭵ", "i"], ["Ꮥ", "d"],
  ["ɑ", "a"], ["ɒ", "a"], ["ɓ", "b"], ["ᴄ", "c"], ["ɗ", "d"], ["ɛ", "e"], ["ɡ", "g"],
  ["ɢ", "G"], ["ʜ", "H"], ["ɪ", "i"], ["ɩ", "i"], ["ʝ", "j"], ["ᴋ", "k"], ["ʟ", "l"],
  ["ɴ", "N"], ["ᴏ", "o"], ["ɵ", "o"], ["ᴘ", "p"], ["ʀ", "R"], ["ʂ", "s"], ["ᴛ", "t"],
  ["ᴜ", "u"], ["ʋ", "v"], ["ᴡ", "w"], ["ʏ", "Y"], ["ᴢ", "z"], ["ı", "i"], ["ſ", "s"],
]);

const HAS_CONFUSABLE_SCRIPT = /\p{Script=Cyrillic}|\p{Script=Greek}|\p{Script=Armenian}|\p{Script=Cherokee}/u;

function foldWordChars(word) {
  let out = "";
  for (const ch of word) out += CONFUSABLE_CHARS.get(ch) ?? ch;
  return out;
}

function isAllConfusableLetters(word) {
  let letters = 0;
  for (const ch of word) {
    if (!/\p{L}/u.test(ch)) continue;
    letters += 1;
    if (!CONFUSABLE_CHARS.has(ch)) return false;
  }
  return letters > 0;
}

/**
 * Fold look-alike characters (Cyrillic, Greek, etc.) to their Latin skeleton where
 * words mix scripts, or where an all-confusable word sits inside a predominantly Latin
 * line. Genuine non-Latin text (Russian, Greek...) is left untouched so language checks
 * still read it accurately.
 *
 * :param text: Normalized text.
 * :return: Text with confusable tokens folded to ASCII Latin.
 */
export function foldConfusableTokens(text) {
  if (typeof text !== "string" || !text) return "";
  return text.split("\n").map((line) => {
    const words = line.split(/(\s+)/);
    const latinCount = words.filter((w) => /\p{Script=Latin}/u.test(w) && !HAS_CONFUSABLE_SCRIPT.test(w)).length;
    const nonLatinNative = words.filter((w) => HAS_CONFUSABLE_SCRIPT.test(w) && !/\p{Script=Latin}/u.test(w) && !isAllConfusableLetters(w)).length;
    const mostlyLatin = latinCount >= 2 && latinCount > nonLatinNative;
    return words.map((tok) => {
      if (!tok || /^\s+$/.test(tok)) return tok;
      const hasLatin = /\p{Script=Latin}/u.test(tok);
      const hasConfusable = HAS_CONFUSABLE_SCRIPT.test(tok) || [...tok].some((ch) => CONFUSABLE_CHARS.has(ch));
      if (!hasConfusable) return tok;
      if (hasLatin || (mostlyLatin && isAllConfusableLetters(tok))) return foldWordChars(tok);
      return tok;
    }).join("");
  }).join("\n");
}

/**
 * Remove hidden tag, bidi, invisible, non-emoji variation, private-use and control
 * characters from runtime text while keeping ordinary writing and emoji intact.
 *
 * :param text: Any runtime string.
 * :return: Cleaned text.
 */
export function stripHiddenChars(text) {
  if (typeof text !== "string" || !text) return String(text ?? "");
  const chars = Array.from(withoutFlagTags(text));
  let out = "";
  for (let i = 0; i < chars.length; i += 1) {
    const cp = chars[i].codePointAt(0);
    if (isTag(cp) || isHiddenAt(chars, i)) continue;
    out += chars[i];
  }
  return out;
}

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
  // Words end at any mark that is not a letter: in `classify("центрифуга")` the Cyrillic word
  // stands apart from the Latin one. A look-alike hides inside one run of letters.
  const tokens = text.split(/[^\p{L}\p{N}\p{M}'’]+/u).filter(Boolean)
    .map((raw) => raw.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, ""))
    .filter(Boolean);
  const latinWords = tokens.filter((w) => /\p{Script=Latin}/u.test(w) && !HAS_CONFUSABLE_SCRIPT.test(w)).length;
  for (const word of tokens) {
    const scripts = CONFUSABLE_SCRIPTS.filter(([, re]) => re.test(word)).map(([name]) => name);
    if (!scripts.length) continue;
    if (/\p{Script=Latin}/u.test(word)) {
      found.push({ word, scripts });
    } else if (latinWords >= 2 && [...word].length >= 3 && isAllConfusableLetters(word)) {
      // A whole word spelled only with look-alike letters among Latin words ("аррӏе ID") passes
      // for English. Lone symbols such as β or γ in formulas are left alone.
      found.push({ word, scripts });
    }
  }
  // Fullwidth Latin letters (Ｐａｙ) and Mathematical styled letters (𝐩𝐚𝐬𝐬) look like ASCII.
  if (/[Ａ-Ｚａ-ｚ]/u.test(text)) found.push({ word: text, scripts: ["Fullwidth Latin"] });
  if (/[\u{1D400}-\u{1D7FF}]/u.test(text)) found.push({ word: text, scripts: ["Mathematical styled Latin"] });
  return found;
}
