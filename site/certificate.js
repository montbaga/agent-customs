// certificate.js: builds a standalone SVG Border Clearance Certificate or Security Advisory
// styled after archival cotton-parchment diplomatic visas, with a bound passport spine,
// guilloche filigree, circular cancellation stamp, deterministic SHA-256 visual glyph,
// and an ICAO-style machine-readable zone. Zero DOM dependencies and zero network calls.

const DEFAULT_THEME = {
  spine: "#0c1d18",
  paperTop: "#f7f1e3",
  paperMid: "#f1e7d2",
  paperEdge: "#e6d8bc",
  wellPaper: "#eadec5",
  rule: "#c8b99b",
  ink: "#0f2019",
  inkMuted: "#4a5b53",
  inkDim: "#6f7d75",
  gold: "#b88a28",
  goldLight: "#e3c067",
  goldDark: "#7d5912",
  okInk: "#0f6e43",
  okTint: "#dff2e7",
  warnInk: "#a1550a",
  warnTint: "#f9ead7",
  badInk: "#a82428",
  badTint: "#fae1e1",
  cautionInk: "#8c6b08",
  cautionTint: "#f7f0d4",
};

const VERDICT_META = {
  CLEARED: {
    documentTitle: "Border Clearance Certificate",
    eyebrow: "ARTICLE VII · ENTRY AUTHORIZATION DIPLOMA",
    stampLabel: "CLEARED",
    mrzCode: "CLEARED",
    toneKey: "ok",
    clearanceAllowed: true,
    advisoryNote: "Version-locked with SHA-256 pinning. Re-inspect live to confirm this target has not changed since issuance.",
  },
  HOLD: {
    documentTitle: "Border Inspection Advisory",
    eyebrow: "HOLD ORDER · HUMAN REVIEW REQUIRED",
    stampLabel: "HELD",
    mrzCode: "HELD<<",
    toneKey: "warn",
    clearanceAllowed: false,
    advisoryNote: "Hold notice: human review is required before granting this network access to your key or browser session.",
  },
  DENIED: {
    documentTitle: "Entry Refusal Notice",
    eyebrow: "CUSTOMS REFUSAL · RULE VIOLATION DETECTED",
    stampLabel: "DENIED",
    mrzCode: "DENIED",
    toneKey: "bad",
    clearanceAllowed: false,
    advisoryNote: "Access refused by deterministic border rules. Do not approve or connect this network to any live workflow.",
  },
  INVALID: {
    documentTitle: "Entry Refusal Notice",
    eyebrow: "INVALID PAPERS · SCHEMA NON-COMPLIANCE",
    stampLabel: "INVALID",
    mrzCode: "INVALID",
    toneKey: "bad",
    clearanceAllowed: false,
    advisoryNote: "Manifest or network papers failed validation. Entry remains refused until compliant papers are published.",
  },
  UNREADABLE: {
    documentTitle: "Inspection Unreadable Notice",
    eyebrow: "PORT BLOCKED · FAIL-CLOSED SAFE DEFAULT",
    stampLabel: "BLOCKED",
    mrzCode: "UNREAD",
    toneKey: "caution",
    clearanceAllowed: false,
    advisoryNote: "Required files could not be fetched or parsed within safety limits. Fail-closed rules prevent execution.",
  },
};

/** Escape XML special characters cleanly and strip disallowed control characters. */
export function escapeXml(value) {
  return String(value ?? "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function normalizeHex(hex, fallback) {
  const m = String(hex ?? "").trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (!m) return fallback;
  const h = m[1];
  return h.length === 3 ? `#${h[0]}${h[0]}${h[1]}${h[1]}${h[2]}${h[2]}` : `#${h.toLowerCase()}`;
}

function mixHex(hexA, hexB, weightB) {
  const a = normalizeHex(hexA, "#0c1d18");
  const b = normalizeHex(hexB, "#000000");
  const w = Math.max(0, Math.min(1, weightB));
  const ch = (s, i) => parseInt(s.slice(i, i + 2), 16);
  const blend = (i) => Math.round(ch(a, i) * (1 - w) + ch(b, i) * w).toString(16).padStart(2, "0");
  return `#${blend(1)}${blend(3)}${blend(5)}`;
}

function clipText(value, maxChars) {
  const s = String(value ?? "").replace(/\s+/g, " ").trim();
  if (s.length <= maxChars) return s;
  const head = Math.max(8, Math.floor((maxChars - 1) * 0.65));
  const tail = Math.max(4, maxChars - 1 - head);
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

function safeHttpUrl(candidate, fallback) {
  try {
    const parsed = new URL(String(candidate ?? "").trim());
    if (parsed.protocol === "http:" || parsed.protocol === "https:") return parsed.href;
  } catch { /* fallback below */ }
  return fallback;
}

function splitExactLines(value, maxPerLine) {
  const s = String(value ?? "").trim();
  if (s.length <= maxPerLine) return [s];
  const lines = [];
  for (let i = 0; i < s.length; i += maxPerLine) lines.push(s.slice(i, i + maxPerLine));
  return lines;
}

function wrapLines(value, maxChars, maxLines) {
  const words = String(value ?? "").replace(/\s+/g, " ").trim().split(" ").filter(Boolean);
  if (!words.length) return [""];
  const lines = [];
  let cur = "";
  let clipped = false;
  for (let i = 0; i < words.length; i += 1) {
    const chunk = words[i].length > maxChars ? `${words[i].slice(0, maxChars - 1)}…` : words[i];
    if (!cur) cur = chunk;
    else if (cur.length + 1 + chunk.length <= maxChars) cur = `${cur} ${chunk}`;
    else {
      lines.push(cur);
      if (lines.length === maxLines) { clipped = true; cur = ""; break; }
      cur = chunk;
    }
  }
  if (cur && lines.length < maxLines) lines.push(cur);
  if (clipped && lines.length === maxLines) {
    const last = lines[maxLines - 1];
    lines[maxLines - 1] = last.length >= maxChars ? `${last.slice(0, maxChars - 1)}…` : `${last}…`;
  }
  return lines;
}

function shortDate(iso) {
  const ts = Date.parse(iso || "");
  if (!Number.isFinite(ts)) return String(iso || "").slice(0, 10).toUpperCase();
  try {
    return new Date(ts).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric", timeZone: "UTC" }).toUpperCase();
  } catch {
    return new Date(ts).toISOString().slice(0, 10);
  }
}

function compactIsoDate(iso) {
  const ts = Date.parse(iso || "");
  if (!Number.isFinite(ts)) return "00000000";
  return new Date(ts).toISOString().slice(0, 10).replace(/-/g, "");
}

function resolveTheme(palette) {
  const spine = normalizeHex(palette?.bgMid, DEFAULT_THEME.spine);
  return {
    ...DEFAULT_THEME,
    spine,
    spineDeep: mixHex(spine, "#000000", 0.35),
    spineEdge: mixHex(spine, "#ffffff", 0.12),
    spineAccent: normalizeHex(palette?.cleared, "#c8f03c"),
  };
}

function tonePair(t, toneKey) {
  const map = {
    ok: { ink: t.okInk, tint: t.okTint },
    warn: { ink: t.warnInk, tint: t.warnTint },
    bad: { ink: t.badInk, tint: t.badTint },
    caution: { ink: t.cautionInk, tint: t.cautionTint },
  };
  return map[toneKey] || map.caution;
}

function buildChecksSummary(report, t) {
  const findings = report.findings || [];
  const byCat = (cat) => findings.filter((f) => f.category === cat);
  const c = report.conformance || { passed: 0, total: 0, failed: 0, warned: 0 };
  const contraband = byCat("contraband").filter((f) => f.severity !== "info");
  const external = (report.itinerary || []).filter((s) => !s.sameSite);
  const privacy = report.privacy || [];
  const hasSecret = byCat("privacy").some((f) => f.rule === "S-SECRET");
  const idFindings = byCat("identity").filter((f) => f.rule !== "D-DRIFT");

  const statusFor = (list, fallbackMark = "✓", fallbackColor = t.okInk) => {
    if (list.some((f) => f.severity === "critical" || f.severity === "high")) return { glyph: "✕", color: t.badInk };
    if (list.some((f) => f.severity === "medium" || f.severity === "low")) return { glyph: "!", color: t.warnInk };
    return { glyph: fallbackMark, color: fallbackColor };
  };

  const pColor = c.failed ? t.badInk : c.warned ? t.cautionInk : t.okInk;
  const pGlyph = c.failed ? "✕" : c.warned ? "!" : "✓";
  const sContra = statusFor(contraband);
  const sItin = external.length && !byCat("itinerary").length ? { glyph: "•", color: t.inkMuted } : statusFor(byCat("itinerary"));
  const sPriv = statusFor(byCat("privacy"));
  const sId = statusFor(idFindings);

  return [
    { num: "01", name: "PAPERS", value: `${c.passed}/${c.total} pass`, sub: c.failed ? `${c.failed} failed` : c.warned ? `${c.warned} warn` : "Spec compliant", glyph: pGlyph, color: pColor },
    { num: "02", name: "CONTRABAND", value: contraband.length ? `${contraband.length} flagged` : "None found", sub: contraband.length ? "Prompt / script" : "Clean copy", glyph: sContra.glyph, color: sContra.color },
    { num: "03", name: "ITINERARY", value: external.length ? `${external.length} external` : "Stays home", sub: external.length ? clipText(external.map((s) => s.host).join(", "), 24) : "Local origin", glyph: sItin.glyph, color: sItin.color },
    { num: "04", name: "PRIVACY", value: hasSecret ? "Leaks secret" : privacy.length ? `${privacy.length} rule(s)` : "No leaks", sub: hasSecret ? "Public key" : privacy.length ? "Shared data" : "Closed context", glyph: sPriv.glyph, color: sPriv.color },
    { num: "05", name: "IDENTITY", value: idFindings.length ? `${idFindings.length} alert(s)` : (report.identity?.short || "No hash"), sub: report.identity?.frontMan ? clipText(report.identity.frontMan, 24) : `${(report.identity?.agents || []).length} agent(s)`, glyph: sId.glyph, color: sId.color },
  ];
}

function verificationStatus(receiptCheck, t, clearanceAllowed = true) {
  const r = receiptCheck?.receipt;
  if (receiptCheck?.valid && receiptCheck.matches === false) {
    return { badge: "CHANGED SINCE SIGNED", color: t.warnInk, fill: t.warnTint, detail: `Signed stamp from ${shortDate(r?.inspectedAt)} no longer matches live hash` };
  }
  if (receiptCheck?.valid && receiptCheck.expired) {
    return { badge: "SIGNED STAMP EXPIRED", color: t.warnInk, fill: t.warnTint, detail: `Key ${r?.inspector?.keyId || ""} expired ${shortDate(r?.expiresAt)}` };
  }
  if (receiptCheck?.valid && r) {
    return {
      badge: "VERIFIED ES256 SIGNATURE",
      color: clearanceAllowed ? t.okInk : t.inkMuted,
      fill: clearanceAllowed ? t.okTint : t.wellPaper,
      detail: `Signed by Agent Customs · Key ${r.inspector?.keyId || "published"} · Valid through ${shortDate(r.expiresAt)}`,
    };
  }
  return { badge: "UNSIGNED BROWSER SNAPSHOT", color: t.inkMuted, fill: t.wellPaper, detail: "Point-in-time client scan · Verify live before connecting" };
}

/** Draw a deterministic 7x7 mirrored cryptographic mosaic seal from a SHA-256 hash. */
function buildFingerprintCrest(hash, x, y, cellSize, color, borderColor) {
  const hex = String(hash || "").replace(/^sha256:/i, "").replace(/[^0-9a-f]/gi, "") || "0000000000000000";
  const cells = [];
  for (let row = 0; row < 7; row++) {
    for (let col = 0; col < 4; col++) {
      const nib = parseInt(hex[(row * 4 + col) % hex.length], 16);
      if ((nib & 1) === 1 || (row === col && (nib & 2) === 2)) {
        const xLeft = x + col * cellSize;
        const xRight = x + (6 - col) * cellSize;
        const cy = y + row * cellSize;
        cells.push(`<rect x="${xLeft}" y="${cy}" width="${cellSize - 1.5}" height="${cellSize - 1.5}" rx="2" fill="${escapeXml(color)}"/>`);
        if (col !== 3) cells.push(`<rect x="${xRight}" y="${cy}" width="${cellSize - 1.5}" height="${cellSize - 1.5}" rx="2" fill="${escapeXml(color)}"/>`);
      }
    }
  }
  const size = cellSize * 7;
  return `<rect x="${x - 8}" y="${y - 8}" width="${size + 15}" height="${size + 15}" rx="8" fill="#faf5e8" stroke="${escapeXml(borderColor)}" stroke-width="1"/>${cells.join("")}`;
}

/** Build radial guilloche rosette petal paths centered cleanly around (cx, cy). */
function buildGuillocheRosette(cx, cy, rOuter, rInner, petals = 18) {
  const paths = [];
  for (let i = 0; i < petals; i++) {
    const angle = (i * 360) / petals;
    paths.push(`<ellipse cx="${cx}" cy="${cy - (rOuter + rInner) / 2}" rx="${((rOuter - rInner) * 0.42).toFixed(1)}" ry="${((rOuter - rInner) * 0.72).toFixed(1)}" transform="rotate(${angle} ${cx} ${cy})"/>`);
  }
  return paths.join("");
}

function mrzToken(text, maxLen) {
  return String(text ?? "")
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "<")
    .replace(/^<+|<+$/g, "")
    .slice(0, maxLen) || "UNKNOWN";
}

function buildMrzLines(report, meta, receiptCheck) {
  const rawName = report.identity?.brand || report.identity?.network || report.target?.host || "NETWORK";
  const line1 = `P<AGTCUSTOMS<<${meta.mrzCode}<<${mrzToken(rawName, 40)}`.padEnd(64, "<").slice(0, 64);
  const hashToken = (report.identity?.hash || "NOHASH").replace(/[^a-zA-Z0-9]/g, "").toUpperCase().slice(0, 16);
  const keyToken = mrzToken(receiptCheck?.valid ? receiptCheck?.receipt?.inspector?.keyId : "UNSIGNED", 12);
  const c = report.conformance || { passed: 0, total: 0 };
  const dateToken = compactIsoDate(report.inspectedAt);
  const line2 = `${hashToken}<<KEY<${keyToken}<<SPEC${String(c.passed).padStart(2, "0")}OF${String(c.total).padStart(2, "0")}<<${dateToken}`.padEnd(64, "<").slice(0, 64);
  return [line1, line2];
}

/**
 * Derive metadata and verdict-safe presentation info for an inspection report.
 *
 * :param report: Inspection report object from analyzeNetwork / inspectNetworkUrl.
 * :param receiptCheck: Optional result from verifyReceipt().
 * :return: Structured metadata including clearanceAllowed, documentTitle, and status labels.
 */
export function certificateMeta(report, receiptCheck = null) {
  const code = String(report?.verdict?.code || "HOLD").toUpperCase();
  const base = VERDICT_META[code] || VERDICT_META.HOLD;
  const sig = verificationStatus(receiptCheck, DEFAULT_THEME);
  const hashHex = String(report?.identity?.hash || "").replace(/^sha256:/i, "").slice(0, 8).toUpperCase() || "00000000";
  const serial = `AC-${compactIsoDate(report?.inspectedAt)}-${hashHex}`;
  return {
    code,
    serial,
    ...base,
    signedStatus: sig.badge,
    signedDetail: sig.detail,
  };
}

/**
 * Build a safe download filename for a certificate or advisory.
 *
 * :param report: Inspection report object.
 * :param ext: File extension ("png" or "svg").
 * :return: Clean slugged filename.
 */
export function certificateFilename(report, ext = "png") {
  const meta = certificateMeta(report);
  const name = (report?.identity?.brand || report?.identity?.network || report?.target?.host || "network")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 36) || "network";
  const stamp = meta.code.toLowerCase();
  const date = new Date(Date.parse(report?.inspectedAt || "") || Date.now()).toISOString().slice(0, 10);
  const safeExt = String(ext || "png").toLowerCase().replace(/[^a-z0-9]/g, "") || "png";
  return `agent-customs-${name}-${stamp}-${date}.${safeExt}`;
}

/**
 * Render an inspection report as a bespoke archival-parchment SVG certificate or advisory.
 *
 * :param report: Full report returned by inspectNetworkUrl / desk.latest.
 * :param options.receiptCheck: Optional result from verifyReceipt().
 * :param options.verifyUrl: Re-check permalink shown on the certificate.
 * :param options.theme: Optional palette overrides (bgMid tints the bound spine).
 * :return: Complete SVG XML markup string.
 */
export function certificateSvg(report, { receiptCheck = null, verifyUrl = "", theme = null } = {}) {
  const t = resolveTheme(theme);
  const meta = certificateMeta(report, receiptCheck);
  const pair = tonePair(t, meta.toneKey);
  const sig = verificationStatus(receiptCheck, t, meta.clearanceAllowed);

  const title = report?.identity?.brand || report?.identity?.network || report?.target?.host || "Inspected Network";
  const url = report?.target?.url || "Unknown URL";
  const summaryLines = wrapLines(report?.verdict?.summary || "", 66, 2);
  const checks = buildChecksSummary(report, t);
  const fullHash = report?.identity?.hash || "n/a (failed before hashing)";
  const fallbackVerify = `https://montbaga.github.io/agent-customs/?inspect=${encodeURIComponent(url)}`;
  const recheckUrl = safeHttpUrl(verifyUrl, fallbackVerify);
  const recheckLines = splitExactLines(recheckUrl, recheckUrl.length > 148 ? Math.max(115, Math.ceil(recheckUrl.length / 2)) : 148);
  const recheckTextMarkup = recheckLines.length === 1
    ? `<text x="202" y="797" class="mono" font-size="11.8" font-weight="700" text-decoration="underline" fill="${escapeXml(pair.ink)}">${escapeXml(recheckLines[0])}</text>`
    : recheckLines.slice(0, 2).map((ln, idx) => `<text x="202" y="${789 + idx * 14}" class="mono" font-size="10.2" font-weight="700" text-decoration="underline" fill="${escapeXml(pair.ink)}">${escapeXml(ln)}</text>`).join("");
  const [mrz1, mrz2] = buildMrzLines(report, meta, receiptCheck);
  const inspectedDate = shortDate(report?.inspectedAt);
  const inspectedTime = report?.inspectedAt ? String(report.inspectedAt).slice(0, 19).replace("T", " ") + "Z" : "—";
  const agentCount = (report?.identity?.agents || []).length;
  const frontAgent = report?.identity?.frontMan || "none";
  const profile = report?.profile || "Open Agentic Web MVP 0.2";
  const pillW = Math.max(230, Math.min(330, sig.badge.length * 8.1 + 44));
  const pillX = 1336 - pillW;

  // Ledger cells across x=188..1336 (width 1148 => 5 columns x 229.6px each)
  const colW = 229.6;
  const ledgerRows = checks.map((c, idx) => {
    const cx = 188 + idx * colW;
    const divider = idx > 0 ? `<line x1="${cx.toFixed(1)}" y1="400" x2="${cx.toFixed(1)}" y2="516" stroke="${escapeXml(t.rule)}" stroke-width="1"/>` : "";
    return `${divider}
      <text x="${(cx + 16).toFixed(1)}" y="422" class="mono" font-size="10.5" letter-spacing="1.4" fill="${escapeXml(t.inkDim)}">${escapeXml(c.num)} · ${escapeXml(c.name)}</text>
      <circle cx="${(cx + 26).toFixed(1)}" cy="456" r="11" fill="none" stroke="${escapeXml(c.color)}" stroke-width="1.6"/>
      <text x="${(cx + 26).toFixed(1)}" y="460.5" text-anchor="middle" class="sans" font-size="13" font-weight="700" fill="${escapeXml(c.color)}">${escapeXml(c.glyph)}</text>
      <text x="${(cx + 46).toFixed(1)}" y="461" class="sans" font-size="18.5" font-weight="700" fill="${escapeXml(t.ink)}">${escapeXml(clipText(c.value, 14))}</text>
      <text x="${(cx + 16).toFixed(1)}" y="496" class="mono" font-size="10.5" fill="${escapeXml(c.color)}">${escapeXml(clipText(c.sub, 24))}</text>
    `;
  }).join("");

  // Perforation dots separating document body from bottom verification & MRZ strip
  const perfDots = Array.from({ length: 48 }, (_, i) => `<circle cx="${174 + i * 24.8}" cy="736" r="2.2" fill="${escapeXml(t.rule)}"/>`).join("");
  const rosette = buildGuillocheRosette(1164, 244, 126, 52, 20);
  const crestSvg = buildFingerprintCrest(fullHash, 1184, 558, 15, pair.ink, t.rule);
  const advisoryLines = wrapLines(meta.advisoryNote, 58, 2);

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1400 940" width="1400" height="940" role="img" aria-label="${escapeXml(meta.documentTitle)} — ${escapeXml(title)}">
  <defs>
    <linearGradient id="paperBg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="${escapeXml(t.paperTop)}"/>
      <stop offset="55%" stop-color="${escapeXml(t.paperMid)}"/>
      <stop offset="100%" stop-color="${escapeXml(t.paperEdge)}"/>
    </linearGradient>
    <linearGradient id="spineBg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${escapeXml(t.spineDeep)}"/>
      <stop offset="50%" stop-color="${escapeXml(t.spine)}"/>
      <stop offset="100%" stop-color="${escapeXml(t.spineDeep)}"/>
    </linearGradient>
    <linearGradient id="goldFoil" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="${escapeXml(t.goldDark)}"/>
      <stop offset="45%" stop-color="${escapeXml(t.goldLight)}"/>
      <stop offset="100%" stop-color="${escapeXml(t.gold)}"/>
    </linearGradient>
    <pattern id="silkWave" width="180" height="90" patternUnits="userSpaceOnUse">
      <path d="M0 45 Q 45 10 90 45 T 180 45" fill="none" stroke="${escapeXml(t.spine)}" stroke-opacity="0.045" stroke-width="0.9"/>
      <path d="M0 45 Q 45 80 90 45 T 180 45" fill="none" stroke="${escapeXml(t.gold)}" stroke-opacity="0.05" stroke-width="0.8"/>
    </pattern>
    <style>
      .sans { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
      .serif { font-family: Georgia, 'Times New Roman', serif; }
      .serifIt { font-family: Georgia, 'Times New Roman', serif; font-style: italic; }
      .mono { font-family: ui-monospace, 'Cascadia Mono', 'SF Mono', Menlo, Consolas, monospace; }
    </style>
  </defs>

  <!-- Archival Cotton-Parchment Paper Base -->
  <rect width="1400" height="940" fill="url(#paperBg)"/>
  <rect width="1400" height="940" fill="url(#silkWave)"/>

  <!-- Watermark Guilloche Rosette behind the Stamp -->
  <g fill="none" stroke="${escapeXml(t.gold)}" stroke-opacity="0.16" stroke-width="1">
    ${rosette}
    <circle cx="1164" cy="244" r="126"/>
    <circle cx="1164" cy="244" r="52"/>
  </g>

  <!-- Ornate Double Diplomatic Border Frame on Paper Sheet -->
  <rect x="160" y="24" width="1214" height="892" rx="14" fill="none" stroke="url(#goldFoil)" stroke-width="2"/>
  <rect x="170" y="34" width="1194" height="872" rx="10" fill="none" stroke="${escapeXml(t.spine)}" stroke-opacity="0.22" stroke-width="1"/>
  <path d="M179 62 V42 H199 M1337 42 H1357 V62 M179 878 V898 H199 M1337 898 H1357 V878" fill="none" stroke="url(#goldFoil)" stroke-width="2.2" stroke-linecap="round"/>

  <!-- Left Bound Sovereign Passport Spine -->
  <rect x="0" y="0" width="148" height="940" fill="url(#spineBg)"/>
  <line x1="148" y1="0" x2="148" y2="940" stroke="url(#goldFoil)" stroke-width="3"/>
  <line x1="138" y1="0" x2="138" y2="940" stroke="${escapeXml(t.goldLight)}" stroke-opacity="0.25" stroke-width="1"/>

  <!-- Spine Foil Crest Medallion -->
  <circle cx="74" cy="96" r="36" fill="none" stroke="url(#goldFoil)" stroke-width="2.2"/>
  <circle cx="74" cy="96" r="29" fill="none" stroke="${escapeXml(t.goldLight)}" stroke-opacity="0.55" stroke-width="1" stroke-dasharray="3 3"/>
  <path d="M61 97 L70 106 L88 86" fill="none" stroke="${escapeXml(t.spineAccent)}" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/>

  <!-- Vertical Embossed Spine Ledger Text -->
  <text x="74" y="476" text-anchor="middle" transform="rotate(-90 74 476)" class="mono" font-size="11.5" font-weight="600" letter-spacing="4.0" fill="url(#goldFoil)">AGENT CUSTOMS · OPEN AGENTIC WEB · FOLIO</text>
  <rect x="34" y="838" width="80" height="30" rx="6" fill="none" stroke="url(#goldFoil)" stroke-opacity="0.6" stroke-width="1"/>
  <text x="74" y="857" text-anchor="middle" class="mono" font-size="11" letter-spacing="1.4" fill="${escapeXml(t.goldLight)}">${escapeXml(meta.code)}</text>

  <!-- Document Header Band (inside parchment) -->
  <text x="192" y="76" class="sans" font-size="13" font-weight="700" letter-spacing="2.4" fill="${escapeXml(t.ink)}">AGENT CUSTOMS AUTHORITY</text>
  <text x="192" y="96" class="mono" font-size="11" letter-spacing="1.2" fill="${escapeXml(t.inkMuted)}">SERIAL NO. ${escapeXml(meta.serial)}  ·  ISSUED ${escapeXml(inspectedDate)}</text>

  <!-- Cryptographic Seal Pill -->
  <rect x="${pillX}" y="58" width="${pillW}" height="34" rx="17" fill="${escapeXml(sig.fill)}" stroke="${escapeXml(sig.color)}" stroke-width="1.4"/>
  <circle cx="${pillX + 19}" cy="75" r="4.5" fill="${escapeXml(sig.color)}"/>
  <text x="${pillX + 32}" y="79" class="mono" font-size="10.8" font-weight="700" letter-spacing="0.9" fill="${escapeXml(sig.color)}">${escapeXml(sig.badge)}</text>

  <line x1="192" y1="114" x2="1336" y2="114" stroke="${escapeXml(t.rule)}" stroke-width="1.2"/>

  <!-- Main Archival Headline & Network Title -->
  <text x="192" y="148" class="mono" font-size="11" letter-spacing="2.0" fill="${escapeXml(t.goldDark)}">${escapeXml(meta.eyebrow)}</text>
  <text x="192" y="206" class="serifIt" font-size="50" font-weight="700" fill="${escapeXml(t.ink)}">${escapeXml(meta.documentTitle)}</text>
  <text x="192" y="254" class="sans" font-size="28" font-weight="700" letter-spacing="-0.4" fill="${escapeXml(pair.ink)}">${escapeXml(clipText(title, 38))}</text>
  <text x="192" y="284" class="mono" font-size="13" fill="${escapeXml(t.inkMuted)}">${escapeXml(clipText(url, 84))}</text>
  <text x="192" y="320" class="sans" font-size="15" fill="${escapeXml(t.ink)}">${escapeXml(summaryLines[0] || "")}</text>
  <text x="192" y="342" class="sans" font-size="15" fill="${escapeXml(t.ink)}">${escapeXml(summaryLines[1] || "")}</text>

  <!-- Circular Wet-Ink Embossed Customs Cancellation Stamp -->
  <g transform="translate(1164, 244) rotate(-8)">
    <circle cx="0" cy="0" r="102" fill="${escapeXml(pair.tint)}" fill-opacity="0.72" stroke="${escapeXml(pair.ink)}" stroke-width="4.2"/>
    <circle cx="0" cy="0" r="91" fill="none" stroke="${escapeXml(pair.ink)}" stroke-width="1.4" stroke-dasharray="5 3.5"/>
    <circle cx="0" cy="0" r="74" fill="none" stroke="${escapeXml(pair.ink)}" stroke-opacity="0.45" stroke-width="1"/>
    <text x="0" y="-44" text-anchor="middle" class="mono" font-size="10.5" font-weight="700" letter-spacing="2.2" fill="${escapeXml(pair.ink)}">BORDER CONTROL</text>
    <line x1="-54" y1="-31" x2="54" y2="-31" stroke="${escapeXml(pair.ink)}" stroke-opacity="0.4" stroke-width="1"/>
    <text x="0" y="11" text-anchor="middle" class="mono" font-size="33" font-weight="700" letter-spacing="2.4" fill="${escapeXml(pair.ink)}">${escapeXml(meta.stampLabel)}</text>
    <line x1="-54" y1="26" x2="54" y2="26" stroke="${escapeXml(pair.ink)}" stroke-opacity="0.4" stroke-width="1"/>
    <text x="0" y="48" text-anchor="middle" class="mono" font-size="11.5" font-weight="700" letter-spacing="1.6" fill="${escapeXml(pair.ink)}">${escapeXml(inspectedDate)}</text>
    <text x="0" y="66" text-anchor="middle" class="mono" font-size="8.5" letter-spacing="1.4" fill="${escapeXml(pair.ink)}">SHA-256 LOCKED</text>
  </g>

  <!-- Five Checks Engraved Ledger Table -->
  <text x="192" y="382" class="mono" font-size="11" letter-spacing="1.8" fill="${escapeXml(t.inkDim)}">DETERMINISTIC PORT-OF-ENTRY LEDGER (5 OF 5 CHECKS)</text>
  <rect x="188" y="394" width="1148" height="128" rx="8" fill="#fbf7ee" stroke="${escapeXml(t.rule)}" stroke-width="1.3"/>
  ${ledgerRows}

  <!-- Cryptographic Proof Box + Deterministic Visual Hash Coat of Arms -->
  <rect x="188" y="536" width="1148" height="188" rx="10" fill="#fbf7ee" stroke="${escapeXml(t.rule)}" stroke-width="1.3"/>
  <text x="212" y="562" class="mono" font-size="10.8" letter-spacing="1.5" fill="${escapeXml(t.inkDim)}">CANONICAL IDENTITY HASH &amp; CRYPTOGRAPHIC ATTESTATION</text>

  <!-- Canonical SHA-256 Strip -->
  <rect x="212" y="574" width="932" height="34" rx="6" fill="${escapeXml(t.wellPaper)}" stroke="${escapeXml(t.rule)}"/>
  <text x="228" y="596" class="mono" font-size="12.5" font-weight="700" fill="${escapeXml(t.ink)}">${escapeXml(clipText(fullHash, 74))}</text>

  <!-- Facts Grid inside Verification Panel -->
  <text x="212" y="629" class="mono" font-size="10" letter-spacing="1.1" fill="${escapeXml(t.inkDim)}">FRONT AGENT</text>
  <text x="212" y="647" class="mono" font-size="12.5" font-weight="700" fill="${escapeXml(t.ink)}">${escapeXml(clipText(`${frontAgent} (${agentCount} agent${agentCount === 1 ? "" : "s"})`, 34))}</text>

  <text x="532" y="629" class="mono" font-size="10" letter-spacing="1.1" fill="${escapeXml(t.inkDim)}">INSPECTED TIMESTAMP (UTC)</text>
  <text x="532" y="647" class="mono" font-size="12.5" font-weight="700" fill="${escapeXml(t.ink)}">${escapeXml(inspectedTime)}</text>

  <text x="772" y="629" class="mono" font-size="10" letter-spacing="1.1" fill="${escapeXml(t.inkDim)}">SPEC PROFILE</text>
  <text x="772" y="647" class="mono" font-size="11.5" font-weight="700" fill="${escapeXml(t.ink)}">${escapeXml(clipText(profile, 52))}</text>

  <text x="212" y="677" class="sans" font-size="13" fill="${escapeXml(t.inkMuted)}">${escapeXml(advisoryLines[0] || "")} ${escapeXml(advisoryLines[1] || "")}</text>
  <text x="212" y="701" class="mono" font-size="11.5" font-weight="700" fill="${escapeXml(sig.color)}">ATTESTATION: ${escapeXml(sig.detail)}</text>

  <!-- Unique Deterministic Visual Hash Crest (top-right inside proof panel) -->
  ${crestSvg}
  <text x="1236" y="683" text-anchor="middle" class="mono" font-size="9.5" letter-spacing="1.2" fill="${escapeXml(t.inkDim)}">HASH EMBLEM</text>
  <text x="1236" y="700" text-anchor="middle" class="mono" font-size="10" font-weight="700" fill="${escapeXml(pair.ink)}">${escapeXml(report?.identity?.short || "")}</text>

  <!-- Tear-line Perforation & High-Contrast Clickable Exact Re-Verify Strip -->
  ${perfDots}
  <a href="${escapeXml(recheckUrl)}" target="_blank">
    <rect x="188" y="746" width="1148" height="64" rx="8" fill="#fffdf8" stroke="${escapeXml(pair.ink)}" stroke-width="1.6"/>
    <rect x="202" y="756" width="132" height="22" rx="5" fill="${escapeXml(pair.ink)}"/>
    <text x="268" y="771" text-anchor="middle" class="mono" font-size="10.5" font-weight="700" letter-spacing="1.1" fill="#fffdf8">RE-VERIFY LIVE</text>
    <text x="346" y="771" class="sans" font-size="12" font-weight="700" fill="${escapeXml(t.ink)}">Click to run a fresh check and open the live result page</text>
    <text x="1322" y="771" text-anchor="end" class="sans" font-size="12" font-weight="700" fill="${escapeXml(pair.ink)}">Open live result ↗</text>
    ${recheckTextMarkup}
  </a>

  <!-- ICAO Machine-Readable Zone -->
  <rect x="188" y="820" width="1148" height="70" rx="8" fill="${escapeXml(t.wellPaper)}" stroke="${escapeXml(t.rule)}" stroke-width="1"/>
  <text x="210" y="849" class="mono" font-size="18" font-weight="600" letter-spacing="2.8" fill="${escapeXml(t.ink)}">${escapeXml(mrz1)}</text>
  <text x="210" y="876" class="mono" font-size="18" font-weight="600" letter-spacing="2.8" fill="${escapeXml(pair.ink)}">${escapeXml(mrz2)}</text>
</svg>`;
}
