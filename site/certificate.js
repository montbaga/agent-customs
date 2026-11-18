// certificate.js: builds and parses standalone SVG Border Clearance Certificates & Advisories
// styled after archival cotton-parchment diplomatic visas, with a bound passport spine,
// guilloche filigree, circular cancellation stamp, deterministic SHA-256 visual glyph,
// and an ICAO-style machine-readable zone. Zero DOM dependencies and zero network calls.

import { verifyReceipt } from "./customs/receipts.js";

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

/** Escape XML special characters and strip disallowed control characters. */
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

/** Build radial guilloche rosette petal paths centered around (cx, cy). */
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
 * :param options.signedReceipt: Optional full signed receipt object embedded in SVG metadata.
 * :param options.verifyUrl: Re-check permalink shown on the certificate.
 * :param options.theme: Optional palette overrides (bgMid tints the bound spine).
 * :return: Complete SVG XML markup string.
 */
export function certificateSvg(report, { receiptCheck = null, signedReceipt = null, verifyUrl = "", theme = null } = {}) {
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
  const certMetadata = {
    type: "agent-customs-certificate",
    version: 1,
    serial: meta.serial,
    url,
    brand: title,
    verdict: meta.code,
    stamp: report?.verdict?.stamp || meta.stampLabel,
    fingerprint: report?.identity?.hash || "",
    shortFingerprint: report?.identity?.short || "",
    inspectedAt: report?.inspectedAt || "",
    protocol: report?.protocol || "open-agentic-web",
    profile,
    signedReceipt: signedReceipt || null,
  };

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1400 940" width="1400" height="940" role="img" aria-label="${escapeXml(meta.documentTitle)} — ${escapeXml(title)}">
  <metadata id="agent-customs-cert">${escapeXml(JSON.stringify(certMetadata))}</metadata>
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

/**
 * Wrap a rendered certificate SVG in a printable HTML document.
 */
export function certificateHtml(svg, title = "Agent Customs Certificate") {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeXml(title)}</title>
<style>
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: #0c1d18; }
  svg { width: min(100%, 1120px); height: auto; border-radius: 14px; box-shadow: 0 24px 60px rgba(0, 0, 0, .55); }
  @media print { body { background: #fff; padding: 0; } svg { width: 100%; box-shadow: none; } }
</style>
</head>
<body>
${svg}
</body>
</html>`;
}

function unescapeXml(value) {
  return String(value ?? "")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

const MRZ_VERDICT_MAP = {
  CLEARED: "CLEARED",
  CONDITIONS: "CONDITIONS",
  HOLD: "HOLD",
  DENIED: "DENIED",
  INVALID: "INVALID",
  UNREAD: "UNREADABLE",
};

/**
 * Parse an Agent Customs SVG, HTML, ES256 signed JSON receipt, or exported JSON report.
 *
 * :param text: Raw file text dropped or selected by a user.
 * :return: Normalized metadata descriptor, or null when unrecognized.
 */
export function parseVerificationFile(text) {
  const raw = String(text ?? "").trim();
  if (!raw) return null;

  if (raw.startsWith("{")) {
    try {
      const doc = JSON.parse(raw);
      if (doc?.type === "agent-customs-receipt" || (doc?.receipt?.type === "agent-customs-receipt" && doc?.signature)) {
        const signed = doc.receipt ? doc : { receipt: doc, signature: null };
        const r = signed.receipt;
        return {
          kind: "receipt",
          url: r.network || "",
          brand: "",
          verdict: r.verdict || "",
          stamp: r.stamp || r.verdict || "",
          fingerprint: r.fingerprint || "",
          shortFingerprint: r.fingerprint ? String(r.fingerprint).replace(/^sha256:/, "").slice(0, 12) : "",
          inspectedAt: r.inspectedAt || "",
          expiresAt: r.expiresAt || "",
          protocol: "open-agentic-web",
          profile: "",
          signedReceipt: signed.signature ? signed : null,
        };
      }
      if (doc?.type === "agent-customs-certificate" && doc?.url) {
        return { kind: "certificate", ...doc };
      }
      if (doc?.tool === "Agent Customs" && doc?.target?.url) {
        return {
          kind: "snapshot",
          url: doc.target.url,
          brand: doc.identity?.brand || "",
          verdict: doc.verdict?.code || "",
          stamp: doc.verdict?.stamp || "",
          fingerprint: doc.identity?.hash || "",
          shortFingerprint: doc.identity?.short || "",
          inspectedAt: doc.inspectedAt || "",
          expiresAt: "",
          protocol: doc.protocol || "open-agentic-web",
          profile: doc.profile || "",
          signedReceipt: null,
        };
      }
    } catch {
      return null;
    }
    return null;
  }

  // HTML export or page embedding either JSON metadata or the certificate SVG.
  if (/<!doctype\s+html|<html\b/i.test(raw)) {
    const scriptMatch = raw.match(/<script[^>]+id=["']agent-customs-cert["'][^>]*>([\s\S]*?)<\/script>/i);
    if (scriptMatch) {
      const fromScript = parseVerificationFile(scriptMatch[1]);
      if (fromScript) return { ...fromScript, kind: "html" };
    }
    const svgStart = raw.search(/<svg\b/i);
    const svgEnd = raw.toLowerCase().lastIndexOf("</svg>");
    if (svgStart >= 0 && svgEnd > svgStart) {
      const fromSvg = parseVerificationFile(raw.slice(svgStart, svgEnd + 6));
      if (fromSvg) return { ...fromSvg, kind: "html" };
    }
  }

  if (!/<svg\b/i.test(raw)) return null;

  const metaMatch = raw.match(/<metadata\s+id=["']agent-customs-cert["'][^>]*>([\s\S]*?)<\/metadata>/i);
  if (metaMatch) {
    try {
      const parsed = JSON.parse(unescapeXml(metaMatch[1]));
      if (parsed?.type === "agent-customs-certificate") {
        return {
          kind: "certificate",
          url: parsed.url || "",
          brand: parsed.brand || "",
          verdict: parsed.verdict || "",
          stamp: parsed.stamp || parsed.verdict || "",
          fingerprint: parsed.fingerprint || "",
          shortFingerprint: parsed.shortFingerprint || "",
          inspectedAt: parsed.inspectedAt || "",
          expiresAt: parsed.signedReceipt?.receipt?.expiresAt || "",
          protocol: parsed.protocol || "",
          profile: parsed.profile || "",
          signedReceipt: parsed.signedReceipt || null,
        };
      }
    } catch { /* fall through to text extraction for edited metadata */ }
  }

  // Fallback parser for certificates without <metadata>.
  let url = "";
  const hrefMatch = raw.match(/<a[^>]+href=["']([^"']+\?inspect=[^"']+)["']/i);
  if (hrefMatch) {
    try {
      const parsedUrl = new URL(unescapeXml(hrefMatch[1]));
      url = parsedUrl.searchParams.get("inspect") || "";
    } catch { /* ignore malformed fallback link */ }
  }
  const hashMatch = raw.match(/sha256:[0-9a-f]{64}/i);
  const fingerprint = hashMatch ? hashMatch[0].toLowerCase() : "";
  const mrzMatch = raw.match(/P&lt;AGTCUSTOMS&lt;&lt;([A-Z]+)&lt;&lt;/);
  const verdict = mrzMatch ? (MRZ_VERDICT_MAP[mrzMatch[1]] || "") : "";
  const issuedMatch = raw.match(/ISSUED\s+([0-9]{2}\s+[A-Z]{3}\s+[0-9]{4})/);
  if (!url && !fingerprint && !verdict) return null;

  return {
    kind: "certificate",
    legacy: true,
    url,
    brand: "",
    verdict,
    stamp: verdict,
    fingerprint,
    shortFingerprint: fingerprint ? fingerprint.replace(/^sha256:/, "").slice(0, 12) : "",
    inspectedAt: issuedMatch ? issuedMatch[1] : "",
    expiresAt: "",
    protocol: "",
    profile: "",
    signedReceipt: null,
  };
}

async function inflatePdfStream(slice) {
  if (typeof DecompressionStream !== "function") return "";
  for (const format of ["deflate", "deflate-raw"]) {
    try {
      const stream = new Blob([slice]).stream().pipeThrough(new DecompressionStream(format));
      const buf = await new Response(stream).arrayBuffer();
      if (buf.byteLength > 4 * 1024 * 1024) continue;
      return new TextDecoder("latin1").decode(buf);
    } catch { /* try fallback format or skip non-zlib stream */ }
  }
  return "";
}

/**
 * Extract verification links or SHA-256 hashes from a PDF byte buffer.
 * Browser Print-to-PDF preserves link annotations (/URI) even when text is outlined as glyphs.
 */
async function parsePdfVerification(bytes) {
  const latin1 = new TextDecoder("latin1").decode(bytes);
  const chunks = [latin1];

  // Collect FlateDecode streams safely (bounded count & size).
  const streamRe = /stream\r?\n/g;
  let count = 0;
  let m;
  while ((m = streamRe.exec(latin1)) !== null && count < 24) {
    const headerSlice = latin1.slice(Math.max(0, m.index - 400), m.index);
    const start = m.index + m[0].length;
    const end = latin1.indexOf("endstream", start);
    if (end < 0) break;
    if (/\/FlateDecode\b/.test(headerSlice)) {
      let streamEnd = end;
      while (streamEnd > start && (latin1[streamEnd - 1] === "\n" || latin1[streamEnd - 1] === "\r")) streamEnd -= 1;
      if (streamEnd > start && streamEnd - start < 2 * 1024 * 1024) {
        const text = await inflatePdfStream(bytes.subarray(start, streamEnd));
        if (text) chunks.push(text);
        count += 1;
      }
    }
    streamRe.lastIndex = end + 9;
  }

  const combined = chunks.join("\n");
  // Extract /URI (...) annotations first, which Chromium preserves reliably on Print -> Save as PDF.
  let url = "";
  const uriRe = /\/URI\s*\(([^)]{6,2048})\)/g;
  while ((m = uriRe.exec(combined)) !== null) {
    const unescaped = m[1].replace(/\\([\\()])/g, "$1");
    if (/[?&]inspect=/.test(unescaped)) {
      try {
        url = new URL(unescaped).searchParams.get("inspect") || "";
        if (url) break;
      } catch { /* keep searching */ }
    }
  }
  if (!url) {
    const inspectMatch = combined.match(/https?:\/\/[^\s)"'<>]+\?inspect=([^\s)"'<>]+)/);
    if (inspectMatch) {
      try { url = decodeURIComponent(inspectMatch[1]); } catch { url = inspectMatch[1]; }
    }
  }

  const hashMatch = combined.match(/sha256:[0-9a-f]{64}/i);
  const fingerprint = hashMatch ? hashMatch[0].toLowerCase() : "";
  const mrzMatch = combined.match(/P<AGTCUSTOMS<<([A-Z]+)<</);
  const verdict = mrzMatch ? (MRZ_VERDICT_MAP[mrzMatch[1]] || "") : "";

  if (!url && !fingerprint) return { ok: false, pdfUnsupported: true };

  return {
    ok: true,
    kind: "pdf",
    pdfExtracted: true,
    url,
    brand: "",
    verdict,
    stamp: verdict,
    fingerprint,
    shortFingerprint: fingerprint ? fingerprint.replace(/^sha256:/, "").slice(0, 12) : "",
    inspectedAt: "",
    expiresAt: "",
    protocol: "",
    profile: "",
    signedReceipt: null,
  };
}

/**
 * Parse .svg, .json, .html, or .pdf verification inputs.
 */
export async function parseAnyVerificationFile(input, fileName = "") {
  if (typeof input === "string") {
    if (input.startsWith("%PDF-")) return parsePdfVerification(new TextEncoder().encode(input));
    return parseVerificationFile(input);
  }
  let bytes = null;
  let name = fileName;
  if (typeof Blob !== "undefined" && input instanceof Blob) {
    name = name || input.name || "";
    bytes = new Uint8Array(await input.arrayBuffer());
  } else if (input instanceof Uint8Array) {
    bytes = input;
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else if (input?.bytes instanceof Uint8Array) {
    bytes = input.bytes;
    name = name || input.name || "";
  }
  if (!bytes) return null;

  const isPdf = /\.pdf$/i.test(name) || new TextDecoder("latin1").decode(bytes.subarray(0, 5)) === "%PDF-";
  if (isPdf) return parsePdfVerification(bytes);
  return parseVerificationFile(new TextDecoder("utf-8").decode(bytes));
}

/**
 * Cryptographically verify a parsed certificate/receipt and compare it with a live report.
 *
 * :param input: Raw string, File/Blob, ArrayBuffer, or Uint8Array (.svg, .json, .html, .pdf).
 * :param options.fileName: Optional filename hint for binary inputs.
 * :param options.publicJwk: Agent Customs' ES256 public JWK for signature verification.
 * :param options.lookupSignedReceipt: Optional async (url) => signedReceipt fallback.
 * :param options.now: Reference date for expiry checks.
 * :param options.liveReport: Optional live report from inspectNetworkUrl for drift checking.
 * :return: Structured verification result.
 */
export async function verifyDroppedArtifact(input, { fileName = "", publicJwk = null, lookupSignedReceipt = null, now = new Date(), liveReport = null } = {}) {
  const parsed = await parseAnyVerificationFile(input, fileName);
  if (!parsed || parsed.pdfUnsupported) {
    return {
      ok: false,
      status: "invalid",
      reason: parsed?.pdfUnsupported
        ? "No readable verification link or receipt found in this PDF. Browser 'Save as PDF' outlines text as vector shapes and drops cryptographic signatures — use .svg, .json, or .html for signature verification."
        : "Unrecognized file. Choose an Agent Customs .svg certificate, .json receipt, .html export, or .pdf print.",
    };
  }

  let signedCandidate = parsed.signedReceipt || null;
  let signedSource = parsed.signedReceipt ? "embedded" : null;
  // Never promote a PDF (which drops signatures/hashes on print) to "verified" via remote receipt lookup.
  if (!signedCandidate && !parsed.pdfExtracted && parsed.fingerprint && typeof lookupSignedReceipt === "function" && parsed.url) {
    try {
      const published = await lookupSignedReceipt(parsed.url);
      if (published) {
        signedCandidate = published;
        signedSource = "published";
      }
    } catch { /* leave unsigned */ }
  }

  let sigCheck = null;
  let tampered = false;
  if (signedCandidate && publicJwk) {
    sigCheck = await verifyReceipt(signedCandidate, publicJwk, { now, fingerprint: parsed.fingerprint || null });
    if (!sigCheck.valid) tampered = true;
    // Detect if certificate fields were altered while keeping an authentic receipt block.
    if (sigCheck.valid && signedSource === "embedded" && sigCheck.receipt) {
      const r = sigCheck.receipt;
      const hashMismatch = parsed.fingerprint && r.fingerprint && parsed.fingerprint !== r.fingerprint;
      const urlMismatch = parsed.url && r.network && parsed.url !== r.network;
      const verdictMismatch = parsed.verdict && r.verdict && parsed.verdict !== r.verdict;
      if (hashMismatch || urlMismatch || verdictMismatch) {
        tampered = true;
        sigCheck = { ...sigCheck, valid: false, reason: "Certificate fields were modified after the receipt was signed." };
      }
    }
  }

  let liveStatus = "unchecked";
  let liveSummary = "";
  if (liveReport) {
    if (liveReport.failure) {
      liveStatus = "unreadable";
      liveSummary = liveReport.verdict?.summary || "Could not reach the live endpoint.";
    } else if (parsed.fingerprint && liveReport.identity?.hash) {
      const same = parsed.fingerprint === liveReport.identity.hash;
      liveStatus = same ? "match" : "changed";
      liveSummary = same
        ? `Live endpoint matches exact SHA-256 fingerprint (${liveReport.identity.short}).`
        : `Live endpoint changed: certificate locked ${parsed.shortFingerprint || parsed.fingerprint.slice(0, 12)}, live now ${liveReport.identity.short} (${liveReport.verdict?.stamp}).`;
    } else if (parsed.url) {
      liveStatus = "live-checked";
      liveSummary = parsed.pdfExtracted
        ? `Live site returned ${liveReport.verdict?.stamp} (${liveReport.identity?.short || "no hash"}) — printed PDF has no SHA-256 hash to match offline.`
        : `Live inspection returned ${liveReport.verdict?.stamp} (${liveReport.identity?.short || "no hash"}).`;
    }
  }

  let status = "unsigned";
  let headline = parsed.pdfExtracted
    ? "PDF has no ES256 signature (extracted link)"
    : "Unsigned browser snapshot";
  let detail = parsed.pdfExtracted
    ? "Browser Print-to-PDF drops ES256 signatures. Extracted the re-verify target from the PDF — check the live result below, or use .svg / .json / .html for offline signature proof."
    : "This file contains no ES256 cryptographic signature, only the inspection metadata recorded at export.";

  if (tampered) {
    status = "tampered";
    headline = "Signature check failed";
    detail = sigCheck?.reason || "This certificate or receipt was altered after signing.";
  } else if (liveStatus === "changed") {
    status = "changed";
    headline = "Website changed since issued";
    detail = liveSummary;
  } else if (sigCheck?.valid && sigCheck.expired) {
    status = "expired";
    headline = "Valid signature, but stamp expired";
    detail = `Signed by Agent Customs on ${String(sigCheck.receipt.inspectedAt).slice(0, 10)}, expired on ${String(sigCheck.receipt.expiresAt).slice(0, 10)}. Re-inspect live to refresh.`;
  } else if (sigCheck?.valid) {
    status = "verified";
    headline = signedSource === "published" ? "Verified against published ES256 receipt" : "Verified ES256 signature";
    detail = liveStatus === "match"
      ? "Cryptographically signed by Agent Customs and confirmed unchanged against live endpoint."
      : `Cryptographically signed by Agent Customs (valid until ${String(sigCheck.receipt.expiresAt).slice(0, 10)}).`;
  }

  return {
    ok: true,
    status,
    headline,
    detail,
    artifact: parsed,
    signature: sigCheck,
    signedSource,
    liveStatus,
    liveSummary,
    liveReport,
  };
}
