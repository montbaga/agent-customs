// install-art.mjs: the README's install art, in the README banners' style (forest palette,
// faint grid, rounded cards), each in a dark and a light version for <picture>.
//
//   node tools/install-art.mjs
//
// Writes docs/images/install-steps-{dark,light}.svg (copy, paste, done) and
// docs/images/install-way-{1..4}-{dark,light}.svg (the header card above each way's code).
// The code itself stays as text in the README, so GitHub gives it a Copy button.

import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "docs", "images");

const THEMES = {
  dark: {
    bg: `<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#091712"/><stop offset="55%" stop-color="#0c1d18"/><stop offset="100%" stop-color="#122a22"/></linearGradient>`,
    glow: "#c8f03c", grid: "#ece4d3", gridOpacity: 0.045,
    ink: "#ece4d3", muted: "#a4a497", accent: "#c8f03c", onAccent: "#0c1d18",
    card: "#ece4d3", cardOpacity: 0.04, line: "#ece4d3", lineOpacity: 0.14, tagText: "#0c1d18", tagFill: "#c8f03c",
  },
  light: {
    bg: `<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#f4efe4"/><stop offset="100%" stop-color="#ece4d3"/></linearGradient>`,
    glow: "#3d6b0a", grid: "#0c1d18", gridOpacity: 0.05,
    ink: "#0c1d18", muted: "#4f5950", accent: "#3d6b0a", onAccent: "#0c1d18",
    card: "#ffffff", cardOpacity: 0.55, line: "#0c1d18", lineOpacity: 0.13, tagText: "#f4efe4", tagFill: "#3d6b0a",
  },
};

const FONTS = `<style>
      .sans { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
      .mono { font-family: ui-monospace, 'SF Mono', 'Cascadia Mono', Menlo, Consolas, monospace; }
    </style>`;
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

// Line icons, drawn on a 24-unit grid.
const ICONS = {
  copy: '<rect x="8" y="8" width="12" height="12" rx="2.5"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
  paste: '<path d="M8.5 7 3.5 12l5 5"/><path d="M15.5 7l5 5-5 5"/><path d="M13.5 4.5l-3 15"/>',
  check: '<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8-7.5 9.5-4.3-1.5-7.5-4.9-7.5-9.5V6z"/><path d="M8.6 12.2l2.3 2.3 4.6-4.8"/>',
  line: '<path d="M4 12h16"/><path d="M14 6l6 6-6 6"/>',
  sliders: '<path d="M4 7h10"/><path d="M18 7h2"/><circle cx="16" cy="7" r="2"/><path d="M4 17h4"/><path d="M12 17h8"/><circle cx="10" cy="17" r="2"/>',
  box: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5"/><path d="M12 12v9"/>',
  folder: '<path d="M3.5 7a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>',
};
const icon = (name, x, y, size, color) =>
  `<g transform="translate(${x} ${y}) scale(${size / 24})" fill="none" stroke="${color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</g>`;

function frame(t, width, height, body, label) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="${esc(label)}">
  <defs>
    ${t.bg}
    <radialGradient id="glow" cx="0.1" cy="0.2" r="0.6"><stop offset="0%" stop-color="${t.glow}" stop-opacity="0.14"/><stop offset="100%" stop-color="${t.glow}" stop-opacity="0"/></radialGradient>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M 32 0 L 0 0 0 32" fill="none" stroke="${t.grid}" stroke-opacity="${t.gridOpacity}" stroke-width="1"/></pattern>
    <clipPath id="clip"><rect x="2" y="2" width="${width - 4}" height="${height - 4}" rx="20"/></clipPath>
    ${FONTS}
  </defs>
  <g clip-path="url(#clip)">
    <rect width="${width}" height="${height}" fill="url(#bg)"/>
    <rect width="${width}" height="${height}" fill="url(#grid)"/>
    <rect width="${width}" height="${height}" fill="url(#glow)"/>
${body}
  </g>
  <rect x="2" y="2" width="${width - 4}" height="${height - 4}" rx="20" fill="none" stroke="${t.line}" stroke-opacity="${t.lineOpacity}" stroke-width="1.5"/>
</svg>
`;
}

function steps(t) {
  const W = 1200;
  const H = 330;
  const cards = [
    ["copy", "Copy the line", "The whole guard as one file,", "with a fingerprint checked."],
    ["paste", "Paste above your scripts", "In the page that holds your", "assistant, before its scripts."],
    ["check", "Every partner is checked", "Before it runs; visitors", "see the stamp in the chat."],
  ];
  const cw = 352;
  const gap = 36;
  const x0 = (W - (cw * 3 + gap * 2)) / 2;
  const y0 = 122;
  let body = `    <text x="${x0}" y="50" class="mono" font-size="14" font-weight="700" letter-spacing="1.8" fill="${t.accent}">ADD IT TO YOUR SITE</text>
    <text x="${x0}" y="92" class="sans" font-size="36" font-weight="600" letter-spacing="-0.6" fill="${t.ink}">Protect your assistant in one line</text>
    <text x="${W - x0}" y="92" text-anchor="end" class="sans" font-size="17" fill="${t.muted}">No server · no build step · runtime unchanged</text>\n`;
  cards.forEach(([ic, title, l1, l2], i) => {
    const x = x0 + i * (cw + gap);
    body += `    <rect x="${x}" y="${y0}" width="${cw}" height="176" rx="16" fill="${t.card}" fill-opacity="${t.cardOpacity}" stroke="${t.line}" stroke-opacity="${t.lineOpacity}"/>
    <circle cx="${x + 38}" cy="${y0 + 40}" r="19" fill="${t.tagFill}"/>
    <text x="${x + 38}" y="${y0 + 47}" text-anchor="middle" class="sans" font-size="18" font-weight="700" fill="${t.tagText}">${i + 1}</text>
    ${icon(ic, x + cw - 56, y0 + 24, 32, t.accent)}
    <text x="${x + 24}" y="${y0 + 96}" class="sans" font-size="23" font-weight="600" fill="${t.ink}">${esc(title)}</text>
    <text x="${x + 24}" y="${y0 + 128}" class="sans" font-size="18" fill="${t.muted}">${esc(l1)}</text>
    <text x="${x + 24}" y="${y0 + 153}" class="sans" font-size="18" fill="${t.muted}">${esc(l2)}</text>\n`;
    if (i < 2) body += `    ${icon("line", x + cw + 5, y0 + 74, 26, t.accent)}\n`;
  });
  return frame(t, W, H, body, "Add it to your site: copy the line, paste it above your scripts, and every partner is checked");
}

const WAYS = [
  ["line", "One line", "EASIEST", "Paste it above your page's other scripts. The guard turns itself on."],
  ["sliders", "Two lines", "YOUR SETTINGS", "Import the guard and pass your own settings, like strict mode."],
  ["box", "npm", "BUILD TOOLS", "For projects with a build step. Includes the command line tool."],
  ["folder", "Copy the folder", "SELF-HOSTED", "Copy customs/ beside your runtime/ folder. Nothing loads from outside."],
];

function way(t, n) {
  const [ic, title, tag, text] = WAYS[n - 1];
  const W = 1200;
  const H = 120;
  const tagW = tag.length * 10.4 + 32;
  const body = `    <circle cx="62" cy="60" r="26" fill="${t.tagFill}"/>
    <text x="62" y="68.5" text-anchor="middle" class="sans" font-size="24" font-weight="700" fill="${t.tagText}">${n}</text>
    <text x="110" y="52" class="sans" font-size="29" font-weight="600" letter-spacing="-0.4" fill="${t.ink}">${esc(title)}</text>
    <text x="110" y="86" class="sans" font-size="19" fill="${t.muted}">${esc(text)}</text>
    <rect x="${W - 96 - tagW}" y="42" width="${tagW}" height="36" rx="18" fill="none" stroke="${t.accent}" stroke-opacity="0.7" stroke-width="1.5"/>
    <text x="${W - 96 - tagW / 2}" y="65" text-anchor="middle" class="mono" font-size="14" font-weight="700" letter-spacing="1.4" fill="${t.accent}">${esc(tag)}</text>
    ${icon(ic, W - 72, 44, 32, t.accent)}`;
  return frame(t, W, H, body, `Way ${n}: ${title}. ${text}`);
}

for (const [name, t] of Object.entries(THEMES)) {
  await writeFile(path.join(OUT, `install-steps-${name}.svg`), steps(t));
  for (let n = 1; n <= WAYS.length; n += 1) await writeFile(path.join(OUT, `install-way-${n}-${name}.svg`), way(t, n));
}
console.log(`Wrote ${2 * (1 + WAYS.length)} SVGs to docs/images/`);
