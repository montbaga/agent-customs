// make-extension.mjs: syncs site/customs/ into extension/customs/ and writes crisp MV3 PNG icons.
//   npm run extension
import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXT_DIR = path.join(ROOT, "extension");

export const EXTENSION_COPIED_FOLDERS = [
  ["vendor/agentify-website/runtime", "extension/runtime"],
  ["site/customs", "extension/customs"],
];

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function renderShieldIconPng(size) {
  const bg = [12, 29, 24, 255];
  const lime = [200, 240, 60, 255];
  const cream = [236, 228, 211, 255];
  const rows = [];
  const c = (size - 1) / 2;
  const rOuter = size * 0.44;
  const rRing = size * 0.34;
  const stroke = Math.max(1.2, size * 0.085);

  for (let y = 0; y < size; y += 1) {
    const row = Buffer.alloc(1 + size * 4);
    for (let x = 0; x < size; x += 1) {
      const dx = x - c;
      const dy = y - c;
      const dist = Math.hypot(dx, dy);
      let px = [0, 0, 0, 0];

      if (dist <= rOuter + 0.5) px = bg;
      if (Math.abs(dist - rRing) <= stroke * 0.55) px = lime;

      const nx = (x / size - 0.5) * 2;
      const ny = (y / size - 0.5) * 2;
      const distSeg = (ax, ay, bx, by) => {
        const vx = bx - ax;
        const vy = by - ay;
        const t = Math.max(0, Math.min(1, ((nx - ax) * vx + (ny - ay) * vy) / (vx * vx + vy * vy)));
        return Math.hypot(nx - (ax + t * vx), ny - (ay + t * vy));
      };
      const checkDist = Math.min(distSeg(-0.24, 0.02, -0.04, 0.22), distSeg(-0.04, 0.22, 0.28, -0.18));
      if (checkDist <= Math.max(0.09, 1.3 / size)) px = cream;

      const off = 1 + x * 4;
      row[off] = px[0];
      row[off + 1] = px[1];
      row[off + 2] = px[2];
      row[off + 3] = px[3];
    }
    rows.push(row);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([sig, pngChunk("IHDR", ihdr), pngChunk("IDAT", deflateSync(Buffer.concat(rows))), pngChunk("IEND", Buffer.alloc(0))]);
}

async function main() {
  for (const [from, to] of EXTENSION_COPIED_FOLDERS) {
    await rm(path.join(ROOT, to), { recursive: true, force: true });
    await cp(path.join(ROOT, from), path.join(ROOT, to), { recursive: true });
    console.log(`Copied ${from}/ to ${to}/`);
  }
  const iconsDir = path.join(EXT_DIR, "icons");
  await mkdir(iconsDir, { recursive: true });
  for (const sz of [16, 48, 128]) {
    await writeFile(path.join(iconsDir, `icon${sz}.png`), renderShieldIconPng(sz));
  }
  console.log("Generated extension PNG icons (16, 48, 128).");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
