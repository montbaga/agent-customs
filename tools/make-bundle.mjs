// make-bundle.mjs: join the one-line install and the whole guard into one file,
// dist/agent-customs.js, so one Subresource Integrity hash covers all of it.
//
//   npm run bundle
//
// A browser checks an integrity hash only on the file a <script> tag names, not on the files
// that file imports. In one file, nothing is left unchecked. The tool reads the ES modules from
// site/customs/auto.js down, turns each into a function, and links them through a small
// require(). It also writes the hash into README.md and site/index.html.
//
// It accepts only the module forms this project uses (named imports, `export function`,
// `export class`, `export const`, and import() of a relative file) and stops on anything else,
// so a form it does not understand can never be bundled wrongly.

import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const ENTRY = "site/customs/auto.js";
export const BUNDLE = "dist/agent-customs.js";
// Exports of the joined file: the installer the page runs, and what the guard offers.
const EXPOSE = {
  "site/customs/auto.js": ["guardWhenReady"],
  "site/customs/guard.js": ["installCustomsGuard", "DEFAULT_POLICY", "STRICT_POLICY", "refusal"],
  "site/customs/inspect.js": ["inspectNetworkUrl"],
};

const STATIC_IMPORT = /^import\s*\{([^}]*)\}\s*from\s*["'](\.{1,2}\/[^"']+)["'];?[ \t]*$/gm;
const DYNAMIC_IMPORT = /import\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)/g;
const EXPORT_DECL = /^export\s+(async\s+function\*?|function\*?|class|const|let|var)\s+([A-Za-z_$][\w$]*)/gm;

const id = (from, spec) => path.posix.normalize(path.posix.join(path.posix.dirname(from), spec));

function transform(file, source) {
  const deps = new Set();
  const exported = [];
  let code = source.replace(/\r\n?/g, "\n");
  code = code.replace(STATIC_IMPORT, (_, names, spec) => {
    const target = id(file, spec);
    deps.add(target);
    const list = names.split(",").map((n) => n.trim()).filter(Boolean).map((n) => n.replace(/\s+as\s+/, ": "));
    return `const { ${list.join(", ")} } = __require(${JSON.stringify(target)});`;
  });
  code = code.replace(DYNAMIC_IMPORT, (_, spec) => {
    const target = id(file, spec);
    deps.add(target);
    return `Promise.resolve().then(() => __require(${JSON.stringify(target)}))`;
  });
  code = code.replace(EXPORT_DECL, (_, kind, name) => {
    exported.push(name);
    return `${kind} ${name}`;
  });
  for (const [pattern, what] of [[/^\s*import[\s{*]/m, "an import form"], [/^\s*export[\s{*]/m, "an export form"], [/import\.meta/, "import.meta"]]) {
    const hit = code.match(pattern);
    if (hit) throw new Error(`${file}: ${what} the bundler does not handle, near "${code.slice(hit.index, hit.index + 60)}"`);
  }
  return { code, deps: [...deps], exported };
}

/**
 * Build the joined file.
 *
 * :return: {code, integrity, files}: the file, its sha384 hash, and the files it holds.
 */
export async function buildBundle() {
  const pkg = JSON.parse(await readFile(path.join(ROOT, "package.json"), "utf8"));
  const modules = new Map();
  const queue = [ENTRY, ...Object.keys(EXPOSE)];
  while (queue.length) {
    const file = queue.shift();
    if (modules.has(file)) continue;
    const mod = transform(file, await readFile(path.join(ROOT, file), "utf8"));
    modules.set(file, mod);
    queue.push(...mod.deps);
  }
  const files = [...modules.keys()].sort();
  for (const [file, names] of Object.entries(EXPOSE)) {
    for (const name of names) if (!modules.get(file).exported.includes(name)) throw new Error(`${file} does not export ${name}`);
  }
  const parts = [
    `// Agent Customs ${pkg.version}: the one-line install and the guard, in one file.`,
    "// Built by tools/make-bundle.mjs from these files; edit them, not this one.",
    "// Apache License 2.0. Files under site/runtime/ are Cognizant's Open Agentic Web runtime,",
    "// unmodified, also under the Apache License 2.0.",
    ...files.map((f) => `//   ${f}`),
    "",
    "const __modules = {};",
    "const __loaded = {};",
    "function __require(name) {",
    "  if (!__loaded[name]) {",
    "    __loaded[name] = {};",
    "    Object.assign(__loaded[name], __modules[name]());",
    "  }",
    "  return __loaded[name];",
    "}",
    "",
  ];
  for (const file of files) {
    const { code, exported } = modules.get(file);
    parts.push(`__modules[${JSON.stringify(file)}] = () => {`, code.replace(/\n+$/, ""), `return { ${exported.join(", ")} };`, "};", "");
  }
  parts.push(`__require(${JSON.stringify(ENTRY)});`);
  for (const [file, names] of Object.entries(EXPOSE)) {
    parts.push(`export const { ${names.join(", ")} } = __require(${JSON.stringify(file)});`);
  }
  const code = `${parts.join("\n")}\n`;
  const integrity = `sha384-${createHash("sha384").update(code, "utf8").digest("base64")}`;
  return { code, integrity, files };
}

// The integrity attribute next to the bundle's address, in the README or in the site's
// highlighted code (where <span> tags sit between them).
export const INTEGRITY_NEAR_BUNDLE = /(dist\/agent-customs\.js"[\s\S]{0,120}?integrity=(?:<span class="s">)?")(sha384-[A-Za-z0-9+/=]+|sha384-PENDING)(")/g;

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { code, integrity, files } = await buildBundle();
  await mkdir(path.join(ROOT, "dist"), { recursive: true });
  await writeFile(path.join(ROOT, BUNDLE), code);
  for (const doc of ["README.md", "site/index.html"]) {
    const full = path.join(ROOT, doc);
    const text = await readFile(full, "utf8");
    await writeFile(full, text.replace(INTEGRITY_NEAR_BUNDLE, `$1${integrity}$3`));
  }
  console.log(`${BUNDLE}: ${files.length} files, ${(code.length / 1024).toFixed(0)} KB, ${integrity}`);
}
