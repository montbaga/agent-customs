// fs-fetch.mjs: a fetch stand-in that serves files from local folders, for tests and
// command-line inspection. Map an origin to a folder: new FsFetch({"http://a.test": "/path"}).
import { readFile } from "node:fs/promises";
import path from "node:path";

export function fsFetch(roots) {
  return async (url) => {
    const u = new URL(url);
    const root = roots[u.origin];
    if (!root) throw new TypeError("Failed to fetch");
    const file = path.join(root, decodeURIComponent(u.pathname));
    try {
      const text = await readFile(file, "utf8");
      return { ok: true, status: 200, url: u.href, redirected: false, text: async () => text, json: async () => JSON.parse(text) };
    } catch {
      return { ok: false, status: 404, url: u.href, redirected: false, text: async () => "", json: async () => { throw new SyntaxError("Not JSON"); } };
    }
  };
}
