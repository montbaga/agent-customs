// cdp.mjs: drive headless Edge or Chrome through the DevTools protocol, over Node's
// built-in WebSocket (Node 22+). No dependencies. smoke.mjs and readme-shots.mjs use it.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Find Edge or Chrome.
 *
 * :param preferred: A path given on the command line, tried first.
 * :return: The browser's path, or undefined when none is installed.
 */
export function findBrowser(preferred = "") {
  return [
    preferred,
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
  ].filter(Boolean).find((p) => existsSync(p));
}

/**
 * Start a headless browser with a fresh profile and attach to its first page.
 *
 * :param options.browserPath: From findBrowser().
 * :param options.port: The DevTools port.
 * :return: {send, evaluate, waitFor, viewport, capture, close, problems}. problems collects
 *   every page exception, console.error and error log entry.
 */
export async function openBrowser({ browserPath, port = 9333 }) {
  const profile = await mkdtemp(path.join(os.tmpdir(), "agent-customs-browser-"));
  const browser = spawn(browserPath, [`--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "--headless=new",
    "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--window-size=1366,900", "about:blank"], { stdio: "ignore" });
  let targets = [];
  for (let i = 0; i < 50; i += 1) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      if (targets.some((t) => t.type === "page")) break;
    } catch { /* still starting */ }
    await sleep(200);
  }
  const page = targets.find((t) => t.type === "page");
  if (!page) { browser.kill(); throw new Error("The browser did not open a page."); }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve) => ws.addEventListener("open", resolve, { once: true }));

  let seq = 0;
  const pending = new Map();
  const problems = [];
  ws.addEventListener("message", (msg) => {
    const data = JSON.parse(msg.data);
    if (data.id && pending.has(data.id)) { pending.get(data.id)(data); pending.delete(data.id); return; }
    if (data.method === "Runtime.exceptionThrown") problems.push(`exception: ${data.params.exceptionDetails.exception?.description || data.params.exceptionDetails.text}`);
    if (data.method === "Runtime.consoleAPICalled" && data.params.type === "error") problems.push(`console.error: ${data.params.args.map((a) => a.value ?? a.description).join(" ")}`);
    if (data.method === "Log.entryAdded" && data.params.entry.level === "error") problems.push(`log: ${data.params.entry.text} ${data.params.entry.url || ""}`);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, (d) => (d.error ? reject(new Error(`${method}: ${d.error.message}`)) : resolve(d.result)));
    ws.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  };
  const waitFor = async (expression, ms = 15000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (await evaluate(expression)) return true;
      await sleep(150);
    }
    throw new Error(`Timed out waiting for: ${expression}`);
  };
  const viewport = (width, height, { mobile = false, scale = 1 } = {}) =>
    send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: scale, mobile });
  const capture = async (file, params = {}) => {
    const { data } = await send("Page.captureScreenshot", { format: "png", ...params });
    await writeFile(file, Buffer.from(data, "base64"));
  };
  const close = () => { try { ws.close(); } finally { browser.kill(); } };

  await send("Page.enable");
  await send("Runtime.enable");
  await send("Log.enable");
  return { send, evaluate, waitFor, viewport, capture, close, problems };
}
