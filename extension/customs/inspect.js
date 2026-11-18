// inspect.js: fetch an agent site's public files and inspect them.
//
// It reads exactly what a caller's runtime reads (spec section 3.2): the site's
// agent-manifest.json, the network definition it names, and links.json. Requests
// carry no cookies, no key and no referrer. It parses and validates with the
// runtime's own HOCON parser and validator, so "valid here" means "valid there".

import { parseHocon } from "../runtime/hocon.js";
import { AgentNetwork, validateNetwork } from "../runtime/kernel.js";
import { VERDICTS, analyzeNetwork, escalateReport } from "./analyze.js";
import { detectProtocol, foreignDiscoveryCandidates, normalizeForeignSpec } from "./protocols.js";

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_TRANSITIVE_CHILDREN = 6;
const DIRECT_FOREIGN_URL = /(?:\/\.well-known\/agent(?:-card)?\.json|\/agent(?:-card)?\.json|\/\.well-known\/mcp\.json|\/mcp\.json|\/tools\/list)$/i;

/**
 * Work out the site base and network name from what a person pasted: a network URL,
 * a site page, a folder, the manifest's own URL, or a foreign A2A/MCP endpoint.
 *
 * :param input: A URL string.
 * :return: {candidates: [{base, name}], directUrl?: string}.
 */
export function targetsFor(input) {
  const raw = String(input || "").trim();
  let u;
  try { u = new URL(raw); } catch { throw new Error(`"${raw.slice(0, 80)}" is not a full web address. Start with https://`); }
  if (!/^https?:$/.test(u.protocol)) throw new Error("Only http and https addresses can be inspected.");
  u.hash = "";
  u.search = "";
  const segs = u.pathname.split("/").filter(Boolean);
  const folder = (parts) => `${u.origin}${parts.length ? "/" + parts.join("/") : ""}`;
  if (/agent-manifest\.json$/i.test(u.pathname)) return { candidates: [{ base: folder(segs.slice(0, -1)), name: null }] };
  if (DIRECT_FOREIGN_URL.test(u.pathname)) {
    return { candidates: [{ base: folder(segs.slice(0, -1)), name: null }], directUrl: u.href, strictForeign: true };
  }
  if (!segs.length || u.pathname.endsWith("/")) return { candidates: [{ base: folder(segs), name: null }] };
  const last = segs[segs.length - 1];
  if (/\.(html?|php|aspx?)$/i.test(last)) return { candidates: [{ base: folder(segs.slice(0, -1)), name: null }] };
  if (/\.network\.json$/i.test(last)) {
    return { candidates: [{ base: folder(segs.slice(0, -1)), name: last.replace(/\.network\.json$/i, "") }] };
  }
  if (/\.json$/i.test(last)) {
    return { candidates: [{ base: folder(segs.slice(0, -1)), name: null }], directUrl: u.href, strictForeign: false };
  }
  if (/^mcp$/i.test(last)) {
    return { candidates: [{ base: folder(segs), name: null }, { base: folder(segs.slice(0, -1)), name: null }], directUrl: u.href, strictForeign: false };
  }
  // Usually ".../<network>"; it may also be a site folder without its trailing slash.
  return { candidates: [{ base: folder(segs.slice(0, -1)), name: last }, { base: folder(segs), name: null }] };
}

// A file the server did send, but too big to be an agent file. It is not a reading
// failure, so it must not be reported as one (such as a missing CORS header).
class FileTooLarge extends Error {}

/**
 * Read a response body as text, stopping as soon as it passes MAX_BYTES, so a hostile
 * server cannot fill the visitor's memory.
 */
async function readCapped(resp, url) {
  const tooLarge = () => new FileTooLarge(`${url} is larger than 2 MB, the most Agent Customs reads. Agent files are usually a few kilobytes.`);
  if (Number(resp.headers?.get?.("content-length")) > MAX_BYTES) throw tooLarge();
  const reader = resp.body?.getReader?.();
  if (!reader) {
    const text = await resp.text();
    if (text.length > MAX_BYTES) throw tooLarge();
    return text;
  }
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BYTES) {
      reader.cancel().catch(() => {});
      throw tooLarge();
    }
    chunks.push(value);
  }
  return new Blob(chunks).text();
}

async function fetchPublic(url, fetchImpl, timeoutMs) {
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    const resp = await fetchImpl(url, {
      credentials: "omit", cache: "no-store", redirect: "follow", referrerPolicy: "no-referrer",
      signal: controller?.signal,
    });
    const text = resp.ok ? await readCapped(resp, url) : "";
    return { ok: resp.ok, status: resp.status, text, finalUrl: resp.url || url, redirected: !!resp.redirected };
  } catch (error) {
    if (error instanceof FileTooLarge) throw error;
    if (error?.name === "AbortError") throw new Error(`No answer from ${hostOf(url)} within ${Math.round(timeoutMs / 1000)} s`);
    throw new Error(`Could not read ${url}: the server is down or unreachable, or it does not allow other sites to read it (no CORS header).`);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Inspect a network by URL.
 *
 * :param input: A network URL, a site/manifest URL, or an A2A Agent Card / MCP catalog URL.
 * :param options.fetchImpl: fetch, or a stand-in for tests.
 * :param options.pins: A PinStore, to compare with the approved version.
 * :param options.pageOrigin: The inspecting page's origin, to tell whether CORS was exercised.
 * :param options.timeoutMs: Per-file timeout.
 * :param options.transitive: Also inspect cross-origin linked partners and MCP endpoints.
 * :return: The report. Failures that stop the inspection give an INVALID report.
 */
export async function inspectNetworkUrl(input, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const pageOrigin = options.pageOrigin || (typeof location !== "undefined" ? location.origin : null);
  const pin = options.pins ? options.pins.get(String(input || "").trim()) : null;
  const visited = options._visited || new Set();
  const depth = options._depth || 0;
  const maxDepth = options.maxDepth ?? 2;

  let parsedTargets;
  try {
    parsedTargets = targetsFor(input);
  } catch (error) {
    return failureReport(String(input), "P-URL", "3.2", "Network URL is usable", error.message);
  }
  const { candidates, directUrl, strictForeign } = parsedTargets;
  visited.add(normalizeTargetUrl(input));

  const redirects = [];
  let manifestInfo = null;
  let lastError = null;
  let unreachable = false;
  let sawTooLarge = false;
  let chosen = null;

  const transitiveOpts = { ...options, fetchImpl, timeoutMs, pageOrigin, _visited: visited, _depth: depth, maxDepth };
  const inspectForeignResponse = async (sourceUrl, got, foreignPin) => {
    let doc = null;
    try { doc = JSON.parse(got.text); } catch { return { invalidJson: true, proto: null, report: null }; }
    const proto = detectProtocol(doc, sourceUrl);
    if (proto !== "a2a" && proto !== "mcp") return { invalidJson: false, proto, report: null };
    if (got.redirected) redirects.push({ from: sourceUrl, to: got.finalUrl, crossOrigin: originOf(got.finalUrl) !== originOf(sourceUrl) });
    const report = await analyzeForeignTarget({
      doc, targetUrl: sourceUrl, protocol: proto, pageOrigin, redirects, sizeBytes: got.text.length,
      pin: foreignPin, options,
    });
    return { invalidJson: false, proto, report: await applyTransitive(report, transitiveOpts) };
  };

  // Direct A2A Agent Card, MCP catalog, or standalone JSON endpoint.
  if (directUrl) {
    try {
      const got = await fetchPublic(directUrl, fetchImpl, timeoutMs);
      if (got.ok) {
        const res = await inspectForeignResponse(directUrl, got, pin);
        if (res.report) return res.report;
        if (strictForeign) {
          return res.invalidJson
            ? failureReport(directUrl, "P-PARSE", "Format", "Endpoint returns valid JSON", `${directUrl} is not valid JSON.`)
            : failureReport(directUrl, res.proto === "a2a" ? "P-A2A-CARD" : "P-MCP-SCHEMA", "Format",
                "Recognized A2A or MCP schema", `${directUrl} did not match A2A Agent Card or MCP tool schema structure.`);
        }
      } else if (strictForeign) {
        return failureReport(directUrl, /mcp/i.test(directUrl) ? "P-MCP-SCHEMA" : "P-A2A-CARD", "Discovery",
          "Endpoint is published", `${directUrl} answered HTTP ${got.status}.`);
      }
    } catch (error) {
      if (error instanceof FileTooLarge) {
        return failureReport(directUrl, "P-MANIFEST-FOUND", "Size", "File within 2 MB limit", error.message);
      }
      if (strictForeign) {
        const rep = failureReport(directUrl, "P-CORS", "Discovery", "Public files readable by other sites (CORS)", error.message);
        rep.verdict = { ...VERDICTS.UNREADABLE, summary: error.message };
        return rep;
      }
      lastError = error.message;
      unreachable = true;
    }
  }

  // Standard Open Agentic Web discovery via agent-manifest.json.
  for (const candidate of candidates) {
    const manifestUrl = `${candidate.base}/agent-manifest.json`;
    try {
      const got = await fetchPublic(manifestUrl, fetchImpl, timeoutMs);
      if (!got.ok) {
        lastError = got.status === 404
          ? `No AI agents are published here: ${manifestUrl} does not exist (HTTP 404). Agentic websites publish this file; most websites do not have one yet.`
          : `${manifestUrl} answered HTTP ${got.status}.`;
        unreachable = false;
        continue;
      }
      let manifest;
      try { manifest = JSON.parse(got.text); } catch { lastError = `${manifestUrl} is not valid JSON.`; unreachable = false; continue; }
      if (got.redirected) redirects.push({ from: manifestUrl, to: got.finalUrl, crossOrigin: originOf(got.finalUrl) !== originOf(manifestUrl) });
      manifestInfo = { manifest, url: manifestUrl };
      chosen = candidate;
      break;
    } catch (error) {
      if (error instanceof FileTooLarge) { lastError = error.message; unreachable = false; sawTooLarge = true; continue; }
      // The browser could not read it at all: down, unreachable, or no CORS header.
      // That says nothing about the network itself, so it gets its own verdict.
      if (!lastError || unreachable) { lastError = error.message; unreachable = true; }
    }
  }

  // Probe well-known A2A and MCP paths when no manifest exists (some hosts omit CORS on 404s for agent-manifest.json).
  if (!manifestInfo && !sawTooLarge) {
    const seenBases = new Set();
    for (const candidate of candidates) {
      if (!candidate.base || seenBases.has(candidate.base)) continue;
      seenBases.add(candidate.base);
      for (const probe of foreignDiscoveryCandidates(candidate.base)) {
        try {
          const got = await fetchPublic(probe.url, fetchImpl, timeoutMs);
          if (!got.ok) continue;
          const res = await inspectForeignResponse(probe.url, got, options.pins ? (options.pins.get(probe.url) || pin) : null);
          if (res.report) return res.report;
        } catch {
          // Fall through to the final P-MANIFEST-FOUND / P-CORS report.
        }
      }
    }
  }

  if (!manifestInfo) {
    const report = failureReport(String(input), "P-MANIFEST-FOUND", "3.2, 3.3", "agent-manifest.json is published", lastError || "No manifest found.",
      "Publish agent-manifest.json in the folder of the network URL, with Access-Control-Allow-Origin: *.");
    if (unreachable) {
      report.verdict = { ...VERDICTS.UNREADABLE, summary: "Your browser could not read any agent files at this address. There may be none here (most websites have none yet), the site may be down, or it may not let other websites read its files (no CORS header). In that last case no caller can run it either (spec sections 3.3 and 3.4)." };
      report.conformance.checks[0] = { id: "P-CORS", section: "3.3, 3.4", title: "Public files readable by other sites (CORS)", status: "fail",
        detail: lastError, fix: "If this is your site: serve agent-manifest.json, the network file and links.json with Access-Control-Allow-Origin: *." };
    }
    return report;
  }
  const { manifest } = manifestInfo;
  const networks = Array.isArray(manifest.networks) ? manifest.networks : [];
  let name = chosen.name;
  if (!name) {
    if (networks.length === 1 && networks[0]?.name) name = networks[0].name;
    else {
      const names = networks.map((n) => n?.name).filter(Boolean);
      return failureReport(`${chosen.base}/`, "P-PICK", "3.2", "One network chosen",
        names.length ? `This site publishes ${names.length} networks. Inspect one of: ${names.map((n) => `${chosen.base}/${n}`).join(", ")}` : "The manifest lists no networks.",
        "Use a network URL: the folder that holds agent-manifest.json, then the network name.", { choices: names.map((n) => `${chosen.base}/${n}`) });
    }
  }
  const networkUrl = `${chosen.base}/${name}`;
  const entry = networks.find((n) => n && n.name === name);
  if (!entry) {
    return failureReport(networkUrl, "P-EXACT", "3.2", "The manifest publishes this exact network",
      `No network named "${name}" at ${hostOf(networkUrl)}. A runtime must fail rather than run another one. Published: ${networks.map((n) => n?.name).filter(Boolean).join(", ") || "none"}.`,
      "Check the network name: it is the last part of the URL and must match networks[].name exactly.");
  }
  if (typeof entry.hocon !== "string" || !entry.hocon) {
    return failureReport(networkUrl, "P-HOCON", "3.3", "The manifest says where the network file is", "The entry has no hocon path.", "Add \"hocon\": \"./<network>.network.json\".");
  }
  const hoconUrl = resolveUrl(chosen.base, entry.hocon);
  let file;
  try {
    file = await fetchPublic(hoconUrl, fetchImpl, timeoutMs);
  } catch (error) {
    return failureReport(networkUrl, "P-NETWORK-FOUND", "3.3", "The network file is published", error.message, "Publish the file the manifest names, with CORS.");
  }
  if (!file.ok) {
    return failureReport(networkUrl, "P-NETWORK-FOUND", "3.3", "The network file is published", `${hoconUrl} answered HTTP ${file.status}.`, "Publish the file the manifest names.");
  }
  if (file.redirected) redirects.push({ from: hoconUrl, to: file.finalUrl, crossOrigin: originOf(file.finalUrl) !== originOf(hoconUrl) });

  let config;
  try {
    config = parseHocon(file.text);
  } catch (error) {
    return failureReport(networkUrl, "P-PARSE", "2, 2.2", "The network file parses", `${hoconUrl}: ${error.message}`, "Publish resolved JSON (or the runtime's HOCON subset) with no includes or substitutions.");
  }
  if (!config || typeof config !== "object" || !Array.isArray(config.tools)) {
    return failureReport(networkUrl, "P-PARSE", "2.1", "The network file has a tools list", "No top-level tools array.", "Put the agents in a top-level \"tools\" array.");
  }

  // links.json, merged the way the runtime merges it.
  let linksState = "missing";
  try {
    const links = await fetchPublic(`${chosen.base}/links.json`, fetchImpl, timeoutMs);
    if (links.ok) {
      try {
        const doc = JSON.parse(links.text);
        if (doc && typeof doc === "object" && doc.networks && typeof doc.networks === "object") {
          linksState = "ok";
          config.links = { ...(config.links || {}), ...(doc.networks[name] || {}) };
        } else linksState = "invalid";
      } catch { linksState = "invalid"; }
    }
  } catch (error) { linksState = error instanceof FileTooLarge ? "too-large" : "missing"; }

  let network;
  let validation;
  let frontMan = null;
  try {
    network = new AgentNetwork(config, name);
    validation = validateNetwork(network);
    try { frontMan = network.findFrontMan(); } catch { frontMan = null; }
  } catch (error) {
    return failureReport(networkUrl, "P-VALID", "3.1", "Network passes the runtime's validator", error.message, "Fix the network structure.");
  }

  const cors = !pageOrigin ? "unchecked" : originOf(networkUrl) === pageOrigin ? "same-origin" : "ok";
  const netPin = options.pins ? options.pins.get(networkUrl) : null;
  const report = await analyzeNetwork({
    networkUrl, manifest, entry, config: network.config, frontMan,
    linkSlots: [...(network.linkSlots || [])], validation,
    transport: { cors, redirects, links: linksState, sizeBytes: file.text.length, hoconUrl },
    pin: netPin,
    protocol: "open-agentic-web",
  });
  return applyTransitive(report, transitiveOpts);
}

async function analyzeForeignTarget({ doc, targetUrl, protocol, pageOrigin, redirects, sizeBytes, pin, options }) {
  const norm = normalizeForeignSpec(doc, targetUrl, protocol);
  const cors = !pageOrigin ? "unchecked" : originOf(targetUrl) === pageOrigin ? "same-origin" : "ok";
  return analyzeNetwork({
    networkUrl: targetUrl,
    manifest: norm.manifest,
    entry: norm.entry,
    config: norm.config,
    frontMan: norm.frontMan,
    linkSlots: norm.linkSlots,
    validation: null,
    transport: { cors, redirects, links: "not-applicable", sizeBytes, hoconUrl: targetUrl },
    pin: options?.pins ? (options.pins.get(targetUrl) || pin) : pin,
    protocol: norm.protocol,
    profile: norm.profile,
    rawDoc: norm.rawDoc,
  });
}

async function applyTransitive(report, options) {
  if (!report || report.failure || options.deep === false) return report;
  const depth = options._depth || 0;
  const maxDepth = options.maxDepth ?? 2;
  if (depth >= maxDepth) return report;

  const visited = options._visited || new Set([normalizeTargetUrl(report.target.url)]);
  const crossOriginAllowed = !!options.transitive;
  const candidateUrls = [];

  for (const stop of report.itinerary || []) {
    if (!stop.sameSite && !crossOriginAllowed) continue;
    if ((stop.kinds || []).every((k) => k === "mentioned in instructions")) continue;
    for (const u of stop.urls || []) {
      const key = normalizeTargetUrl(u);
      if (visited.has(key)) continue;
      if (!candidateUrls.includes(u)) candidateUrls.push(u);
    }
  }
  if (!candidateUrls.length) return report;

  const checked = [];
  let updated = report;
  for (const subUrl of candidateUrls.slice(0, MAX_TRANSITIVE_CHILDREN)) {
    const key = normalizeTargetUrl(subUrl);
    if (visited.has(key)) continue;
    visited.add(key);
    const subReport = await inspectNetworkUrl(subUrl, {
      ...options,
      pins: undefined,
      _visited: visited,
      _depth: depth + 1,
    });
    if (subReport.failure && ["P-MANIFEST-FOUND", "P-A2A-CARD", "P-MCP-SCHEMA"].includes(subReport.conformance?.checks?.[0]?.id)) {
      // Non-agent endpoints (such as plain REST APIs) are expected and left alone.
      continue;
    }
    checked.push({
      url: subReport.target?.url || subUrl,
      protocol: subReport.protocol || "open-agentic-web",
      verdict: subReport.verdict?.code || "INVALID",
      hash: subReport.identity?.short || "",
      summary: subReport.verdict?.summary || "",
    });
    if (subReport.verdict?.code === "DENIED" || subReport.verdict?.code === "HOLD" || subReport.verdict?.code === "INVALID") {
      updated = escalateReport(updated, {
        rule: "R-TRANSITIVE",
        category: "itinerary",
        severity: subReport.verdict.code === "DENIED" ? "critical" : "high",
        title: `Downstream dependency flagged (${subReport.verdict.stamp})`,
        detail: `Referenced target ${subUrl} evaluated as ${subReport.verdict.code}: ${subReport.verdict.summary}`,
        where: { field: "transitive dependency" },
        why: "Even a clean front agent exposes the visitor to compromised or risky behavior when it delegates to a dangerous partner or MCP endpoint.",
        fix: "Remove or replace the compromised downstream dependency, or isolate it behind explicit visitor approval.",
      });
    }
  }

  if (checked.length) {
    updated = { ...updated, transitive: { depth: depth + 1, checked } };
  }
  return updated;
}

function normalizeTargetUrl(url) {
  try {
    const u = new URL(String(url ?? "").trim());
    return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
  } catch {
    return String(url || "").trim();
  }
}

function failureReport(url, id, section, title, detail, fix = "", extra = {}) {
  let host = "";
  let origin = "";
  try { const u = new URL(url); host = u.host; origin = u.origin; } catch { /* keep blank */ }
  return {
    tool: "Agent Customs", inspectedAt: new Date().toISOString(),
    target: { url, base: "", origin, host, network: "" },
    identity: { brand: "", description: "", frontMan: "", agents: [], hash: "", linksHash: "", short: "", model: "" },
    verdict: { ...VERDICTS.INVALID, summary: detail },
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    conformance: { passed: 0, warned: 0, failed: 1, total: 1, score: 0, checks: [{ id, section, title, status: "fail", detail, fix }] },
    findings: [], itinerary: [], privacy: [], budget: {}, drift: null, conditions: [], snapshot: null,
    failure: true, ...extra,
  };
}

function resolveUrl(base, path) {
  if (/^https?:\/\//i.test(path)) return path;
  try {
    return new URL(path, `${base.replace(/\/$/, "")}/`).href;
  } catch {
    return base.replace(/\/$/, "") + (path.startsWith("/") ? path : "/" + path);
  }
}

function hostOf(url) {
  try { return new URL(url).host; } catch { return String(url); }
}

function originOf(url) {
  try { return new URL(url).origin; } catch { return ""; }
}
