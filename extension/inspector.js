// inspector.js: browser-extension auto-discovery across Open Agentic Web, A2A, and MCP endpoints.
import { inspectNetworkUrl } from "./customs/inspect.js";

export const ORIGIN_DISCOVERY_PATHS = [
  "agent-manifest.json",
  ".well-known/agent.json",
  ".well-known/agent-card.json",
  "mcp.json",
  ".well-known/mcp.json",
  "server.json",
];

/**
 * Inspect either a specific endpoint URL or discover well-known agent manifests on an origin.
 */
export async function inspectOriginAgents(target, { fetchImpl = globalThis.fetch, transitive = false } = {}) {
  const parsed = new URL(target);
  if (parsed.pathname && parsed.pathname !== "/") {
    const direct = await inspectNetworkUrl(parsed.href, { fetchImpl, pageOrigin: parsed.origin, transitive });
    if (!direct.failure) return { found: true, endpoint: direct.target.url, checked: [parsed.href], report: direct };
  }

  const origin = parsed.origin;
  const checked = [];
  for (const rel of ORIGIN_DISCOVERY_PATHS) {
    const candidate = `${origin}/${rel}`;
    checked.push(candidate);
    try {
      const probe = await fetchImpl(candidate, { headers: { Accept: "application/json" } });
      if (!probe.ok) continue;
      const report = await inspectNetworkUrl(candidate, { fetchImpl, pageOrigin: origin, transitive });
      if (!report.failure) return { found: true, endpoint: report.target.url, checked, report };
    } catch { /* probe next well-known path */ }
  }

  return { found: false, endpoint: "", checked, origin };
}
