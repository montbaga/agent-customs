// capabilities.js: structural "Lethal Trifecta" capability & data-flow analyzer.
//
// Text rules inspect what an agent *says*. Capability analysis inspects what an agent
// can structurally *do*: combining Untrusted Input + Sensitive Access + External Egress
// creates an exfiltration path even if the published wording looks completely polite.

const UNTRUSTED_TOOL = /\b(fetch|scrape|browse|crawl|search_web|web_search|read_email|read_mail|get_emails|read_page|fetch_url|webhook_listen)\b/i;
const SENSITIVE_TOOL = /\b(read_file|list_files|read_env|get_env|secrets|credentials|wallet|bank_account|payment_method|credit_card|order_history|inbox|messages|db_query|sql_query|private_data)\b/i;
const SENSITIVE_PARAM = /\b(token|secret|password|passwd|cookie|session|auth_header|credential|api_key|private_key|ssh_key|ssn|iban)\b/i;
const EGRESS_TOOL = /\b(http_post|send_email|send_message|post_message|webhook|exfil|upload|export_data|publish|write_file|push_data|transfer_funds)\b/i;

/**
 * Analyze structural input, sensitivity, and egress capabilities across agents/tools.
 *
 * :param input.agents: Normalized agents/tools array from config.tools.
 * :param input.itinerary: Evaluated itinerary stops array (or Map values).
 * :param input.privacy: Extracted privacy forwarding rules ({agent, direction, fields}).
 * :param input.manifest: Published manifest object.
 * :param input.frontMan: Entry agent name.
 * :param input.protocol: "open-agentic-web" | "a2a" | "mcp".
 * :param input.targetOrigin: Origin of the inspected site so same-site endpoints aren't treated as external.
 * :return: {untrustedInput, sensitiveAccess, externalEgress, trifecta, riskLevel, paths}.
 */
export function analyzeCapabilities({ agents = [], itinerary = [], privacy = [], manifest = {}, frontMan = "", protocol = "open-agentic-web", targetOrigin = "" }) {
  const untrustedInput = [];
  const sensitiveAccess = [];
  const externalEgress = [];

  const externalStops = [...itinerary].filter((s) => !s.sameSite && s.contacted);
  const openPolicy = (manifest?.peer_policy || manifest?.web_policy)?.mode === "open";
  const agentTools = new Set(manifest?.actions?.agentTools || []);

  // Front agent receives arbitrary caller/user text or partner outputs.
  if (frontMan) {
    untrustedInput.push({ source: frontMan, kind: "caller_prompt", detail: `Entry "${frontMan}" receives untrusted prompt/query text` });
  } else if (agents.length) {
    untrustedInput.push({ source: agents[0].name || "entry", kind: "tool_input", detail: "Exposes tool inputs reachable by a model" });
  }

  for (const agent of agents) {
    const name = agent.name || "agent";
    const ann = agent.annotations || {};
    const toolId = String(name);

    if (UNTRUSTED_TOOL.test(toolId) || (ann.openWorldHint === true && ann.readOnlyHint === true)) {
      untrustedInput.push({ source: name, kind: "external_read", detail: `"${name}" ingests external/open-world content` });
    }
    if (SENSITIVE_TOOL.test(toolId) || [...agentTools].some((t) => SENSITIVE_TOOL.test(t))) {
      sensitiveAccess.push({ source: name, kind: "sensitive_tool", detail: `"${name}" accesses potentially sensitive data or files` });
    }

    const paramKeys = schemaPropertyNames(agent.function?.parameters);
    const sensitiveParams = paramKeys.filter((k) => SENSITIVE_PARAM.test(k));
    if (sensitiveParams.length) {
      sensitiveAccess.push({
        source: name,
        kind: "sensitive_param",
        detail: `"${name}" declares sensitive schema fields (${sensitiveParams.slice(0, 4).join(", ")})`,
      });
    }

    if (EGRESS_TOOL.test(toolId) || (ann.openWorldHint === true && ann.readOnlyHint === false) || ann.destructiveHint === true) {
      externalEgress.push({ sink: name, kind: ann.destructiveHint ? "destructive_action" : "outbound_tool", detail: `"${name}" performs external or state-changing egress` });
    }

    if (agent.toolbox && typeof agent.args?.url === "string") {
      let restOrigin = "";
      try { restOrigin = new URL(agent.args.url, targetOrigin || undefined).origin; } catch { restOrigin = ""; }
      if (!targetOrigin || !restOrigin || restOrigin !== targetOrigin) {
        externalEgress.push({ sink: agent.args.url, kind: "rest_toolbox", detail: `REST toolbox "${name}" sends requests to ${agent.args.url}` });
      }
    }
  }

  for (const p of privacy) {
    sensitiveAccess.push({
      source: p.agent,
      kind: "private_context",
      detail: `Agent "${p.agent}" shares private context (${p.direction.replace("_", " ")}: ${p.fields.join(", ")})`,
    });
  }

  for (const stop of externalStops) {
    const kindList = [...(stop.kinds || [])].join(", ");
    externalEgress.push({
      sink: stop.host,
      kind: kindList,
      detail: `Contacts external host ${stop.host} (${kindList})`,
    });
  }

  if (manifest.coded_tools?.bundle) {
    externalEgress.push({ sink: manifest.coded_tools.bundle, kind: "code_bundle", detail: "Executes publisher code bundle in browser worker" });
  }
  if (openPolicy && externalStops.length) {
    externalEgress.push({ sink: "any origin (open policy)", kind: "open_policy", detail: "peer_policy.mode is open with active external refs" });
  }

  const uniq = (arr) => {
    const seen = new Set();
    return arr.filter((item) => {
      if (seen.has(item.detail)) return false;
      seen.add(item.detail);
      return true;
    });
  };

  const inputs = uniq(untrustedInput);
  const secrets = uniq(sensitiveAccess);
  const egress = uniq(externalEgress);

  // Only treat external egress as a Trifecta when there is concrete sensitive access
  // (beyond generic caller prompts + external web fetches with zero sensitive reads).
  const concreteSensitive = secrets.filter((s) => s.kind === "private_context" || s.kind === "sensitive_tool" || s.kind === "sensitive_param");
  const concreteEgress = egress.filter((e) => e.kind !== "code_bundle");

  // External stops + external partner calls make cross-origin exfiltration concrete.
  const crossOriginEgress = concreteEgress.some((e) => externalStops.some((s) => e.sink === s.host) || e.kind === "rest_toolbox" || e.kind === "outbound_tool");
  const trifecta = inputs.length > 0 && concreteSensitive.length > 0 && concreteEgress.length > 0 && (crossOriginEgress || protocol === "mcp");

  const paths = [];
  if (trifecta) {
    for (const s of concreteSensitive.slice(0, 3)) {
      for (const e of concreteEgress.slice(0, 3)) {
        paths.push({
          from: inputs[0].source,
          through: s.source,
          to: e.sink,
          reason: `${inputs[0].detail} -> ${s.detail} -> ${e.detail}`,
        });
      }
    }
  }

  const riskLevel = trifecta ? (crossOriginEgress ? "high" : "medium") : (concreteSensitive.length && concreteEgress.length ? "medium" : "none");

  return {
    untrustedInput: inputs,
    sensitiveAccess: secrets,
    externalEgress: egress,
    trifecta,
    riskLevel,
    paths,
  };
}

function schemaPropertyNames(node, out = []) {
  if (!node || typeof node !== "object") return out;
  if (Array.isArray(node)) {
    for (const item of node) schemaPropertyNames(item, out);
    return out;
  }
  if (node.properties && typeof node.properties === "object" && !Array.isArray(node.properties)) {
    for (const [k, v] of Object.entries(node.properties)) {
      out.push(k);
      schemaPropertyNames(v, out);
    }
  }
  for (const [k, v] of Object.entries(node)) {
    if (k !== "properties" && v && typeof v === "object") schemaPropertyNames(v, out);
  }
  return out;
}
