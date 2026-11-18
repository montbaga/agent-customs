// capabilities.js: name- and schema-based "Lethal Trifecta" capability & data-flow analyzer.
//
// Text rules inspect what an agent *says*. Capability analysis inspects what declared tools,
// parameter schemas, and external endpoints allow an agent to *do*: combining Untrusted Input
// + Sensitive Access + External Egress creates an exfiltration path even in polite prose.
// MCP self-declared annotations can raise risk when present, but never suppress name,
// schema, REST toolbox, or off-origin URL signals.

function splitWords(value) {
  return String(value || "")
    .replace(/([a-z\d])([A-Z])/g, "$1 $2")
    .replace(/[_\-./:]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

const UNTRUSTED_TOOL = /\b(?:fetch|scrape|browse|crawl|search web|web search|read emails?|read mails?|get emails?|read pages?|fetch url|webhook listen|receive webhook)\b/i;
const SENSITIVE_TOOL = /\b(?:read files?|list files?|read env|get env|get config|read config|dump config|env(?:ironment)? settings?|env(?:ironment)? variables?|secrets?|credentials?|wallet|bank accounts?|payment methods?|credit cards?|order history|inbox|messages?|db query|sql query|private data)\b/i;
const SENSITIVE_PARAM = /\b(?:token|secret|password|passwd|cookie|session (?:cookie|secret|key|data|state)|auth(?:orization)?|auth header|credential|api key|private key|ssh key|ssn|iban)\b/i;
const NON_SECRET_PARAM = /\b(?:(?:session|delete|confirm(?:ation)?|status|cancel(?:lation)?|page(?:ination)?|next(?: page)?|cursor|continuation|resume|reset|idempotency|csrf|xsrf|job|task|run|upload|download|share|invite|signed) token|token (?:id|address|symbol|name|mint|decimals|amount|supply|balance|price|pair|type|standard|count|limit|budget|usage))\b/i;
const SENSITIVE_DESC = /\b(?:environment settings?|environment variables?|api credentials?|database credentials?|private files?|secret keys?|ssh keys?|access tokens?|(?:read|reads|load|loads|fetch|fetches|dump|dumps|extract|extracts|get|gets|access|accesses|collect|collects|steal|steals)\s+(?:the\s+|host\s+|local\s+|user\s+)?(?:env(?:ironment)?(?:\s+vars?)?|\.env|credentials?|cookies?|config(?:uration)?\s+files?|private\s+data))\b/i;
const EGRESS_TOOL = /\b(?:http post|send email|send message|post message|send webhook|webhook|notify(?: team)?|dispatch|exfil|upload|export data|publish|write file|push data|transfer funds|send telemetry)\b/i;
const EGRESS_PARAM_URL = /\b(?:webhook(?:\s*url)?|callback(?:\s*url)?|exfil(?:\s*url)?|(?:destination|endpoint|upload|forward|recipient)\s*(?:url|uri|webhook|hook|email))\b/i;
const EGRESS_PARAM_WEAK = /\b(?:destination|recipient|endpoint|callback|forward\s*to)\b/i;
const EGRESS_PARAM_DESC_URL = /\b(?:url|uri|webhook|endpoint|https?|e-?mail)\b/i;
const EGRESS_DESC = /\b(?:send|sends|post|posts|upload|uploads|transmit|transmits|forward|forwards|push|pushes|stream|streams|relay|relays|export|exports|ship|ships|submit|submits|deliver|delivers|exfiltrate|exfiltrates)\b[^.!?\n]{0,45}\b(?:webhook|callback|external\s+(?:url|endpoint|server|host|api)|remote\s+(?:url|endpoint|server|host)|https?:\/\/|url\s+you\s+(?:give|provide|pass|specify)|destination\s+url|configured\s+address|team|channel)\b|\b(?:telemetry\s+payload|notify\s+team|send\s+telemetry|webhook\s+url)\b/i;

/**
 * Analyze declared input, sensitivity, and egress capabilities across agents/tools.
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
    const toolWords = splitWords(name);
    const descWords = splitWords([agent.function?.description, agent.instructions].filter(Boolean).join(" "));
    const schemaInfo = collectSchemaInfo(agent.function?.parameters);
    const agentToolHit = [...agentTools].some((t) => SENSITIVE_TOOL.test(splitWords(t)));

    if (UNTRUSTED_TOOL.test(toolWords) || (ann.openWorldHint === true && ann.readOnlyHint === true)) {
      untrustedInput.push({ source: name, kind: "external_read", detail: `"${name}" ingests external/open-world content` });
    }
    if (SENSITIVE_TOOL.test(toolWords) || SENSITIVE_DESC.test(descWords) || SENSITIVE_DESC.test(schemaInfo.descWords) || agentToolHit) {
      sensitiveAccess.push({ source: name, kind: "sensitive_tool", detail: `"${name}" accesses potentially sensitive data, config, or files` });
    }

    const sensitiveParams = schemaInfo.paramSpecs
      .filter(({ key, description }) => {
        const kw = splitWords(key);
        if (!SENSITIVE_PARAM.test(kw) || NON_SECRET_PARAM.test(kw)) return false;
        if (/^api ?key$/i.test(kw) && /\b(?:optional\s+partner|partner\s+api\s+key)\b/i.test(description || "")) return false;
        return true;
      })
      .map((p) => p.key);
    if (sensitiveParams.length) {
      sensitiveAccess.push({
        source: name,
        kind: "sensitive_param",
        detail: `"${name}" declares sensitive schema fields (${sensitiveParams.slice(0, 4).join(", ")})`,
      });
    }

    // Hints can raise risk (e.g. destructiveHint: true or openWorld write), never lower or suppress
    // name/description/URL/REST egress findings when a server lies about readOnlyHint/openWorldHint.
    const hintRaisesEgress = ann.destructiveHint === true || (ann.openWorldHint === true && ann.readOnlyHint === false);
    const toolExternalUrl = toolOffOriginUrl(agent, targetOrigin);
    const egressParams = schemaInfo.paramSpecs.filter(({ key, format, description }) => {
      const kw = splitWords(key);
      if (EGRESS_PARAM_URL.test(kw)) return true;
      if (EGRESS_PARAM_WEAK.test(kw)) {
        const fmt = String(format || "").toLowerCase();
        return fmt === "uri" || fmt === "url" || fmt === "email" || EGRESS_PARAM_DESC_URL.test(splitWords(description));
      }
      return false;
    }).map((p) => p.key);
    if (EGRESS_TOOL.test(toolWords) || EGRESS_DESC.test(descWords) || hintRaisesEgress || toolExternalUrl || egressParams.length) {
      externalEgress.push({
        sink: toolExternalUrl || (egressParams.length ? `${name}(${egressParams[0]})` : name),
        kind: toolExternalUrl ? "external_endpoint" : egressParams.length ? "egress_param" : ann.destructiveHint === true ? "destructive_action" : "outbound_tool",
        detail: toolExternalUrl
          ? `"${name}" sends tool requests off-origin (${toolExternalUrl})`
          : egressParams.length
            ? `"${name}" accepts external destination parameter(s) (${egressParams.slice(0, 3).join(", ")})`
            : `"${name}" performs external or state-changing egress`,
      });
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

  // Only treat external egress as a Trifecta when there is concrete sensitive access.
  const concreteSensitive = secrets.filter((s) => s.kind === "private_context" || s.kind === "sensitive_tool" || s.kind === "sensitive_param");
  const concreteEgress = egress.filter((e) => e.kind !== "code_bundle");

  const crossOriginEgress = concreteEgress.some((e) => externalStops.some((s) => e.sink === s.host) || e.kind === "rest_toolbox" || e.kind === "outbound_tool" || e.kind === "external_endpoint" || e.kind === "egress_param");
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

function toolOffOriginUrl(agent, targetOrigin) {
  const candidates = [];
  if (typeof agent?.url === "string") candidates.push(agent.url);
  for (const ref of agent?.tools || []) {
    if (typeof ref === "string" && /^https?:\/\//i.test(ref)) candidates.push(ref);
    else if (ref && typeof ref === "object" && typeof ref.url === "string") candidates.push(ref.url);
  }
  for (const raw of candidates) {
    try {
      const u = new URL(raw, targetOrigin || undefined);
      if (/^https?:$/.test(u.protocol) && (!targetOrigin || u.origin !== targetOrigin)) return u.href;
    } catch { /* ignore invalid */ }
  }
  return "";
}

function collectSchemaInfo(node, keys = [], descs = [], paramSpecs = []) {
  if (!node || typeof node !== "object") return { keys, descWords: splitWords(descs.join(" ")), paramSpecs };
  if (Array.isArray(node)) {
    for (const item of node) collectSchemaInfo(item, keys, descs, paramSpecs);
    return { keys, descWords: splitWords(descs.join(" ")), paramSpecs };
  }
  if (node.properties && typeof node.properties === "object" && !Array.isArray(node.properties)) {
    for (const [k, v] of Object.entries(node.properties)) {
      keys.push(k);
      if (v && typeof v === "object") {
        if (typeof v.title === "string") descs.push(v.title);
        if (typeof v.description === "string") descs.push(v.description);
        paramSpecs.push({ key: k, format: v.format || "", description: v.description || "" });
      } else {
        paramSpecs.push({ key: k, format: "", description: "" });
      }
      collectSchemaInfo(v, keys, descs, paramSpecs);
    }
  }
  for (const [k, v] of Object.entries(node)) {
    if (k !== "properties" && v && typeof v === "object") collectSchemaInfo(v, keys, descs, paramSpecs);
  }
  return { keys, descWords: splitWords(descs.join(" ")), paramSpecs };
}
