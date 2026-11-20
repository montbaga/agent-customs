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

const UNTRUSTED_TOOL = /\b(?:fetch|scrape|browse|crawl|search web|web search|read emails?|read mails?|get emails?|read pages?|read web ?pages?|get web ?pages?|read urls?|fetch url|web fetch|webhook listen|receive webhook)\b/i;
const SENSITIVE_TOOL = /\b(?:read files?|list files?|(?:user|private|personal)\s+(?:files?|documents?|docs|notes|photos)|read env|get env|get config|read config|dump config|env(?:ironment)? settings?|env(?:ironment)? variables?|secrets?|credentials?|(?<!\b(?:phone|sms)\s)wallet|bank accounts?|payment methods?|credit cards?|order history|inbox|(?:read|get|search|list)\s+(?:an?\s+)?emails?|(?:read|get|list|fetch|search|dump)\s+(?:private\s+|direct\s+|user\s+)?messages?|db query|sql query|private data)\b/i;
// Reading a wallet's balance or status is not reading its keys. A wallet tool is sensitive
// when its name or description says it can move money or show keys.
const WALLET_CONTROL = /\b(?:transfer|transfers|send|sends|withdraw|withdrawal|export|keys?|seed|private|mnemonic|secret|sign|signs|pay|pays|payout|import|recover|drain)\b/i;
const NON_VISITOR_TOOL_SECRET = /\b(?:(?:rotate|roll|revoke|renew|verify|create|generate|regenerate|reset|set|update|delete)\s+(?:the\s+|your\s+|a\s+|an\s+)?(?:webhook|signing|forward|client|app|room)?\s*secrets?|(?:webhook|signing|forward)\s+secrets?)\b/i;
const CREDENTIAL_LIFECYCLE_ONLY = /\b(?:rotate|roll|revoke|renew|regenerate|reset)\b/i;
// A lifecycle tool that hands the current values back is a reader of secrets after all.
const RETURNS_SECRET_VALUES = /\breturn(?:s|ing)?\b[^.!?\n]{0,40}\b(?:values?|secrets?|keys?|tokens?|credentials?|passwords?)\b/i;
const NO_SECRET_VALUES_RETURNED = /\bvalues?\s+(?:are|is)\s+write[- ]?only\b[^.!?\n]{0,35}\bnever\s+(?:returned|exposed|readable)\b/i;
const STORED_SECRET_AUDIT_RISK = /\b(?:users?|visitors?|customers?|members?|employees?|vault|all\s+credentials|\.env|passwords?)\b/i;
const SENSITIVE_PARAM = /\b(?:tokens?|secrets?|passwords?|passwd|passcodes?|passphrases?|cookies?|session (?:cookie|secret|key|data|state)|auth(?:orization)?|auth header|credentials?|api key|private key|ssh key|ssn|iban)\b/i;
const UNIVERSAL_SECRET_PARAM = /\b(?:passwords?|passwd|passcodes?|passphrases?|cookies?|session (?:cookie|secret|key)|auth code|private key|ssh key|ssn|iban)\b/i;
const SECRET_COMPOUND_MODIFIER = /\b(?:access|auth(?:entication)?|bearer|refresh|oauth|id|api|secret|private|signing|user|visitor|account|client|personal|l402|third[- ]party)\s+(?:token|credential|secret)s?\b/i;
const SAFE_OPAQUE_HANDLE_NAME = /^(?:delete|status|cancel|retry|page|pagination|cursor|next|prev|previous|idempotency|upload|download|lease|claim|approval|confirm|confirmation|csrf|xsrf|webhook|signing)\s+(?:token|key|secret)$/i;
const NON_SECRET_TOKEN_METRIC = /\btokens?\s+(?:budget|limit|cap|count|max|min|size|price|amount|decimals|saved)\b/i;
const CRYPTO_OR_TEMPLATE_TOKEN_DESC = /\b(?:coingecko|erc-?20|spl|solana|base:0x|0x\s*address|contract address|token address|symbol|ticker|mint|liquidity|swap|swapping|dex aggregator|token swap|token substitutions?|design tokens?|template tokens?|brand colou?rs?|html references?|css tokens?)\b/i;
const BARE_TOKEN_NONSECRET_CONTEXT = /\b(?:concurrency|e-?tag|precondition|css\s+custom|brand\s+kits?)\b/i;
// Provenance that names this server itself.
const EXPLICIT_OWN_PROVENANCE_RE = /\b(?:returned|issued|generated|created|obtained|received|assigned|provided)\s+(?:by|from)\s+this\s+(?:server|service|mcp|api)\b/i;
// Provenance that only says "an earlier step": enough for this server's handles, not for
// real credential types (access, OAuth, bearer, API tokens), which another service may issue.
const GENERIC_PROVENANCE_RE = /\b(?:returned|issued|generated|created|obtained|received|assigned|provided)\s+(?:by|from)\s+a\s+(?:previous|prior)\s+(?:call|step)\b|\b(?:returned|received|obtained|copied)\s+(?:with|from|in)\s+(?:a|an|the)?\s*(?:previous|prior|earlier)?\s*(?:result|response|payload|call|retry\w*|creation)\b|\bfrom\s+(?:a|an|the)\s+(?:previous|prior|earlier|ready)\s+(?:result|response|payload|report)\b|\b(?:returned|issued|given|sent)\s+when\s+(?:the|this|a|your)\s+\w+\s+(?:was|is)\s+(?:created|opened|started|submitted|placed|registered)\b|\(\s*[a-z]{2,5}_[a-z0-9_….*-]{1,20}\s*[),]|\b(?:your|an?)\s+[a-z]{2,6}_\s+(?:api\s+)?(?:key|token)\b|\bauthorization\s*:\s*bearer\s+header\b|\boptional\s+(?:partner\s+)?api\s+key\b/i;
// Tools that link the visitor's account at another service. A token "from connect_dropbox"
// belongs to Dropbox and the visitor, not to this server.
const LINKING_TOOL = /\b(?:connect|link|oauth|login|log in|sign in|signin|authori[sz]e|auth)\b/i;
const PASSWORD_GATE_DESC = /\boptional\s+password\s+to\b|\b(?:set|add|remove|clear|protect|lock|gate)\s+(?:a|an|this|the|optional)?\s*password\b[^.]{0,30}\b(?:page|site|link|url|file|room|document|pdf)\b|\bpassword[- ]?(?:gate|protect(?:ed)?)\s+(?:a|an|this|the)?\s*(?:page|site|link|url|file|room|document|pdf)\b/i;
const PASSWORD_REUSE_RISK = /\b(?:same\s+password|reuse|online\s+bank|banking|e-?mail|account\s+password|existing\s+password)\b/i;
const USER_OWNED_PARAM_DESC = /\b(?:user's|users'|visitor's|visitors'|customer's|customers'|guest's|guests'|(?:the|your)\s+(?:user|visitor|customer|guest)\b|(?:user|visitor|customer|guest)\s+account|their|dashboard)\b/i;
const HANDLE_CREDENTIAL_RISK_DESC = /\b(?:password|passcode|login|bank|banking|wallet|exchange|e-?mail\s+account|third[- ]party)\b/i;

// True when the description names one of this server's own tools as the source, and that
// tool is not one that links an account at another service.
function mentionsOwnToolProvenance(desc, ownToolNames, linkingToolNames = new Set()) {
  if (!desc || !ownToolNames.size) return false;
  if (!/\b(?:from|by|via|call(?:ing)?|returned|issued|generated|created)\b/i.test(desc)) return false;
  const lower = desc.toLowerCase();
  const normalized = splitWords(desc);
  let named = false;
  for (const name of ownToolNames) {
    if (name.length < 4 || !(lower.includes(name) || normalized.includes(splitWords(name)))) continue;
    if (linkingToolNames.has(name)) return false;
    named = true;
  }
  return named;
}

function provenanceIsOwn(kw, desc, ownToolNames, linkingToolNames) {
  if (mentionsOwnToolProvenance(desc, ownToolNames, linkingToolNames)) return true;
  if (EXPLICIT_OWN_PROVENANCE_RE.test(desc)) return true;
  // Real credential types need the server itself (or one of its tools) named as the source.
  if (SECRET_COMPOUND_MODIFIER.test(kw)) return false;
  return GENERIC_PROVENANCE_RE.test(desc) && !USER_OWNED_PARAM_DESC.test(desc);
}

function hasOwnServerProvenance(param, ownToolNames, linkingToolNames) {
  const kw = splitWords(param.key);
  if (!kw || !SENSITIVE_PARAM.test(kw) || UNIVERSAL_SECRET_PARAM.test(kw)) return false;
  return provenanceIsOwn(kw, String(param.description || ""), ownToolNames, linkingToolNames);
}

/**
 * How a schema field counts as visitor-sensitive.
 *
 * :return: "yes" (sensitive), "no" (not a secret at all: a flag, a count, an id) or
 *   "exempt" (looks like this server's own handle). Exempt fields do not make a Lethal
 *   Trifecta on their own, but they still make a "possible data path" note, so wording
 *   that imitates an own handle never clears a path silently.
 */
function schemaParamSensitivity({ key, type, description }, ctx) {
  const { toolWords, toolDescWords, ownToolNames, linkingToolNames, provenancedKeys, siblingKeys } = ctx;
  const kw = splitWords(key);
  if (!kw || !SENSITIVE_PARAM.test(kw)) return "no";
  if (type === "boolean") return "no";
  if ((type === "integer" || type === "number") && /\btokens?\b/i.test(kw)) return "no";
  if (NON_SECRET_TOKEN_METRIC.test(kw)) return "no";
  if (/\bid$/i.test(kw) || /\b(?:auth )?state$/i.test(kw)) return "no";
  // A token's prefix, hash or last digits identifies it without being it.
  if (/\b(?:prefix|suffix|last ?4|hint|hash|hashed|fingerprint|length|preview|masked|redacted)$/i.test(kw)) return "no";
  if (/\bpasswords? (?:setup|reset|change|recovery|policy)(?: (?:link|url|page|token))?\b/i.test(kw)) return "no";
  const desc = String(description || "");
  if (PASSWORD_GATE_DESC.test(desc) && !/^(?:login|sign in|auth)/i.test(toolWords) && !PASSWORD_REUSE_RISK.test(desc)) {
    return "exempt";
  }
  if (UNIVERSAL_SECRET_PARAM.test(kw)) return "yes";

  if (!SECRET_COMPOUND_MODIFIER.test(kw) && (CRYPTO_OR_TEMPLATE_TOKEN_DESC.test(desc) || CRYPTO_OR_TEMPLATE_TOKEN_DESC.test(toolDescWords))) {
    return "exempt";
  }
  if ((kw === "token" || kw === "tokens") && (BARE_TOKEN_NONSECRET_CONTEXT.test(desc) || BARE_TOKEN_NONSECRET_CONTEXT.test(toolDescWords))) {
    return "exempt";
  }
  // A token "returned by a previous call" of a tool that links a bank or a login is that
  // account's token, whatever the wording says.
  const linksAccount = LINKING_TOOL.test(toolWords) || HANDLE_CREDENTIAL_RISK_DESC.test(`${toolWords} ${toolDescWords}`);
  if (!linksAccount && provenanceIsOwn(kw, desc, ownToolNames, linkingToolNames)) return "exempt";
  if (!desc.trim() && provenancedKeys.has(kw)) return "exempt";

  // Plural "tokens" (CSS/template/UI/LLM token counts) is not a secret unless explicitly a secret modifier.
  if (/\btokens$/i.test(kw) && !SECRET_COMPOUND_MODIFIER.test(kw)) return "exempt";

  // Known lifecycle/pagination handles.
  if (SAFE_OPAQUE_HANDLE_NAME.test(kw) && !HANDLE_CREDENTIAL_RISK_DESC.test(desc)) return "exempt";

  // A plain token next to the id of the object it opens (application_id + token): an access
  // handle for that one object, unless the tool links an account or talks about logins.
  const plainToken = kw === "token" || (/^\w+ (?:token|secret|key)$/i.test(kw) && !SECRET_COMPOUND_MODIFIER.test(kw));
  if (plainToken && siblingKeys.some((k) => /(?:^|_|\b)id$|Id$|^slug$|^reference$/i.test(k))
    && !HANDLE_CREDENTIAL_RISK_DESC.test(`${desc} ${toolDescWords}`) && !LINKING_TOOL.test(toolWords)) {
    return "exempt";
  }
  return "yes";
}
const SENSITIVE_DESC = /\b(?:private\s+(?:documents?|notes|photos|messages)|(?:user|visitor|customer)'?s?\s+(?:private\s+)?(?:files|documents|notes|photos)|environment settings?|environment variables?|api credentials?|database credentials?|private files?|secret keys?|ssh keys?|(?:read|reads|load|loads|fetch|fetches|dump|dumps|extract|extracts|get|gets|access|accesses|collect|collects|steal|steals)\s+(?:the\s+|host\s+|local\s+|user\s+)?(?:env(?:ironment)?(?:\s+vars?)?|\.env|credentials?|cookies?|access\s+tokens?|config(?:uration)?\s+files?|private\s+data))\b/i;
const EGRESS_TOOL = /\b(?:http post|post to url|post url|send to url|http request|post data|send email|send message|post message|send reply|send to|send webhook|webhook|notify(?: team)?|dispatch|exfil|upload|export data|publish|write file|push data|transfer funds|transfer domain|domain transfer|send telemetry)\b/i;
const OWN_STORE_TOOL = /\b(?:upload|write file|export data|push data)\b/i;
const EGRESS_TO_OTHERS_TOOL = /\b(?:http post|post to url|post url|send to url|http request|post data|send email|send message|post message|send reply|send to|send webhook|webhook|notify|dispatch|exfil|publish|transfer funds|transfer domain|domain transfer|send telemetry)\b/i;
const EGRESS_PARAM_URL =/\b(?:webhook(?:\s*url)?|callback(?:\s*url)?|exfil(?:\s*url)?|(?:destination|endpoint|upload|forward|recipient|target|post)\s*(?:url|uri|webhook|hook|email))\b/i;
const EGRESS_PARAM_WEAK = /\b(?:destination|recipient|endpoint|callback|forward\s*to)\b/i;
const EGRESS_PARAM_DESC_URL = /\b(?:url|uri|webhook|endpoint|https?|e-?mail)\b/i;
const EGRESS_DESC = /\b(?:send|sends|post|posts|upload|uploads|transmit|transmits|forward|forwards|push|pushes|stream|streams|relay|relays|export|exports|ship|ships|submit|submits|deliver|delivers|exfiltrate|exfiltrates)\b[^.!?\n]{0,45}\b(?:webhook|callback|external\s+(?:url|endpoint|server|host|api)|remote\s+(?:url|endpoint|server|host)|https?:\/\/|url\s+you\s+(?:give|provide|pass|specify)|destination\s+url|configured\s+address|team|channel)\b|\b(?:send|sends)\s+(?:a\s+)?(?:real\s+)?(?:e-?mail|reply|message|link)\s+to\b|\b(?:post|posts|send|sends|upload|uploads)\b[^.!?\n]{0,30}\bto\s+any\s+(?:url|address|endpoint|server|host|webhook)\b|\b(?:telemetry\s+payload|notify\s+team|send\s+telemetry|webhook\s+url)\b/i;

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
  // Access that only looks harmless because of wording ("own handle", "returned by …").
  const exemptAccess = [];
  const externalEgress = [];

  const externalStops = [...itinerary].filter((s) => !s.sameSite && s.contacted);
  const openPolicy = (manifest?.peer_policy || manifest?.web_policy)?.mode === "open";
  const agentTools = new Set(manifest?.actions?.agentTools || []);
  const ownToolNames = new Set(agents.map((a) => String(a?.name || "").toLowerCase()).filter(Boolean));
  const linkingToolNames = new Set(agents
    .filter((a) => LINKING_TOOL.test(splitWords(a?.name || "")))
    .map((a) => String(a.name).toLowerCase()));
  const EGRESS_HINT_TOOL = /\b(?:post|send|share|publish|submit|upload|export|transfer|forward|relay|notify|broadcast|webhook|e-?mail|exfil|transmit|dispatch|push)\b/i;
  const EGRESS_HINT_DESC = /\b(?:send|sends|post|posts|share|shares|publish|publishes|upload|uploads|export|exports|transfer|transfers|forward|forwards|relay|relays|notify|notifies|broadcast|broadcasts|transmit|transmits|e-?mail|e-?mails)\s+(?:a|an|the|this|given|your|user|external|it|data|text|message|report|file|content|to)\b/i;

  const toolSchemas = agents.map((agent) => collectSchemaInfo(agent.function?.parameters));
  const provenancedKeys = new Set();
  for (const schemaInfo of toolSchemas) {
    for (const param of schemaInfo.paramSpecs) {
      if (hasOwnServerProvenance(param, ownToolNames, linkingToolNames)) provenancedKeys.add(splitWords(param.key));
    }
  }

  // Front agent receives arbitrary caller/user text or partner outputs.
  if (frontMan) {
    untrustedInput.push({ source: frontMan, kind: "caller_prompt", detail: `Entry "${frontMan}" receives untrusted prompt/query text` });
  } else if (agents.length) {
    untrustedInput.push({ source: agents[0].name || "entry", kind: "tool_input", detail: "Exposes tool inputs reachable by a model" });
  }

  for (let i = 0; i < agents.length; i++) {
    const agent = agents[i];
    const name = agent.name || "agent";
    const ann = agent.annotations || {};
    const toolWords = splitWords(name);
    const descWords = splitWords([agent.function?.description, agent.instructions].filter(Boolean).join(" "));
    const schemaInfo = toolSchemas[i];
    const agentToolHit = [...agentTools].some((t) => SENSITIVE_TOOL.test(splitWords(t)));

    if (UNTRUSTED_TOOL.test(toolWords) || (ann.openWorldHint === true && ann.readOnlyHint === true)) {
      untrustedInput.push({ source: name, kind: "external_read", detail: `"${name}" ingests external/open-world content` });
    }
    const sensitiveMatch = toolWords.match(SENSITIVE_TOOL);
    const toolText = `${toolWords} ${descWords}`;
    const onlyOwnCredentialLifecycle = sensitiveMatch
      && /^(?:secrets?|credentials?)$/i.test(sensitiveMatch[0])
      && ((CREDENTIAL_LIFECYCLE_ONLY.test(toolText) && !STORED_SECRET_AUDIT_RISK.test(toolText) && !RETURNS_SECRET_VALUES.test(descWords))
        || (ann.readOnlyHint === true && NO_SECRET_VALUES_RETURNED.test(descWords)));
    // The description decides: a "wallet_balance" tool that "transfers it" moves money.
    const walletReadOnly = sensitiveMatch && /wallet/i.test(sensitiveMatch[0]) && !WALLET_CONTROL.test(toolText);
    const sensitiveToolName = Boolean(sensitiveMatch) && !NON_VISITOR_TOOL_SECRET.test(toolWords) && !onlyOwnCredentialLifecycle && !walletReadOnly;
    if (sensitiveToolName || SENSITIVE_DESC.test(descWords) || SENSITIVE_DESC.test(schemaInfo.descWords) || agentToolHit) {
      sensitiveAccess.push({ source: name, kind: "sensitive_tool", detail: `"${name}" accesses potentially sensitive data, config, or files` });
    } else if (sensitiveMatch) {
      exemptAccess.push({ source: name, kind: "sensitive_tool", detail: `"${name}" handles its own credentials or balances` });
    }
    if (sensitiveToolName && /^(?:secrets?|credentials?)$/i.test(sensitiveMatch[0]) && NO_SECRET_VALUES_RETURNED.test(descWords)) {
      // "Values are write-only and never returned": it lists names only. Only the tool's own
      // word says so, so the path stays visible as a note instead of a hold.
      const i = sensitiveAccess.findIndex((s) => s.source === name && s.kind === "sensitive_tool");
      if (i >= 0) exemptAccess.push({ ...sensitiveAccess.splice(i, 1)[0], detail: `"${name}" lists secret names; it says values are never returned` });
    }

    const ctx = { toolWords, toolDescWords: descWords, ownToolNames, linkingToolNames, provenancedKeys, siblingKeys: schemaInfo.keys };
    const graded = schemaInfo.paramSpecs.map((param) => ({ param, level: schemaParamSensitivity(param, ctx) }));
    const sensitiveParams = graded.filter((g) => g.level === "yes").map((g) => g.param.key);
    const exemptParams = graded.filter((g) => g.level === "exempt").map((g) => g.param.key);
    if (sensitiveParams.length) {
      sensitiveAccess.push({
        source: name,
        kind: "sensitive_param",
        detail: `"${name}" declares sensitive schema fields (${sensitiveParams.slice(0, 4).join(", ")})`,
      });
    }
    if (exemptParams.length) {
      exemptAccess.push({
        source: name,
        kind: "sensitive_param",
        detail: `"${name}" declares fields that look like the server's own handles (${exemptParams.slice(0, 4).join(", ")})`,
      });
    }

    // Hints may raise risk (openWorld mutating tools with sharing/outbound semantics), never lower concrete findings.
    const hintRaisesEgress = ann.openWorldHint === true && ann.readOnlyHint === false
      && (EGRESS_HINT_TOOL.test(toolWords) || EGRESS_HINT_DESC.test(descWords));
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
    // An MCP server's upload or write tool stores data on that server, which already receives
    // every call. Only a way to send data on to someone else adds a path.
    const storesOnServerOnly = protocol === "mcp" && OWN_STORE_TOOL.test(toolWords) && !EGRESS_TO_OTHERS_TOOL.test(toolWords)
      && !EGRESS_DESC.test(descWords) && !hintRaisesEgress && !toolExternalUrl && !egressParams.length;
    if (!storesOnServerOnly && (EGRESS_TOOL.test(toolWords) || EGRESS_DESC.test(descWords) || hintRaisesEgress || toolExternalUrl || egressParams.length)) {
      externalEgress.push({
        sink: toolExternalUrl || (egressParams.length ? `${name}(${egressParams[0]})` : name),
        kind: toolExternalUrl ? "external_endpoint" : egressParams.length ? "egress_param" : "outbound_tool",
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

  // The same path through fields or tools that were let off as the server's own: a note.
  const exempt = uniq(exemptAccess);
  const softTrifecta = !trifecta && inputs.length > 0 && exempt.length > 0 && concreteEgress.length > 0 && (crossOriginEgress || protocol === "mcp");
  const softPaths = softTrifecta
    ? exempt.slice(0, 2).map((s) => ({
      from: inputs[0].source, through: s.source, to: concreteEgress[0].sink,
      reason: `${inputs[0].detail} -> ${s.detail} -> ${concreteEgress[0].detail}`,
    }))
    : [];

  return {
    untrustedInput: inputs,
    sensitiveAccess: secrets,
    externalEgress: egress,
    trifecta,
    riskLevel,
    paths,
    softTrifecta,
    softPaths,
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
        paramSpecs.push({ key: k, type: String(v.type || "").toLowerCase(), format: v.format || "", description: v.description || "" });
      } else {
        paramSpecs.push({ key: k, type: "", format: "", description: "" });
      }
      collectSchemaInfo(v, keys, descs, paramSpecs);
    }
  }
  for (const [k, v] of Object.entries(node)) {
    if (k !== "properties" && v && typeof v === "object") collectSchemaInfo(v, keys, descs, paramSpecs);
  }
  return { keys, descWords: splitWords(descs.join(" ")), paramSpecs };
}
