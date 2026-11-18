// protocols.js: detect and normalize Google A2A Agent Cards and MCP tool catalogs
// into the unified structure analyzed by analyze.js, rules.js, canonical.js and diff.js.
//
// Everything stays pure (no network access): inspect.js fetches public files, passes
// parsed foreign specs here when appropriate, and analyze.js evaluates Papers,
// Contraband, Itinerary, Privacy, Identity and Capabilities uniformly across protocols.

export const PROTOCOL_PROFILES = {
  "open-agentic-web": "Open Agentic Web MVP Profile 0.2 (6 Nov 2026)",
  a2a: "Google A2A Agent Card",
  mcp: "Model Context Protocol (MCP) Catalog",
};

const DESTRUCTIVE_NAME = /\b(delete|remove|drop|destroy|wipe|purge|exec|eval|run_command|shell|bash|write|overwrite|send_email|transfer|pay|charge|purchase|post_)\w*/i;
const SHELL_RUNNER = /(?:^|\s)(?:ba?sh|sh|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\b|(?:curl|wget)[^|\n]*\|/i;

/**
 * Identify which agent protocol a fetched JSON document describes.
 *
 * :param doc: Parsed JSON value.
 * :param url: Optional source URL to disambiguate minimal or malformed files.
 * :return: "open-agentic-web", "a2a", "mcp", or null when unrecognized.
 */
export function detectProtocol(doc, url = "") {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  if (Array.isArray(doc.networks)) return "open-agentic-web";
  if (Array.isArray(doc.tools) && doc.tools.some((t) => t && typeof t === "object" && ("instructions" in t || "command" in t || "function" in t || "class" in t || "toolbox" in t))) {
    return "open-agentic-web";
  }
  if (typeof doc.name === "string" && (Array.isArray(doc.skills) || Array.isArray(doc.supportedInterfaces) || doc.capabilities || doc.defaultInputModes || doc.preferredTransport)) {
    return "a2a";
  }
  if (doc.mcpServers && typeof doc.mcpServers === "object" && !Array.isArray(doc.mcpServers)) {
    return "mcp";
  }
  if (typeof doc.protocol === "string" && /model context protocol|\bmcp\b/i.test(doc.protocol)) {
    return "mcp";
  }
  if ((typeof doc.$schema === "string" && /modelcontextprotocol\.io/i.test(doc.$schema)) || (typeof doc.name === "string" && (Array.isArray(doc.packages) || Array.isArray(doc.remotes)))) {
    return "mcp";
  }
  const rpcTools = doc.result?.tools;
  if (Array.isArray(rpcTools) || (Array.isArray(doc.tools) && doc.tools.some((t) => t && typeof t === "object" && ("inputSchema" in t || "annotations" in t)))) {
    return "mcp";
  }
  if (doc.serverInfo || Array.isArray(doc.prompts) || Array.isArray(doc.resources) || Array.isArray(doc.result?.prompts)) {
    return "mcp";
  }
  if (/(?:\/\.well-known\/agent(?:-card)?\.json|\/agent(?:-card)?\.json)$/i.test(url)) return "a2a";
  if (/(?:\/\.well-known\/mcp\.json|\/mcp\.json|\/tools\/list)$/i.test(url)) return "mcp";
  return null;
}

/**
 * Return fallback discovery URLs to probe when a site does not publish agent-manifest.json.
 *
 * :param baseUrl: Folder/root base URL without trailing slash.
 * :return: Candidate {url, protocolHint} descriptors in priority order.
 */
export function foreignDiscoveryCandidates(baseUrl) {
  const base = String(baseUrl || "").replace(/\/+$/, "");
  if (!base) return [];
  return [
    { url: `${base}/.well-known/agent.json`, protocolHint: "a2a" },
    { url: `${base}/.well-known/agent-card.json`, protocolHint: "a2a" },
    { url: `${base}/.well-known/mcp.json`, protocolHint: "mcp" },
    { url: `${base}/mcp.json`, protocolHint: "mcp" },
  ];
}

/**
 * Normalize an A2A Agent Card or MCP JSON catalog into analyzeNetwork() inputs.
 *
 * :param doc: Parsed JSON document.
 * :param targetUrl: URL where the document was published.
 * :param protocol: Optional explicit protocol ("a2a" or "mcp").
 * :return: Normalized {protocol, profile, manifest, entry, config, frontMan, linkSlots, rawDoc}.
 */
export function normalizeForeignSpec(doc, targetUrl, protocol = detectProtocol(doc, targetUrl)) {
  if (protocol === "a2a") return normalizeA2aCard(doc, targetUrl);
  if (protocol === "mcp") return normalizeMcpCatalog(doc, targetUrl);
  return null;
}

function a2aServiceUrls(card) {
  const out = [];
  if (typeof card?.url === "string" && card.url.trim()) out.push(card.url.trim());
  for (const iface of [...(card?.supportedInterfaces || []), ...(card?.additionalInterfaces || [])]) {
    if (typeof iface?.url === "string" && iface.url.trim()) out.push(iface.url.trim());
  }
  return [...new Set(out)];
}

function a2aServiceUrl(card) {
  return a2aServiceUrls(card)[0] || "";
}

function normalizeA2aCard(doc, targetUrl) {
  const card = doc && typeof doc === "object" ? doc : {};
  const cardOrigin = originOf(targetUrl);
  const serviceUrl = a2aServiceUrl(card);
  const rpcOrigin = originOf(serviceUrl);
  const entryName = safeSlug(card.name) || "a2a_agent";
  const skills = Array.isArray(card.skills) ? card.skills : [];
  const allExamples = [];
  const frontTools = [];
  const tools = [];

  if (serviceUrl && rpcOrigin && cardOrigin && rpcOrigin !== cardOrigin) {
    frontTools.push(serviceUrl);
  }
  for (const iface of [...(card.supportedInterfaces || []), ...(card.additionalInterfaces || [])]) {
    if (typeof iface?.url === "string" && originOf(iface.url) && originOf(iface.url) !== cardOrigin) {
      frontTools.push(iface.url);
    }
  }

  for (let i = 0; i < skills.length; i += 1) {
    const s = skills[i] && typeof skills[i] === "object" ? skills[i] : { name: String(skills[i] || `skill_${i + 1}`) };
    const skillName = safeSlug(s.id || s.name) || `skill_${i + 1}`;
    frontTools.push(skillName);
    const examples = (Array.isArray(s.examples) ? s.examples : [])
      .map((ex) => (typeof ex === "string" ? ex : JSON.stringify(ex)))
      .filter(Boolean);
    allExamples.push(...examples);
    const tags = Array.isArray(s.tags) ? s.tags.filter((t) => typeof t === "string") : [];
    const schema = s.inputSchema && typeof s.inputSchema === "object"
      ? s.inputSchema
      : (examples.length || tags.length)
        ? { type: "object", properties: { request: { type: "string", description: [...tags, ...examples].join(" | ") } } }
        : { type: "object", properties: { request: { type: "string" } } };

    tools.push({
      name: skillName,
      instructions: tags.length ? `Tags: ${tags.join(", ")}` : "",
      command: [s.name, ...examples].filter(Boolean).join("\n"),
      function: {
        description: String(s.description || s.name || ""),
        parameters: schema,
      },
      tools: [],
      _skillId: s.id || "",
      _rawProtocolItem: "a2a_skill",
    });
  }

  const versionSuffix = card.protocolVersion ? ` (${card.protocolVersion})` : card.version ? ` v${card.version}` : "";
  const frontAgent = {
    name: entryName,
    instructions: String(card.description || ""),
    command: "",
    function: {
      description: String(card.description || card.name || ""),
      parameters: { type: "object", properties: { request: { type: "string" } }, required: ["request"] },
    },
    tools: [...new Set(frontTools)],
    allow: card.capabilities?.pushNotifications ? { to_downstream: { push: true } } : undefined,
    _rawProtocolItem: "a2a_card",
  };

  const allowedPeers = [];
  if (serviceUrl && rpcOrigin === cardOrigin) allowedPeers.push(rpcOrigin);

  const manifest = {
    brand: String(card.provider?.organization || card.name || ""),
    networks: [{
      name: entryName,
      front_man: entryName,
      description: String(card.description || ""),
      sample_queries: allExamples,
    }],
    allowed_peers: allowedPeers,
    peer_policy: { mode: "closed" },
    a2a: card,
  };

  return {
    protocol: "a2a",
    profile: `${PROTOCOL_PROFILES.a2a}${versionSuffix}`,
    manifest,
    entry: manifest.networks[0],
    frontMan: entryName,
    linkSlots: [],
    config: {
      metadata: {
        name: String(card.name || ""),
        description: String(card.description || ""),
        sample_queries: allExamples,
      },
      tools: [frontAgent, ...tools],
    },
    rawDoc: card,
  };
}

function normalizeMcpCatalog(doc, targetUrl) {
  const root = doc?.result && typeof doc.result === "object" ? { ...doc, ...doc.result } : (doc || {});
  const serverName = root.serverInfo?.name || root.name || "mcp_server";
  const frontMan = safeSlug(serverName) || "mcp_server";
  const rawTools = Array.isArray(root.tools) ? root.tools : [];
  const rawPrompts = Array.isArray(root.prompts) ? root.prompts : [];
  const rawResources = Array.isArray(root.resources) ? root.resources : [];
  const rawServers = root.mcpServers && typeof root.mcpServers === "object" ? root.mcpServers : {};
  const rawPackages = Array.isArray(root.packages) ? root.packages : [];
  const rawRemotes = Array.isArray(root.remotes) ? root.remotes : [];
  const targetOrigin = originOf(targetUrl);

  const normalizedTools = [];
  const frontRefs = [];
  const allowedPeers = [];

  for (const pkg of rawPackages) {
    if (!pkg || typeof pkg !== "object") continue;
    const pkgName = safeSlug(pkg.identifier || pkg.name) || "mcp_package";
    frontRefs.push(pkgName);
    normalizedTools.push({
      name: pkgName,
      instructions: pkg.transport?.type ? `Transport: ${pkg.transport.type}` : "",
      command: "",
      function: {
        description: String(`${pkg.registryType || "package"} ${pkg.identifier || ""} ${pkg.version || ""}`.trim()),
        parameters: { type: "object", properties: {} },
      },
      tools: [],
      _rawProtocolItem: "mcp_package",
    });
  }

  for (let i = 0; i < rawRemotes.length; i += 1) {
    const rem = rawRemotes[i];
    if (!rem || typeof rem !== "object") continue;
    const remName = safeSlug(rem.name || `remote_${i + 1}`) || `remote_${i + 1}`;
    frontRefs.push(remName);
    const refs = [];
    if (typeof rem.url === "string" && /^https?:\/\//i.test(rem.url)) {
      refs.push({ url: rem.url, type: "mcp" });
      if (originOf(rem.url) === targetOrigin) allowedPeers.push(targetOrigin);
    }
    normalizedTools.push({
      name: remName,
      instructions: rem.transportType ? `Remote transport: ${rem.transportType}` : "",
      command: "",
      function: { description: `Remote MCP endpoint (${rem.transportType || "http"})`, parameters: { type: "object", properties: {} } },
      tools: refs,
      _rawProtocolItem: "mcp_remote",
    });
  }

  for (const [name, spec] of Object.entries(rawServers)) {
    if (!spec || typeof spec !== "object") continue;
    const entryName = safeSlug(name) || "mcp_endpoint";
    frontRefs.push(entryName);
    const serverRefs = [];
    if (typeof spec.url === "string" && /^https?:\/\//i.test(spec.url)) {
      serverRefs.push({ url: spec.url, type: "mcp" });
      const o = originOf(spec.url);
      if (o && o === targetOrigin) allowedPeers.push(o);
    }
    const cmdLine = [spec.command, ...(Array.isArray(spec.args) ? spec.args : [])].filter(Boolean).map(String).join(" ");
    normalizedTools.push({
      name: entryName,
      instructions: cmdLine ? `Server command: ${cmdLine}` : "",
      command: "",
      function: {
        description: String(spec.description || `Configured MCP server "${name}"`),
        parameters: { type: "object", properties: {} },
      },
      tools: serverRefs,
      _mcpServer: { name, command: spec.command || "", args: spec.args || [], url: spec.url || "", hasEnv: !!spec.env },
      _rawProtocolItem: "mcp_server",
    });
  }

  for (let i = 0; i < rawTools.length; i += 1) {
    const raw = rawTools[i];
    const t = raw && typeof raw === "object" ? raw : { name: typeof raw === "string" ? raw : `tool_${i + 1}` };
    const name = String(t.name || `tool_${i + 1}`);
    frontRefs.push(name);
    const refs = [];
    if (typeof t.url === "string" && /^https?:\/\//i.test(t.url)) refs.push({ url: t.url, type: "mcp" });
    normalizedTools.push({
      name,
      instructions: "",
      command: "",
      function: {
        description: String(t.description || ""),
        parameters: t.inputSchema && typeof t.inputSchema === "object" ? t.inputSchema : null,
      },
      outputSchema: t.outputSchema && typeof t.outputSchema === "object" ? t.outputSchema : null,
      tools: refs,
      annotations: t.annotations && typeof t.annotations === "object" ? { ...t.annotations } : null,
      _rawProtocolItem: "mcp_tool",
    });
  }

  for (let i = 0; i < rawPrompts.length; i += 1) {
    const p = rawPrompts[i] && typeof rawPrompts[i] === "object" ? rawPrompts[i] : { name: `prompt_${i + 1}` };
    const argsProps = {};
    for (const arg of Array.isArray(p.arguments) ? p.arguments : []) {
      if (arg?.name) argsProps[arg.name] = { type: "string", description: String(arg.description || "") };
    }
    const promptTexts = [];
    for (const msg of Array.isArray(p.messages) ? p.messages : []) {
      if (!msg) continue;
      if (typeof msg === "string") { promptTexts.push(msg); continue; }
      const content = msg.content;
      if (typeof content === "string") promptTexts.push(content);
      else if (Array.isArray(content)) {
        for (const part of content) {
          if (typeof part === "string") promptTexts.push(part);
          else if (typeof part?.text === "string") promptTexts.push(part.text);
        }
      } else if (content && typeof content === "object" && typeof content.text === "string") {
        promptTexts.push(content.text);
      }
    }
    normalizedTools.push({
      name: `prompt:${p.name || i + 1}`,
      instructions: String(p.description || ""),
      command: promptTexts.join("\n"),
      function: {
        description: String(p.description || ""),
        parameters: { type: "object", properties: argsProps },
      },
      tools: [],
      _rawProtocolItem: "mcp_prompt",
    });
  }

  const serverUrl = typeof root.url === "string" ? root.url : typeof root.endpoint === "string" ? root.endpoint : "";
  if (serverUrl && /^https?:\/\//i.test(serverUrl)) {
    const o = originOf(serverUrl);
    if (o && targetOrigin && o === targetOrigin) allowedPeers.push(o);
    if (o && targetOrigin && o !== targetOrigin) frontRefs.push({ url: serverUrl, type: "mcp" });
  }

  const versionSuffix = root.protocolVersion ? ` (${root.protocolVersion})` : root.serverInfo?.version ? ` v${root.serverInfo.version}` : "";
  const entryAgent = {
    name: frontMan,
    instructions: String(root.instructions || root.description || ""),
    command: rawResources.map((r) => `${r?.name || ""} ${r?.description || ""} ${r?.uri || ""}`.trim()).filter(Boolean).join("\n"),
    function: {
      description: String(root.description || `MCP server exposing ${rawTools.length || Object.keys(rawServers).length} item(s).`),
      parameters: { type: "object", properties: { request: { type: "string" } } },
    },
    tools: [...new Set(frontRefs)],
    _rawProtocolItem: "mcp_entry",
  };

  // Avoid duplicating the entry name if a single tool has the same slug.
  const deduped = normalizedTools.filter((t) => t.name !== frontMan);
  const manifest = {
    brand: String(root.serverInfo?.title || root.serverInfo?.name || root.name || ""),
    networks: [{
      name: frontMan,
      front_man: frontMan,
      description: String(root.description || ""),
    }],
    allowed_peers: [...new Set(allowedPeers)],
    peer_policy: { mode: "closed" },
    mcp: doc,
  };

  return {
    protocol: "mcp",
    profile: `${PROTOCOL_PROFILES.mcp}${versionSuffix}`,
    manifest,
    entry: manifest.networks[0],
    frontMan,
    linkSlots: [],
    config: {
      metadata: {
        name: String(serverName),
        description: String(root.description || ""),
      },
      tools: [entryAgent, ...deduped],
    },
    rawDoc: doc,
  };
}

/**
 * Evaluate Papers conformance and safety checks for Google A2A Agent Cards and MCP catalogs.
 */
export function evaluateForeignPapers({ protocol, target, rawDoc = {}, manifest = {}, config = {}, addFinding, addCheck, secretResult }) {
  const { published = [], publishedList = "" } = secretResult || {};
  addCheck({
    id: "P-SECRETS",
    section: protocol === "a2a" ? "A2A Security" : "MCP Security",
    title: "No keys or passwords in public files",
    status: published.length ? "fail" : "pass",
    detail: published.length ? `${published.length} found: ${publishedList}.` : "None found.",
    fix: "Remove secrets from public manifests and env maps, and rotate them immediately.",
  });
  if (published.length) {
    addFinding({
      rule: "S-SECRET",
      category: "privacy",
      severity: "medium",
      title: "Publishes a key or password",
      detail: `${published.length} in its public files: ${publishedList}. Shown shortened here.`,
      where: { agent: published[0].agent, field: published[0].field },
      why: "Anyone can read public manifests and copy published tokens or secrets.",
      fix: "Remove credentials from public configs and supply tokens via runtime environment bindings.",
    });
  }

  const blocking = [];

  if (protocol === "a2a") {
    const hasName = typeof rawDoc.name === "string" && rawDoc.name.trim().length > 0;
    const urlStr = a2aServiceUrl(rawDoc);
    let urlValid = false;
    let parsedUrl = null;
    try {
      if (urlStr) {
        parsedUrl = new URL(urlStr, target.origin ? `${target.origin}/` : undefined);
        urlValid = /^https?:$/.test(parsedUrl.protocol);
      }
    } catch { urlValid = false; }

    const cardOk = hasName && urlValid;
    addCheck({
      id: "P-A2A-CARD",
      section: "A2A §4",
      title: "Agent Card declares name, description and URL",
      status: cardOk ? (rawDoc.description ? "pass" : "warn") : "fail",
      detail: !hasName ? "Missing required agent name." : !urlValid ? "Missing or invalid http/https service url." : rawDoc.description ? `Card "${rawDoc.name}" -> ${parsedUrl.origin}.` : "Valid card, but missing description.",
      fix: "Provide valid name, description, and HTTPS url in the A2A Agent Card.",
    });
    if (!cardOk) blocking.push("its A2A card lacks a required name or valid URL");

    if (urlValid && target.origin) {
      const parsedAll = [];
      for (const ifaceUrl of a2aServiceUrls(rawDoc)) {
        try {
          const u = new URL(ifaceUrl, target.origin ? `${target.origin}/` : undefined);
          if (/^https?:$/.test(u.protocol)) parsedAll.push(u);
        } catch { /* ignore invalid secondary */ }
      }
      const insecure = parsedAll.filter((u) => u.protocol !== "https:" && !target.loopback);
      const offOrigin = parsedAll.filter((u) => u.origin !== target.origin);
      addCheck({
        id: "P-A2A-ENDPOINT",
        section: "A2A §4, §7",
        title: "A2A endpoint uses HTTPS on the expected origin",
        status: insecure.length ? "fail" : offOrigin.length ? "warn" : "pass",
        detail: insecure.length
          ? `Endpoint ${insecure[0].href} uses plain HTTP.`
          : offOrigin.length
            ? `Points execution to another host (${[...new Set(offOrigin.map((u) => u.host))].join(", ")}).`
            : "Matches publishing origin over HTTPS.",
        fix: "Host all A2A JSON-RPC and interface endpoints on HTTPS on your own origin.",
      });
      if (offOrigin.length) {
        const offHosts = [...new Set(offOrigin.map((u) => u.host))];
        addFinding({
          rule: "R-CROSS-ORIGIN-ENDPOINT",
          category: "itinerary",
          severity: "medium",
          title: `Delegates execution to another origin (${offHosts.join(", ")})`,
          detail: `The card published at ${target.host} declares interface URL(s) on ${offOrigin.map((u) => u.href).join(", ")}.`,
          where: { field: "url / interfaces" },
          why: "A card hosted on one domain can quietly route visitor requests to an unrelated server.",
          fix: "Serve the Agent Card and all its RPC interface endpoints on the same origin.",
        });
      }
    }

    const skills = Array.isArray(rawDoc.skills) ? rawDoc.skills : [];
    const badSkills = skills.filter((s) => !s?.name || !s?.description);
    addCheck({
      id: "P-A2A-SKILLS",
      section: "A2A §4.4",
      title: "Declares skills with names and descriptions",
      status: !skills.length ? "warn" : badSkills.length ? "warn" : "pass",
      detail: !skills.length ? "No skills[] declared." : badSkills.length ? `${badSkills.length} skill(s) lack name or description.` : `${skills.length} skill(s) described.`,
      fix: "Describe each entry in skills[] with id, name, and description.",
    });

    const hasAuth = !!(rawDoc.authentication || rawDoc.securitySchemes || rawDoc.security?.length);
    addCheck({
      id: "P-A2A-AUTH",
      section: "A2A §4.5",
      title: "Declares authentication requirements",
      status: hasAuth ? "pass" : "warn",
      detail: hasAuth ? "Authentication / securitySchemes declared." : "No authentication or securitySchemes field (public unauthenticated card).",
      fix: "Declare securitySchemes or authentication modes required by callers.",
    });

    const hasModes = Array.isArray(rawDoc.defaultInputModes) || Array.isArray(rawDoc.defaultOutputModes);
    addCheck({
      id: "P-A2A-MODES",
      section: "A2A §4",
      title: "Declares supported input/output MIME modes",
      status: hasModes ? "pass" : "warn",
      detail: hasModes ? `Modes: ${(rawDoc.defaultInputModes || []).join(", ") || "default"}.` : "No defaultInputModes/defaultOutputModes.",
      fix: 'Add defaultInputModes (e.g. ["text"]) and defaultOutputModes.',
    });
    return { blocking };
  }

  // ---- MCP Catalog Checks --------------------------------------------------
  const mcpRoot = rawDoc?.result && typeof rawDoc.result === "object" ? rawDoc.result : rawDoc;
  const tools = Array.isArray(mcpRoot?.tools) ? mcpRoot.tools : [];
  const servers = mcpRoot?.mcpServers && typeof mcpRoot.mcpServers === "object" ? Object.entries(mcpRoot.mcpServers) : [];
  const packages = Array.isArray(mcpRoot?.packages) ? mcpRoot.packages : [];
  const remotes = Array.isArray(mcpRoot?.remotes) ? mcpRoot.remotes : [];
  const serverCount = servers.length + packages.length + remotes.length;
  const hasItems = tools.length > 0 || serverCount > 0 || (Array.isArray(mcpRoot?.prompts) && mcpRoot.prompts.length > 0);
  addCheck({
    id: "P-MCP-SCHEMA",
    section: "MCP Spec",
    title: "Publishes valid MCP tools or server entries",
    status: hasItems ? "pass" : "fail",
    detail: hasItems ? `${tools.length} tool(s), ${serverCount} server/package ${serverCount === 1 ? "entry" : "entries"}.` : "No tools[], mcpServers, or packages[] found.",
    fix: "Publish valid tools[], packages[], or mcpServers config entries.",
  });
  if (!hasItems) blocking.push("the MCP manifest lists no tools or servers");

  const objectTools = tools.filter((t) => t && typeof t === "object");
  const missingDesc = objectTools.filter((t) => !t.description).map((t) => t.name || "unnamed");
  const missingSchema = objectTools.filter((t) => t.inputSchema?.type !== "object").map((t) => t.name || "unnamed");
  const stringOnlyTools = tools.length > 0 && objectTools.length === 0;
  addCheck({
    id: "P-MCP-TOOLS",
    section: "MCP Tools",
    title: "Every MCP tool has a description and object inputSchema",
    status: !tools.length ? (serverCount ? "pass" : "warn") : (stringOnlyTools || missingDesc.length || missingSchema.length) ? "warn" : "pass",
    detail: !tools.length
      ? (packages.length ? `MCP registry manifest declaring ${packages.length} package(s).` : "No direct tools[] array (config manifest only).")
      : stringOnlyTools
        ? `Lists ${tools.length} tool name(s) without inline JSON schemas.`
        : (missingDesc.length || missingSchema.length)
          ? `Incomplete tool specs: ${[...new Set([...missingDesc, ...missingSchema])].slice(0, 5).join(", ")}.`
          : `${tools.length} tool(s) expose structured JSON schemas.`,
    fix: "Add clear description and type:\"object\" inputSchema for every MCP tool.",
  });

  const destructive = [];
  const undocumentedPower = [];
  for (const t of objectTools) {
    const ann = t.annotations || {};
    if (ann.destructiveHint === true) destructive.push(t.name);
    else if (DESTRUCTIVE_NAME.test(String(t.name || "")) && ann.readOnlyHint !== true && ann.destructiveHint === undefined) {
      undocumentedPower.push(t.name);
    }
  }
  addCheck({
    id: "P-MCP-ANNOTATIONS",
    section: "MCP 2025-03-26",
    title: "Destructive or external tools declare behavior hints",
    status: destructive.length ? "warn" : undocumentedPower.length ? "warn" : "pass",
    detail: destructive.length
      ? `Destructive tool(s): ${destructive.join(", ")}.`
      : undocumentedPower.length
        ? `State-changing names lack readOnlyHint/destructiveHint: ${undocumentedPower.join(", ")}.`
        : "Safety annotations look consistent.",
    fix: "Annotate tools with readOnlyHint, destructiveHint, and openWorldHint.",
  });
  if (destructive.length) {
    addFinding({
      rule: "M-DESTRUCTIVE",
      category: "budget",
      severity: "medium",
      title: "Declares destructive MCP tool(s)",
      detail: `Tool(s) marked destructiveHint: true — ${destructive.join(", ")}.`,
      where: { agent: destructive[0], field: "annotations.destructiveHint" },
      why: "Destructive tools can irreversibly modify or delete visitor or account state if invoked by a misled model.",
      fix: "Require explicit user confirmation before invoking destructive tools.",
    });
  }

  const shellServers = [];
  const plainHttpServers = [];
  for (const [name, spec] of servers) {
    if (!spec || typeof spec !== "object") continue;
    const cmdLine = [spec.command, ...(Array.isArray(spec.args) ? spec.args : [])].filter(Boolean).map(String).join(" ");
    if (SHELL_RUNNER.test(cmdLine)) shellServers.push({ name, cmdLine });
    if (typeof spec.url === "string" && /^http:\/\//i.test(spec.url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(spec.url)) {
      plainHttpServers.push({ name, url: spec.url });
    }
  }
  if (shellServers.length) {
    addFinding({
      rule: "M-SHELL",
      category: "itinerary",
      severity: "high",
      title: "MCP server config spawns an arbitrary shell command",
      detail: `${shellServers.map((s) => `${s.name}: "${s.cmdLine.slice(0, 90)}"`).join("; ")}.`,
      where: { agent: shellServers[0].name, field: "mcpServers.command" },
      why: "Manifests running sh/bash/powershell or piping remote downloads run arbitrary OS commands on the host.",
      fix: "Pin a specific non-shell binary/package and inspect arguments carefully.",
    });
  }
  if (plainHttpServers.length) {
    addCheck({
      id: "P-MCP-TRANSPORT",
      section: "MCP Auth",
      title: "Remote MCP server endpoints use HTTPS",
      status: "fail",
      detail: `Plain HTTP endpoints: ${plainHttpServers.map((s) => s.url).join(", ")}.`,
      fix: "Use HTTPS for remote MCP endpoints.",
    });
  }

  return { blocking };
}

function safeSlug(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 48);
}

function originOf(url) {
  try {
    const u = new URL(String(url ?? ""));
    return /^https?:$/.test(u.protocol) ? u.origin : "";
  } catch {
    return "";
  }
}
