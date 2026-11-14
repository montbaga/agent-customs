// diff.js: what changed in a network since it was approved.
//
// A visitor's approval is given to what a network says at that moment. If the
// publisher later changes its instructions (a "rug pull"), the old approval should
// not carry over silently. A snapshot keeps what matters for that decision; diff()
// lists the changes in plain terms and line by line.

/**
 * Take a snapshot of a compiled network and its manifest.
 *
 * :param config: AgentNetwork.config.
 * :param manifest: The site's agent-manifest.json.
 * :param fingerprint: {hash, linksHash} from canonical.js.
 * :return: A small JSON object that diff() can compare.
 */
export function snapshotOf(config, manifest, fingerprint) {
  const agents = {};
  for (const agent of config?.tools || []) {
    if (!agent || typeof agent.name !== "string") continue;
    agents[agent.name] = {
      description: String(agent.function?.description || ""),
      instructions: String(agent.instructions || ""),
      tools: (agent.tools || []).map((t) => (typeof t === "string" ? t : JSON.stringify(t))).sort(),
      parameters: JSON.stringify(agent.function?.parameters || null),
      allow: JSON.stringify(agent.allow || null),
      limits: JSON.stringify({ max_steps: agent.max_steps, max_execution_seconds: agent.max_execution_seconds }),
    };
  }
  return {
    hash: fingerprint?.hash || "",
    linksHash: fingerprint?.linksHash || "",
    description: String(config?.metadata?.description || ""),
    linkLabels: config?.link_labels || {},
    links: config?.links || {},
    manifest: {
      brand: manifest?.brand || "",
      allowedPeers: [...(manifest?.allowed_peers || [])].sort(),
      peerPolicy: manifest?.peer_policy?.mode || "",
      codedTools: manifest?.coded_tools ? JSON.stringify(manifest.coded_tools) : "",
    },
    agents,
  };
}

/**
 * Compare two snapshots.
 *
 * :param before: The approved snapshot.
 * :param after: The snapshot of what is published now.
 * :return: [{kind, severity, agent?, title, added?, removed?}], empty when nothing changed.
 */
export function diffSnapshots(before, after) {
  const changes = [];
  if (!before || !after) return changes;
  if (before.hash === after.hash && before.linksHash === after.linksHash) return changes;
  const add = (change) => changes.push(change);

  const beforeAgents = before.agents || {};
  const afterAgents = after.agents || {};
  for (const name of Object.keys(afterAgents)) {
    if (!(name in beforeAgents)) {
      add({ kind: "agent_added", severity: "high", agent: name, title: `New agent "${name}"`,
        added: lines(afterAgents[name].instructions) });
    }
  }
  for (const name of Object.keys(beforeAgents)) {
    if (!(name in afterAgents)) add({ kind: "agent_removed", severity: "low", agent: name, title: `Agent "${name}" removed` });
  }
  for (const name of Object.keys(afterAgents)) {
    const a = beforeAgents[name];
    const b = afterAgents[name];
    if (!a) continue;
    if (a.instructions !== b.instructions) {
      const d = lineDiff(lines(a.instructions), lines(b.instructions));
      add({ kind: "instructions_changed", severity: "high", agent: name,
        title: `Instructions of "${name}" changed (${d.added.length} line(s) added, ${d.removed.length} removed)`,
        added: d.added, removed: d.removed });
    }
    if (a.description !== b.description) {
      add({ kind: "description_changed", severity: "medium", agent: name, title: `Description of "${name}" changed`,
        added: [b.description], removed: [a.description] });
    }
    const toolsAdded = b.tools.filter((t) => !a.tools.includes(t));
    const toolsRemoved = a.tools.filter((t) => !b.tools.includes(t));
    if (toolsAdded.length) {
      const external = toolsAdded.some((t) => /^https?:|^\{/.test(t));
      add({ kind: "tools_added", severity: external ? "high" : "medium", agent: name,
        title: external ? `"${name}" can now reach other sites or services` : `"${name}" can now call more agents`,
        added: toolsAdded });
    }
    if (toolsRemoved.length) add({ kind: "tools_removed", severity: "low", agent: name, title: `"${name}" calls fewer tools`, removed: toolsRemoved });
    if (a.allow !== b.allow) {
      add({ kind: "privacy_changed", severity: "high", agent: name, title: `Private-context rules of "${name}" changed`,
        added: [b.allow], removed: [a.allow] });
    }
    if (a.parameters !== b.parameters) add({ kind: "schema_changed", severity: "low", agent: name, title: `Input schema of "${name}" changed` });
    if (a.limits !== b.limits) {
      add({ kind: "limits_changed", severity: "medium", agent: name, title: `Execution limits of "${name}" changed`,
        added: [b.limits], removed: [a.limits] });
    }
  }
  if (before.description !== after.description) {
    add({ kind: "metadata_changed", severity: "low", title: "Network description changed", added: [after.description], removed: [before.description] });
  }
  const m0 = before.manifest || {};
  const m1 = after.manifest || {};
  if (m0.brand !== m1.brand) add({ kind: "brand_changed", severity: "medium", title: `Brand changed from "${m0.brand}" to "${m1.brand}"` });
  const peersAdded = (m1.allowedPeers || []).filter((p) => !(m0.allowedPeers || []).includes(p));
  if (peersAdded.length) add({ kind: "peers_added", severity: "high", title: "It may now contact more origins", added: peersAdded });
  if (m0.peerPolicy !== m1.peerPolicy) {
    add({ kind: "policy_changed", severity: m1.peerPolicy === "open" ? "high" : "low",
      title: `Peer policy changed from "${m0.peerPolicy || "none"}" to "${m1.peerPolicy || "none"}"` });
  }
  if (m0.codedTools !== m1.codedTools) add({ kind: "code_changed", severity: "high", title: "Its executable code bundle changed" });
  if (JSON.stringify(before.links) !== JSON.stringify(after.links) || JSON.stringify(before.linkLabels) !== JSON.stringify(after.linkLabels)) {
    add({ kind: "links_changed", severity: "medium", title: "Its partner links or their labels changed" });
  }
  if (!changes.length) add({ kind: "other", severity: "low", title: "Formatting or settings changed (no agent behavior changes found)" });
  return changes;
}

function lines(text) {
  return String(text || "").split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim());
}

/**
 * Line diff by longest common subsequence. Instructions are short (well under a
 * thousand lines), so the quadratic table is fine.
 *
 * :param a: Old lines.
 * :param b: New lines.
 * :return: {added, removed}
 */
export function lineDiff(a, b) {
  const n = a.length;
  const m = b.length;
  if (n * m > 2_000_000) {
    const setA = new Set(a);
    const setB = new Set(b);
    return { added: b.filter((l) => !setA.has(l)), removed: a.filter((l) => !setB.has(l)) };
  }
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const added = [];
  const removed = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { i += 1; j += 1; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { removed.push(a[i]); i += 1; }
    else { added.push(b[j]); j += 1; }
  }
  while (i < n) removed.push(a[i++]);
  while (j < m) added.push(b[j++]);
  return { added, removed };
}
