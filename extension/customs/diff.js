// diff.js: what changed in a network since it was approved.
//
// A visitor's approval is given to what a network says at that moment. If the
// publisher later changes its instructions (a "rug pull"), the old approval should
// not carry over silently. A snapshot keeps what matters for that decision; diff()
// lists the changes in plain terms and line by line.

import { canonicalJson } from "./canonical.js";

/**
 * The text the runtime sends as an agent's system prompt: its instructions, then its
 * "command" (runner.js and langchain-runner.mjs). Every check that reads an agent's words
 * reads both, so nothing the model reads goes unchecked.
 *
 * :param agent: An agent from the network file, or one from a snapshot.
 * :return: The two texts, trimmed and joined the way the runtime joins them.
 */
export function promptOf(agent) {
  return [agent?.instructions, agent?.command]
    .filter((text) => typeof text === "string" && text.trim())
    .map((text) => text.trim())
    .join("\n\n");
}

/**
 * The peer policy mode the runtime applies: peer_policy, or web_policy when there is no
 * peer_policy (engine.js manifestAllowsPeer).
 *
 * :param manifest: A site's agent-manifest.json.
 * :return: "open", "closed", "allowlist" or "".
 */
export function peerPolicyOf(manifest) {
  return (manifest?.peer_policy || manifest?.web_policy)?.mode || "";
}

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
    const record = {
      description: String(agent.function?.description || ""),
      instructions: String(agent.instructions || ""),
      // The runtime adds "command" to the system prompt after the instructions.
      command: String(agent.command || ""),
      tools: (agent.tools || []).map((t) => (typeof t === "string" ? t : JSON.stringify(t))).sort(),
      parameters: JSON.stringify(agent.function?.parameters || null),
      allow: JSON.stringify(agent.allow || null),
      limits: JSON.stringify({ max_steps: agent.max_steps, max_execution_seconds: agent.max_execution_seconds }),
    };
    if (agent.annotations) record.annotations = JSON.stringify(agent.annotations);
    agents[agent.name] = record;
  }
  return {
    hash: fingerprint?.hash || "",
    linksHash: fingerprint?.linksHash || "",
    description: String(config?.metadata?.description || ""),
    linkLabels: config?.link_labels || {},
    links: config?.links || {},
    manifest: {
      brand: manifest?.brand || "",
      allowedPeers: (manifest?.allowed_peers || []).toSorted(),
      peerPolicy: peerPolicyOf(manifest),
      codedTools: manifest?.coded_tools ? JSON.stringify(manifest.coded_tools) : "",
    },
    agents,
  };
}

/**
 * Whether two snapshots describe the same version: the same network fingerprint, the
 * same partner links, and the same manifest fields that matter for trust (brand,
 * allowed peers, peer policy and code bundle). The fingerprint covers only the network
 * file, so a publisher could otherwise change its manifest without anyone noticing.
 *
 * :param before: A snapshot, such as the one stored with an approval.
 * :param after: A snapshot of what is published now.
 * :return: True when nothing the snapshots cover has changed.
 */
export function sameSnapshot(before, after) {
  if (!before || !after) return false;
  // The whole recorded manifest block, so a field added to snapshotOf counts here too.
  return before.hash === after.hash && before.linksHash === after.linksHash
    && canonicalJson(before.manifest || {}) === canonicalJson(after.manifest || {});
}

/**
 * Whether an approval covers exactly the version in a snapshot.
 *
 * :param pin: A stored approval (pins.js).
 * :param snapshot: The snapshot of what is published now.
 * :return: True when the approval still applies.
 */
export function matchesPin(pin, snapshot) {
  if (!pin?.hash || !snapshot) return false;
  // An approval without a snapshot holds only the fingerprint.
  return pin.hash === snapshot.hash && (!pin.snapshot || sameSnapshot(pin.snapshot, snapshot));
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
  if (sameSnapshot(before, after)) return changes;
  const add = (change) => changes.push(change);
  // Text the model reads, compared line by line.
  const textChanged = (kind, name, label, old, now) => {
    if ((old || "") === (now || "")) return;
    const d = lineDiff(lines(old), lines(now));
    add({ kind, severity: "high", agent: name, title: `${label} changed (${d.added.length} line(s) added, ${d.removed.length} removed)`,
      added: d.added, removed: d.removed });
  };

  const beforeAgents = before.agents || {};
  const afterAgents = after.agents || {};
  for (const name of Object.keys(afterAgents)) {
    if (!(name in beforeAgents)) {
      add({ kind: "agent_added", severity: "high", agent: name, title: `New agent "${name}"`,
        added: lines(promptOf(afterAgents[name])) });
    }
  }
  for (const name of Object.keys(beforeAgents)) {
    if (!(name in afterAgents)) add({ kind: "agent_removed", severity: "low", agent: name, title: `Agent "${name}" removed` });
  }
  for (const name of Object.keys(afterAgents)) {
    const a = beforeAgents[name];
    const b = afterAgents[name];
    if (!a) continue;
    textChanged("instructions_changed", name, `Instructions of "${name}"`, a.instructions, b.instructions);
    // Approvals saved before "command" was recorded have none; they match an agent without one.
    textChanged("command_changed", name, `The "command" text of "${name}", which the model reads after its instructions,`, a.command, b.command);
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
    // A calling model reads the whole input schema, so its text is shown like the rest.
    if (a.parameters !== b.parameters) {
      add({ kind: "schema_changed", severity: "medium", agent: name, title: `Input schema of "${name}" changed`,
        added: [b.parameters], removed: [a.parameters] });
    }
    if (a.limits !== b.limits) {
      add({ kind: "limits_changed", severity: "medium", agent: name, title: `Execution limits of "${name}" changed`,
        added: [b.limits], removed: [a.limits] });
    }
    if ((a.annotations || "") !== (b.annotations || "")) {
      add({ kind: "annotations_changed", severity: "medium", agent: name, title: `Safety annotations of "${name}" changed`,
        added: [b.annotations || ""], removed: [a.annotations || ""] });
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
  // The fingerprint ignores formatting, so a change here is real content this list does
  // not cover. Say so, rather than suggest that nothing important changed.
  if (!changes.length) add({ kind: "other", severity: "medium", title: "Other parts of the network file changed. This list does not show them, so read the file before approving." });
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
