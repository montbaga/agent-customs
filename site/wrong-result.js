// wrong-result.js: the "Wrong result? Tell us" link under a report.
//
// It opens a new GitHub issue with the address, the verdict and what was found already filled
// in, so a person only has to say why the result looks wrong. Only what the report shows goes
// in: the public address and the matched text from the inspected file, never the chat or a key.

export const ISSUES_NEW = "https://github.com/montbaga/agent-customs/issues/new";

const AI_CHECK_WORDS = {
  clear: "on, found nothing",
  flagged: "on, raised it",
  skipped: "on, not asked (the rules had already stopped it)",
  failed: "on, gave no usable answer",
  "needs-key": "on, waiting for a key",
  locked: "on, key locked",
};

const clipText = (text, max) => {
  const flat = String(text || "").replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
};

/**
 * The address of a new GitHub issue about one report.
 *
 * :param report: A report from analyzeNetwork or inspectNetworkUrl.
 * :param options.maxFindings: How many findings to list (the most serious first).
 * :return: The issue address, or "" when there is no report to describe.
 */
export function wrongResultUrl(report, { maxFindings = 6 } = {}) {
  const address = report?.target?.url;
  if (!address) return "";
  const stamp = report.verdict?.stamp || report.verdict?.code || "unknown";
  let host = address;
  try { host = new URL(address).host || address; } catch { /* keep the address as it is */ }
  const findings = (report.findings || [])
    .filter((f) => ["critical", "high", "medium"].includes(f.severity))
    .slice(0, maxFindings)
    .map((f) => {
      const quote = f.evidence ? `: "${clipText(f.evidence, 140)}"` : "";
      return `- ${clipText(f.title || f.rule, 80)} (${f.rule}, ${f.severity})${quote}`;
    });
  const body = [
    "<!-- This issue is public. Check that it holds nothing private before you send it. -->",
    "",
    `**Address checked:** ${address}`,
    `**Result:** ${stamp}`,
    `**AI double-check:** ${AI_CHECK_WORDS[report.aiCheck?.status] || "off"}`,
    "",
    "**What it found:**",
    ...(findings.length ? findings : ["- nothing above a note"]),
    "",
    "**What did you expect, and why?**",
    "",
  ].join("\n");
  const params = new URLSearchParams({ title: `Wrong result: ${host} (${stamp})`, body });
  return `${ISSUES_NEW}?${params}`;
}
