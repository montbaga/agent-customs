// stamp-renewal.mjs: whether a network's last stamp still describes it, so the sign run after
// every publish re-signs only the networks that changed.

const DAY = 24 * 60 * 60 * 1000;

/**
 * True when the last stamp for a network still applies: the same fingerprint and the same
 * verdict as today's inspection, with more than `minDays` left before it expires.
 *
 * :param previous: The network's entry in site/receipts/index.json, or undefined.
 * :param report: Today's inspection report.
 * :param options.now: The time now.
 * :param options.minDays: Days a kept stamp must still be valid for.
 * :return: true to keep the stamp, false to sign a new one.
 */
export function stampStillApplies(previous, report, { now = new Date(), minDays = 10 } = {}) {
  if (!previous || !report?.identity?.hash) return false;
  if (previous.fingerprint !== report.identity.hash) return false;
  if (previous.verdict !== report.verdict?.code) return false;
  const expires = Date.parse(previous.expiresAt);
  return Number.isFinite(expires) && expires - now.getTime() > minDays * DAY;
}
