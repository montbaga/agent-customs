// hero-demo.js: the inspection replay in the hero.
//
// It replays a real inspection (hero-data.js, checked against the engine by
// tests/hero-data.test.mjs): the five checks resolve one after another, the verdict
// stamp lands, and the reason appears. About 2.2 seconds, played once on load and again
// when the visitor picks a network. "Run it for real" runs the actual inspection.
//
// Order: the check rows go first, the stamp lands when the last row resolves, and the
// reason follows the stamp. Every run cancels the one
// before it, so rapid clicks never stack. Under reduced motion it shows the result.

import { EXAMPLES } from "./desk.js";
import { CHECK_NAMES, HERO_DEMO } from "./hero-data.js";

const EASE_OUT = "cubic-bezier(0.23, 1, 0.32, 1)";
const EASE_IN_OUT = "cubic-bezier(0.77, 0, 0.175, 1)";
// Non-uniform row starts: the first checks take a beat, the rest pick up pace.
const ROW_START = [120, 270, 400, 510, 610];
const ROW_RESOLVE = 150;
const STAMP_AT = 800;
const REASON_AT = 960;
const TONE_OF = { pass: "ok", low: "info", medium: "caution", high: "warn", critical: "bad" };
const ICON_OF = { pass: "#i-check", low: "#i-dot", medium: "#i-alert", high: "#i-alert", critical: "#i-x" };

const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

function valueText(check) {
  if (check.state === "pass") return "Clear";
  return `${check.count} finding${check.count === 1 ? "" : "s"}`;
}

/**
 * Wire the replay to its markup.
 *
 * :param root: The .hero-demo element.
 * :return: {play(id)}
 */
export function mountHeroDemo(root) {
  const $ = (sel) => root.querySelector(sel);
  const frame = $(".demo-frame");
  const url = $(".demo-url");
  const status = $(".demo-status");
  const bar = $(".demo-progress span");
  const rows = CHECK_NAMES.map((name) => root.querySelector(`[data-check="${name}"]`));
  const stamp = $(".demo-stamp");
  const stampText = $(".demo-stamp strong");
  const reason = $(".demo-reason");
  const line = $(".demo-line");
  const quote = $(".demo-quote");
  const picks = [...root.querySelectorAll("[data-demo]")];
  let timers = [];
  let animations = [];
  let current = HERO_DEMO[0];

  const later = (ms, fn) => timers.push(setTimeout(fn, ms));
  const run = (el, keyframes, options) => {
    const a = el.animate(keyframes, { fill: "both", ...options });
    animations.push(a);
    return a;
  };
  const cancel = () => {
    timers.forEach(clearTimeout);
    timers = [];
    animations.forEach((a) => a.cancel());
    animations = [];
  };

  const setRow = (row, state, check) => {
    row.dataset.state = state;
    const icon = row.querySelector(".row-icon use");
    const value = row.querySelector(".row-value");
    if (state === "pending") { icon.setAttribute("href", "#i-ring"); value.textContent = ""; row.style.removeProperty("--tone"); }
    if (state === "checking") { icon.setAttribute("href", "#i-spin"); value.textContent = "Checking"; }
    if (state === "done") {
      icon.setAttribute("href", ICON_OF[check.state]);
      value.textContent = valueText(check);
      row.style.setProperty("--tone", `var(--${TONE_OF[check.state]})`);
    }
  };

  const showResult = (demo) => {
    stamp.dataset.tone = demo.tone;
    stampText.textContent = demo.stamp;
    line.textContent = demo.line;
    if (demo.quote) { quote.textContent = `“${demo.quote}”`; quote.dataset.kind = "quote"; }
    else { quote.textContent = demo.note || ""; quote.dataset.kind = "note"; }
    quote.dataset.tone = demo.tone;
  };

  const settle = (demo) => {
    CHECK_NAMES.forEach((name, i) => setRow(rows[i], "done", demo.checks[name]));
    showResult(demo);
    status.textContent = "Inspected in your browser";
    frame.dataset.state = "done";
  };

  const play = (id) => {
    const demo = HERO_DEMO.find((d) => d.id === id) || HERO_DEMO[0];
    current = demo;
    cancel();
    for (const p of picks) p.setAttribute("aria-pressed", String(p.dataset.demo === demo.id));
    const runLabel = root.querySelector(".demo-run");
    if (runLabel?.firstChild) runLabel.firstChild.textContent = `Inspect ${demo.id === "rug" ? "the updated bakery" : demo.label} `;
    const example = EXAMPLES.find((e) => e.id === demo.id);
    url.textContent = example ? example.url.replace(/^https?:\/\//, "") : demo.label;

    if (reduced()) {
      settle(demo);
      run(frame.querySelector(".demo-body"), [{ opacity: .4 }, { opacity: 1 }], { duration: 200, easing: "ease" });
      return;
    }

    frame.dataset.state = "running";
    status.textContent = "Inspecting";
    rows.forEach((row) => setRow(row, "pending"));
    run(stamp, [{ opacity: 0 }, { opacity: 0 }], { duration: 1 });
    run(reason, [{ opacity: 0 }, { opacity: 0 }], { duration: 1 });
    // Constant progress reads as work being done: linear.
    run(bar, [{ transform: "scaleX(0)" }, { transform: "scaleX(1)" }], { duration: STAMP_AT, easing: "linear" });

    CHECK_NAMES.forEach((name, i) => {
      later(ROW_START[i], () => setRow(rows[i], "checking"));
      later(ROW_START[i] + ROW_RESOLVE, () => {
        setRow(rows[i], "done", demo.checks[name]);
        run(rows[i].querySelector(".row-icon"), [{ transform: "scale(.82)", opacity: .4 }, { transform: "scale(1)", opacity: 1 }], { duration: 180, easing: EASE_OUT });
      });
    });

    later(STAMP_AT, () => {
      showResult(demo);
      status.textContent = "Inspected in your browser";
      frame.dataset.state = "done";
      // The stamp lands: a short, decisive press with the ink settling (blur to sharp).
      run(stamp, [
        { opacity: 0, transform: "scale(1.28) rotate(-12deg)", filter: "blur(3px)" },
        { opacity: 1, transform: "scale(1) rotate(-6deg)", filter: "blur(0)" },
      ], { duration: 300, easing: EASE_OUT });
      run(frame.querySelector(".demo-body"), [{ transform: "translateY(0)" }, { transform: "translateY(1.5px)" }, { transform: "translateY(0)" }],
        { duration: 160, delay: 90, easing: "ease-out", fill: "none" });
    });

    later(REASON_AT, () => {
      run(reason, [{ opacity: 0, transform: "translateY(4px)" }, { opacity: 1, transform: "translateY(0)" }], { duration: 220, easing: EASE_OUT });
      // The reason is revealed left to right, like text being decoded.
      run(quote, [{ clipPath: "inset(0 100% 0 0)" }, { clipPath: "inset(0 0 0 0)" }], { duration: 480, delay: 60, easing: EASE_IN_OUT });
    });
  };

  for (const p of picks) p.addEventListener("click", () => play(p.dataset.demo));
  root.querySelector(".demo-run")?.addEventListener("click", () => {
    const example = EXAMPLES.find((e) => e.id === current.id);
    if (example) document.dispatchEvent(new CustomEvent("customs:inspect", { detail: { url: example.url } }));
  });

  // Draw the first network's result at once (so the hero is never empty), then replay it.
  settle(HERO_DEMO[0]);
  return { play };
}
