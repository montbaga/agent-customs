// effects.js: the page's motion layers, no dependencies.
//  - Palette: three colours (60-30-10), forest by default; chosen in the footer or with ?palette=, remembered.
//  - Liquid glass: real refraction where SVG backdrop filters work (Chromium).
//  - The hero background (scene-gl.js), with its pause button.
//  - The replay (hero-demo.js): load once, and again on a click.
//  - The diagram: one pulse loop that runs on screen, restarts on hover, and pauses.
// The hidden sentence is plain CSS: scrolling through its section lights it up.

import { startHeroGround } from "./scene-gl.js";
import { mountHeroDemo } from "./hero-demo.js";

const root = document.documentElement;
const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const phone = () => matchMedia("(max-width: 640px)").matches;
if (navigator.userAgentData?.brands?.some((b) => /Chromium/i.test(b.brand))) root.classList.add("liquid-ok");

// ---- Palette -----------------------------------------------------------------------
const PALETTES = { forest: "#0c1d18", terracotta: "#0f1012", navy: "#0a1430", espresso: "#1b1310" };
function setPalette(name, remember) {
  if (!Object.hasOwn(PALETTES, name)) name = "forest";
  if (name === "forest") delete root.dataset.palette;
  else root.dataset.palette = name;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", PALETTES[name]);
  for (const b of document.querySelectorAll(".palette-picker button")) b.setAttribute("aria-pressed", String(b.dataset.palette === name));
  if (remember) { try { localStorage.setItem("agent-customs-palette", name); } catch { /* storage blocked */ } }
  document.dispatchEvent(new CustomEvent("palettechange", { detail: { name } }));
}
let initial = new URLSearchParams(location.search).get("palette");
if (!initial) { try { initial = localStorage.getItem("agent-customs-palette"); } catch { initial = null; } }
setPalette(initial || "forest", false);
document.querySelector(".palette-picker")?.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-palette]");
  if (button) setPalette(button.dataset.palette, true);
});

// ---- Hero background ------------------------------------------------------------------
const canvas = document.getElementById("hero-gl");
if (canvas) {
  try {
    startHeroGround(canvas, { toggle: document.getElementById("motion-toggle") });
  } catch (error) {
    console.warn("Hero ground skipped:", error.message);
  }
}

// ---- Replay: load once, while the hero enters ---------------------------------------------
const demoRoot = document.getElementById("hero-demo");
if (demoRoot) {
  const demo = mountHeroDemo(demoRoot);
  setTimeout(() => demo.play("shady"), reduced() ? 0 : 300);
}

// ---- Diagram loop ----------------------------------------------------------------------
const diagram = document.querySelector("[data-diagram]");
if (diagram) {
  const disc = diagram.querySelector(".dg-pause");
  let paused = false;
  const restart = () => {
    diagram.classList.remove("run");
    void diagram.offsetWidth;          // let the animations start again from their first beat
    diagram.classList.add("run");
  };
  const sync = () => {
    const live = !reduced() && !phone();
    diagram.classList.toggle("run", live);
    if (disc) {
      disc.hidden = !live;
      disc.setAttribute("aria-pressed", String(paused));
      disc.querySelector("use")?.setAttribute("href", paused ? "#i-play" : "#i-pause");
      const label = disc.querySelector(".visually-hidden");
      if (label) label.textContent = paused ? "Play the diagram" : "Pause the diagram";
    }
    diagram.classList.toggle("paused", paused);
  };
  sync();
  new IntersectionObserver(([entry]) => diagram.classList.toggle("offscreen", !entry.isIntersecting)).observe(diagram);
  diagram.addEventListener("pointerenter", (event) => { if (event.pointerType !== "touch" && !paused && diagram.classList.contains("run")) restart(); });
  diagram.addEventListener("focusin", () => { if (!paused && diagram.classList.contains("run")) restart(); });
  disc?.addEventListener("click", () => { paused = !paused; sync(); });
  matchMedia("(max-width: 640px)").addEventListener?.("change", sync);
  matchMedia("(prefers-reduced-motion: reduce)").addEventListener?.("change", sync);
}
