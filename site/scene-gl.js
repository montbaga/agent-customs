// scene-gl.js: the hero's moving ground. One small WebGL fragment shader, no library.
//
// Flowing ink in the page's three palette colors, a faint scan line that crosses the
// hero now and then, and a gentle pull toward the pointer (smoothed like a spring, so it
// follows rather than jumps). It is the page's one continuous effect, so:
//  - it renders at reduced resolution and stops when the hero is off screen or the tab
//    is hidden;
//  - the visitor can pause it (the button in the hero), and the choice is remembered;
//  - under prefers-reduced-motion it draws one still frame;
//  - without WebGL the hero keeps its CSS gradient.

const VERT = `attribute vec2 a;void main(){gl_Position=vec4(a,0.,1.);}`;

const FRAG = `
precision mediump float;
uniform vec2 u_res;
uniform float u_time;
uniform vec3 u_c1;
uniform vec3 u_c2;
uniform vec3 u_c3;
uniform vec2 u_pointer;

float hash(vec2 p){ p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }
float noise(vec2 p){
  vec2 i = floor(p); vec2 f = fract(p); vec2 u = f * f * (3. - 2. * f);
  return mix(mix(hash(i), hash(i + vec2(1., 0.)), u.x), mix(hash(i + vec2(0., 1.)), hash(i + vec2(1., 1.)), u.x), u.y);
}
float fbm(vec2 p){
  float v = 0.; float a = .5; mat2 m = mat2(1.6, 1.2, -1.2, 1.6);
  for (int i = 0; i < 5; i++) { v += a * noise(p); p = m * p; a *= .5; }
  return v;
}

void main(){
  vec2 uv = gl_FragCoord.xy / u_res;
  vec2 p = (gl_FragCoord.xy - .5 * u_res) / u_res.y;
  vec2 m = (u_pointer - .5) * vec2(u_res.x / u_res.y, 1.);
  // The field leans toward the pointer, strongest nearby.
  p += (m - p) * .10 * exp(-length(p - m) * 2.2);
  float t = u_time * .035;
  vec2 q = vec2(fbm(p * 1.5 + t), fbm(p * 1.5 - t + 4.2));
  vec2 r = vec2(fbm(p * 1.5 + 2.4 * q + vec2(1.7, 9.2) + t * 1.2), fbm(p * 1.5 + 2.4 * q + vec2(8.3, 2.8) - t));
  float f = fbm(p * 1.7 + 2.7 * r);

  vec3 col = u_c1;
  // Ink: broad, soft bodies of the accent, brighter where the flow folds over itself.
  float body = smoothstep(.30, .78, f);
  float vein = smoothstep(.55, .86, f);
  float side = smoothstep(-.55, 1.0, uv.x);
  col = mix(col, u_c3 * .5 + u_c1 * .5, body * .78 * side);
  col = mix(col, u_c3, vein * .95 * side);
  col = mix(col, u_c2, smoothstep(.72, 1.0, f + r.x * .22) * .30 * side);

  // A scan line crosses the hero from top to bottom every eleven seconds.
  float s = fract(u_time / 11.);
  float d = uv.y - (1. - s);
  col += u_c3 * exp(-d * d * 14000.) * .55 * smoothstep(0., .08, s) * smoothstep(1., .85, s);
  col += u_c3 * exp(-max(d, 0.) * 40.) * step(0., d) * .05 * smoothstep(1., .85, s);

  // Fade to the page color at the edges and the bottom.
  float vig = smoothstep(1.7, .25, length((p - vec2(.18, .02)) * vec2(.72, 1.05)));
  col = mix(u_c1, col, vig);
  col = mix(col, u_c1, smoothstep(.30, .0, uv.y) * .9);
  col += (hash(gl_FragCoord.xy + floor(u_time * 24.)) - .5) * .03;
  gl_FragColor = vec4(col, 1.);
}`;

const SCALE = 0.5;          // render at half the CSS size, then let the browser scale up
const MAX_DPR = 1.5;
const STORAGE_KEY = "agent-customs-motion";

function hexToRgb(value) {
  const hex = String(value || "").trim().replace("#", "");
  const full = hex.length === 3 ? hex.split("").map((c) => c + c).join("") : hex;
  const n = Number.parseInt(full.slice(0, 6), 16);
  if (!Number.isFinite(n)) return [0, 0, 0];
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

function compile(gl, type, source) {
  const shader = gl.createShader(type);
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader) || "shader failed");
  return shader;
}

/**
 * Start the hero ground.
 *
 * :param canvas: The canvas to draw on.
 * :param options.toggle: The pause button, or null.
 * :return: {pause, play, destroy}, or null when WebGL is unavailable.
 */
export function startHeroGround(canvas, { toggle = null } = {}) {
  const gl = canvas.getContext("webgl", { antialias: false, alpha: false, premultipliedAlpha: false, powerPreference: "low-power" });
  if (!gl) return null;
  let program;
  try {
    program = gl.createProgram();
    gl.attachShader(program, compile(gl, gl.VERTEX_SHADER, VERT));
    gl.attachShader(program, compile(gl, gl.FRAGMENT_SHADER, FRAG));
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program) || "link failed");
  } catch (error) {
    console.warn("Hero ground unavailable:", error.message);
    return null;
  }
  gl.useProgram(program);
  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(program, "a");
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  const u = Object.fromEntries(["u_res", "u_time", "u_c1", "u_c2", "u_c3", "u_pointer"].map((n) => [n, gl.getUniformLocation(program, n)]));

  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  let paused = false;
  try { paused = localStorage.getItem(STORAGE_KEY) === "paused"; } catch { /* storage blocked */ }
  let visible = true;
  let frame = 0;
  // A clock from load: off screen it skips drawing but keeps time, so returning never
  // shows a restart. Only the pause button stops the clock.
  const start = performance.now();
  let stopped = 0;
  let pausedAt = paused ? start : null;
  let time = 7.5;
  const pointer = { x: .62, y: .55, tx: .62, ty: .55 };

  const setColors = () => {
    const styles = getComputedStyle(document.documentElement);
    gl.uniform3fv(u.u_c1, hexToRgb(styles.getPropertyValue("--c1")));
    gl.uniform3fv(u.u_c2, hexToRgb(styles.getPropertyValue("--c2")));
    gl.uniform3fv(u.u_c3, hexToRgb(styles.getPropertyValue("--c3")));
  };
  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR) * SCALE;
    const w = Math.max(1, Math.round(canvas.clientWidth * dpr));
    const h = Math.max(1, Math.round(canvas.clientHeight * dpr));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
      gl.viewport(0, 0, w, h);
    }
    gl.uniform2f(u.u_res, w, h);
  };
  const draw = () => {
    // Spring-like follow: close a fraction of the gap each frame.
    pointer.x += (pointer.tx - pointer.x) * .06;
    pointer.y += (pointer.ty - pointer.y) * .06;
    gl.uniform2f(u.u_pointer, pointer.x, pointer.y);
    gl.uniform1f(u.u_time, time);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  };
  const running = () => visible && !paused && !reduced.matches && !document.hidden;
  const tick = (now) => {
    frame = 0;
    if (!running()) return;
    time = 7.5 + (now - start - stopped) / 1000;
    draw();
    frame = requestAnimationFrame(tick);
  };
  const schedule = () => {
    if (running() && !frame) frame = requestAnimationFrame(tick);
    if (!running()) draw();   // keep one honest still frame on screen
  };
  const syncToggle = () => {
    if (!toggle) return;
    toggle.setAttribute("aria-pressed", String(paused));
    toggle.querySelector("use")?.setAttribute("href", paused ? "#i-play" : "#i-pause");
    const label = toggle.querySelector(".visually-hidden");
    if (label) label.textContent = paused ? "Play background motion" : "Pause background motion";
    toggle.hidden = reduced.matches;
  };

  setColors();
  resize();
  draw();
  canvas.closest(".hero-ground")?.classList.add("ready");
  syncToggle();
  schedule();

  const observer = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; schedule(); }, { threshold: 0 });
  observer.observe(canvas);
  const onResize = () => { resize(); if (!running()) draw(); };
  const onPointer = (event) => {
    const rect = canvas.getBoundingClientRect();
    pointer.tx = (event.clientX - rect.left) / rect.width;
    pointer.ty = 1 - (event.clientY - rect.top) / rect.height;
  };
  const onVisibility = () => schedule();
  const onPalette = () => { setColors(); if (!running()) draw(); };
  window.addEventListener("resize", onResize, { passive: true });
  window.addEventListener("pointermove", onPointer, { passive: true });
  document.addEventListener("visibilitychange", onVisibility);
  document.addEventListener("palettechange", onPalette);
  reduced.addEventListener?.("change", () => { syncToggle(); schedule(); });
  toggle?.addEventListener("click", () => {
    paused = !paused;
    if (paused) pausedAt = performance.now();
    else if (pausedAt !== null) { stopped += performance.now() - pausedAt; pausedAt = null; }
    try { localStorage.setItem(STORAGE_KEY, paused ? "paused" : "playing"); } catch { /* storage blocked */ }
    syncToggle();
    schedule();
  });

  return {
    pause() { paused = true; syncToggle(); schedule(); },
    play() { paused = false; syncToggle(); schedule(); },
    destroy() {
      cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onPointer);
      document.removeEventListener("visibilitychange", onVisibility);
      document.removeEventListener("palettechange", onPalette);
    },
  };
}
