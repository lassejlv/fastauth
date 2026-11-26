const layers = Array.from(document.querySelectorAll<HTMLElement>("[data-ambient]"));
const reduce = matchMedia("(prefers-reduced-motion: reduce)");

type State = { fx: number; fy: number; angle: number; x: number; y: number };

function restore(): State | null {
  try {
    return JSON.parse(sessionStorage.getItem("ambient") ?? "null");
  } catch {
    return null;
  }
}

let state: State = restore() ?? { fx: Math.random(), fy: Math.random(), angle: 28 + Math.random() * 14, x: 0, y: 0 };
let animations: Animation[] = [];
let period = { x: 0, y: 0 };
let bounds = { x0: 0, x1: 0, y0: 0, y1: 0 };
let geometry = "";

function phase(animation: Animation, length: number) {
  return (Number(animation.currentTime) % (2 * length)) / (2 * length);
}

function along(f: number, from: number, to: number) {
  return from + (to - from) * (f < 0.5 ? f * 2 : 2 - f * 2);
}

function capture() {
  if (!animations.length) return;
  const fx = phase(animations[0], period.x);
  const fy = phase(animations[1], period.y);
  state = { ...state, fx, fy, x: along(fx, bounds.x0, bounds.x1), y: along(fy, bounds.y0, bounds.y1) };
}

function save() {
  capture();
  sessionStorage.setItem("ambient", JSON.stringify(state));
}

function layout(force = false) {
  const stage = layers[0];
  const size = (stage.firstElementChild as HTMLElement).offsetWidth;
  const width = stage.clientWidth;
  const height = stage.clientHeight;
  const key = `${width}x${height}x${size}x${reduce.matches}`;
  if (key === geometry && !force) return;
  geometry = key;
  capture();
  for (const animation of animations) animation.cancel();
  animations = [];

  const pad = size * 0.16;
  bounds = { x0: -pad, x1: Math.max(1 - pad, width - size + pad), y0: -pad, y1: Math.max(1 - pad, height - size + pad) };

  for (const layer of layers.slice(1)) {
    layer.style.left = `${-(layer.parentElement as HTMLElement).getBoundingClientRect().left}px`;
  }

  if (reduce.matches) {
    state = { ...state, x: bounds.x1, y: bounds.y1 };
    document.documentElement.style.setProperty("--ambient-x", `${state.x}px`);
    document.documentElement.style.setProperty("--ambient-y", `${state.y}px`);
    save();
    return;
  }

  const speed = Math.min(96, Math.max(32, Math.hypot(width, height) / 20));
  const angle = ((height > width ? 90 - state.angle : state.angle) * Math.PI) / 180;
  period = {
    x: ((bounds.x1 - bounds.x0) / (speed * Math.cos(angle))) * 1000,
    y: ((bounds.y1 - bounds.y0) / (speed * Math.sin(angle))) * 1000,
  };
  const timing = { iterations: Infinity, direction: "alternate", easing: "linear" } as const;

  for (const layer of layers) {
    const x = layer.firstElementChild as HTMLElement;
    const y = x.firstElementChild as HTMLElement;
    const ax = x.animate(
      [{ transform: `translate3d(${bounds.x0}px, 0, 0)` }, { transform: `translate3d(${bounds.x1}px, 0, 0)` }],
      { ...timing, duration: period.x },
    );
    const ay = y.animate(
      [{ transform: `translate3d(0, ${bounds.y0}px, 0)` }, { transform: `translate3d(0, ${bounds.y1}px, 0)` }],
      { ...timing, duration: period.y },
    );
    ax.currentTime = state.fx * 2 * period.x;
    ay.currentTime = state.fy * 2 * period.y;
    if (document.hidden) {
      ax.pause();
      ay.pause();
    }
    animations.push(ax, ay);
  }
}

if (layers.length) {
  layout();

  let queued = false;
  addEventListener("resize", () => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      layout();
    });
  });

  reduce.addEventListener("change", () => layout(true));

  document.addEventListener("visibilitychange", () => {
    for (const animation of animations) {
      if (document.hidden) animation.pause();
      else animation.play();
    }
    if (document.hidden) save();
  });

  addEventListener("pagehide", save);
}
