import { flagLabel, EMOJI_FLAGS } from '/flags.js';

/**
 * Animated arc layer.
 *
 * Each arc is a quadratic bezier with a travelling head and a fading tail.
 * Arcs whose endpoints are more than half a world apart are routed across the
 * antimeridian instead of the long way round, and drawn three times (shifted by
 * -W, 0, +W) so the segment that leaves one edge reappears on the other.
 */

const LIFE_MS = 2400;
const TAIL = 0.34;
const SAMPLES = 44;
const RIPPLE_MS = 1100;

export const LAYER_COLORS = {
  block_in: [255, 59, 48],
  block_out: [255, 138, 0],
  pass_in: [74, 222, 128],
  pass_out: [34, 211, 238],
  ids: [255, 43, 209],
  internal: [143, 166, 196],
};

// IDS severity comes from the ET signature class (see server/normalize.js).
const IDS_BY_SEVERITY = {
  1: [255, 209, 102],
  2: [255, 178, 70],
  3: [255, 138, 0],
  4: [255, 43, 209],
};

export function colorFor(arc) {
  if (arc.layer === 'ids') return IDS_BY_SEVERITY[arc.severity] ?? LAYER_COLORS.ids;
  return LAYER_COLORS[arc.layer] ?? [140, 170, 210];
}

const rgba = ([r, g, b], a) => `rgba(${r},${g},${b},${a})`;

class Arc {
  constructor(data, from, to) {
    this.data = data;
    this.color = colorFor(data);
    this.born = performance.now();
    this.count = data.count ?? 1;

    // The end that is not home - where an inbound attack came from, or where
    // outbound traffic is going. That is the end worth labelling.
    const far = data.dir === 'in' ? data.src : data.dst;
    this.farCC = far?.geo?.cc ?? null;
    this.farAtSource = data.dir === 'in';

    // This is a flat map, not a globe: draw the direct chord between the two
    // points. Routing "the short way" around the antimeridian instead sends the
    // arc off one edge to reappear on the other, which just reads as an attack
    // travelling in the wrong direction. The projection is centred on home so
    // the direct path is also the geographically sensible one.
    const [x1, y1] = from;
    const [x2, y2] = to;

    this.x1 = x1; this.y1 = y1; this.x2 = x2; this.y2 = y2;

    // Lift the control point perpendicular to the chord; longer hops bow more.
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const len = Math.hypot(x2 - x1, y2 - y1);
    const lift = 0.28 * len;
    const nx = -(y2 - y1) / (len || 1);
    const ny = (x2 - x1) / (len || 1);
    // Always bow "upward" on screen so arcs do not dive through the map edge.
    const sign = ny > 0 ? -1 : 1;
    this.cx = mx + nx * lift * sign;
    this.cy = my + ny * lift * sign;

    this.pts = [];
    for (let i = 0; i <= SAMPLES; i++) {
      const t = i / SAMPLES;
      const u = 1 - t;
      this.pts.push([
        u * u * x1 + 2 * u * t * this.cx + t * t * x2,
        u * u * y1 + 2 * u * t * this.cy + t * t * y2,
      ]);
    }
  }

  get age() { return (performance.now() - this.born) / LIFE_MS; }
  get dead() { return this.age > 1 + RIPPLE_MS / LIFE_MS; }
}

export class ArcLayer {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.arcs = [];
    this.byId = new Map();
    this.ripples = [];
    this.maxArcs = 300;
    this.home = null;
    this.dpr = 1;
    this.proj = null;
  }

  configure({ proj, dpr, maxArcs, home }) {
    this.proj = proj;
    this.dpr = dpr;
    if (maxArcs) this.maxArcs = maxArcs;
    if (home) this.home = home;
    this.canvas.width = Math.round(proj.w * dpr);
    this.canvas.height = Math.round(proj.h * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  add(data) {
    const s = data.src?.geo;
    const d = data.dst?.geo;
    if (!s || !d || !this.proj) return;

    const from = this.proj.project(s.lon, s.lat);
    const to = this.proj.project(d.lon, d.lat);
    const arc = new Arc(data, from, to);

    this.arcs.push(arc);
    this.byId.set(data.id, arc);
    // Oldest-drop, so a scan burst cannot stall the renderer.
    if (this.arcs.length > this.maxArcs) {
      const gone = this.arcs.splice(0, this.arcs.length - this.maxArcs);
      for (const a of gone) this.byId.delete(a.data.id);
    }
  }

  bump(id, count) {
    const arc = this.byId.get(id);
    if (arc) arc.count = count;
  }

  clear() {
    this.arcs.length = 0;
    this.ripples.length = 0;
    this.byId.clear();
  }

  render() {
    const { ctx, proj } = this;
    if (!proj) return;
    ctx.clearRect(0, 0, proj.w, proj.h);
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';


    for (let i = this.arcs.length - 1; i >= 0; i--) {
      const arc = this.arcs[i];
      if (arc.dead) {
        this.arcs.splice(i, 1);
        this.byId.delete(arc.data.id);
        continue;
      }
      const t = Math.min(arc.age, 1);
      this.#drawArc(arc, t);
      if (arc.age >= 1 && !arc.impacted) {
        arc.impacted = true;
        this.ripples.push({ x: arc.x2, y: arc.y2, color: arc.color, born: performance.now() });
      }
    }

    this.#drawRipples();
    this.#drawCountryLabels();
    this.#drawHome();
  }

  /**
   * The country label rides the arc's head, so you watch the origin fly across
   * the map and land on the target. Reading the map is then optional - the flag
   * arrives with the attack.
   *
   * Labels are clustered by screen position: a scan from one network produces
   * many arcs converging on the same pixel, and stacking a pill per arc would
   * be a solid block. One label per country per cell, at the brightest alpha of
   * the arcs in it, capped so a burst cannot fill the map with pills.
   */
  #drawCountryLabels() {
    const { ctx, proj } = this;
    const cells = new Map();

    // A phone-sized map needs coarser clustering and fewer labels, or the same
    // traffic that reads fine on a desktop turns into a wall of pills.
    const small = proj.mapW < 700;
    const cellW = small ? 66 : 46;
    const cellH = small ? 32 : 24;
    const maxLabels = small ? 10 : 26;

    for (const arc of this.arcs) {
      if (!arc.farCC) continue;
      const t = Math.min(arc.age, 1);
      if (t < 0.06) continue; // let the arc establish itself first
      const fade = t > 0.72 ? 1 - (t - 0.72) / 0.28 : 1;
      if (fade <= 0.05) continue;

      // Travel with the head rather than sitting at the endpoint.
      const head = Math.min(Math.floor(t * SAMPLES), SAMPLES);
      const [x, y] = arc.pts[head];

      const key = `${arc.farCC}|${Math.round(x / cellW)}|${Math.round(y / cellH)}`;
      const prev = cells.get(key);
      if (!prev || fade > prev.alpha) {
        cells.set(key, { x, y, cc: arc.farCC, alpha: fade, color: arc.color });
      }
    }

    if (!cells.size) return;

    const labels = [...cells.values()].sort((a, b) => b.alpha - a.alpha).slice(0, maxLabels);

    // Emoji flags need a font that actually has them and sit larger than text.
    ctx.font = EMOJI_FLAGS ? '15px sans-serif' : '600 11px ui-monospace, monospace';
    ctx.textBaseline = 'middle';

    for (const l of labels) {
      const text = flagLabel(l.cc);
      if (!text) continue;

      const w = ctx.measureText(text).width;
      const padX = EMOJI_FLAGS ? 4 : 5;
      const h = EMOJI_FLAGS ? 20 : 16;
      const bx = l.x - w / 2 - padX;
      const by = l.y - h - 10; // ride just above the head, not on top of it

      ctx.beginPath();
      // roundRect is recent enough that a plain rect fallback is worth keeping.
      if (ctx.roundRect) ctx.roundRect(bx, by, w + padX * 2, h, 4);
      else ctx.rect(bx, by, w + padX * 2, h);
      ctx.fillStyle = `rgba(4, 8, 18, ${0.82 * l.alpha})`;
      ctx.fill();
      ctx.strokeStyle = rgba(l.color, 0.55 * l.alpha);
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.fillStyle = `rgba(233, 243, 255, ${l.alpha})`;
      ctx.fillText(text, l.x - w / 2, by + h / 2 + 0.5);
    }
    ctx.textBaseline = 'alphabetic';
  }

  #drawArc(arc, t, shift = 0) {
    const { ctx } = this;
    const head = Math.min(Math.floor(t * SAMPLES), SAMPLES);
    const tail = Math.max(0, Math.floor(Math.max(0, t - TAIL) * SAMPLES));
    if (head <= 0) return;

    // Fade the whole arc out over its final third.
    const fade = t > 0.72 ? 1 - (t - 0.72) / 0.28 : 1;
    const weight = Math.min(1.9 + Math.log2(arc.count || 1) * 0.9, 6);

    const path = (from, to) => {
      ctx.beginPath();
      ctx.moveTo(arc.pts[from][0] + shift, arc.pts[from][1]);
      for (let i = from + 1; i <= to; i++) ctx.lineTo(arc.pts[i][0] + shift, arc.pts[i][1]);
    };

    // Ghost of the full route, so the trajectory reads even before the head
    // gets there. Without it a single thin comet is almost invisible against
    // the map at full-screen widths.
    path(0, SAMPLES);
    ctx.strokeStyle = rgba(arc.color, 0.14 * fade);
    ctx.lineWidth = 1;
    ctx.stroke();

    // Trail.
    path(tail, head);
    ctx.strokeStyle = rgba(arc.color, 0.5 * fade);
    ctx.lineWidth = weight;
    ctx.stroke();

    // Bright leading section with a glow - this is what actually catches the eye.
    const glowFrom = Math.max(tail, head - 8);
    path(glowFrom, head);
    ctx.strokeStyle = rgba(arc.color, 0.95 * fade);
    ctx.lineWidth = weight * 1.15;
    ctx.shadowBlur = 14;
    ctx.shadowColor = rgba(arc.color, 0.9 * fade);
    ctx.stroke();
    ctx.shadowBlur = 0;

    const hp = arc.pts[head];
    ctx.beginPath();
    ctx.arc(hp[0] + shift, hp[1], weight * 0.95, 0, Math.PI * 2);
    ctx.fillStyle = rgba(arc.color, fade);
    ctx.shadowBlur = 16;
    ctx.shadowColor = rgba(arc.color, 0.95 * fade);
    ctx.fill();
    ctx.shadowBlur = 0;

    // Origin pin, so you can see where a burst is coming from even mid-flight.
    ctx.beginPath();
    ctx.arc(arc.x1 + shift, arc.y1, 2.6, 0, Math.PI * 2);
    ctx.fillStyle = rgba(arc.color, 0.75 * fade);
    ctx.fill();

    if (arc.count > 1 && t > 0.25) {
      ctx.font = '600 11px ui-monospace, monospace';
      ctx.fillStyle = rgba(arc.color, 0.9 * fade);
      ctx.fillText(`×${arc.count}`, arc.x1 + shift + 6, arc.y1 - 5);
    }
  }

  #drawRipples() {
    const { ctx } = this;
    const now = performance.now();
    for (let i = this.ripples.length - 1; i >= 0; i--) {
      const r = this.ripples[i];
      const t = (now - r.born) / RIPPLE_MS;
      if (t >= 1) { this.ripples.splice(i, 1); continue; }
      ctx.beginPath();
      ctx.arc(r.x, r.y, 4 + t * 28, 0, Math.PI * 2);
      ctx.strokeStyle = rgba(r.color, (1 - t) * 0.6);
      ctx.lineWidth = 1.6;
      ctx.stroke();
    }
  }

  #drawHome() {
    if (!this.home || !this.proj) return;
    const { ctx } = this;
    const [x, y] = this.proj.project(this.home.lon, this.home.lat);
    const pulse = 0.5 + 0.5 * Math.sin(performance.now() / 620);

    ctx.beginPath();
    ctx.arc(x, y, 5 + pulse * 5, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(120, 220, 255, ${0.16 + pulse * 0.28})`;
    ctx.lineWidth = 1.2;
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(x, y, 3.2, 0, Math.PI * 2);
    ctx.fillStyle = '#8fe9ff';
    ctx.shadowBlur = 16;
    ctx.shadowColor = 'rgba(120, 220, 255, 0.9)';
    ctx.fill();
    ctx.shadowBlur = 0;
  }
}
