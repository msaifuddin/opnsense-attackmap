/**
 * Equirectangular projection + static world renderer.
 *
 * The world is drawn once onto its own canvas and only redrawn on resize; the
 * arc layer animates on a separate canvas above it. Redrawing 177 country
 * polygons every frame would dominate the frame budget for no visual gain.
 *
 * Latitude is cropped to [-58, 84] rather than the full [-90, 90]: it drops
 * Antarctica and the empty Arctic, so the inhabited world fills the viewport
 * instead of floating in a band of blank ocean.
 */

export const LAT_MAX = 84;
export const LAT_MIN = -58;

const SPAN_LON = 360;
const SPAN_LAT = LAT_MAX - LAT_MIN;

/** Shortest signed longitude difference, in (-180, 180]. */
export const wrapLon = (d) => ((((d + 180) % 360) + 360) % 360) - 180;

export class Projection {
  constructor(width, height, pad, centerLon = 0) {
    this.centerLon = centerLon;
    this.resize(width, height, pad);
  }

  /**
   * Re-centre the map on a longitude. Anchoring it on home means every source
   * is within 180 degrees of the destination, so no arc ever has to run off one
   * edge and reappear on the other - on a flat map that just reads as an arc
   * flying the wrong way.
   */
  setCenter(lon) {
    this.centerLon = Number.isFinite(lon) ? lon : 0;
  }

  /**
   * `pad` insets the drawable area by the space the UI chrome occupies, so the
   * map is laid out *between* the panels rather than underneath them - the home
   * marker sitting behind a sidebar is otherwise the one thing you can never
   * see. Aspect ratio is preserved and the result centred in what is left.
   */
  resize(width, height, pad = { l: 0, r: 0, t: 0, b: 0 }) {
    this.w = width;
    this.h = height;
    this.pad = pad;

    const innerW = Math.max(80, width - pad.l - pad.r);
    const innerH = Math.max(80, height - pad.t - pad.b);

    // One uniform scale: stretching the vertical axis to fill the box makes the
    // continents visibly wrong. The leftover space is not left blank - the ocean
    // and graticule are painted across the whole viewport and the land is drawn
    // with wrapped copies, so the map reads as full-bleed while the part you
    // actually read stays correctly proportioned and clear of the panels.
    const scale = Math.min(innerW / SPAN_LON, innerH / SPAN_LAT);
    this.scaleX = scale;
    this.scaleY = scale;
    this.mapW = SPAN_LON * this.scaleX;
    this.mapH = SPAN_LAT * this.scaleY;
    this.ox = pad.l + (innerW - this.mapW) / 2;
    this.oy = pad.t + (innerH - this.mapH) / 2;
  }

  /** [lon, lat] -> [x, y] in css pixels */
  project(lon, lat) {
    return [
      this.ox + (wrapLon(lon - this.centerLon) + 180) * this.scaleX,
      this.oy + (LAT_MAX - lat) * this.scaleY,
    ];
  }

  /**
   * Project a longitude already expressed relative to the centre and allowed to
   * run outside [-180, 180]. Polygon rings need this: wrapping each vertex
   * independently tears a ring that crosses the seam.
   */
  projectRaw(lonRel, lat) {
    return [this.ox + (lonRel + 180) * this.scaleX, this.oy + (LAT_MAX - lat) * this.scaleY];
  }

  /** Horizontal wrap distance, used to route arcs the short way around. */
  get wrapWidth() {
    return this.mapW;
  }
}

export class WorldRenderer {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.geo = null;
  }

  async load(url = '/world-110m.json') {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`world data ${res.status}`);
    this.geo = await res.json();
    return this.geo;
  }

  draw(proj, dpr) {
    const { ctx } = this;
    const { w, h } = proj;

    this.canvas.width = Math.round(w * dpr);
    this.canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    // Ocean fills the entire viewport. Confining it to the map rectangle is what
    // produced the visible empty bands - the leftover space now simply reads as
    // more ocean.
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, '#04070f');
    g.addColorStop(0.32, '#071227');
    g.addColorStop(0.68, '#08152b');
    g.addColorStop(1, '#04070f');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);

    // Map content is confined to the map rectangle; the ocean above covers the
    // rest of the viewport so there are no hard edges. The wrapped copies drawn
    // below exist to carry rings across the seam, and without this clip the one
    // a whole map-width away shows up as a second copy of the continents in the
    // margin - very visible in the stacked layout, where nothing covers it.
    ctx.save();
    ctx.beginPath();
    ctx.rect(proj.ox, proj.oy, proj.mapW, proj.mapH);
    ctx.clip();

    this.#graticule(proj);
    if (this.geo) this.#land(proj);

    ctx.restore();
  }

  /**
   * Country outlines.
   *
   * Each ring's longitudes are "unwrapped" into a continuous run before
   * projecting: wrapping every vertex independently tears any ring that crosses
   * the seam (Russia, Fiji, Antarctica), and closing the torn pieces fills a
   * straight chord straight across the map. The unwrapped ring is then drawn
   * three times, offset by one map width each way, so whatever leaves one edge
   * reappears on the other.
   */
  #land(proj) {
    const { ctx } = this;
    const cl = proj.centerLon;

    ctx.beginPath();
    for (const f of this.geo.features) {
      const polys = f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates;
      for (const poly of polys) {
        for (const ring of poly) {
          if (ring.length < 2) continue;

          let prev = wrapLon(ring[0][0] - cl);
          const pts = [[prev, ring[0][1]]];
          for (let i = 1; i < ring.length; i++) {
            let d = wrapLon(ring[i][0] - cl);
            // Pick the representation of this vertex nearest the previous one.
            while (d - prev > 180) d -= 360;
            while (d - prev < -180) d += 360;
            pts.push([d, ring[i][1]]);
            prev = d;
          }

          for (const shift of [-proj.mapW, 0, proj.mapW]) {
            const [x0, y0] = proj.projectRaw(pts[0][0], pts[0][1]);
            ctx.moveTo(x0 + shift, y0);
            for (let i = 1; i < pts.length; i++) {
              const [x, y] = proj.projectRaw(pts[i][0], pts[i][1]);
              ctx.lineTo(x + shift, y);
            }
            ctx.closePath();
          }
        }
      }
    }

    ctx.fillStyle = 'rgba(24, 48, 82, 0.55)';
    ctx.fill();
    ctx.lineWidth = 0.6;
    ctx.strokeStyle = 'rgba(96, 152, 214, 0.42)';
    ctx.stroke();
  }

  // Spans the map rectangle (the caller clips to it).
  #graticule(proj) {
    const { ctx } = this;
    const top = proj.oy;
    const bottom = proj.oy + proj.mapH;
    ctx.beginPath();
    for (let lon = -180; lon <= 180; lon += 30) {
      const [x] = proj.project(lon, 0);
      ctx.moveTo(x, top);
      ctx.lineTo(x, bottom);
    }
    for (let lat = -40; lat <= 80; lat += 20) {
      const [, y] = proj.project(0, lat);
      ctx.moveTo(proj.ox, y);
      ctx.lineTo(proj.ox + proj.mapW, y);
    }
    ctx.strokeStyle = 'rgba(70, 120, 180, 0.07)';
    ctx.lineWidth = 1;
    ctx.stroke();
  }
}
