import fs from 'node:fs';
import path from 'node:path';
import { config, ROOT } from './config.js';
import { isThreatAlert } from './normalize.js';

/**
 * Time-bucketed counters behind the ranking panels.
 *
 * The panels used to be computed by walking every raw event in a one-hour
 * window, six times a second. That is why the window was an hour: at 514 bytes
 * per event and ~5 events/sec, a day costs 170 MB and 634 ms per stats() call -
 * two thirds of a core doing nothing but re-counting, and past ~3 days a single
 * call takes longer than the tick that triggers it.
 *
 * Counting into buckets as events arrive makes cost scale with the number of
 * DISTINCT attackers, ports and signatures rather than with traffic volume, so
 * a week costs about the same as an hour. Ingest is O(1); merging is O(distinct
 * keys) and happens once a minute, off the broadcast path.
 *
 * Two tiers, because a week of minute buckets would be 10,080 of them:
 *   - minute buckets for the last MINUTE_KEEP minutes, serving the 1h view
 *   - hour buckets for the last HOUR_KEEP hours, serving 24h and 7d
 * A minute bucket is folded into its hour bucket as it ages out, so nothing is
 * counted twice.
 */

const MIN_MS = 60_000;
const HOUR_MS = 3_600_000;

// Two hours of minute resolution covers the 1h window with room to spare.
const MINUTE_KEEP = 120;

/**
 * How long a computed ranking is reused, scaled to the window it covers.
 *
 * A 1h ranking should feel responsive, so it refreshes every 5 s. A 7-day
 * ranking cannot visibly change in 30 s and is the most expensive to build, so
 * it refreshes at the cap. Recomputing everything every second would spend more
 * CPU than the raw-event code this replaces, for numbers nobody can see move.
 */
const cacheMsFor = (windowMs) => Math.min(30_000, Math.max(5_000, windowMs / 2000));

// Per-bucket cardinality caps. Without these a scan burst hitting the box from
// tens of thousands of addresses in one minute would be stored in full. Once a
// map is full, existing keys keep counting and new ones are dropped - the
// ranking stays right at the top, which is the only part anyone reads, and the
// bucket is flagged so the UI can say the total is approximate rather than
// quietly reporting a wrong number.
const CAP = { attackers: 300, ports: 100, sigs: 60, sources: 10 };

// An hour bucket legitimately holds sixty minutes' worth of distinct addresses,
// so applying the per-minute cap to it would throw away real attackers and mark
// the ranking approximate for no good reason. Only direct ingestion into the
// hour tier is affected - folding a minute bucket in is never capped.
const HOUR_SCALE = 8;

const newBucket = () => ({
  n: 0, fw: 0, ids: 0, blockIn: 0, alerts: 0,
  countries: new Map(),
  attackers: new Map(),
  ports: new Map(),
  sigs: new Map(),
  truncated: false,
});

/** Increment map[key], respecting the cap. Returns false if the key was dropped. */
function bump(map, key, cap, init) {
  const hit = map.get(key);
  if (hit !== undefined) return hit;
  if (map.size >= cap) return null;
  map.set(key, init);
  return init;
}

export class Rollup {
  constructor(opts = {}) {
    this.minuteKeep = opts.minuteKeep ?? MINUTE_KEEP;
    this.hourKeep = opts.hourKeep ?? config.stats.retainHours;
    this.minutes = new Map(); // minute index -> bucket
    this.hours = new Map();   // hour index   -> bucket
    this.cache = new Map();   // windowMs -> { at, value }
    this.file = path.resolve(ROOT, config.stats.file);
    this.dirty = false;
  }

  #minuteIdx(t) { return Math.floor(t / MIN_MS); }
  #hourIdx(t) { return Math.floor(t / HOUR_MS); }

  /**
   * How far back this rollup actually has data. The UI needs it to avoid
   * captioning three minutes of history as "7d" - after a fresh deploy the long
   * windows are honest about being mostly empty.
   */
  get coverageMs() {
    const oldest = this.hours.size
      ? Math.min(...this.hours.keys()) * HOUR_MS
      : this.minutes.size ? Math.min(...this.minutes.keys()) * MIN_MS : null;
    return oldest === null ? 0 : Date.now() - oldest;
  }

  /**
   * A predicate for "this moment has no counts yet", snapshotted now.
   *
   * Used to seed history without double counting. It must be taken BEFORE any
   * seeding starts: ingesting creates buckets, so testing live state would let
   * the first event of a minute through and then reject the rest of that same
   * minute.
   *
   * Hour granularity means a partially recorded hour is skipped whole. That can
   * leave up to an hour unfilled at the seam, which is far preferable to
   * counting the same attack twice.
   */
  gapFilter() {
    const minutes = new Set(this.minutes.keys());
    const hours = new Set(this.hours.keys());
    return (t) => !minutes.has(this.#minuteIdx(t)) && !hours.has(this.#hourIdx(t));
  }

  /**
   * Count one event. Called on the live path, so it does no allocation beyond
   * first sight of a key and never sorts.
   */
  ingest(ev, isThreat, now = Date.now()) {
    const t = Date.parse(ev.ts) || now;
    const idx = this.#minuteIdx(t);
    // An event older than the minute tier (clock skew, a late poll, seeded
    // history) is counted straight into its hour bucket rather than resurrecting
    // a rolled-up minute.
    const recent = idx > this.#minuteIdx(now) - this.minuteKeep;
    let b;
    if (recent) {
      b = this.minutes.get(idx) ?? this.minutes.set(idx, newBucket()).get(idx);
    } else {
      const h = this.#hourIdx(t);
      b = this.hours.get(h) ?? this.hours.set(h, newBucket()).get(h);
    }
    const scale = recent ? 1 : HOUR_SCALE;

    b.n++;
    if (ev.source === 'ids') { b.ids++; b.alerts++; } else b.fw++;
    if (ev.action === 'block' && ev.dir === 'in') b.blockIn++;

    // Signatures are kept for every direction and every class; the threats/all
    // split is derived from severity at merge time, so only one copy is stored.
    if (ev.signature) {
      const row = bump(b.sigs, ev.signature, CAP.sigs * scale, {
        n: 0, sev: ev.severity ?? 2, cat: ev.category ?? null,
        threat: isThreatAlert(ev), src: new Map(),
      });
      if (row) {
        row.n++;
        this.#source(row.src, ev.__far__, scale);
      } else b.truncated = true;
    }

    // The "who is hitting us" rankings stay scoped to inbound threats, exactly
    // as they were when they walked the raw window.
    if (!isThreat) { this.dirty = true; return; }

    const cc = ev.src.geo?.cc;
    if (cc) {
      const c = bump(b.countries, cc, CAP.attackers * scale, 0);
      if (c === null) b.truncated = true;
      else b.countries.set(cc, c + 1);
    }
    if (ev.src.ip) {
      const a = bump(b.attackers, ev.src.ip, CAP.attackers * scale, 0);
      if (a === null) b.truncated = true;
      else b.attackers.set(ev.src.ip, a + 1);
    }
    if (ev.dst.port) {
      const row = bump(b.ports, ev.dst.port, CAP.ports * scale, { n: 0, src: new Map() });
      if (row) {
        row.n++;
        this.#source(row.src, { ip: ev.src.ip, dir: ev.dir }, scale);
      } else b.truncated = true;
    }
    this.dirty = true;
  }

  /**
   * Sources are kept deeper than the five that are displayed: merged over a
   * week, a contributor sitting just below the cut in every bucket can be first
   * overall. It stays approximate for long windows, which is the right trade for
   * a statistic.
   */
  #source(map, far, scale) {
    if (!far?.ip) return;
    const hit = map.get(far.ip);
    if (hit) { hit.n++; return; }
    // Deliberately does NOT set `truncated`. Keeping the top contributors per
    // bucket rather than all of them is how this sub-list is designed to work,
    // not evidence of a burst - and a warning that is permanently lit on any
    // long window is a warning nobody reads. `truncated` stays reserved for the
    // primary rankings actually losing keys.
    if (map.size >= CAP.sources * scale) return;
    map.set(far.ip, { n: 1, dir: far.dir });
  }

  /**
   * Fold minute buckets that have aged out into their hour buckets, and drop
   * hour buckets past the retention horizon. Cheap, and only touches what moved.
   */
  roll(now = Date.now()) {
    let changed = false;
    const minCutoff = this.#minuteIdx(now) - this.minuteKeep;
    for (const [idx, b] of this.minutes) {
      if (idx > minCutoff) continue;
      const h = this.#hourIdx(idx * MIN_MS);
      const into = this.hours.get(h) ?? this.hours.set(h, newBucket()).get(h);
      mergeInto(into, b);
      this.minutes.delete(idx);
      changed = true;
    }
    const hourCutoff = this.#hourIdx(now) - this.hourKeep;
    for (const idx of this.hours.keys()) {
      if (idx <= hourCutoff) { this.hours.delete(idx); changed = true; }
    }
    // Only when buckets actually moved. roll() runs every second off prune(), so
    // clearing unconditionally destroyed the cache on every tick - which made a
    // "cached" read measurably slower than a cold one.
    if (changed) { this.cache.clear(); this.dirty = true; }
  }

  /**
   * Merge every bucket covering the last `windowMs`.
   *
   * The most recent two hours come from minute buckets and the rest from hour
   * buckets, which makes long-window boundaries accurate to about an hour -
   * immaterial for a ranking, worth knowing before reading the totals as exact.
   */
  merge(windowMs, now = Date.now()) {
    const since = now - windowMs;
    const out = newBucket();
    for (const [idx, b] of this.minutes) {
      if (idx * MIN_MS + MIN_MS > since) mergeInto(out, b);
    }
    for (const [idx, b] of this.hours) {
      if (idx * HOUR_MS + HOUR_MS > since) mergeInto(out, b);
    }
    return out;
  }

  /**
   * The finished ranking lists, cached.
   *
   * Measured cost of a cold build: ~12 ms for 1h, ~24 ms for 24h, ~47 ms for 7d,
   * plus ~8 ms to rank. Paying that every second per window would be wasteful
   * for numbers that barely move, so it is recomputed on the schedule above.
   * The header counters are not cached and stay per-second, so the page still
   * reads as live while the statistics lag by at most a few seconds.
   */
  rankings(windowMs, now = Date.now()) {
    const hit = this.cache.get(windowMs);
    if (hit && now - hit.at < cacheMsFor(windowMs)) return hit.value;
    const value = rankingsFrom(this.merge(windowMs, now));
    this.cache.set(windowMs, { at: now, value });
    return value;
  }

  // ---- persistence ---------------------------------------------------------

  /**
   * Written atomically, the same tmp-then-rename the GeoLite2 download uses: a
   * process killed mid-write must not leave a half-parsed file that loses the
   * history it was trying to protect.
   */
  save() {
    if (!config.stats.persist || !this.dirty) return false;
    const payload = {
      v: 1,
      savedAt: Date.now(),
      minutes: [...this.minutes].map(([i, b]) => [i, encodeBucket(b)]),
      hours: [...this.hours].map(([i, b]) => [i, encodeBucket(b)]),
    };
    const tmp = `${this.file}.tmp`;
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(tmp, JSON.stringify(payload));
      fs.renameSync(tmp, this.file);
      this.dirty = false;
      return true;
    } catch (e) {
      console.warn(`[rollup] could not save (${e.message})`);
      try { fs.unlinkSync(tmp); } catch {}
      return false;
    }
  }

  load(now = Date.now()) {
    if (!config.stats.persist || !fs.existsSync(this.file)) return null;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      if (raw.v !== 1) throw new Error(`unknown format v${raw.v}`);
      const minCutoff = this.#minuteIdx(now) - this.minuteKeep;
      const hourCutoff = this.#hourIdx(now) - this.hourKeep;
      for (const [i, b] of raw.minutes ?? []) if (i > minCutoff) this.minutes.set(i, decodeBucket(b));
      for (const [i, b] of raw.hours ?? []) if (i > hourCutoff) this.hours.set(i, decodeBucket(b));
      // Anything that aged out while the process was down belongs in the hour
      // tier, so run a roll immediately rather than waiting for the first tick.
      this.roll(now);
      const oldest = this.hours.size ? Math.min(...this.hours.keys()) * HOUR_MS
        : this.minutes.size ? Math.min(...this.minutes.keys()) * MIN_MS : now;
      return { buckets: this.minutes.size + this.hours.size, coverageMs: now - oldest };
    } catch (e) {
      console.warn(`[rollup] could not load history (${e.message}); starting empty`);
      return null;
    }
  }
}

// ---- merge helpers ----------------------------------------------------------

function addCount(map, key, n) {
  map.set(key, (map.get(key) || 0) + n);
}

function addSources(into, from) {
  for (const [ip, s] of from) {
    const hit = into.get(ip);
    if (hit) hit.n += s.n;
    else into.set(ip, { n: s.n, dir: s.dir });
  }
}

/** Accumulate `from` into `to`. Merging is uncapped - the inputs are already capped. */
function mergeInto(to, from) {
  to.n += from.n; to.fw += from.fw; to.ids += from.ids;
  to.blockIn += from.blockIn; to.alerts += from.alerts;
  to.truncated = to.truncated || from.truncated;
  for (const [k, v] of from.countries) addCount(to.countries, k, v);
  for (const [k, v] of from.attackers) addCount(to.attackers, k, v);
  for (const [k, v] of from.ports) {
    const row = to.ports.get(k) ?? to.ports.set(k, { n: 0, src: new Map() }).get(k);
    row.n += v.n;
    addSources(row.src, v.src);
  }
  for (const [k, v] of from.sigs) {
    const row = to.sigs.get(k)
      ?? to.sigs.set(k, { n: 0, sev: v.sev, cat: v.cat, threat: v.threat, src: new Map() }).get(k);
    row.n += v.n;
    addSources(row.src, v.src);
  }
}

// ---- ranking -----------------------------------------------------------------

const topOf = (map, limit) => [...map]
  .sort((a, b) => b[1] - a[1])
  .slice(0, limit)
  .map(([key, count]) => ({ key, count }));

const topSources = (map, limit) => [...map]
  .sort((a, b) => b[1].n - a[1].n)
  .slice(0, limit)
  .map(([ip, s]) => ({ ip, count: s.n, dir: s.dir }));

const topWithSources = (map, limit, subLimit, extra) => [...map]
  .sort((a, b) => b[1].n - a[1].n)
  .slice(0, limit)
  .map(([key, row]) => ({
    key, count: row.n, ...(extra?.(row) ?? {}), sources: topSources(row.src, subLimit),
  }));

// Rows per panel, and contributors shown inside an expanded row. A round five
// reads as "top five"; the previous eight was an arbitrary number that just made
// the rail longer.
const TOP_N = 5;
const SUB_N = 5;

/** The ranking half of the stats payload, from a merged bucket. */
export function rankingsFrom(b) {
  const sigs = (filter) => topWithSources(
    new Map([...b.sigs].filter(([, r]) => filter(r))),
    TOP_N, SUB_N, (r) => ({ severity: r.sev, category: r.cat })
  );
  return {
    truncated: b.truncated,
    topCountries: topOf(b.countries, TOP_N),
    topAttackers: topOf(b.attackers, TOP_N),
    topPorts: topWithSources(b.ports, TOP_N, SUB_N),
    topSignatures: sigs((r) => r.threat),
    topSignaturesAll: sigs(() => true),
    uniqueAttackers: b.attackers.size,
  };
}

// ---- serialisation ----------------------------------------------------------

const encSources = (m) => [...m].map(([ip, s]) => [ip, s.n, s.dir]);
const decSources = (a) => new Map(a.map(([ip, n, dir]) => [ip, { n, dir }]));

function encodeBucket(b) {
  return {
    n: b.n, fw: b.fw, ids: b.ids, blockIn: b.blockIn, alerts: b.alerts, t: b.truncated ? 1 : 0,
    c: [...b.countries],
    a: [...b.attackers],
    p: [...b.ports].map(([k, v]) => [k, v.n, encSources(v.src)]),
    s: [...b.sigs].map(([k, v]) => [k, v.n, v.sev, v.cat, v.threat ? 1 : 0, encSources(v.src)]),
  };
}

function decodeBucket(b) {
  return {
    n: b.n, fw: b.fw, ids: b.ids, blockIn: b.blockIn, alerts: b.alerts,
    truncated: Boolean(b.t),
    countries: new Map(b.c),
    attackers: new Map(b.a),
    ports: new Map(b.p.map(([k, n, src]) => [k, { n, src: decSources(src) }])),
    sigs: new Map(b.s.map(([k, n, sev, cat, threat, src]) => [k, { n, sev, cat, threat: Boolean(threat), src: decSources(src) }])),
  };
}
