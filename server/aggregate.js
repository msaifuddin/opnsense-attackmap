import { config } from './config.js';
import { layerOf } from './normalize.js';

/**
 * Turns a raw event stream into something a map can actually render.
 *
 * At the measured mix (~907 of every 1000 events are outbound passes) drawing
 * one arc per event produces an unreadable blob, so repeats of the same
 * src -> dst:port inside COLLAPSE_MS become a single arc carrying a hit count.
 * Rolling stats are kept over the full stream regardless, so the panels report
 * real totals rather than post-collapse ones.
 */

const HOUR_MS = 3600_000;

export class Aggregator {
  constructor(opts = {}) {
    this.collapseMs = opts.collapseMs ?? config.render.collapseMs;
    this.bufferSize = opts.bufferSize ?? config.render.bufferSize;

    this.open = new Map();   // collapse key -> arc
    this.recent = [];        // rendered arcs, newest last, capped at bufferSize
    this.window = [];        // every event in the last hour, for stats
    this.totals = { fw: 0, ids: 0, block_in: 0, pass_out: 0, internal: 0, alerts: 0, all: 0 };
    this.startedAt = Date.now();
  }

  static collapseKey(ev) {
    return [ev.source, ev.action, ev.src.ip, ev.dst.ip, ev.dst.port, ev.sid ?? ''].join('|');
  }

  /**
   * @returns {{type:'arc', arc}|{type:'bump', id, count}|null}
   *   'arc'  - a new arc to draw
   *   'bump' - an existing arc's hit count changed; no new arc
   */
  ingest(ev) {
    const now = Date.parse(ev.ts) || Date.now();

    this.window.push({ t: now, ev });
    this.totals.all++;
    this.totals[ev.source]++;
    const layer = layerOf(ev);
    if (layer === 'block_in') this.totals.block_in++;
    else if (layer === 'pass_out') this.totals.pass_out++;
    else if (layer === 'internal') this.totals.internal++;
    if (ev.source === 'ids') this.totals.alerts++;

    const key = Aggregator.collapseKey(ev);
    const existing = this.open.get(key);
    if (existing && now - existing.firstTs < this.collapseMs) {
      existing.count++;
      existing.lastTs = now;
      return { type: 'bump', id: existing.id, count: existing.count };
    }

    const arc = {
      ...ev,
      layer,
      firstTs: now,
      lastTs: now,
      count: 1,
    };
    this.open.set(key, arc);
    this.recent.push(arc);
    if (this.recent.length > this.bufferSize) this.recent.splice(0, this.recent.length - this.bufferSize);
    return { type: 'arc', arc };
  }

  prune(now = Date.now()) {
    const cutoff = now - HOUR_MS;
    let i = 0;
    while (i < this.window.length && this.window[i].t < cutoff) i++;
    if (i) this.window.splice(0, i);

    for (const [key, arc] of this.open) {
      if (now - arc.lastTs > this.collapseMs * 2) this.open.delete(key);
    }
  }

  #topOf(fn, limit, since) {
    const counts = new Map();
    for (const { t, ev } of this.window) {
      if (t < since) continue;
      const k = fn(ev);
      if (k === null || k === undefined || k === '') continue;
      counts.set(k, (counts.get(k) || 0) + 1);
    }
    return [...counts]
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([key, count]) => ({ key, count }));
  }

  /** Anything hostile: an inbound block, or any IDS alert. Internal is neither. */
  static isThreat(ev) {
    if (ev.dir === 'internal') return false;
    return (ev.source === 'ids') || (ev.action === 'block' && ev.dir === 'in');
  }

  /** Something arriving from the internet and aimed at us. */
  static isInboundThreat(ev) {
    return ev.dir === 'in' && Aggregator.isThreat(ev);
  }

  stats(now = Date.now()) {
    this.prune(now);
    const minAgo = now - 60_000;
    const hourAgo = now - HOUR_MS;

    let blocksMin = 0;
    let alertsMin = 0;
    let eventsMin = 0;
    const attackers = new Set();

    for (const { t, ev } of this.window) {
      if (t >= minAgo) {
        eventsMin++;
        if (ev.action === 'block' && ev.dir === 'in') blocksMin++;
        if (ev.source === 'ids') alertsMin++;
      }
      if (t >= hourAgo && Aggregator.isInboundThreat(ev)) attackers.add(ev.src.ip);
    }

    // The three "who is hitting us" panels are all scoped to inbound threats.
    // Counting every event instead would fill them with our own outbound traffic
    // to Cloudflare and rank the home country first.
    const threatSrc = (pick) => (ev) => (Aggregator.isInboundThreat(ev) ? pick(ev) : null);

    return {
      uptimeSec: Math.round((now - this.startedAt) / 1000),
      totals: { ...this.totals },
      rates: { eventsMin, blocksMin, alertsMin, uniqueAttackersHour: attackers.size },
      topCountries: this.#topOf(threatSrc((ev) => ev.src.geo?.cc), 8, hourAgo),
      topAttackers: this.#topOf(threatSrc((ev) => ev.src.ip), 8, hourAgo),
      topPorts: this.#topOf(threatSrc((ev) => ev.dst.port), 8, hourAgo),
      // Signatures are useful in every direction, so this one is not scoped.
      topSignatures: this.#topOf((ev) => ev.signature, 6, hourAgo),
    };
  }

  /** Arcs a freshly-connected client should draw so the map is never blank. */
  snapshot(limit = 150) {
    return this.recent.slice(-limit);
  }
}
