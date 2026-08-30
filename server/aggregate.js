import { config } from './config.js';
import { layerOf, isThreatAlert, isAttackTarget, farEnd } from './normalize.js';
import { Rollup } from './rollup.js';

const HOUR_MS = 3_600_000;

/**
 * Turns a raw event stream into something a map can actually render.
 *
 * At the measured mix (~907 of every 1000 events are outbound passes) drawing
 * one arc per event produces an unreadable blob, so repeats of the same
 * src -> dst:port inside COLLAPSE_MS become a single arc carrying a hit count.
 * Rolling stats are kept over the full stream regardless, so the panels report
 * real totals rather than post-collapse ones.
 */

// Only what the live per-minute counters need. Rankings come from the rollup,
// which is why this is 90 seconds and not an hour: holding an hour of raw events
// is precisely the cost that capped the window at 1h in the first place.
const RATES_MS = 90_000;

export class Aggregator {
  constructor(opts = {}) {
    this.collapseMs = opts.collapseMs ?? config.render.collapseMs;
    this.bufferSize = opts.bufferSize ?? config.render.bufferSize;

    this.open = new Map();   // collapse key -> arc
    this.recent = [];        // rendered arcs, newest last, capped at bufferSize
    this.rates = [];         // last 90s of events, for the live header counters
    this.rollup = opts.rollup ?? new Rollup();
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

    this.rates.push({ t: now, ev });
    // The rollup needs to know which end to attribute a signature to, and
    // farEnd() is cheap enough to resolve once here rather than per merge.
    ev.__far__ = { ip: farEnd(ev).ip, dir: ev.dir };
    this.rollup.ingest(ev, Aggregator.isInboundThreat(ev), now);
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
      // Marked here rather than re-derived in the browser, so the threat console
      // and the rankings cannot drift apart on what counts as an attack.
      // Internal alerts qualify too: a LAN host running an amplification scan is
      // a threat activity even though it is not an inbound attack.
      threat: Aggregator.isThreat(ev) || (ev.source === 'ids' && isThreatAlert(ev)),
      firstTs: now,
      lastTs: now,
      count: 1,
    };
    this.open.set(key, arc);
    this.recent.push(arc);
    if (this.recent.length > this.bufferSize) this.recent.splice(0, this.recent.length - this.bufferSize);
    return { type: 'arc', arc };
  }

  /**
   * Count a historical event into the statistics only.
   *
   * Backfilled events must not become arcs - replaying yesterday's attacks
   * across the map would be a lie - and must not touch the live rates ring or
   * the session totals, both of which mean "since this process started".
   */
  ingestHistory(ev) {
    ev.__far__ = { ip: farEnd(ev).ip, dir: ev.dir };
    this.rollup.ingest(ev, Aggregator.isInboundThreat(ev), Date.now());
  }

  prune(now = Date.now()) {
    const cutoff = now - RATES_MS;
    let i = 0;
    while (i < this.rates.length && this.rates[i].t < cutoff) i++;
    if (i) this.rates.splice(0, i);

    for (const [key, arc] of this.open) {
      if (now - arc.lastTs > this.collapseMs * 2) this.open.delete(key);
    }
    this.rollup.roll(now);
  }

  /**
   * Anything hostile: an inbound block, or a threat-class IDS alert. Internal is
   * neither.
   *
   * The alert side is filtered rather than taken wholesale - an inbound "ET INFO
   * Observed DNS Query" is a record of something happening, not an attack, and
   * counting it here is what let ordinary hosts appear in "Top attackers".
   */
  static isThreat(ev) {
    if (ev.dir === 'internal') return false;
    if (ev.source === 'ids') return isThreatAlert(ev);
    // A block only counts as an attack if it was aimed at something. Late
    // replies from Cloudflare/Google to connections we opened get blocked too,
    // and used to rank them alongside real scanners on equal footing.
    return ev.action === 'block' && ev.dir === 'in' && isAttackTarget(ev);
  }

  /** Something arriving from the internet and aimed at us. */
  static isInboundThreat(ev) {
    return ev.dir === 'in' && Aggregator.isThreat(ev);
  }

  /**
   * The live half: header counters over the last 60 seconds, straight from the
   * rates ring so they stay as immediate as they were rather than stepping once
   * a minute with the rollup.
   */
  #liveRates(now) {
    const minAgo = now - 60_000;
    let blocksMin = 0;
    let alertsMin = 0;
    let eventsMin = 0;
    for (const { t, ev } of this.rates) {
      if (t < minAgo) continue;
      eventsMin++;
      if (ev.action === 'block' && ev.dir === 'in') blocksMin++;
      if (ev.source === 'ids') alertsMin++;
    }
    return { eventsMin, blocksMin, alertsMin };
  }

  /**
   * @param {number} windowMs ranking window; the header counters ignore it and
   *   stay on their live basis, so the top bar reads "now" while the panels read
   *   whatever period was asked for.
   */
  stats(windowMs = HOUR_MS, now = Date.now()) {
    this.prune(now);
    const ranks = this.rollup.rankings(windowMs, now);
    return {
      uptimeSec: Math.round((now - this.startedAt) / 1000),
      windowMs,
      coverageMs: Math.min(this.rollup.coverageMs, windowMs),
      totals: { ...this.totals },
      rates: {
        ...this.#liveRates(now),
        // Distinct attackers over the selected window, not a fixed hour - the
        // label follows the window so the number is never mislabelled.
        uniqueAttackersHour: ranks.uniqueAttackers,
      },
      ...ranks,
    };
  }

  /** Arcs a freshly-connected client should draw so the map is never blank. */
  snapshot(limit = 150) {
    return this.recent.slice(-limit);
  }
}
