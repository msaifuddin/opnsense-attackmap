import { EventEmitter } from 'node:events';
import { config } from './config.js';
import { OPNsenseClient } from './opnsense.js';
import { makeNetMatcher } from './nets.js';
import {
  normalizeFw, normalizeIds, fwTimestampToDate,
  setFwTzOffsetMinutes, detectFwTzOffset, formatTzOffset,
} from './normalize.js';
import { geoLookup, geoCached, initGeo, geoMode, geoProviderDomain } from './geo.js';
import { parseFilterLine } from './filterlog.js';

/**
 * Owns both feeds and turns them into geo-enriched, deduped events.
 *
 * The two loops are deliberately independent: the firewall log is the reliable
 * high-rate feed and must not stall because Suricata's alert endpoint is slow,
 * restarting, or empty.
 */
export class Pipeline extends EventEmitter {
  constructor(client = new OPNsenseClient()) {
    super();
    this.client = client;
    this.isHome = makeNetMatcher(config.home.nets);
    this.homeGeo = null;
    this.wanIp = null;
    this.fwDigest = null;
    this.interfaceNames = {};
    this.suppressed = 0;
    this.seenIds = new Set();
    this.seenIdsOrder = [];
    this.running = false;
    this.health = {
      fw: { ok: false, lastAt: null, lastError: null, consecutiveErrors: 0 },
      ids: { ok: false, lastAt: null, lastError: null, consecutiveErrors: 0 },
    };
  }

  async start() {
    await initGeo();

    this.wanIp = await this.client.wanAddress().catch(() => null);
    if (this.wanIp) this.isHome.add(this.wanIp);
    this.interfaceNames = await this.client.interfaceNames().catch(() => ({}));
    await this.#resolveTimezone();

    if (Number.isFinite(config.home.lat) && Number.isFinite(config.home.lon)) {
      this.homeGeo = { lat: config.home.lat, lon: config.home.lon, cc: null, country: null, city: config.home.label, asn: null, org: null };
    } else if (this.wanIp) {
      const g = await geoLookup(this.wanIp);
      if (g) this.homeGeo = { ...g, city: config.home.label };
    }
    if (!this.homeGeo) {
      console.warn('[pipeline] could not place home on the map - set HOME_LAT/HOME_LON in .env');
      this.homeGeo = { lat: 0, lon: 0, cc: null, country: null, city: config.home.label, asn: null, org: null };
    }
    console.log(`[pipeline] wan=${this.wanIp ?? 'unknown'} home=${this.homeGeo.lat.toFixed(2)},${this.homeGeo.lon.toFixed(2)} geo=${geoMode()}`);

    this.running = true;
    // Boundary between "history" and "live", so backfill never double-counts
    // events the pollers have already ingested.
    this.startedAt = Date.now();

    if (config.replay.enabled) {
      this.#replay();
    } else {
      // Seed the digest so we start from "now" instead of replaying history.
      const seed = await this.client.fwLog({ limit: 1 });
      this.fwDigest = seed[0]?.__digest__ ?? null;
      this.#loop('fw', () => this.#pollFw(), config.poll.fwMs);
    }
    this.#loop('ids', () => this.#pollIds(), config.poll.idsMs);
  }

  stop() {
    this.running = false;
  }

  /**
   * The firewall log has no timezone on its timestamps, so with FW_TZ_OFFSET=auto
   * we infer it: a freshly written log line is "now" in the firewall's local
   * time, so reading it as UTC and diffing against real now gives the offset.
   * Snapped to 15 minutes, which covers every real-world zone.
   */
  async #resolveTimezone() {
    if (!config.fwTzAuto) {
      console.log(`[tz] firewall offset ${config.fwTzOffsetSpec} (from FW_TZ_OFFSET)`);
      return;
    }
    try {
      const [row] = await this.client.fwLog({ limit: 1 });
      if (!row?.__timestamp__) throw new Error('no log rows to sample');
      const minutes = detectFwTzOffset(row.__timestamp__);
      if (minutes === null) throw new Error('implausible offset');
      setFwTzOffsetMinutes(minutes);
      console.log(`[tz] firewall offset detected: ${formatTzOffset(minutes)} (set FW_TZ_OFFSET to pin it)`);
    } catch (e) {
      console.warn(`[tz] auto-detect failed (${e.message}); assuming UTC. Set FW_TZ_OFFSET if arcs look time-shifted.`);
      setFwTzOffsetMinutes(0);
    }
  }

  /** Self-rescheduling loop with exponential backoff, so a dead feed backs off. */
  #loop(name, fn, intervalMs) {
    const tick = async () => {
      if (!this.running) return;
      const h = this.health[name];
      let delay = intervalMs;
      try {
        await fn();
        h.ok = true;
        h.lastAt = new Date().toISOString();
        h.lastError = null;
        h.consecutiveErrors = 0;
      } catch (e) {
        h.ok = false;
        h.lastError = e.message;
        h.consecutiveErrors++;
        delay = Math.min(intervalMs * 2 ** Math.min(h.consecutiveErrors, 5), 60_000);
        if (h.consecutiveErrors === 1 || h.consecutiveErrors % 10 === 0) {
          console.warn(`[${name}] ${e.message} (retry in ${delay}ms)`);
        }
        this.emit('health', this.health);
      }
      setTimeout(tick, delay);
    };
    tick();
  }

  async #pollFw() {
    const { rows, digest, saturated } = await this.client.fwLogSince(this.fwDigest);
    if (saturated) {
      console.warn(`[fw] fetch saturated at ${config.poll.fwLimit} rows - events may have been missed; resyncing`);
    }
    this.fwDigest = digest ?? this.fwDigest;
    // Oldest first, so arcs appear in the order they actually happened.
    const events = rows.reverse().map((row) => normalizeFw(row, { isHome: this.isHome }));
    await this.#emitAll(events);
  }

  /**
   * True for alerts this process caused by geolocating addresses. ET writes
   * domains with a space before the TLD ("ip-api .com"), so whitespace is
   * stripped before matching.
   */
  #isOwnGeoNoise(ev) {
    if (!config.geo.suppressOwnAlerts || ev.source !== 'ids' || !ev.signature) return false;
    const domain = geoProviderDomain();
    if (!domain) return false;
    return ev.signature.replace(/\s+/g, '').toLowerCase().includes(domain);
  }

  async #pollIds() {
    const { rows } = await this.client.idsAlerts({ rowCount: config.poll.idsRowCount });
    const fresh = [];
    for (const row of rows) {
      const ev = normalizeIds(row, { isHome: this.isHome });
      if (this.seenIds.has(ev.key)) continue;
      this.#remember(ev.key);
      if (this.#isOwnGeoNoise(ev)) { this.suppressed++; continue; }
      fresh.push(ev);
    }
    // First pass just primes the dedupe set; without this every alert already in
    // eve.json would flood the map on startup.
    if (this.firstIdsPass === undefined) {
      this.firstIdsPass = false;
      return;
    }
    await this.#emitAll(fresh.reverse());
  }

  #remember(key) {
    this.seenIds.add(key);
    this.seenIdsOrder.push(key);
    if (this.seenIdsOrder.length > 20_000) {
      for (const old of this.seenIdsOrder.splice(0, 10_000)) this.seenIds.delete(old);
    }
  }

  /**
   * Enrich a whole batch concurrently, then emit in order.
   *
   * Awaiting geo per event in sequence would be pathological on the ip-api
   * fallback: every uncached address would wait a full flush interval of its
   * own, turning one poll's worth of events into minutes of lag. Resolving the
   * batch together means the entire poll costs at most one flush.
   */
  async #emitAll(events) {
    if (!events.length) return;
    await Promise.all(
      events.flatMap((ev) => [
        this.#geoFor(ev.src.ip).then((g) => { ev.src.geo = g; }),
        this.#geoFor(ev.dst.ip).then((g) => { ev.dst.geo = g; }),
      ])
    );
    for (const ev of events) {
      ev.src.home = this.isHome(ev.src.ip);
      ev.dst.home = this.isHome(ev.dst.ip);
      this.emit('event', ev);
    }
  }

  async #geoFor(ip) {
    if (this.isHome(ip)) return this.homeGeo;
    // A miss must NOT fall back to the home anchor. Doing so both placed remote
    // addresses on the operator's own coordinates and leaked the unredacted
    // home record - including the ISP name and ASN - because the redactor only
    // sanitises geo on endpoints flagged as home, and these are not.
    // Unlocatable addresses simply have no position; the client skips the arc.
    return (await geoLookup(ip)) ?? null;
  }

  /**
   * Seed the statistics from the firewall log's own history.
   *
   * Without this a fresh deploy shows two minutes of data under a "24h" label,
   * which is the one thing the panels must not do. Events are handed to a
   * callback rather than emitted: this is history, so it must reach the rollup
   * without replaying old attacks as arcs on the map.
   *
   * Bounded on purpose. The endpoint has no cursor, so paging backwards is not
   * possible and one fetch is all we get - and asking for too much kills the
   * request server-side: 400k rows exhausts PHP's 1 GB limit on the firewall.
   *
   * Walks the log backwards a page at a time until it reaches BACKFILL_HOURS or
   * runs out of log. Paging is what makes a full day reachable at all: each
   * page costs ~3 MB whatever its depth, whereas asking the parsed endpoint for
   * a day in one request kills the PHP worker.
   *
   * Pages get slower the deeper they go (the API seeks from the top each time:
   * ~0.6 s at page 1, ~3.6 s at page 26), so this runs in the background and
   * yields between pages rather than blocking startup.
   *
   * @param {(t:number)=>boolean} isGap true when that moment has no counts yet.
   *   Restored history is therefore left alone and only the holes are filled -
   *   both the period before the service ever ran and any downtime since.
   */
  async backfill(onEvents, isGap) {
    const hours = config.stats.backfillHours;
    if (!hours || !this.running) return null;

    const t0 = Date.now();
    const horizon = t0 - hours * 3_600_000;
    // Geo-enrich so the origins panel covers history too, but only against a
    // local database: a day is a quarter of a million addresses, which through
    // the ip-api fallback at ~15 requests/minute would take days and leave the
    // live path queued behind it. There we use whatever is already cached.
    const local = geoMode() === 'mmdb' || geoMode() === 'mmdb+asn';

    let pages = 0;
    let scanned = 0;
    let used = 0;
    let oldestUsed = t0;

    for (let page = 1; page <= config.stats.backfillMaxPages; page++) {
      if (!this.running) break;
      const rows = await this.client.filterLogPage({ page, rowCount: config.stats.backfillPageRows });
      pages++;
      if (!rows.length) break; // end of the retained log
      scanned += rows.length;

      // Handled a page at a time rather than accumulated: a day is ~264k events
      // and holding them all before processing costs well over a hundred
      // megabytes for no benefit.
      const events = [];
      let reachedHorizon = false;
      for (const r of rows) {
        const parsed = parseFilterLine(r.line, r.timestamp);
        if (!parsed) continue;
        const ev = normalizeFw(parsed, { isHome: this.isHome });
        const t = Date.parse(ev.ts);
        if (!Number.isFinite(t)) continue;
        if (t < horizon) { reachedHorizon = true; continue; }
        // Do not re-count restored history, nor anything the live poller has
        // already ingested since startup.
        if (t >= this.startedAt || !isGap(t)) continue;
        if (t < oldestUsed) oldestUsed = t;
        events.push(ev);
      }

      if (events.length) {
        // Oldest first within the page, so counts land in ascending time order.
        events.reverse();
        for (const ev of events) {
          ev.src.geo = local ? await this.#geoFor(ev.src.ip) : (geoCached(ev.src.ip) ?? null);
          ev.dst.geo = local ? await this.#geoFor(ev.dst.ip) : (geoCached(ev.dst.ip) ?? null);
          ev.src.home = this.isHome(ev.src.ip);
          ev.dst.home = this.isHome(ev.dst.ip);
        }
        onEvents(events);
        used += events.length;
      }

      if (reachedHorizon) break;
      // Let the event loop breathe: the live pollers must keep running while
      // this walks a day of history.
      await new Promise((r) => setTimeout(r, 50));
    }

    const spanH = used ? (Date.now() - oldestUsed) / 3_600_000 : 0;
    return { rows: scanned, used, pages, spanH, ms: Date.now() - t0 };
  }

  /** Feed historical firewall events back at speed, to exercise the renderer. */
  async #replay() {
    const rows = await this.client.fwLog({ limit: config.poll.fwLimit });
    rows.reverse();
    console.log(`[replay] feeding ${rows.length} historical events at ${config.replay.speed}x`);
    let i = 0;
    const base = fwTimestampToDate(rows[0]?.__timestamp__).getTime();
    const t0 = Date.now();
    const step = async () => {
      if (!this.running || i >= rows.length) {
        if (i >= rows.length) console.log('[replay] complete');
        return;
      }
      const row = rows[i++];
      await this.#emitAll([normalizeFw(row, { isHome: this.isHome })]);
      const nextAt = rows[i] ? fwTimestampToDate(rows[i].__timestamp__).getTime() : null;
      const wall = nextAt ? (nextAt - base) / config.replay.speed - (Date.now() - t0) : 0;
      setTimeout(step, Math.max(0, Math.min(wall, 2000)));
    };
    step();
  }
}
