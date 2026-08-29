import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { config, ROOT } from './config.js';
import { isUnroutable } from './nets.js';

/**
 * IP -> {lat, lon, cc, country, city, asn, org}
 *
 * Primary source is a local MaxMind GeoLite2 mmdb: offline, no rate limit, and
 * it carries ASN/org which is what makes an attacker label readable
 * ("CHINANET-BACKBONE" beats "unknown"). If no database is present it falls
 * back to ip-api.com's batch endpoint, which is fine at this event volume.
 */

const MAX_CACHE = 50_000;
const cache = new Map(); // ip -> record | null (null = looked up, no data)

function cacheSet(ip, rec) {
  if (cache.size >= MAX_CACHE) {
    // Cheap LRU-ish eviction: drop the oldest insertion.
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
  cache.set(ip, rec);
  return rec;
}

let cityReader = null;
let asnReader = null;
let mode = 'none';

/** Open whatever databases are on disk right now. Returns true if City loaded. */
async function openLocal() {
  const cityPath = path.resolve(ROOT, config.geo.cityDb);
  const asnPath = path.resolve(ROOT, config.geo.asnDb);
  if (!fs.existsSync(cityPath)) return false;

  try {
    const maxmind = (await import('maxmind')).default;
    const city = await maxmind.open(cityPath);
    const asn = fs.existsSync(asnPath) ? await maxmind.open(asnPath) : null;
    cityReader = city;
    asnReader = asn;
    mode = asn ? 'mmdb+asn' : 'mmdb';
    // Entries resolved through ip-api are coarser and carry weaker org names,
    // so they are dropped once a real database is available.
    cache.clear();
    return true;
  } catch (e) {
    console.warn(`[geo] local database present but unusable (${e.message})`);
    return false;
  }
}

export async function initGeo() {
  const cityPath = path.resolve(ROOT, config.geo.cityDb);

  await openLocal();

  if (mode === 'none') {
    mode = config.geo.fallback ? 'ip-api' : 'disabled';
    if (mode === 'ip-api' && config.geo.autoDownload) {
      console.log(`[geo] no local database yet - starting on ip-api while GeoLite2 downloads to ${path.dirname(cityPath)}`);
    } else if (mode === 'ip-api') {
      console.warn(
        '[geo] no GeoLite2 database found and auto-download is off - using ip-api.com.\n' +
        `      Place GeoLite2-City.mmdb (and optionally GeoLite2-ASN.mmdb) in ${path.dirname(cityPath)}.`
      );
    }
  }

  // Fetch/refresh in the background and switch over when a database lands. The
  // City database is ~60 MB; blocking startup on it would be a poor trade.
  const { startAutoUpdate } = await import('./geodb.js');
  startAutoUpdate(async (reason) => {
    const before = mode;
    if (await openLocal()) {
      console.log(`[geo] mode = ${mode} (${reason}${before !== mode ? `, was ${before}` : ''})`);
    }
  });

  console.log(`[geo] mode = ${mode}`);
  return mode;
}

export const geoMode = () => mode;

/**
 * Domain this process contacts to geolocate addresses, or null when lookups are
 * local. Used to filter out the IDS alerts our own lookups trigger - with
 * Suricata running, "ET POLICY External IP Lookup ip-api.com" otherwise becomes
 * the single most frequent signature on the map, generated entirely by the map.
 */
export function geoProviderDomain() {
  return mode === 'ip-api' ? 'ip-api.com' : null;
}

function fromMmdb(ip) {
  const city = cityReader?.get(ip);
  if (!city?.location) return cacheSet(ip, null);
  const asn = asnReader?.get(ip);
  return cacheSet(ip, {
    lat: city.location.latitude,
    lon: city.location.longitude,
    cc: city.country?.iso_code ?? city.registered_country?.iso_code ?? null,
    country: city.country?.names?.en ?? city.registered_country?.names?.en ?? null,
    city: city.city?.names?.en ?? null,
    asn: asn?.autonomous_system_number ?? null,
    org: asn?.autonomous_system_organization ?? null,
  });
}

// ---- ip-api.com batch fallback ---------------------------------------------

const FIELDS = 'status,country,countryCode,city,lat,lon,as,query';

// ip-api's free batch endpoint allows ~15 requests per minute but up to 100 IPs
// per request. Flushing eagerly burns the request budget on batches of one, so
// the queue is deliberately allowed to accumulate for a few seconds first.
const FLUSH_MS = 4000;
const MAX_BATCH = 100;

const pending = new Map(); // ip -> [resolve, ...]
let flushTimer = null;
let rlRemaining = 15;
let rlResetAt = 0;

function ipApiBatch(ips) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(ips);
    const req = http.request(
      {
        host: 'ip-api.com',
        path: `/batch?fields=${FIELDS}`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      },
      (res) => {
        const rl = Number(res.headers['x-rl']);
        const ttl = Number(res.headers['x-ttl']);
        if (Number.isFinite(rl)) rlRemaining = rl;
        if (Number.isFinite(ttl)) rlResetAt = Date.now() + ttl * 1000;
        const chunks = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            resolve([]);
          }
        });
      }
    );
    req.setTimeout(10_000, () => req.destroy());
    req.on('error', () => resolve([]));
    req.write(payload);
    req.end();
  });
}

async function flushPending() {
  flushTimer = null;
  if (!pending.size) return;

  if (rlRemaining <= 1 && Date.now() < rlResetAt) {
    // Out of budget: retry after the window resets rather than burning requests.
    flushTimer = setTimeout(flushPending, Math.max(1000, rlResetAt - Date.now()));
    return;
  }

  const ips = [...pending.keys()].slice(0, MAX_BATCH);
  const results = await ipApiBatch(ips);
  const byIp = new Map();
  for (const r of results) if (r?.query) byIp.set(r.query, r);

  for (const ip of ips) {
    const r = byIp.get(ip);
    // ip-api answers "success" for reserved ranges (TEST-NET, documentation
    // blocks) with literal placeholders - countryCode "cc", city "city". A real
    // ISO code is the cheapest way to tell those apart from a genuine hit.
    const plausible = r && /^[A-Za-z]{2}$/.test(r.countryCode || '')
      && (r.countryCode || '').toLowerCase() !== 'cc';
    const rec =
      r && r.status === 'success' && Number.isFinite(r.lat) && plausible
        ? {
            lat: r.lat, lon: r.lon, cc: r.countryCode ?? null, country: r.country ?? null,
            city: r.city || null,
            asn: Number(/^AS(\d+)/.exec(r.as || '')?.[1]) || null,
            org: (r.as || '').replace(/^AS\d+\s*/, '') || null,
          }
        : null;
    cacheSet(ip, rec);
    for (const resolve of pending.get(ip) || []) resolve(rec);
    pending.delete(ip);
  }

  if (pending.size) flushTimer = setTimeout(flushPending, FLUSH_MS);
}

function viaIpApi(ip) {
  return new Promise((resolve) => {
    if (!pending.has(ip)) pending.set(ip, []);
    pending.get(ip).push(resolve);
    // A full batch is worth sending immediately; anything less waits.
    if (pending.size >= MAX_BATCH) {
      clearTimeout(flushTimer);
      flushTimer = setTimeout(flushPending, 0);
    } else if (!flushTimer) {
      flushTimer = setTimeout(flushPending, FLUSH_MS);
    }
  });
}

// ---- public API -------------------------------------------------------------

export function geoCached(ip) {
  return cache.get(ip) ?? undefined;
}

export async function geoLookup(ip) {
  if (!ip || isUnroutable(ip)) return null;
  const hit = cache.get(ip);
  if (hit !== undefined) return hit;
  if (mode === 'mmdb' || mode === 'mmdb+asn') return fromMmdb(ip);
  if (mode === 'ip-api') return viaIpApi(ip);
  return null;
}

export function geoStats() {
  return { mode, cached: cache.size, queued: pending.size, rlRemaining };
}
