import dns from 'node:dns';
import { config } from './config.js';
import { isUnroutable, isV4, isV6 } from './nets.js';

/**
 * IP -> PTR hostname, for the ranking panels.
 *
 * "45.155.205.233" says nothing at a glance; "scan-07.internet-census.org" tells
 * you immediately whether you are looking at a research scanner or a bot. The
 * lookup is deliberately non-blocking: a miss returns undefined and schedules
 * the query, and the next stats tick (one second later) picks up the answer.
 * Nothing on the broadcast path ever waits on DNS.
 *
 * Privacy is enforced here rather than at the call site, so there is no way to
 * ask for a hostname we should not be resolving:
 *   - local/RFC1918 addresses are never queried - a LAN PTR would publish your
 *     internal host inventory, which is exactly what MASK_LOCAL_IPS prevents
 *   - the WAN address is never queried
 *   - only literal IPs are queried, and redaction runs first, so a pseudonym
 *     like "lan-cebf28" is not a lookup candidate in the first place
 */

const HIT_TTL_MS = 6 * 3600_000;
const MISS_TTL_MS = 30 * 60_000;
const MAX_CACHE = 20_000;
const MAX_INFLIGHT = 8;

// dns.reverse() has no timeout of its own and will sit on a black-holed
// nameserver until the OS gives up. A Resolver can be bounded.
const resolver = new dns.promises.Resolver({ timeout: 3000, tries: 1 });

const cache = new Map(); // ip -> { host: string|null, at: number }
const inflight = new Set();
const queue = [];

let wanIp = null;
let stats = { hits: 0, misses: 0, errors: 0 };

/** Told by the pipeline once the WAN address is known, as the redactor is. */
export function rdnsLearn({ wanIp: ip } = {}) {
  if (ip) wanIp = ip;
}

function cacheSet(ip, host) {
  if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
  cache.set(ip, { host, at: Date.now() });
  return host;
}

/**
 * A PTR record is text controlled by whoever owns the address block, so it is
 * treated as hostile input. The client escapes HTML already; rejecting anything
 * outside the hostname charset additionally keeps bidi overrides and lookalike
 * scripts out of the panel.
 */
function sanitize(name) {
  if (typeof name !== 'string') return null;
  const host = name.trim().replace(/\.$/, '').toLowerCase();
  if (!host || host.length > 100) return null;
  if (!/^[a-z0-9._-]+$/.test(host)) return null;
  if (!host.includes('.')) return null; // a bare label is not a useful answer
  return host;
}

function resolvable(ip) {
  if (!config.rdns.enabled) return false;
  if (typeof ip !== 'string' || !ip) return false;
  if (!isV4(ip) && !isV6(ip)) return false; // pseudonym, or not an address at all
  if (ip === wanIp) return false;
  return !isUnroutable(ip);
}

async function run(ip) {
  inflight.add(ip);
  try {
    const [name] = await resolver.reverse(ip);
    const host = sanitize(name);
    cacheSet(ip, host);
    if (host) stats.hits++; else stats.misses++;
  } catch (e) {
    // ENOTFOUND/ENODATA is the common case - most scanner addresses have no PTR
    // at all - and is a legitimate answer, not a failure.
    cacheSet(ip, null);
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') stats.misses++;
    else stats.errors++;
  } finally {
    inflight.delete(ip);
    pump();
  }
}

function pump() {
  while (queue.length && inflight.size < MAX_INFLIGHT) {
    const ip = queue.shift();
    if (!inflight.has(ip)) run(ip);
  }
}

function schedule(ip) {
  if (inflight.has(ip) || queue.includes(ip)) return;
  // A scan burst must not fan out into hundreds of concurrent DNS queries.
  queue.push(ip);
  pump();
}

/**
 * @returns {string|null|undefined}
 *   string    - resolved hostname
 *   null      - looked up, no PTR record (or not resolvable at all)
 *   undefined - not known yet; a lookup has been scheduled
 */
export function rdnsCached(ip) {
  if (!resolvable(ip)) return null;
  const hit = cache.get(ip);
  if (hit) {
    const ttl = hit.host ? HIT_TTL_MS : MISS_TTL_MS;
    if (Date.now() - hit.at < ttl) return hit.host;
    cache.delete(ip);
  }
  schedule(ip);
  return undefined;
}

/**
 * Attach hostnames to a stats payload that has ALREADY been through the
 * redactor. Order matters: anything the redactor replaced with a pseudonym is
 * no longer an IP, so `resolvable()` refuses it and no query is ever made for a
 * local address.
 */
export function withHostnames(s) {
  if (!config.rdns.enabled) return s;
  const tag = (r) => {
    const host = rdnsCached(r.key);
    return host ? { ...r, host } : r;
  };
  const tagSrc = (r) => {
    const host = rdnsCached(r.ip);
    return host ? { ...r, host } : r;
  };
  const sources = (rows) => rows.map((r) => (
    r.sources ? { ...r, sources: r.sources.map(tagSrc) } : r
  ));
  return {
    ...s,
    topAttackers: s.topAttackers.map(tag),
    topPorts: sources(s.topPorts),
    topSignatures: sources(s.topSignatures),
    topSignaturesAll: sources(s.topSignaturesAll),
  };
}

export function rdnsStats() {
  return {
    enabled: config.rdns.enabled,
    cached: cache.size,
    queued: queue.length,
    inflight: inflight.size,
    ...stats,
  };
}
