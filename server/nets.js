/** IP classification helpers: is this address "us" or is it out on the internet? */

const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export const isV4 = (ip) => v4.test(ip);
export const isV6 = (ip) => typeof ip === 'string' && ip.includes(':');

function v4ToInt(ip) {
  const m = v4.exec(ip);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = (n * 256) + o;
  }
  return n;
}

// Expand to 32 hex nibbles so prefix comparison is a plain string compare.
function v6ToNibbles(ip) {
  if (!isV6(ip)) return null;
  let addr = ip.split('%')[0];
  const [head, tail = ''] = addr.split('::');
  const h = head ? head.split(':').filter(Boolean) : [];
  const t = tail ? tail.split(':').filter(Boolean) : [];
  const fill = addr.includes('::') ? Array(8 - h.length - t.length).fill('0') : [];
  const groups = [...h, ...fill, ...t];
  if (groups.length !== 8) return null;
  return groups.map((g) => g.padStart(4, '0')).join('').toLowerCase();
}

function parseCidr(cidr) {
  const [addr, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (isV4(addr)) {
    const base = v4ToInt(addr);
    if (base === null || !Number.isFinite(bits)) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return { v: 4, base: (base & mask) >>> 0, mask };
  }
  const nib = v6ToNibbles(addr);
  if (!nib || !Number.isFinite(bits)) return null;
  return { v: 6, prefix: nib.slice(0, Math.ceil(bits / 4)), bits };
}

/**
 * Build a predicate matching any of the given CIDRs. Extra single addresses
 * (such as the WAN IP) can be added later via `.add()`, since the WAN address
 * is only discovered at startup.
 */
export function makeNetMatcher(cidrs = []) {
  const ranges = cidrs.map(parseCidr).filter(Boolean);
  const singles = new Set();

  const match = (ip) => {
    if (!ip) return false;
    if (singles.has(ip)) return true;
    if (isV4(ip)) {
      const n = v4ToInt(ip);
      if (n === null) return false;
      return ranges.some((r) => r.v === 4 && ((n & r.mask) >>> 0) === r.base);
    }
    const nib = v6ToNibbles(ip);
    if (!nib) return false;
    return ranges.some((r) => r.v === 6 && nib.startsWith(r.prefix));
  };

  match.add = (ip) => {
    if (ip) singles.add(ip);
    return match;
  };
  match.has = (ip) => singles.has(ip);
  return match;
}

/** Addresses that can never be geolocated, so we should not waste a lookup. */
export function isUnroutable(ip) {
  if (!ip) return true;
  if (isV4(ip)) {
    const n = v4ToInt(ip);
    if (n === null) return true;
    const o = ip.split('.').map(Number);
    return (
      o[0] === 0 || o[0] === 10 || o[0] === 127 ||
      (o[0] === 169 && o[1] === 254) ||
      (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
      (o[0] === 192 && o[1] === 168) ||
      (o[0] === 100 && o[1] >= 64 && o[1] <= 127) ||
      (o[0] === 198 && (o[1] === 18 || o[1] === 19)) ||
      o[0] >= 224
    );
  }
  if (isV6(ip)) {
    const s = ip.toLowerCase();
    return s === '::1' || s === '::' || s.startsWith('fe80') || s.startsWith('fd') ||
           s.startsWith('fc') || s.startsWith('ff');
  }
  return true;
}
