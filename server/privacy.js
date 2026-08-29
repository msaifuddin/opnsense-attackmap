import crypto from 'node:crypto';
import { config } from './config.js';
import { isUnroutable } from './nets.js';

/**
 * Strips identifying detail out of events before they leave the server.
 *
 * This runs on the broadcast path, not in the browser: hiding a field in CSS
 * still ships it over the WebSocket, where anyone with devtools - or anyone
 * you hand a recording to - can read it. If it is redacted here, it was never
 * sent.
 *
 * What counts as private:
 *   - the WAN address (it is your home's public identity)
 *   - LAN/RFC1918 addresses (your internal topology and host inventory)
 *   - firewall rule labels (they describe how your network is segmented)
 *   - TLS SNI and DNS query names (they are a log of what you browse)
 *   - the precise geolocation of home
 *
 * Outbound destination addresses are left alone - those are other people's
 * servers, not yours.
 */

// Random per boot unless pinned, so pseudonyms cannot be correlated across
// separate publications of the same network.
const SALT = config.privacy.salt || crypto.randomBytes(16).toString('hex');

const pseudonymCache = new Map();

function pseudonym(ip, prefix = 'host') {
  if (!ip) return ip;
  const hit = pseudonymCache.get(ip);
  if (hit) return hit;
  const h = crypto.createHmac('sha256', SALT).update(ip).digest('hex').slice(0, 6);
  const label = `${prefix}-${h}`;
  if (pseudonymCache.size < 20_000) pseudonymCache.set(ip, label);
  return label;
}

/**
 * Deterministic offset of up to `km`, derived from the coordinate itself so the
 * marker lands in the same wrong place every restart. A random-per-frame jitter
 * would let an observer average the samples back to the true position.
 */
function fuzzCoords(lat, lon, km) {
  if (!km || !Number.isFinite(lat) || !Number.isFinite(lon)) return { lat, lon };
  const seed = crypto.createHmac('sha256', SALT).update(`${lat},${lon}`).digest();
  const angle = (seed.readUInt16BE(0) / 65535) * Math.PI * 2;
  const dist = (seed.readUInt16BE(2) / 65535) * km;
  const dLat = (dist / 111.32) * Math.cos(angle);
  const dLon = (dist / (111.32 * Math.cos((lat * Math.PI) / 180) || 1)) * Math.sin(angle);
  return {
    lat: Math.round((lat + dLat) * 1e4) / 1e4,
    lon: Math.round((lon + dLon) * 1e4) / 1e4,
  };
}

export class Redactor {
  constructor(opts = config.privacy) {
    this.opts = opts;
    this.wanIp = null;
    this.homeGeo = null;
    this.ifaceRoles = new Map(); // device name -> wan | lan | opt
  }

  /** Told by the pipeline once the WAN address and interface map are known. */
  learn({ wanIp, interfaceNames, homeGeo } = {}) {
    if (wanIp) this.wanIp = wanIp;
    if (homeGeo) this.homeGeo = homeGeo;
    for (const [dev, label] of Object.entries(interfaceNames || {})) {
      const l = String(label).toLowerCase();
      // Substring match, so a dedicated physical capture interface (one assigned
      // to sniff the parent NIC of a PPPoE link, typically named something like
      // "WAN_PHY") still reads as wan rather than falling through to opt.
      const role = l === 'loopback' ? 'lo'
        : l.includes('wan') ? 'wan'
        : l.includes('lan') ? 'lan'
        : 'opt';
      this.ifaceRoles.set(dev, role);
    }
  }

  get active() {
    const o = this.opts;
    return !o.showWanIp || o.maskLocalIps || !o.showRuleLabels || !o.showDnsSni || !o.showInterfaces || o.homeFuzzKm > 0;
  }

  #ip(ip) {
    if (!ip) return ip;
    if (ip === this.wanIp) return this.opts.showWanIp ? ip : pseudonym(ip, 'wan');
    if (isUnroutable(ip)) return this.opts.maskLocalIps ? pseudonym(ip, 'lan') : ip;
    return ip; // public address of some other party - not ours to hide
  }

  /** Is this the operator's own geo record, however it got attached? */
  #isHomeGeo(g) {
    if (!g || !this.homeGeo) return false;
    return g.lat === this.homeGeo.lat && g.lon === this.homeGeo.lon;
  }

  #iface(name) {
    if (this.opts.showInterfaces || !name) return name;
    // Suricata's netmap capture tags the host-stack ring as "igc0^"; the trailing
    // caret is a capture-layer detail, not a different interface.
    return this.ifaceRoles.get(String(name).replace(/\^+$/, '')) ?? 'iface';
  }

  home(h) {
    if (!h) return h;
    const { lat, lon } = fuzzCoords(h.lat, h.lon, this.opts.homeFuzzKm);
    return {
      ...h,
      lat,
      lon,
      // The ASN/org of a home connection names the ISP and, with the city, is
      // close to an address. City stays - it is what makes the map readable.
      org: this.opts.showWanIp ? h.org : null,
      asn: this.opts.showWanIp ? h.asn : null,
    };
  }

  /** Returns a redacted copy; the original is left intact for internal stats. */
  event(ev) {
    if (!this.active) return ev;
    const out = {
      ...ev,
      iface: this.#iface(ev.iface),
      src: { ...ev.src, ip: this.#ip(ev.src.ip) },
      dst: { ...ev.dst, ip: this.#ip(ev.dst.ip) },
    };
    // Redact by matching the home record itself, not by trusting a flag on the
    // endpoint: an unlocatable remote address used to be stamped with the home
    // geo while its home flag stayed false, which slipped the ISP name past a
    // flag-only check.
    if (ev.src.home || this.#isHomeGeo(ev.src.geo)) out.src.geo = this.home(ev.src.geo);
    if (ev.dst.home || this.#isHomeGeo(ev.dst.geo)) out.dst.geo = this.home(ev.dst.geo);
    if (!this.opts.showRuleLabels) out.rule = null;
    if (!this.opts.showDnsSni) {
      out.sni = null;
      out.dnsQuery = null;
    }
    return out;
  }

  /** Rankings can name attackers freely, but not our own hosts. */
  stats(s) {
    if (!this.active) return s;
    return {
      ...s,
      topAttackers: s.topAttackers.map((r) => ({ ...r, key: this.#ip(r.key) })),
    };
  }

  health(h) {
    if (!this.active) return h;
    return {
      ...h,
      wanIp: this.opts.showWanIp ? h.wanIp : null,
      home: this.home(h.home),
    };
  }
}
