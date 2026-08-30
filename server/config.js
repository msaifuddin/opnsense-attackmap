import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Minimal .env loader so the service needs no dotenv dependency and no
// --env-file flag (which would differ between the local run and the container).
function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
}
loadEnvFile(path.join(ROOT, '.env'));

const str = (k, d = '') => (process.env[k] ?? d).trim();
const num = (k, d) => {
  // Number('') is 0, not NaN - without the empty check every unset numeric
  // variable silently resolves to 0 instead of its default, which is how
  // GEO_REFRESH_DAYS ended up re-downloading the databases on every check.
  const raw = str(k, '');
  if (raw === '') return d;
  const v = Number(raw);
  return Number.isFinite(v) ? v : d;
};
const bool = (k, d) => {
  const v = str(k, '').toLowerCase();
  if (!v) return d;
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
};
const list = (k, d = []) => {
  const v = str(k, '');
  return v ? v.split(',').map((s) => s.trim()).filter(Boolean) : d;
};

// "+10:00" / "-05:30" / "+1000" / "Z" -> minutes east of UTC
export function parseTzOffset(spec) {
  const s = (spec || '').trim();
  if (!s || s === 'Z' || s.toUpperCase() === 'UTC') return 0;
  const m = /^([+-])(\d{1,2}):?(\d{2})?$/.exec(s);
  if (!m) throw new Error(`FW_TZ_OFFSET is not a valid offset: "${spec}" (expected e.g. +10:00)`);
  const sign = m[1] === '-' ? -1 : 1;
  return sign * (Number(m[2]) * 60 + Number(m[3] || 0));
}

/** "90m" / "24h" / "7d" -> milliseconds. Returns null if it is not a duration. */
export function parseWindow(spec) {
  const m = /^(\d+)\s*([mhd])$/.exec(String(spec || '').trim().toLowerCase());
  if (!m) return null;
  const mult = { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
  const ms = Number(m[1]) * mult;
  return ms > 0 ? ms : null;
}

// "auto" (the default) derives the offset at startup by comparing a firewall
// log timestamp to the current time. Hard-coding a default here would be wrong
// for everyone who does not share the author's timezone.
const fwTzOffsetSpec = str('FW_TZ_OFFSET', 'auto');
const fwTzAuto = fwTzOffsetSpec.toLowerCase() === 'auto';

// Privacy presets. "public" is the default: this is meant to be publishable, so
// nothing identifying about the local network leaves the server unless someone
// deliberately turns it on. Individual keys below always override the preset.
const PRIVACY_PRESETS = {
  public: {
    showWanIp: false,
    maskLocalIps: true,
    showRuleLabels: false,
    showDnsSni: false,
    showInterfaces: false,
    homeFuzzKm: 25,
  },
  private: {
    showWanIp: true,
    maskLocalIps: false,
    showRuleLabels: true,
    showDnsSni: true,
    showInterfaces: true,
    homeFuzzKm: 0,
  },
};

const presetName = str('PRIVACY', 'public').toLowerCase();
const preset = PRIVACY_PRESETS[presetName] ?? PRIVACY_PRESETS.public;
// Only override the preset when the variable is actually present, so an unset
// key inherits the preset rather than silently defaulting to false.
const pick = (key, fallback) => (str(key, '') === '' ? fallback : bool(key, fallback));

export const config = {
  branding: {
    title: str('SITE_TITLE', 'ATTACK MAP'),
    subtitle: str('SITE_SUBTITLE', ''),
    description: str('SITE_DESCRIPTION', 'Live firewall and IDS activity'),
    pageTitle: str('PAGE_TITLE', ''),
  },
  // Clicking an address opens a reputation/whois lookup. "{ip}" is substituted.
  // Set empty to turn the links off - note that following one tells that
  // service which addresses you are looking at.
  ipLookupUrl: str('IP_LOOKUP_URL', 'https://radar.cloudflare.com/ip/{ip}'),
  privacy: {
    preset: presetName in PRIVACY_PRESETS ? presetName : 'public',
    showWanIp: pick('SHOW_WAN_IP', preset.showWanIp),
    maskLocalIps: pick('MASK_LOCAL_IPS', preset.maskLocalIps),
    showRuleLabels: pick('SHOW_RULE_LABELS', preset.showRuleLabels),
    showDnsSni: pick('SHOW_DNS_SNI', preset.showDnsSni),
    showInterfaces: pick('SHOW_INTERFACES', preset.showInterfaces),
    homeFuzzKm: str('HOME_FUZZ_KM', '') === '' ? preset.homeFuzzKm : num('HOME_FUZZ_KM', preset.homeFuzzKm),
    // Salt for the stable pseudonyms local addresses are replaced with. RFC1918
    // space is small enough to brute-force an unsalted hash, so this defaults to
    // a per-boot random value. Set it only if you want labels stable across
    // restarts, and treat it as a secret.
    salt: str('PRIVACY_SALT', ''),
  },
  opnsense: {
    url: str('OPNSENSE_URL', 'https://192.168.1.1').replace(/\/+$/, ''),
    key: str('OPNSENSE_KEY'),
    secret: str('OPNSENSE_SECRET'),
    user: str('OPNSENSE_USER'),
    pass: str('OPNSENSE_PASS'),
    tlsInsecure: bool('TLS_INSECURE', true),
  },
  // Ranking panels are computed from time-bucketed counters, so their cost
  // scales with the number of distinct attackers rather than with traffic
  // volume - which is what makes a week affordable when an hour of raw events
  // was already the ceiling.
  stats: {
    // Windows offered in the UI, shortest first. The first is the default.
    windows: list('STATS_WINDOWS', ['1h', '24h']),
    // Must cover the longest window above. A little headroom, so the oldest
    // bucket is not being evicted at the exact moment the 24h view asks for it.
    retainHours: num('STATS_RETAIN_HOURS', 26),
    // History survives restarts. The file holds real, unredacted addresses from
    // your network - it lives in data/, which is gitignored, and redaction still
    // happens on the way out so nothing changes on the wire.
    persist: bool('STATS_PERSIST', true),
    file: str('STATS_FILE', './data/rollup.json'),
    saveEveryMs: num('STATS_SAVE_MS', 300_000),
    // Rows pulled from the firewall log at startup to seed the statistics, so a
    // fresh deploy does not show two minutes of data under a "24h" label. Only
    // the gap since the last save is used; the rest is discarded.
    //
    // Keep this well clear of the firewall's limits: measured on OPNsense
    // 26.7.1, 100k rows returns ~9h in 14s, but 400k exhausts PHP's 1 GB memory
    // limit and the request dies server-side. 50k is roughly 4.5h with room for
    // a much higher event rate than the box currently sees.
    backfillRows: num('BACKFILL_ROWS', 50_000),
  },
  ids: {
    // What counts as a threat rather than telemetry, on the 1-4 scale
    // classifySignature() derives from the ET class token. 3 keeps SCAN,
    // EXPLOIT, TROJAN, MALWARE, CNC, DOS and friends while dropping the INFO /
    // POLICY / DNS / TLS / CHAT chatter your own hosts generate. Set 1 to rank
    // every alert, which is what the panel used to do.
    minSeverity: num('IDS_MIN_SEVERITY', 3),
  },
  // Resolve attacker addresses to hostnames for the ranking panels. Turning
  // this off is a reasonable choice when publishing: PTR queries tell your
  // resolver chain which addresses you are inspecting, the same class of
  // disclosure IP_LOOKUP_URL carries. Local addresses are never resolved
  // regardless of this setting.
  rdns: {
    enabled: bool('RDNS', true),
  },
  poll: {
    fwMs: num('FW_POLL_MS', 2000),
    idsMs: num('IDS_POLL_MS', 5000),
    fwLimit: num('FW_LIMIT', 1000),
    idsRowCount: num('IDS_ROWCOUNT', 200),
  },
  fwTzOffsetSpec,
  fwTzAuto,
  fwTzOffsetMinutes: fwTzAuto ? null : parseTzOffset(fwTzOffsetSpec),
  home: {
    lat: str('HOME_LAT') ? Number(str('HOME_LAT')) : null,
    lon: str('HOME_LON') ? Number(str('HOME_LON')) : null,
    label: str('HOME_LABEL', 'home.lan'),
    // Longitude the map is centred on. Default 0 is the conventional world map
    // everyone recognises. The literal "home" re-centres on your own longitude
    // instead - which does put every arc dead-centre, but at the cost of an
    // unfamiliar layout with the Americas on the right.
    centerLon: str('MAP_CENTER_LON', '0').toLowerCase() === 'home'
      ? null
      : (Number(str('MAP_CENTER_LON', '0')) || 0),
    nets: list('HOME_NETS', [
      '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12',
      '100.64.0.0/10', '169.254.0.0/16', 'fd00::/8', 'fe80::/10',
    ]),
  },
  geo: {
    cityDb: str('GEO_CITY_DB', './data/GeoLite2-City.mmdb'),
    asnDb: str('GEO_ASN_DB', './data/GeoLite2-ASN.mmdb'),
    fallback: bool('GEO_FALLBACK', true),
    // GeoLite2 databases are fetched automatically from FyraLabs' mirror of
    // MaxMind's releases, which needs no account or licence key. Downloads
    // happen in the background; the service starts on the ip-api fallback and
    // switches over once a database is on disk.
    autoDownload: bool('GEO_AUTO_DOWNLOAD', true),
    // How stale a database may get before it is re-fetched, and equally how
    // often the check runs. One number, not two.
    refreshDays: num('GEO_REFRESH_DAYS', 7),
    // When lookups go to a third-party service, Suricata alerts on them and the
    // map fills with signatures it generated itself. Drop those so the feed
    // reflects your network rather than this tool. Set 0 to see them.
    suppressOwnAlerts: bool('SUPPRESS_GEO_ALERTS', true),
  },
  server: {
    port: num('PORT', 8474),
    host: str('HOST', '0.0.0.0'),
  },
  render: {
    collapseMs: num('COLLAPSE_MS', 10000),
    maxArcs: num('MAX_ARCS', 300),
    bufferSize: num('BUFFER_SIZE', 2000),
  },
  replay: {
    enabled: bool('REPLAY', false),
    speed: num('REPLAY_SPEED', 10),
  },
};

export const usingApiKey = Boolean(config.opnsense.key && config.opnsense.secret);
