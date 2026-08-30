import { config } from './config.js';

// The firewall's UTC offset in minutes. Set from config, or detected at startup
// when FW_TZ_OFFSET=auto.
let fwOffsetMinutes = config.fwTzOffsetMinutes ?? 0;

export function setFwTzOffsetMinutes(m) {
  if (Number.isFinite(m)) fwOffsetMinutes = m;
}
export const getFwTzOffsetMinutes = () => fwOffsetMinutes;

/**
 * The firewall log's __timestamp__ ("2026-08-29T22:35:02") carries NO timezone,
 * but it is in the firewall's local time. Parsed naively as UTC, every arc lands
 * hours away from now. IDS alerts are unaffected - they carry an explicit offset.
 */
export function fwTimestampToDate(ts, offsetMinutes = fwOffsetMinutes) {
  if (!ts) return new Date(NaN);
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/.exec(ts.trim());
  if (!m) return new Date(ts); // already zoned, or a format we did not expect
  const asUtc = Date.UTC(
    +m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], m[7] ? +m[7].slice(0, 3) : 0
  );
  return new Date(asUtc - offsetMinutes * 60000);
}

/**
 * Infer the firewall's UTC offset from one log timestamp: a freshly written
 * line is "now" in the firewall's local time, so reading it as UTC and diffing
 * against real now gives the offset. Snapped to 15 minutes, which covers every
 * real-world zone. Returns null if the result is implausible.
 */
export function detectFwTzOffset(sampleTs, now = Date.now()) {
  if (!sampleTs) return null;
  const asUtc = fwTimestampToDate(sampleTs, 0).getTime();
  if (!Number.isFinite(asUtc)) return null;
  const minutes = Math.round((asUtc - now) / 60000 / 15) * 15;
  return Math.abs(minutes) > 14 * 60 ? null : minutes;
}

/** "+10:00" style label for an offset in minutes. */
export function formatTzOffset(minutes) {
  const sign = minutes < 0 ? '-' : '+';
  const abs = Math.abs(minutes);
  return `${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
}

/**
 * Emerging Threats signature names encode their class in the second token
 * ("ET INFO ...", "ET SCAN ...", "ET TROJAN ..."). OPNsense's alert feed gives
 * us the signature string and SID but no severity field, so severity is derived
 * from that class rather than invented.
 */
const SEVERITY_BY_CLASS = {
  TROJAN: 4, MALWARE: 4, EXPLOIT: 4, EXPLOIT_KIT: 4, WORM: 4, CNC: 4, PHISHING: 4,
  ATTACK_RESPONSE: 3, SCAN: 3, DOS: 3, SHELLCODE: 3, WEB_SPECIFIC_APPS: 3, WEB_SERVER: 3,
  CURRENT_EVENTS: 3, MOBILE_MALWARE: 4, USER_AGENTS: 2, ADWARE_PUP: 3,
  // HUNTING is the "this could be command-and-control, go and look" class, and
  // it is where malware hiding inside legitimate services - Telegram, Discord,
  // tunnelling providers - actually shows up. Rating it below the threat bar
  // hid exactly the alerts worth investigating, so it sits at 3. Individual
  // noisy rules are handled with IDS_MUTE_SIDS rather than by demoting a whole
  // class of genuine signal.
  POLICY: 2, HUNTING: 3, GAMES: 1, P2P: 2, CHAT: 1, DNS: 2, TLS: 1, TFTP: 2,
  INFO: 1, MISC: 2, COINMINER: 3, JA3: 2, INAPPROPRIATE: 2,
};

export function classifySignature(sig) {
  if (!sig) return { category: 'UNKNOWN', severity: 2 };
  const m = /^(?:ET|GPL)\s+([A-Z0-9_]+)\s/.exec(sig.trim());
  const category = m ? m[1] : 'OTHER';
  return { category, severity: SEVERITY_BY_CLASS[category] ?? 2 };
}

/**
 * Is this alert a genuine threat, or telemetry?
 *
 * With the sensor on LAN most alerts are ET INFO / ET POLICY / ET DNS chatter
 * from your own hosts - real records, but not attacks, and they otherwise
 * outrank actual attacks purely on volume.
 *
 * `blocked` is kept in the test even though Suricata in IDS (non-inline) mode
 * always reports "allowed": it costs nothing now and makes the filter strictly
 * more accurate if the sensor is ever moved to IPS. It cannot be the only test
 * for the same reason - in IDS mode it would match nothing at all.
 */
export function isThreatAlert(ev) {
  if (ev.source !== 'ids') return false;
  // Muting is absolute, deliberately: a rule you have judged to be noise on your
  // network should not reappear in the threats panel because it happened to be
  // dropped. Predictable beats clever, and the alert is still there under "all".
  if (ev.sid != null && config.ids.muteSids.has(String(ev.sid))) return false;
  if (ev.blocked === true) return true;
  return (ev.severity ?? 0) >= config.ids.minSeverity;
}

let seq = 0;
const nextId = () => `${Date.now().toString(36)}-${(seq = (seq + 1) % 1e6).toString(36)}`;

/** Firewall filterlog row -> unified event. */
export function normalizeFw(row, { isHome }) {
  const src = row.src;
  const dst = row.dst;
  // The log's own `dir` is per-interface; for the map what matters is whether
  // the far end is us, so direction is derived from the addresses and only
  // falls back to the logged value when neither end looks like home.
  const srcHome = isHome(src);
  const dstHome = isHome(dst);
  // Both ends ours (LAN -> the firewall's own DNS, IoT chatter) is "internal":
  // it has no far end, so it is neither an attack nor drawable as an arc.
  const dir = srcHome && dstHome ? 'internal'
    : dstHome && !srcHome ? 'in'
    : srcHome && !dstHome ? 'out'
    : row.dir === 'in' ? 'in' : 'out';

  return {
    id: nextId(),
    key: row.__digest__,
    ts: fwTimestampToDate(row.__timestamp__).toISOString(),
    source: 'fw',
    action: row.action === 'block' ? 'block' : 'pass',
    dir,
    iface: row.interface,
    proto: (row.protoname || '').toLowerCase() || 'ip',
    src: { ip: src, port: row.srcport ? Number(row.srcport) : null },
    dst: { ip: dst, port: row.dstport ? Number(row.dstport) : null },
    signature: null,
    sid: null,
    category: null,
    severity: row.action === 'block' ? 3 : 1,
    rule: row.label || null,
    bytes: row.length ? Number(row.length) : null,
    count: 1,
  };
}

/** Suricata eve.json alert row -> unified event. */
export function normalizeIds(row, { isHome }) {
  const src = row.src_ip;
  const dst = row.dest_ip;
  const srcHome = isHome(src);
  const dstHome = isHome(dst);
  // Most current alerts are LAN host -> the firewall's own resolver, which is
  // internal, not an inbound attack. Mislabelling those as "in" is what puts
  // your own hosts at the top of the attacker list.
  const dir = srcHome && dstHome ? 'internal'
    : dstHome && !srcHome ? 'in'
    : srcHome && !dstHome ? 'out'
    : 'in';
  const { category, severity } = classifySignature(row.alert);

  return {
    id: nextId(),
    // eve.json has no digest, so dedupe on the tuple that is unique per alert.
    key: `${row.timestamp}|${row.flow_id}|${row.alert_sid}`,
    ts: new Date(row.timestamp).toISOString(),
    source: 'ids',
    action: 'alert',
    dir,
    iface: row.in_iface,
    proto: (row.proto || '').toLowerCase() || 'ip',
    src: { ip: src, port: row.src_port ?? null },
    dst: { ip: dst, port: row.dest_port ?? null },
    signature: row.alert || null,
    sid: row.alert_sid ?? null,
    category,
    severity,
    blocked: row.alert_action === 'blocked',
    appProto: row.app_proto || null,
    sni: row.tls?.sni || null,
    dnsQuery: row.dns?.queries?.[0]?.rrname || null,
    bytes: row.flow ? (row.flow.bytes_toserver ?? 0) + (row.flow.bytes_toclient ?? 0) : null,
    count: 1,
  };
}

/**
 * The endpoint an event is *about* - who to name when attributing it.
 *
 * Which end that is depends on direction, and getting it wrong is misleading
 * rather than merely unhelpful:
 *   in       - the source; they came to us
 *   out      - the destination; our host is the source, and naming it would
 *              attribute every outbound alert to a pseudonymised LAN host
 *   internal - the source host; there is no far end, and which of our hosts
 *              triggered the rule is the whole question
 */
export function farEnd(ev) {
  return ev.dir === 'out' ? ev.dst : ev.src;
}

// Service ports above 1024 that are worth attacking, so a block aimed at one is
// a real attempt rather than stray traffic. Mirrors PORT_NAMES in public/app.js.
const SERVICE_PORTS = new Set([
  1433, 1521, 1900, 2375, 2376, 3306, 3389, 4444, 5000, 5060, 5432, 5555, 5900,
  5901, 6379, 7547, 8000, 8006, 8080, 8081, 8443, 8728, 8888, 9000, 9200, 11211,
  27017, 32764,
]);

const isServicePort = (p) => p > 0 && (p < 1024 || SERVICE_PORTS.has(p));

/**
 * Was this inbound block actually aimed at something?
 *
 * The rankings were being diluted by blocks from Google and Akamai landing on
 * odd high ports - those are late replies to connections we opened, arriving
 * after the state entry expired, not attacks.
 *
 * The discriminator is the SOURCE port, not the destination. A reply comes FROM
 * the service we talked to, so it carries sport=443; a scanner picks an
 * ephemeral source port and aims at a service. Judging by destination port
 * instead does not work: measured against the live log, the replies land on
 * 8836, 14325, 19445, 25408, 30277 - OPNsense is FreeBSD, whose ephemeral range
 * starts at 10000 rather than Linux's 32768, and some land below even that.
 *
 * Ordering matters. A service destination is an attack whatever the source port,
 * so someone probing SMTP from port 443 is still counted.
 */
export function isAttackTarget(ev) {
  const dport = ev.dst.port;
  if (!dport) return true; // ICMP and friends have no port to judge
  if (isServicePort(dport)) return true;
  // Non-service destination: a service source port means this is the reply leg
  // of a conversation we started.
  return !isServicePort(ev.src.port);
}

/** Layer an event belongs to, which is what the UI toggles are bound to. */
export function layerOf(ev) {
  if (ev.dir === 'internal') return 'internal';
  if (ev.source === 'ids') return 'ids';
  if (ev.action === 'block') return ev.dir === 'in' ? 'block_in' : 'block_out';
  return ev.dir === 'in' ? 'pass_in' : 'pass_out';
}
