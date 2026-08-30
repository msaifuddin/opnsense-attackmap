import crypto from 'node:crypto';

/**
 * Parser for raw pf filterlog lines.
 *
 * The paged log endpoint (/api/diagnostics/log/core/filter) returns raw syslog
 * rather than the parsed rows /api/diagnostics/firewall/log gives us. That is
 * worth handling, because it is the only way to read more than a few hours of
 * history: the parsed endpoint has no cursor, so reaching a day back means one
 * enormous request, and at 400k rows that exhausts PHP's memory limit and dies
 * on the firewall. The paged one costs ~3 MB per 10k rows and reaches 72 hours.
 *
 * The format is positional CSV, and the field order changes after the IP
 * version, which is the part that actually needs care:
 *
 *   0 rulenr  1 subrulenr  2 anchor  3 label  4 interface  5 reason
 *   6 action  7 dir  8 ipversion
 *   v4:  9 tos  10 ecn  11 ttl  12 id  13 offset  14 flags  15 protonum
 *        16 protoname  17 length  18 src  19 dst  [20 srcport  21 dstport]
 *   v6:  9 class  10 flowlabel  11 hoplimit  12 protoname  13 protonum
 *        14 length  15 src  16 dst  [17 srcport  18 dstport]
 *
 * Note v4 puts protonum before protoname and v6 reverses them. Protocols
 * without ports (icmp, gre, esp) simply stop after dst, where a `datalength=N`
 * field appears instead - so port fields are read defensively, never assumed.
 */

const isPort = (v) => /^\d{1,5}$/.test(v ?? '');

/**
 * @returns a row shaped like /api/diagnostics/firewall/log's, so normalizeFw()
 *   consumes it unchanged, or null for anything that is not a usable filterlog
 *   line.
 */
export function parseFilterLine(line, timestamp) {
  if (!line) return null;
  const f = String(line).trim().split(',');
  // Shortest useful form is icmp/gre: through dst plus a datalength field.
  if (f.length < 20) return null;

  const action = f[6];
  if (action !== 'pass' && action !== 'block') return null;
  const ipver = f[8];

  let protoname, length, src, dst, sport, dport;
  if (ipver === '4') {
    protoname = f[16]; length = f[17]; src = f[18]; dst = f[19];
    sport = f[20]; dport = f[21];
  } else if (ipver === '6') {
    protoname = f[12]; length = f[14]; src = f[15]; dst = f[16];
    sport = f[17]; dport = f[18];
  } else {
    return null;
  }
  if (!src || !dst) return null;

  // icmp and friends put "datalength=64" where a port would be.
  const hasPorts = isPort(sport) && isPort(dport);

  return {
    // The parsed endpoint's __digest__ is unique per row; field 3 here is the
    // matching RULE's label and repeats across thousands of rows, so it cannot
    // serve as an identity. History is deduplicated by time bucket rather than
    // by key, but a stable synthetic digest keeps the shape honest.
    __digest__: crypto.createHash('md5').update(`${timestamp}|${line}`).digest('hex'),
    __timestamp__: timestamp,
    action,
    interface: f[4],
    dir: f[7] === 'in' ? 'in' : 'out',
    protoname: protoname || 'ip',
    src,
    dst,
    srcport: hasPorts ? sport : null,
    dstport: hasPorts ? dport : null,
    length: /^\d+$/.test(length ?? '') ? length : null,
    label: f[3] || null,
  };
}
