/**
 * Smoke test against the live OPNsense box.
 *   npm run smoke
 *
 * Proves the three things the whole service depends on:
 *   1. auth works for both GET and the POST-only IDS feed
 *   2. digest-based polling returns an exact, gap-free, non-overlapping delta
 *   3. FW_TZ_OFFSET is correct (the firewall log carries no timezone)
 */
import { OPNsenseClient } from '../server/opnsense.js';
import { config } from '../server/config.js';
import {
  fwTimestampToDate, detectFwTzOffset, formatTzOffset, setFwTzOffsetMinutes,
} from '../server/normalize.js';

const ok = (m) => console.log(`  \x1b[32mPASS\x1b[0m ${m}`);
const bad = (m) => console.log(`  \x1b[31mFAIL\x1b[0m ${m}`);
const info = (m) => console.log(`  \x1b[90m${m}\x1b[0m`);
let failures = 0;
const check = (cond, m) => (cond ? ok(m) : (failures++, bad(m)));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const client = new OPNsenseClient();

console.log(`\nOPNsense ${config.opnsense.url}  (auth: ${client.authMode})\n`);

console.log('1. connectivity + auth');
const ids = await client.idsStatus();
check(ids.status === 'running', `IDS service status = ${ids.status}`);
const ifaces = await client.interfaceNames();
info(`interfaces: ${Object.entries(ifaces).map(([k, v]) => `${k}=${v}`).join(' ')}`);
const wan = await client.wanAddress().catch(() => null);
info(`WAN address: ${wan ?? '(not detected)'}`);

console.log('\n2. firewall log + digest delta');
const seed = await client.fwLog({ limit: 1 });
check(seed.length === 1, `seed fetch returned ${seed.length} row`);
const digest = seed[0]?.__digest__;
check(Boolean(digest), `seed digest = ${digest}`);
info(`seed timestamp = ${seed[0]?.__timestamp__}`);

// Mirror what the service does at startup, so the timezone check below tests
// the offset that will actually be used.
let tzSource = `FW_TZ_OFFSET=${config.fwTzOffsetSpec}`;
if (config.fwTzAuto) {
  const detected = detectFwTzOffset(seed[0]?.__timestamp__);
  check(detected !== null, `auto-detected firewall offset = ${detected === null ? 'FAILED' : formatTzOffset(detected)}`);
  if (detected !== null) setFwTzOffsetMinutes(detected);
  tzSource = 'auto-detected';
}

const waitMs = 6000;
info(`waiting ${waitMs / 1000}s for new events...`);
await sleep(waitMs);

// NOTE: the digest filter is INCLUSIVE - it returns the digest row itself as the
// oldest entry. fwLogSince() drops it, otherwise the boundary event would be
// re-emitted on every single poll.
const raw = await client.fwLog({ limit: config.poll.fwLimit, digest });
check(
  raw.some((r) => r.__digest__ === digest),
  'raw digest fetch is inclusive of the seed row (documented API behaviour)'
);

const { rows: delta, saturated } = await client.fwLogSince(digest);
check(delta.length > 0, `fwLogSince returned ${delta.length} new rows`);
check(!saturated, 'fetch was not saturated (no silent event loss)');
check(
  !delta.some((r) => r.__digest__ === digest),
  'fwLogSince strips the seed row, so nothing is emitted twice'
);
check(delta.length === raw.length - 1, `stripped exactly one row (${raw.length} -> ${delta.length})`);
const uniq = new Set(delta.map((r) => r.__digest__));
check(uniq.size === delta.length, `delta rows are unique (${uniq.size}/${delta.length})`);

if (delta.length) {
  const times = delta.map((r) => fwTimestampToDate(r.__timestamp__).getTime());
  const span = (Math.max(...times) - Math.min(...times)) / 1000;
  check(
    span <= waitMs / 1000 + 2,
    `delta spans ${span}s, consistent with the ${waitMs / 1000}s wait (no backfill)`
  );
  info(`rate: ~${(delta.length / (waitMs / 1000)).toFixed(1)} events/sec`);

  const mix = {};
  for (const r of delta) {
    const k = `${r.action}/${r.interface}/${r.dir}`;
    mix[k] = (mix[k] || 0) + 1;
  }
  info(`mix: ${Object.entries(mix).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join(' ')}`);
}

console.log('\n3. IDS alerts (POST)');
let alerts = { rows: [], total: 0 };
try {
  alerts = await client.idsAlerts({ rowCount: 200 });
  check(alerts.rows.length > 0, `queryAlerts returned ${alerts.rows.length} rows (total=${alerts.total})`);
  const byIface = {};
  for (const r of alerts.rows) byIface[r.in_iface] = (byIface[r.in_iface] || 0) + 1;
  info(`by interface: ${Object.entries(byIface).map(([k, v]) => `${k}=${v}`).join(' ') || '(none)'}`);
  // Which device is WAN varies per install, so ask the firewall rather than
  // assuming a naming convention.
  const wanDev = Object.entries(ifaces).find(([, label]) => String(label).toLowerCase() === 'wan')?.[0];
  if (wanDev && byIface[wanDev]) ok(`WAN IDS alerts present (${wanDev}=${byIface[wanDev]})`);
  else if (wanDev) info(`no alerts on the WAN interface (${wanDev}) yet - Suricata may not be bound to it, or may still be warming up`);
  else info('could not identify a WAN interface to check');
  const sigs = {};
  for (const r of alerts.rows) sigs[r.alert] = (sigs[r.alert] || 0) + 1;
  Object.entries(sigs).sort((a, b) => b[1] - a[1]).slice(0, 5)
    .forEach(([s, n]) => info(`  ${String(n).padStart(4)}  ${s}`));
} catch (e) {
  failures++;
  bad(`queryAlerts threw: ${e.message}`);
  if (client.authMode === 'session') {
    info('POST needs a valid CSRF token; an API key would avoid this entirely.');
  }
}

console.log('\n4. timezone sanity (FW_TZ_OFFSET)');
if (delta.length && alerts.rows.length) {
  const fwNewest = Math.max(...delta.map((r) => fwTimestampToDate(r.__timestamp__).getTime()));
  const idsNewest = Math.max(...alerts.rows.map((r) => Date.parse(r.timestamp)));
  const skewMin = Math.abs(fwNewest - idsNewest) / 60000;
  info(`offset source: ${tzSource}`);
  info(`fw newest  = ${new Date(fwNewest).toISOString()}`);
  info(`ids newest = ${new Date(idsNewest).toISOString()}`);
  info(`host now   = ${new Date().toISOString()}`);
  check(skewMin < 5, `fw/ids clock skew = ${skewMin.toFixed(1)} min (must be < 5)`);
} else {
  info('skipped - need both feeds to compare');
}

console.log(failures ? `\n\x1b[31m${failures} check(s) failed\x1b[0m\n` : '\n\x1b[32mall checks passed\x1b[0m\n');
process.exit(failures ? 1 : 0);
