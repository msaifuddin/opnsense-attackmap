import { Projection, WorldRenderer } from '/map.js';
import { ArcLayer, colorFor } from '/arcs.js';
import { flagHtml, ccUpper as ccText } from '/flags.js';

const $ = (id) => document.getElementById(id);

const world = new WorldRenderer($('world'));
const layer = new ArcLayer($('arcs'));
let proj = new Projection(innerWidth, innerHeight);

// block_out is rare (~1 in 1000 events) and conceptually outbound, so it rides
// the Outbound toggle rather than earning a legend row of its own.
const GROUP = {
  block_in: 'block_in', ids: 'ids', pass_in: 'pass_in',
  pass_out: 'pass_out', block_out: 'pass_out', internal: 'internal',
};
// Everything on by default - the map shows the whole picture and you switch
// layers off to narrow it, rather than having to discover them.
const enabled = { block_in: true, ids: true, pass_in: true, pass_out: true, internal: true };

const visible = (arc) => enabled[GROUP[arc.layer] ?? 'pass_out'] === true;

// ---------- layout ----------

const rectOf = (sel) => {
  const el = document.querySelector(sel);
  if (!el) return null;
  const r = el.getBoundingClientRect();
  return r.width && r.height ? r : null;
};

/**
 * Insets are derived by intersecting the chrome with the canvas, not from
 * hard-coded widths. That way the same code covers both layouts: on desktop the
 * side rails overlap the canvas and push the map inward, while on mobile they
 * sit below it, overlap nothing, and the map gets the full width.
 */
function chromeInsets(canvasRect) {
  const gap = 12;
  const overlapsVertically = (r) => r.bottom > canvasRect.top + 1 && r.top < canvasRect.bottom - 1;
  const inset = { l: gap, r: gap, t: gap, b: gap };

  const bar = rectOf('.bar');
  if (bar && bar.bottom > canvasRect.top) inset.t = Math.max(inset.t, bar.bottom - canvasRect.top + gap);

  // The console sits above the legend, so it is the lower boundary when present.
  // Without this the map would draw behind it rather than moving up out of the
  // way - which is the whole point of putting it in the map's dead band.
  for (const sel of ['.legend', '.console']) {
    const r = rectOf(sel);
    if (r && r.top < canvasRect.bottom) inset.b = Math.max(inset.b, canvasRect.bottom - r.top + gap);
  }

  const left = rectOf('.panel-left');
  if (left && overlapsVertically(left)) inset.l = Math.max(inset.l, left.right - canvasRect.left + gap);

  const right = rectOf('.panel-right');
  if (right && overlapsVertically(right)) {
    inset.r = Math.max(inset.r, canvasRect.right - right.left + gap);
  }
  return inset;
}

function resize() {
  const dpr = Math.min(devicePixelRatio || 1, 2);
  // The canvas is not always the full viewport - in the stacked layout it is a
  // banner at the top - so measure it rather than assuming innerWidth/Height.
  const rect = document.getElementById('world').getBoundingClientRect();
  proj.resize(rect.width, rect.height, chromeInsets(rect));
  world.draw(proj, dpr);
  layer.configure({ proj, dpr });
}

addEventListener('resize', resize);
addEventListener('orientationchange', () => setTimeout(resize, 200));

// ---------- render loop ----------

// A throw inside a rAF callback kills the chain silently: the canvas freezes on
// its last good frame and nothing in the UI says why. Keep the loop alive and
// surface the error instead.
let renderErrors = 0;
function frame() {
  try {
    layer.render();
  } catch (e) {
    if (renderErrors++ === 0) {
      console.error('[render] frame failed, continuing:', e);
      $('meta').textContent = `render error: ${e.message}`;
    }
  }
  requestAnimationFrame(frame);
}

// ---------- panels ----------

// Flag rendering lives in flags.js so the canvas layer can use it too.

const PORT_NAMES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
  123: 'ntp', 143: 'imap', 443: 'https', 445: 'smb', 587: 'smtp', 1433: 'mssql',
  1900: 'ssdp', 3306: 'mysql', 3389: 'rdp', 5060: 'sip', 5432: 'postgres',
  5900: 'vnc', 6379: 'redis', 8080: 'http-alt', 8443: 'https-alt', 9200: 'elastic',
};

const fmtTime = (iso) => new Date(iso).toLocaleTimeString([], { hour12: false });

function tickerRow(arc) {
  const inbound = arc.dir === 'in';
  const internal = arc.dir === 'internal';
  // Same rule the ranking panels attribute by (server/normalize.js farEnd): for
  // internal traffic neither end is "far", so the source host is what matters.
  const far = arc.dir === 'out' ? arc.dst : arc.src;
  const geo = internal ? {} : far.geo || {};
  const li = document.createElement('li');
  li.style.setProperty('--c', `rgb(${colorFor(arc).join(',')})`);

  const port = arc.dst.port;
  const portLabel = port ? `${port}${PORT_NAMES[port] ? `/${PORT_NAMES[port]}` : ''}` : arc.proto;

  const sub = arc.signature
    ? arc.signature
    : `${arc.proto} ${inbound ? '→' : '←'} ${portLabel}${arc.rule ? ` · ${arc.rule}` : ''}`;

  const verb = internal ? 'LAN'
    : arc.source === 'ids' ? 'ALERT'
    : inbound ? (arc.action === 'block' ? 'BLOCK' : 'ALLOW')
    : 'OUT';

  const whereText = internal
    ? `→ ${arc.dst.ip}`
    : `${[geo.city, geo.country].filter(Boolean).join(', ') || 'locating…'}${geo.org ? ` · ${geo.org}` : ''}`;
  const whereHtml = internal
    ? escapeHtml(whereText)
    : flagHtml(geo.cc) + escapeHtml(whereText);

  li.innerHTML =
    `<span class="t">${fmtTime(arc.ts)}</span>` +
    `<span class="m">` +
      `<span class="ip">${verb} ${ipHtml(far.ip)}</span> ` +
      `<span class="sub">${whereHtml}</span>` +
      `<span class="sub">${escapeHtml(sub)}</span>` +
    `</span>`;
  // Full text on hover, so nothing is unrecoverable even if a line is clipped.
  li.title = [
    `${fmtTime(arc.ts)}  ${verb}  ${far.ip}`,
    [ccText(geo.cc), whereText].filter(Boolean).join(' '),
    sub,
  ].filter(Boolean).join('\n');
  return li;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Set from the server's hello; empty disables the links entirely.
let ipLookupUrl = '';

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

/**
 * Only real addresses get linked. Redacted values are pseudonyms like
 * "lan-cebf28", and sending one to a lookup service would be both useless and a
 * hint that it stands for something.
 */
const isRealIp = (v) => typeof v === 'string' && (IPV4.test(v) || (v.includes(':') && IPV6.test(v)));

function ipHtml(ip) {
  const safe = escapeHtml(ip);
  if (!ipLookupUrl || !isRealIp(ip)) return safe;
  const href = escapeHtml(ipLookupUrl.replace('{ip}', encodeURIComponent(ip)));
  return `<a href="${href}" target="_blank" rel="noopener noreferrer">${safe}</a>`;
}

// ---------- threat console ----------

/**
 * Plain-language rendering of a hostile event.
 *
 * The map shows that something happened and the ticker shows the raw record;
 * neither says what it *means*. "ET SCAN Potential SSH Scan" assumes you already
 * know, and the point of this line is that it should read to someone who does
 * not.
 */

// What an attacker is after when they knock on a given port. Only ports where
// the intent is genuinely unambiguous - guessing beyond that would be inventing
// detail the log does not support.
const PORT_INTENT = {
  21: 'FTP file transfer', 22: 'SSH remote login', 23: 'telnet remote login',
  25: 'the mail server', 53: 'the DNS service', 80: 'the web server',
  110: 'POP3 mail', 143: 'IMAP mail', 443: 'the web server over HTTPS',
  445: 'Windows file sharing', 587: 'the mail server', 993: 'IMAP mail',
  1433: 'a Microsoft SQL database', 1900: 'UPnP discovery',
  3306: 'a MySQL database', 3389: 'Windows Remote Desktop',
  5060: 'the VoIP/SIP service', 5432: 'a PostgreSQL database',
  5900: 'VNC remote desktop', 6379: 'a Redis database',
  8080: 'the web server', 8443: 'the web server over HTTPS',
  9200: 'an Elasticsearch database', 7547: 'the router management port',
  2375: 'the Docker control socket', 27017: 'a MongoDB database',
};

// Emerging Threats class -> what the rule is actually reporting.
const CATEGORY_INTENT = {
  SCAN: 'was scanning for a way in',
  DOS: 'was involved in denial-of-service traffic',
  EXPLOIT: 'tried to exploit a known vulnerability',
  EXPLOIT_KIT: 'tried to deliver malware through an exploit kit',
  TROJAN: 'showed signs of malware talking to its operator',
  MALWARE: 'showed signs of malware activity',
  CNC: 'contacted a known malware command-and-control server',
  WORM: 'showed worm-like spreading behaviour',
  PHISHING: 'was involved in a phishing attempt',
  SHELLCODE: 'sent an attack payload',
  WEB_SERVER: 'attacked the web server',
  WEB_SPECIFIC_APPS: 'attacked a web application',
  ATTACK_RESPONSE: 'looked like a successful compromise responding',
  COINMINER: 'showed cryptocurrency mining activity',
  MOBILE_MALWARE: 'showed mobile malware activity',
  ADWARE_PUP: 'showed adware or unwanted-program activity',
  CURRENT_EVENTS: 'matched an active threat campaign',
};

const place = (geo) => {
  const where = [geo?.city, geo?.country].filter(Boolean).join(', ');
  return where ? `from ${where}` : '';
};

/** "port 23 (telnet remote login)" or just "port 44321". */
function portPhrase(port) {
  if (!port) return null;
  return PORT_INTENT[port] ? `${PORT_INTENT[port]} on port ${port}` : `port ${port}`;
}

function threatSentence(arc) {
  const internal = arc.dir === 'internal';
  const far = arc.dir === 'out' ? arc.dst : arc.src;
  const who = far.host ? `${far.ip} (${far.host})` : far.ip;
  // Location belongs next to the address it describes. Appended to the end it
  // reads as though the port were in Minneapolis.
  const from = place(far.geo);

  if (arc.source === 'ids') {
    const what = CATEGORY_INTENT[arc.category] ?? 'triggered an intrusion-detection rule';
    if (internal) {
      // Both ends are ours, so "attacker" would be misleading - this is one of
      // your own machines misbehaving, which is worth saying differently.
      return { who: arc.src.ip, text: `${what} — this is a device on your own network`, kind: 'internal' };
    }
    const text = arc.dir === 'out'
      ? `${from} was contacted by a device on your network, and ${what}`
      : `${from} ${what}`;
    return { who, text: text.trim(), kind: 'alert' };
  }

  // Firewall block: inbound, aimed at something.
  const target = portPhrase(arc.dst.port) ?? `your network over ${arc.proto}`;
  const verb = arc.dst.port && PORT_INTENT[arc.dst.port] ? 'tried to reach' : 'probed';
  return {
    who,
    text: `${from} ${verb} ${target} — blocked by the firewall`.trim(),
    kind: 'blocked',
  };
}

const threatLog = $('threat-log');
let threatSeen = 0;

/**
 * @param {boolean} historical seeded from the firewall log at startup rather
 *   than observed live. Dimmed and date-stamped so a day-old attack is never
 *   mistaken for something happening now, and excluded from the live counter.
 */
function pushThreat(arc, historical = false) {
  if (!arc.threat) return;
  const { who, text, kind } = threatSentence(arc);
  const li = document.createElement('li');
  li.className = `tl-${kind}${historical ? ' tl-old' : ''}`;
  li.innerHTML =
    `<span class="t">${historical ? fmtWhen(arc.ts) : fmtTime(arc.ts)}</span>` +
    `<span class="msg"><b>${ipHtml(who)}</b> ${escapeHtml(text)}` +
    (arc.count > 1 ? ` <span class="rep">×${arc.count}</span>` : '') +
    `</span>`;
  li.title = arc.signature || `${arc.proto} → ${arc.dst.port ?? ''}`;
  threatLog.prepend(li);
  while (threatLog.children.length > 400) threatLog.lastElementChild.remove();
  if (historical) return;
  const c = $('console-count');
  if (c) c.textContent = `${++threatSeen} since load`;
}

/** Time alone is ambiguous once entries span a day, so older ones carry a date. */
function fmtWhen(iso) {
  const d = new Date(iso);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay
    ? d.toLocaleTimeString([], { hour12: false })
    : `${d.toLocaleDateString([], { day: '2-digit', month: 'short' })} ${d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' })}`;
}

const ticker = $('ticker');
function pushTicker(arc) {
  ticker.prepend(tickerRow(arc));
  while (ticker.children.length > 40) ticker.lastElementChild.remove();
}

function rankItem(el, { keyHtml, count, max, title }) {
  const li = document.createElement('li');
  li.style.setProperty('--w', `${(count / max) * 100}%`);
  li.innerHTML = `<span class="k">${keyHtml}</span><span class="v">${count}</span>`;
  if (title) li.title = title;
  el.appendChild(li);
  return li;
}

function emptyRow(el, text) {
  const li = document.createElement('li');
  li.className = 'empty';
  li.textContent = text;
  el.replaceChildren(li);
}

function renderRank(el, rows, decorate = (k) => escapeHtml(String(k))) {
  const max = rows[0]?.count || 1;
  el.replaceChildren();
  for (const { key, count } of rows) {
    rankItem(el, { keyHtml: decorate(key), count, max, title: `${key} — ${count}` });
  }
}

/**
 * A hostname line is only drawn when a PTR actually resolved. Most scanner
 * addresses have none, and a column of "(no PTR)" would spend a line each to say
 * nothing; the tooltip still says so explicitly.
 */
const hostLine = (host) => (host ? `<span class="host">${escapeHtml(host)}</span>` : '');
const hostTitle = (host) => host || 'no PTR record';

function renderAttackers(el, rows) {
  const max = rows[0]?.count || 1;
  el.replaceChildren();
  for (const { key, count, host } of rows) {
    rankItem(el, {
      keyHtml: ipHtml(key) + hostLine(host),
      count,
      max,
      title: `${key}\n${hostTitle(host)}\n${count} hits — 1h`,
    });
  }
}

// Rows the operator has expanded, per panel. Held out here because renderStats
// rebuilds both lists every second - without this an expanded row would snap
// shut on the next stats tick, mid-read.
const expandedPorts = new Set();
const expandedSigs = new Set();

/**
 * Which end of the event an attributed address sits on. Without this an outbound
 * alert's destination reads as an attacker - "149.154.166.110" under a Telegram
 * signature is a server one of our own hosts contacted, not someone hitting us.
 */
const DIR_MARK = { in: '←', out: '→', internal: '·' };
const DIR_WORD = { in: 'inbound, they contacted us', out: 'outbound, we contacted them', internal: 'internal' };

function portLabel(p) {
  return `${p}${PORT_NAMES[p] ? ` <span class="cc">${PORT_NAMES[p]}</span>` : ''}`;
}

/**
 * Attach the "who" breakdown to a ranking row: one dim line naming the biggest
 * contributor, expanding on click to the full list. Shared by the ports and
 * signature panels, which ask the same question of different keys.
 */
function attachSources(li, key, sources, expanded, what) {
  if (!sources.length) return;

  li.classList.add('has-sub');
  li.dataset.key = key;
  li.tabIndex = 0;
  li.setAttribute('role', 'button');

  // Collapsed: name the biggest contributor so the row is useful without a
  // click. Plain text, not a link - the whole row is a toggle here.
  const top = sources[0];
  const hint = document.createElement('span');
  hint.className = 'sub-hint';
  hint.textContent = `↳ ${DIR_MARK[top.dir] ?? ''} ${top.ip}${top.host ? ` · ${top.host}` : ''} · ${top.count}`;
  li.appendChild(hint);

  const sub = document.createElement('ul');
  sub.className = 'subrank';
  sub.innerHTML = sources.map((s) => (
    `<li data-dir="${escapeHtml(s.dir ?? '')}" title="${escapeHtml(`${s.ip}\n${hostTitle(s.host)}\n${DIR_WORD[s.dir] ?? ''}\n${s.count} × ${what}`)}">` +
      `<span class="sdir">${DIR_MARK[s.dir] ?? ''}</span>` +
      `<span class="sip">${ipHtml(s.ip)}</span>` +
      `<span class="shost">${s.host ? escapeHtml(s.host) : '—'}</span>` +
      `<span class="sv">${s.count}</span>` +
    `</li>`
  )).join('');
  li.appendChild(sub);

  const open = expanded.has(String(key));
  li.classList.toggle('open', open);
  li.setAttribute('aria-expanded', String(open));
}

function toggleRow(li, expanded) {
  const key = li.dataset.key;
  const open = !li.classList.contains('open');
  li.classList.toggle('open', open);
  li.setAttribute('aria-expanded', String(open));
  if (open) expanded.add(key); else expanded.delete(key);
}

/** Click/keyboard expansion, delegated because the list is replaced every second. */
function wireExpansion(el, expanded) {
  el.addEventListener('click', (e) => {
    // Let a link through: an expanded row's addresses are reputation lookups,
    // and following one should not also collapse the row behind it.
    if (e.target.closest('a')) return;
    const li = e.target.closest('li.has-sub');
    if (li) toggleRow(li, expanded);
  });
  el.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const li = e.target.closest('li.has-sub');
    if (!li) return;
    e.preventDefault();
    toggleRow(li, expanded);
  });
}

function renderPorts(el, rows) {
  const max = rows[0]?.count || 1;
  el.replaceChildren();
  for (const { key, count, sources = [] } of rows) {
    const li = rankItem(el, {
      keyHtml: portLabel(key),
      count,
      max,
      title: `port ${key} — ${count} hits, 1h`,
    });
    attachSources(li, key, sources, expandedPorts, `port ${key}`);
  }
}

const SEV_NAME = { 1: 'info', 2: 'low', 3: 'high', 4: 'critical' };

// Which signature list the panel is showing. Threats is the default: the
// unfiltered list is dominated by your own hosts' telemetry.
let sigMode = 'threats';

function renderSignatures(el, rows) {
  if (!rows.length) {
    emptyRow(el, sigMode === 'threats'
      ? 'no threat-class alerts in the last hour — switch to “all” to see telemetry'
      : 'no IDS alerts in the last hour');
    return;
  }
  const max = rows[0]?.count || 1;
  el.replaceChildren();
  for (const { key, count, severity, category, sources = [] } of rows) {
    const li = rankItem(el, {
      // The ET prefix is on every rule and carries no information in a list of
      // ET rules, so the class token leads instead.
      keyHtml: escapeHtml(String(key).replace(/^ET\s+/, '')),
      count,
      max,
      title: `${key}\n${category ?? 'unclassified'} · ${SEV_NAME[severity] ?? 'unknown'}\n${count} in 1h`,
    });
    li.dataset.sev = String(severity ?? 2);
    attachSources(li, key, sources, expandedSigs, 'this signature');
  }
}

let lastStats = null;

/**
 * How much history actually backs the selected window. After a fresh deploy the
 * rollup holds minutes, and captioning that "7d" would be a lie - so the panel
 * says so until the window has genuinely filled.
 */
function renderCoverage(s) {
  const el = $('coverage');
  if (!el) return;
  const covered = s.coverageMs ?? 0;
  const asked = s.windowMs ?? 0;
  // A little slack, so it stops nagging the moment it is essentially full.
  const partial = asked > 0 && covered < asked * 0.95;
  const parts = [];
  if (partial) {
    const h = covered / 3600000;
    parts.push(`only ${h < 1 ? `${Math.max(1, Math.round(h * 60))}m` : `${h.toFixed(1)}h`} of history so far`);
  }
  if (s.truncated) parts.push('ranking approximate — capped during a burst');
  el.textContent = parts.join(' · ');
  el.hidden = !parts.length;
}

function renderStats(s) {
  lastStats = s;
  $('c-blocks').textContent = s.rates.blocksMin;
  $('c-alerts').textContent = s.rates.alertsMin;
  $('c-attackers').textContent = s.rates.uniqueAttackersHour;
  $('c-events').textContent = s.rates.eventsMin;

  // In text mode the chip already shows the code, so the duplicate label is
  // hidden by CSS rather than built differently here.
  renderRank($('top-countries'), s.topCountries, (cc) => `${flagHtml(cc)}<span class="cc">${escapeHtml(cc)}</span>`);
  renderAttackers($('top-attackers'), s.topAttackers);
  renderPorts($('top-ports'), s.topPorts);
  renderSignatures($('top-signatures'), (sigMode === 'all' ? s.topSignaturesAll : s.topSignatures) ?? []);
  renderCoverage(s);
  updateFoldCounts();
}

// ---------- websocket ----------

let ws = null;
let retry = 0;

function setConn(state, text) {
  const dot = $('conn-dot');
  dot.className = `dot ${state}`;
  if (text) $('meta').textContent = text;
}

function connect() {
  const url = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
  ws = new WebSocket(url);

  ws.onopen = () => {
    retry = 0;
    setConn('live', 'connected');
    // Re-assert the remembered window: the server defaults a fresh socket to the
    // first one, and a reconnect must not silently reset the panels.
    if (statsWindow) ws.send(JSON.stringify({ type: 'window', window: statsWindow }));
  };

  ws.onclose = () => {
    setConn('down', 'disconnected — reconnecting…');
    retry = Math.min(retry + 1, 6);
    setTimeout(connect, 500 * 2 ** retry);
  };

  ws.onerror = () => ws.close();

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    switch (msg.type) {
      case 'hello': {
        // Centre the map on home (unless the server pins a longitude) so every
        // arc runs directly to the middle instead of off an edge.
        const center = Number.isFinite(msg.centerLon) ? msg.centerLon : msg.home?.lon;
        if (Number.isFinite(center)) {
          proj.setCenter(center);
          resize();
        }
        layer.configure({ proj, dpr: Math.min(devicePixelRatio || 1, 2), maxArcs: msg.maxArcs, home: msg.home });

        if (Array.isArray(msg.windows) && msg.windows.length) {
          buildWindowControl(msg.windows, msg.window ?? msg.windows[0]);
        }
        ipLookupUrl = msg.ipLookupUrl || '';
        if (msg.title) $('site-title').textContent = msg.title;
        if (msg.pageTitle) document.title = msg.pageTitle;
        if (msg.description) {
          $('meta-description')?.setAttribute('content', msg.description);
        }
        // Explicit subtitle wins; otherwise fall back to whatever host identity
        // the server was willing to disclose, then to the description.
        const identity = `${msg.wanIp ?? ''} ${msg.homeLabel ?? ''}`.trim();
        $('site-subtitle').textContent = msg.subtitle || identity || msg.description || '';

        $('replay-badge').hidden = !msg.replay;
        setConn('live', `geo:${msg.geo.mode} · privacy:${msg.privacy ?? 'public'}`);
        break;
      }
      case 'snapshot': {
        layer.clear();
        ticker.replaceChildren();
        threatLog.replaceChildren();
        threatSeen = 0;
        // History first, oldest to newest, so that after prepending it reads
        // newest-first - and live events then stack above it.
        for (const arc of msg.history ?? []) pushThreat(arc, true);
        // Newest last in the buffer; show oldest first so the ticker reads
        // top-newest after prepending.
        for (const arc of msg.arcs) {
          if (visible(arc)) pushTicker(arc);
          pushThreat(arc);
        }
        renderStats(msg.stats);
        break;
      }
      case 'arc': {
        if (!visible(msg.arc)) break;
        // Internal (LAN -> LAN) events have both ends on the home anchor, so
        // there is no arc to draw - they only make sense in the feed.
        if (msg.arc.layer !== 'internal') layer.add(msg.arc);
        pushTicker(msg.arc);
        pushThreat(msg.arc);
        break;
      }
      case 'history': {
        // Backfill finished after we connected. Rebuild the log with the seeded
        // events beneath whatever has arrived live in the meantime.
        const live = [...threatLog.children].filter((li) => !li.classList.contains('tl-old'));
        threatLog.replaceChildren();
        for (const arc of msg.history ?? []) pushThreat(arc, true);
        for (const li of live.reverse()) threatLog.prepend(li);
        break;
      }
      case 'bump':
        layer.bump(msg.id, msg.count);
        break;
      case 'stats':
        renderStats(msg.stats);
        break;
      case 'health': {
        const bad = Object.entries(msg.health).filter(([, h]) => !h.ok);
        if (bad.length) setConn('down', `feed error: ${bad.map(([k, h]) => `${k}: ${h.lastError}`).join(' · ')}`);
        else setConn('live', 'connected');
        break;
      }
    }
  };
}

// ---------- panel interaction ----------

wireExpansion($('top-ports'), expandedPorts);
wireExpansion($('top-signatures'), expandedSigs);

// ---------- stats window ----------

// Remembered per browser, so reloading does not throw you back to 1h.
const WINDOW_KEY = 'attackmap.window';
let statsWindow = (() => {
  try { return localStorage.getItem(WINDOW_KEY) || ''; } catch { return ''; }
})();

function setWindow(w, { tell = true } = {}) {
  statsWindow = w;
  try { localStorage.setItem(WINDOW_KEY, w); } catch { /* private mode */ }
  for (const b of document.querySelectorAll('#win-mode button')) {
    b.classList.toggle('on', b.dataset.window === w);
    b.setAttribute('aria-pressed', String(b.dataset.window === w));
  }
  // The per-panel captions follow the control, so a number is never shown under
  // a window label it does not belong to. Same for the attacker counter's unit:
  // it counts distinct attackers over this window, and leaving it reading "/ hr"
  // beside a 24h figure would simply be wrong.
  for (const el of document.querySelectorAll('.grp h2 small.win')) el.textContent = w;
  const unit = $('c-attackers-unit');
  if (unit) unit.textContent = ` / ${w}`;
  if (tell && ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'window', window: w }));
  }
}

/** Built from the server's list rather than hardcoded, so STATS_WINDOWS drives it. */
function buildWindowControl(windows, active) {
  const el = $('win-mode');
  el.replaceChildren(...windows.map((w) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.dataset.window = w;
    b.textContent = w;
    b.addEventListener('click', () => setWindow(w));
    return b;
  }));
  setWindow(windows.includes(statsWindow) ? statsWindow : active, { tell: false });
}

for (const btn of document.querySelectorAll('#sig-mode button')) {
  btn.addEventListener('click', () => {
    sigMode = btn.dataset.mode;
    for (const b of document.querySelectorAll('#sig-mode button')) {
      b.classList.toggle('on', b === btn);
      b.setAttribute('aria-pressed', String(b === btn));
    }
    // Re-render immediately rather than waiting up to a second for the next tick.
    if (lastStats) renderStats(lastStats);
  });
}

// ---------- layer toggles ----------

for (const label of document.querySelectorAll('.lay')) {
  const key = label.dataset.layer;
  const input = label.querySelector('input');
  input.checked = enabled[key];
  input.addEventListener('change', () => {
    enabled[key] = input.checked;
    layer.clear();
  });
}

// ---------- collapsible sections (narrow screens) ----------

/**
 * On a phone or tablet every panel is still present, just folded.
 *
 * Hiding them outright was the earlier approach and it threw away information
 * rather than deferring it. Folding costs one heading row per section, so the
 * page ends up only as tall as what you have actually opened - which is the
 * "no scrolling beyond what's needed" part.
 *
 * The threat log is open by default because it is the section that answers the
 * question you opened the page to ask.
 */
const FOLD = [
  ['#threat-console', false],                  // the log leads, open
  ['.panel-left', true],
  ['.grp:has(#top-countries)', true],
  ['.grp-attackers', true],
  ['.grp:has(#top-ports)', true],
  ['.grp:has(#top-signatures)', true],
];

const narrow = matchMedia('(max-width: 900px)');
// Remembered per section so a fold you opened does not snap shut on rotate.
const foldState = new Map();

function applyFolding() {
  const on = narrow.matches;
  for (const [sel, collapsedByDefault] of FOLD) {
    const el = document.querySelector(sel);
    if (!el) continue;
    if (!on) {
      el.removeAttribute('data-collapse');
      el.classList.remove('collapsed');
      continue;
    }
    el.setAttribute('data-collapse', '');
    const h2 = el.querySelector(':scope > h2');
    if (h2 && !h2.dataset.foldWired) {
      h2.dataset.foldWired = '1';
      h2.setAttribute('role', 'button');
      h2.tabIndex = 0;
      const toggle = () => {
        const nowCollapsed = !el.classList.contains('collapsed');
        el.classList.toggle('collapsed', nowCollapsed);
        h2.setAttribute('aria-expanded', String(!nowCollapsed));
        foldState.set(sel, nowCollapsed);
      };
      // A control inside the heading - the window selector, threats|all - must
      // not also fold the section it sits in.
      h2.addEventListener('click', (e) => { if (!e.target.closest('button, a, .seg')) toggle(); });
      h2.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        if (e.target.closest('button, a, .seg')) return;
        e.preventDefault();
        toggle();
      });
    }
    const collapsed = foldState.get(sel) ?? collapsedByDefault;
    el.classList.toggle('collapsed', collapsed);
    h2?.setAttribute('aria-expanded', String(!collapsed));
  }
  updateFoldCounts();
}

/** A folded heading should still say whether there is anything inside. */
function updateFoldCounts() {
  if (!narrow.matches) return;
  for (const [sel] of FOLD) {
    const el = document.querySelector(sel);
    const h2 = el?.querySelector(':scope > h2');
    if (!h2) continue;
    const list = el.querySelector('ul');
    const n = list ? list.querySelectorAll(':scope > li:not(.empty)').length : 0;
    let badge = h2.querySelector('.fold-n');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'fold-n';
      h2.appendChild(badge);
    }
    badge.textContent = n ? String(n) : '—';
  }
}

narrow.addEventListener('change', applyFolding);
addEventListener('resize', updateFoldCounts);
applyFolding();

// ---------- boot ----------

await world.load().catch((e) => console.error('world data failed to load', e));
resize();
frame();
connect();

// Debug handle: inspect live arc state from the console.
window.__map = { layer, world, get proj() { return proj; }, enabled, renderErrors: () => renderErrors };
