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

  const legend = rectOf('.legend');
  if (legend && legend.top < canvasRect.bottom) {
    inset.b = Math.max(inset.b, canvasRect.bottom - legend.top + gap);
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
  // For internal traffic neither end is "far"; the source host is what matters.
  const far = internal ? arc.src : inbound ? arc.src : arc.dst;
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

const ticker = $('ticker');
function pushTicker(arc) {
  ticker.prepend(tickerRow(arc));
  while (ticker.children.length > 40) ticker.lastElementChild.remove();
}

function renderRank(el, rows, decorate = (k) => escapeHtml(String(k))) {
  const max = rows[0]?.count || 1;
  el.replaceChildren(
    ...rows.map(({ key, count }) => {
      const li = document.createElement('li');
      li.style.setProperty('--w', `${(count / max) * 100}%`);
      li.innerHTML = `<span class="k">${decorate(key)}</span><span class="v">${count}</span>`;
      li.title = `${key} — ${count}`;
      return li;
    })
  );
}

function renderStats(s) {
  $('c-blocks').textContent = s.rates.blocksMin;
  $('c-alerts').textContent = s.rates.alertsMin;
  $('c-attackers').textContent = s.rates.uniqueAttackersHour;
  $('c-events').textContent = s.rates.eventsMin;

  // In text mode the chip already shows the code, so the duplicate label is
  // hidden by CSS rather than built differently here.
  renderRank($('top-countries'), s.topCountries, (cc) => `${flagHtml(cc)}<span class="cc">${escapeHtml(cc)}</span>`);
  renderRank($('top-attackers'), s.topAttackers, ipHtml);
  renderRank($('top-ports'), s.topPorts, (p) => `${p}${PORT_NAMES[p] ? ` <span class="cc">${PORT_NAMES[p]}</span>` : ''}`);
  renderRank($('top-signatures'), s.topSignatures, (sig) => escapeHtml(String(sig).replace(/^ET\s+/, '')));
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

  ws.onopen = () => { retry = 0; setConn('live', 'connected'); };

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
        // Newest last in the buffer; show oldest first so the ticker reads
        // top-newest after prepending.
        for (const arc of msg.arcs) if (visible(arc)) pushTicker(arc);
        renderStats(msg.stats);
        break;
      }
      case 'arc': {
        if (!visible(msg.arc)) break;
        // Internal (LAN -> LAN) events have both ends on the home anchor, so
        // there is no arc to draw - they only make sense in the feed.
        if (msg.arc.layer !== 'internal') layer.add(msg.arc);
        pushTicker(msg.arc);
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

// ---------- boot ----------

await world.load().catch((e) => console.error('world data failed to load', e));
resize();
frame();
connect();

// Debug handle: inspect live arc state from the console.
window.__map = { layer, world, get proj() { return proj; }, enabled, renderErrors: () => renderErrors };
