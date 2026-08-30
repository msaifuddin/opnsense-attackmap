import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { config, ROOT, usingApiKey, parseWindow } from './config.js';
import { OPNsenseClient } from './opnsense.js';
import { Pipeline } from './poller.js';
import { Aggregator } from './aggregate.js';
import { Hub } from './ws.js';
import { geoStats } from './geo.js';
import { Redactor } from './privacy.js';
import { withHostnames, rdnsLearn, rdnsStats } from './rdns.js';

const PUBLIC = path.join(ROOT, 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const client = new OPNsenseClient();
const pipeline = new Pipeline(client);
const agg = new Aggregator();
// Everything leaving this process goes through the redactor first.
const redact = new Redactor();

// Windows offered to clients, validated once at startup so a typo in
// STATS_WINDOWS fails loudly here rather than silently serving an empty panel.
const WINDOWS = new Map(
  config.stats.windows
    .map((w) => [w, parseWindow(w)])
    .filter(([w, ms]) => ms !== null || !console.warn(`[stats] ignoring invalid STATS_WINDOWS entry "${w}"`))
);
if (!WINDOWS.size) WINDOWS.set('1h', 3_600_000);
const DEFAULT_WINDOW = [...WINDOWS.keys()][0];

/**
 * The one place stats are prepared for the wire. Redaction runs first and
 * hostname enrichment second, deliberately: withHostnames() only resolves
 * literal public addresses, so anything the redactor turned into a pseudonym is
 * structurally incapable of triggering a PTR query.
 */
const statsOut = (window = DEFAULT_WINDOW) =>
  withHostnames(redact.stats(agg.stats(WINDOWS.get(window) ?? WINDOWS.get(DEFAULT_WINDOW))));

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/api/health') {
    res.writeHead(200, { 'Content-Type': MIME['.json'] });
    res.end(JSON.stringify(redact.health({
      ok: pipeline.health.fw.ok,
      auth: client.authMode,
      privacy: config.privacy.preset,
      wanIp: pipeline.wanIp,
      home: pipeline.homeGeo,
      feeds: pipeline.health,
      geo: { ...geoStats(), ownAlertsSuppressed: pipeline.suppressed },
      rdns: rdnsStats(),
      clients: hub?.clientCount ?? 0,
      stats: statsOut(),
    }), null, 2));
    return;
  }

  // Static files, path-traversal safe.
  const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  const file = path.join(PUBLIC, rel);
  if (!file.startsWith(PUBLIC)) { res.writeHead(403).end('forbidden'); return; }

  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }).end('not found'); return; }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] ?? 'application/octet-stream',
      'Cache-Control': path.extname(file) === '.json' ? 'public, max-age=86400' : 'no-cache',
    });
    res.end(data);
  });
});

const hub = new Hub(server, {
  // The only thing a client may ask for is a different stats window.
  onMessage: (msg, ws) => {
    if (msg?.type !== 'window' || !WINDOWS.has(msg.window)) return [];
    ws.statsWindow = msg.window;
    // Answer immediately rather than leaving the panels stale until the next
    // tick - switching window should feel instant.
    return [{ type: 'stats', stats: statsOut(msg.window) }];
  },
  onConnect: (ws) => [
    {
      type: 'hello',
      windows: [...WINDOWS.keys()],
      window: ws.statsWindow ?? DEFAULT_WINDOW,
      title: config.branding.title,
      subtitle: config.branding.subtitle,
      description: config.branding.description,
      pageTitle: config.branding.pageTitle || config.branding.title,
      home: redact.home(pipeline.homeGeo),
      // The host label is a hostname, so it is only offered when local detail
      // is being shown at all.
      homeLabel: config.privacy.showWanIp ? config.home.label : '',
      centerLon: config.home.centerLon,
      ipLookupUrl: config.ipLookupUrl,
      wanIp: config.privacy.showWanIp ? pipeline.wanIp : null,
      privacy: config.privacy.preset,
      geo: geoStats(),
      auth: client.authMode,
      replay: config.replay.enabled,
      maxArcs: config.render.maxArcs,
    },
    {
      type: 'snapshot',
      arcs: agg.snapshot().map((a) => redact.event(a)),
      // Seeded hostile events, for the threat log only - they are history, so
      // they must not be drawn as arcs or counted as live.
      history: agg.historySnapshot().map((a) => redact.event(a)),
      stats: statsOut(ws.statsWindow),
    },
  ],
});

pipeline.on('event', (ev) => {
  const out = agg.ingest(ev);
  if (!out) return;
  // Aggregation and stats run on the real values; only the wire copy is redacted.
  hub.broadcast(out.type === 'arc' ? { type: 'arc', arc: redact.event(out.arc) } : out);
});

pipeline.on('health', (health) => hub.broadcast({ type: 'health', health }));

// One payload built per distinct window in use, not per client - the merge is
// cached inside the rollup, so this costs a few milliseconds a minute regardless
// of how far back anyone is looking.
setInterval(() => {
  hub.each(
    (ws) => ws.statsWindow ?? DEFAULT_WINDOW,
    (window) => ({ type: 'stats', stats: statsOut(window) })
  );
}, 1000).unref();

if (config.stats.persist) {
  setInterval(() => agg.rollup.save(), config.stats.saveEveryMs).unref();
}

server.listen(config.server.port, config.server.host, async () => {
  console.log(`\n  OPNsense attack map`);
  console.log(`  http://localhost:${config.server.port}`);
  console.log(`  target ${config.opnsense.url}  auth=${client.authMode}${usingApiKey ? '' : ' (no API key set - POST feeds may fail)'}`);
  if (config.replay.enabled) console.log(`  REPLAY MODE at ${config.replay.speed}x - not live traffic\n`);
  else console.log('');

  // Before the pipeline, so the first events land on top of restored history
  // rather than racing it.
  const restored = agg.rollup.load();
  if (restored) {
    const hrs = restored.coverageMs / 3_600_000;
    console.log(`  restored ${restored.buckets} stats buckets (${hrs < 1 ? `${Math.round(hrs * 60)}m` : `${hrs.toFixed(1)}h`} of history)`);
  }

  try {
    await pipeline.start();
    redact.learn({
      wanIp: pipeline.wanIp,
      interfaceNames: pipeline.interfaceNames,
      homeGeo: pipeline.homeGeo,
    });
    // The WAN address is excluded from reverse lookups the same way it is from
    // the map's detail, so its PTR - which names the ISP and often the circuit -
    // is never fetched.
    rdnsLearn({ wanIp: pipeline.wanIp });

    // Seed the statistics from the firewall's own log, so a fresh deploy is not
    // showing two minutes of data under a "24h" label. Deliberately not awaited:
    // it takes seconds and the map should be live immediately.
    // Snapshotted before any seeding, so restored history is never recounted.
    const isGap = agg.rollup.gapFilter();
    pipeline.backfill((events) => {
      for (const ev of events) agg.ingestHistory(ev);
    }, isGap).then((r) => {
      if (!r) return;
      const threats = agg.finalizeHistory();
      console.log(
        `[backfill] +${r.spanH.toFixed(1)}h of history: ${r.used} events from ${r.rows} log rows ` +
        `across ${r.pages} pages, ${threats} hostile kept for the log (${(r.ms / 1000).toFixed(1)}s)`
      );
      agg.rollup.save();
      // Anyone already watching connected before this finished, so their panels
      // and threat log are still empty. Push the seeded view to them.
      hub.broadcast({
        type: 'history',
        history: agg.historySnapshot().map((a) => redact.event(a)),
      });
      hub.each((ws) => ws.statsWindow ?? DEFAULT_WINDOW, (w) => ({ type: 'stats', stats: statsOut(w) }));
    }).catch((e) => console.warn(`[backfill] skipped: ${e.message}`));
    console.log(`  privacy=${config.privacy.preset}${redact.active ? '' : ' (nothing redacted)'}\n`);
  } catch (e) {
    console.error(`\n  failed to start pipeline: ${e.message}\n`);
    if (!usingApiKey) console.error('  set OPNSENSE_KEY / OPNSENSE_SECRET in .env\n');
    process.exit(1);
  }
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log('\nshutting down');
    // Save before anything else: a redeploy is exactly when losing the history
    // would be most annoying.
    if (agg.rollup.save()) console.log('  stats history saved');
    pipeline.stop();
    hub.close();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
