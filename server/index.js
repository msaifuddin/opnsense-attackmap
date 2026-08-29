import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { config, ROOT, usingApiKey } from './config.js';
import { OPNsenseClient } from './opnsense.js';
import { Pipeline } from './poller.js';
import { Aggregator } from './aggregate.js';
import { Hub } from './ws.js';
import { geoStats } from './geo.js';
import { Redactor } from './privacy.js';

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
      clients: hub?.clientCount ?? 0,
      stats: redact.stats(agg.stats()),
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
  onConnect: () => [
    {
      type: 'hello',
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
      stats: redact.stats(agg.stats()),
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

setInterval(() => hub.broadcast({ type: 'stats', stats: redact.stats(agg.stats()) }), 1000).unref();

server.listen(config.server.port, config.server.host, async () => {
  console.log(`\n  OPNsense attack map`);
  console.log(`  http://localhost:${config.server.port}`);
  console.log(`  target ${config.opnsense.url}  auth=${client.authMode}${usingApiKey ? '' : ' (no API key set - POST feeds may fail)'}`);
  if (config.replay.enabled) console.log(`  REPLAY MODE at ${config.replay.speed}x - not live traffic\n`);
  else console.log('');

  try {
    await pipeline.start();
    redact.learn({
      wanIp: pipeline.wanIp,
      interfaceNames: pipeline.interfaceNames,
      homeGeo: pipeline.homeGeo,
    });
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
    pipeline.stop();
    hub.close();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
