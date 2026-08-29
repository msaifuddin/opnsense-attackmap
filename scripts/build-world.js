/**
 * Bakes world-atlas TopoJSON down to a plain GeoJSON the browser can draw with
 * nothing but canvas. Run once: npm run build-map
 *
 * Keeping this a build step (rather than a runtime dependency or a CDN fetch)
 * means the container ships everything it needs and the map still renders with
 * no internet access.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import * as topojson from 'topojson-client';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const topo = require('world-atlas/countries-110m.json');
const geo = topojson.feature(topo, topo.objects.countries);

// ~1 km precision is far finer than a world map at screen resolution needs, and
// it roughly halves the file.
const round = (n) => Math.round(n * 100) / 100;
const walk = (c) => (typeof c[0] === 'number' ? [round(c[0]), round(c[1])] : c.map(walk));

const out = {
  type: 'FeatureCollection',
  features: geo.features.map((f) => ({
    type: 'Feature',
    id: f.id,
    properties: { name: f.properties?.name ?? null },
    geometry: { type: f.geometry.type, coordinates: walk(f.geometry.coordinates) },
  })),
};

const dest = path.join(ROOT, 'public', 'world-110m.json');
fs.mkdirSync(path.dirname(dest), { recursive: true });
fs.writeFileSync(dest, JSON.stringify(out));
console.log(`wrote ${dest} (${out.features.length} countries, ${(fs.statSync(dest).size / 1024).toFixed(0)} KB)`);
