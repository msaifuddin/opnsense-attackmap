import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import https from 'node:https';
import { pipeline } from 'node:stream/promises';
import { URL } from 'node:url';
import { config, ROOT } from './config.js';

/**
 * Keeps the local GeoLite2 databases current.
 *
 * MaxMind's own endpoint needs an account and a licence key, which is a poor
 * default for something meant to be cloned and run. FyraLabs republishes the
 * same databases as GitHub release assets, rebuilt daily, fetchable without
 * authentication - and unlike the npm/jsDelivr mirrors it keeps the ASN
 * database current too, which is where the org names come from.
 *
 * Downloads never block startup: the service comes up on the ip-api fallback
 * and switches over once a database is on disk.
 */

const SOURCES = [
  { name: 'GeoLite2-City', url: 'https://github.com/FyraLabs/geolite2/releases/latest/download/GeoLite2-City.mmdb', key: 'cityDb' },
  { name: 'GeoLite2-ASN', url: 'https://github.com/FyraLabs/geolite2/releases/latest/download/GeoLite2-ASN.mmdb', key: 'asnDb' },
];

const MAX_REDIRECTS = 5;
const DAY_MS = 86_400_000;

function fetchTo(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.get(
      u,
      { headers: { 'User-Agent': 'opnsense-attackmap', Accept: 'application/octet-stream' } },
      (res) => {
        const { statusCode, headers } = res;

        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          res.resume();
          if (redirects >= MAX_REDIRECTS) return reject(new Error('too many redirects'));
          // Release downloads redirect to a separate asset host, so redirects
          // have to be followed across origins.
          return resolve(fetchTo(new URL(headers.location, u).href, dest, redirects + 1));
        }
        if (statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${statusCode}`));
        }

        const tmp = `${dest}.part`;
        let bytes = 0;
        res.on('data', (c) => { bytes += c.length; });
        pipeline(res, fs.createWriteStream(tmp))
          .then(() => resolve({ tmp, bytes }))
          .catch(reject);
      }
    );
    req.setTimeout(180_000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

/**
 * A truncated download is still a file, so the candidate is opened and queried
 * before it is allowed to replace a working database.
 */
async function validate(file) {
  const maxmind = (await import('maxmind')).default;
  const reader = await maxmind.open(file);
  if (!reader.get('8.8.8.8')) throw new Error('opened but returned no data for a known address');
}

async function ageDays(file) {
  try {
    const st = await fsp.stat(file);
    return (Date.now() - st.mtimeMs) / DAY_MS;
  } catch {
    return Infinity;
  }
}

async function writable(dir) {
  try {
    await fsp.mkdir(dir, { recursive: true });
    const probe = path.join(dir, '.write-test');
    await fsp.writeFile(probe, '');
    await fsp.rm(probe, { force: true });
    return true;
  } catch {
    return false;
  }
}

/**
 * Download anything missing or older than the refresh window.
 * @param {() => void} [onReady] called when a database changed on disk
 */
export async function updateDatabases(onReady) {
  if (!config.geo.autoDownload) return false;

  const dir = path.dirname(path.resolve(ROOT, config.geo.cityDb));
  if (!(await writable(dir))) {
    console.warn(
      `[geodb] ${dir} is not writable, so GeoLite2 cannot be downloaded.\n` +
      '        Make the volume writable, or set GEO_AUTO_DOWNLOAD=0 and place the .mmdb files there yourself.'
    );
    return false;
  }

  let changed = false;
  for (const src of SOURCES) {
    const dest = path.resolve(ROOT, config.geo[src.key]);
    try {
      if ((await ageDays(dest)) < config.geo.refreshDays) continue;

      const { tmp, bytes } = await fetchTo(src.url, dest);
      try {
        await validate(tmp);
      } catch (e) {
        await fsp.rm(tmp, { force: true });
        throw new Error(`downloaded file is not a usable database: ${e.message}`);
      }
      // Replaced only after validating, so a bad download cannot break a good copy.
      await fsp.rename(tmp, dest);
      changed = true;
      console.log(`[geodb] ${src.name} updated (${(bytes / 1048576).toFixed(1)} MB)`);
    } catch (e) {
      // Non-fatal: an existing database keeps working, and without one the
      // service simply stays on the ip-api fallback.
      console.warn(`[geodb] ${src.name} update failed: ${e.message}`);
    }
  }

  if (changed && onReady) onReady();
  return changed;
}

/** Check now, then once per refresh window. Never blocks the caller. */
export function startAutoUpdate(onReady) {
  if (!config.geo.autoDownload) return;
  const run = () => updateDatabases(onReady).catch((e) => console.warn(`[geodb] ${e.message}`));
  run();
  setInterval(run, Math.max(1, config.geo.refreshDays) * DAY_MS).unref();
}
