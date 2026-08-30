# Runtime data (contents gitignored)

Created and managed by the service; nothing here needs to be set up by hand.

- `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb` — downloaded on first run (~74 MB).
  See README → GeoIP.
- `rollup.json` — the statistics history behind the ranking panels, saved every
  five minutes and on shutdown so a restart does not empty them.

**`rollup.json` contains real, unredacted addresses from your network**, including
LAN hosts. That is why this directory's contents are gitignored, and why the
Docker build context excludes it. Redaction happens on the way out to browsers,
so nothing here changes what the map discloses.

Deleting the directory is safe: the databases re-download and the history
rebuilds from the firewall log (`BACKFILL_ROWS`) plus normal running.
