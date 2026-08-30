# OPNsense Live Attack Map

A Norse-style live attack map for your own firewall: inbound blocks and Suricata
IDS alerts drawn as animated arcs on a world map in real time, with live
rankings of who is hitting you, from where, and on which ports.

![screenshot](docs/screenshot.jpg)

**Safe to publish by default.** Redaction happens server-side, so a screenshot,
a stream, or a publicly exposed instance does not give away your WAN address,
your internal topology, or where you live. See [Privacy](#privacy).

Developed against OPNsense **26.7.x**. It only reads two documented API
endpoints, so it should work on any reasonably recent release.

## What it shows

- **Red arcs** — inbound connections your firewall blocked.
- **Amber → magenta arcs** — Suricata IDS alerts, coloured by severity derived
  from the Emerging Threats signature class (`ET INFO` low … `ET TROJAN` high).
- **Cyan arcs** — outbound traffic. On a typical connection this is ~90% of all
  events, so switch it off when you want only what is hitting you.
- **Live feed** — recent events with geo, ASN owner, port and signature.
- **Threat activity** — the same events in plain language, in the band below the
  map: `10:33:51  69.5.169.89 from Frankfurt am Main, Germany probed port 54121
  — blocked by the firewall`. The map shows that *something* happened and the
  feed shows the raw record; neither says what it means. Only hostile events
  appear, so it stays readable.
- **Rankings** — top origin countries, top attacker addresses, most-targeted
  ports and most-fired IDS signatures, over a rolling hour.
- **Attribution** — the ports and signature rankings name *who* is responsible,
  not just what happened. Each row shows its biggest contributor and expands on
  click to the top five, with reverse-DNS hostnames where a PTR record exists.
- **Selectable window** — rankings cover **1h or 24h**, chosen with one control
  for the whole rail. History is seeded from the firewall's own log at startup,
  survives restarts, and the panels say so when the window is not yet full
  rather than captioning ten minutes of data "24h". The header counters stay
  live regardless: the top bar is *now*, the panels are statistics.
- **Clickable addresses** — every real address in the feed and the attacker
  rankings links to a reputation lookup (Cloudflare Radar by default,
  configurable via `IP_LOOKUP_URL`). Redacted pseudonyms are never linked.

### What counts as an attack

Both filters exist because the honest answer to "what is hitting me" is much
smaller than the raw event count, and the noise was outranking the signal.

- **IDS signatures** default to threat classes — `SCAN`, `EXPLOIT`, `TROJAN`,
  `MALWARE`, `CNC`, `DOS`, `HUNTING` and similar — and hide the `ET INFO` /
  `ET POLICY` / `ET DNS` telemetry your own hosts generate. On the author's
  network that is the difference between 6 signatures and 1: roughly 90% of
  alerts are Telegram and Discord DNS lookups. The `all` toggle in the panel
  header shows everything. `IDS_MIN_SEVERITY` sets the bar; `1` restores the
  unfiltered ranking.

  `HUNTING` counts as a threat class deliberately. It is the "this could be
  command-and-control, go and look" category, and it is where malware hiding
  inside services you legitimately run — Telegram, Discord, tunnelling
  providers — actually surfaces. Rating it below the bar hides the alerts most
  worth investigating. The cost is that one rule can drown the panel if you use
  the service it watches, which is what **`IDS_MUTE_SIDS`** is for: mute the
  individual rule rather than demoting the whole class. Muted alerts remain
  visible under `all`, and muting is absolute — a muted rule stays out even if
  your IPS policy drops it.
- **Blocked inbound traffic** counts as an attack only when it was aimed at
  something. A block that came *from* a well-known service port and landed on a
  non-service port is the reply leg of a connection you opened, arriving after
  the state entry expired — not a scan. Without this the rankings fill with
  Google and Akamai. The test is on the **source** port: judging by destination
  does not work, because OPNsense is FreeBSD and its ephemeral range starts at
  10000, with replies observed landing as low as 8836. A scanner picks an
  ephemeral source port, so genuine probes of high ports are still counted.

Attribution follows the direction of the event, which is not always the source:
an inbound alert names the sender, an **outbound** alert names the destination
your host contacted, and an internal alert names the local host that triggered
it. Each entry is marked `←` inbound, `→` outbound or `·` internal — without
that, a Telegram server your laptop contacted reads as an attacker.

Every arc has one end anchored on your network. That is what makes it read as an
attack map rather than a traffic graph.

## Requirements

- An OPNsense firewall you can reach over HTTPS.
- Node 20+, or Docker.
- Optional: Suricata enabled (Services → Intrusion Detection) for the IDS layer.
  Without it the map runs perfectly well on firewall logs alone.

## Setup

```bash
git clone <this repo>
cd opnsense-attackmap
cp .env.example .env       # fill in OPNSENSE_URL, OPNSENSE_KEY, OPNSENSE_SECRET
npm install
node scripts/smoke.js      # verifies auth, incremental polling and the timezone
node server/index.js       # http://localhost:8474
```

> One smoke-test check samples six seconds of live firewall traffic. On a quiet
> network it can report a failure simply because nothing was logged in that
> window — re-run it before concluding something is broken.

With Docker:

```bash
docker compose up -d --build
```

`node:22-alpine` is multi-arch, so this builds on x86 and ARM (including a NAS)
without changes.

### Getting an API key

**System → Access → Users → _your user_ → API keys → “+”**, then put the key and
secret in `.env`.

An API key is **required for the IDS alert feed**. A session cookie is enough for
`GET`, but the alert endpoint is POST-only and a plain session is rejected by
CSRF. The service falls back to scraping the login form if no key is set, and
firewall logs will still work, but IDS alerts will not.

A dedicated user with read access to the diagnostics and IDS pages is enough —
this tool never writes anything to your firewall.

## Privacy

The point of this section: you should be able to publish this without publishing
yourself.

Redaction runs on the **broadcast path**, not in the browser. Hiding a field in
CSS still ships it over the WebSocket where anyone with devtools can read it. If
something is redacted here, it was never sent.

`PRIVACY=public` is the default:

| Data | `public` | `private` |
|---|---|---|
| WAN address | `wan-f3a4d4` | shown |
| LAN addresses | `lan-cebf28` | shown |
| Interface names | `wan` / `lan` / `opt` | `pppoe0`, `igc1`, … |
| Firewall rule labels | dropped | shown |
| TLS SNI, DNS query names | dropped | shown |
| Home marker position | displaced up to `HOME_FUZZ_KM` | exact |
| ISP / ASN of your line | dropped | shown |
| Outbound destinations | shown | shown |

An address that cannot be geolocated is left without a position rather than
being pinned to the home marker — placing a remote host on your own coordinates
would be both wrong and a way for the home record to escape redaction.

Local addresses become **stable pseudonyms**, so you can still see that the same
host is responsible for a burst without revealing which host it is. The salt
defaults to a fresh random value each boot, so pseudonyms cannot be correlated
across separate publications; pin `PRIVACY_SALT` only if you want them stable,
and treat it as a secret.

The home marker offset is **deterministic** rather than random per frame — a
per-frame jitter could be averaged back to the true position by an observer.

Outbound destination addresses are deliberately never redacted: those are other
people's servers, not yours.

All display text (`SITE_TITLE`, `SITE_SUBTITLE`, `SITE_DESCRIPTION`,
`PAGE_TITLE`) is configurable so the page does not announce whose network it is.

> Even on `public`, this page reveals real activity on a real network — traffic
> volumes, timing patterns, which countries you talk to. Think before exposing an
> instance to the open internet. The page is served without authentication and
> ships a `noindex` header; put it behind your own auth if it needs to be remote.

## Configuration

Everything lives in `.env`; `.env.example` documents every key. The ones that
matter most:

| Variable | Default | Purpose |
|---|---|---|
| `OPNSENSE_URL` | `https://192.168.1.1` | Your firewall. |
| `OPNSENSE_KEY` / `OPNSENSE_SECRET` | – | API credentials. Required for IDS alerts. |
| `PRIVACY` | `public` | `public` or `private`. Individual `SHOW_*` keys override it. |
| `HOME_LAT` / `HOME_LON` | auto | Where “home” sits. Defaults to the geolocation of your WAN address; setting it explicitly is the most reliable way not to reveal where you are. |
| `HOME_FUZZ_KM` | `25` on public | Displacement applied to the home marker. |
| `FW_TZ_OFFSET` | `auto` | See below. |
| `MAP_CENTER_LON` | `0` | Conventional world map. `home` centres on your own longitude. |
| `IP_LOOKUP_URL` | Cloudflare Radar | Where addresses link to; `{ip}` is substituted. Empty disables the links. |
| `IDS_MIN_SEVERITY` | `3` | Threat bar for the signature panel, on the 1–4 scale derived from the ET class. `1` ranks every alert. |
| `IDS_MUTE_SIDS` | – | Rule SIDs kept out of the threats panel, comma separated. Still shown under `all`. Prefer this to lowering the bar. |
| `RDNS` | `1` | Resolve attacker addresses to hostnames. Local addresses are never resolved regardless. |
| `STATS_WINDOWS` | `1h,24h` | Ranking windows offered in the UI; the first is the default. |
| `STATS_RETAIN_HOURS` | `26` | How much history to keep. Must cover your longest window. |
| `STATS_PERSIST` | `1` | Keep history across restarts in `data/rollup.json`. |
| `BACKFILL_HOURS` | `24` | History seeded from the firewall log at startup, by paging. `0` disables. |
| `COLLAPSE_MS` | `10000` | Window for merging repeat `src → dst:port` hits into one arc. |
| `MAX_ARCS` | `300` | Hard cap, oldest dropped, so a scan burst cannot stall the renderer. |
| `REPLAY` | `0` | Replay recent firewall events at 10× to exercise the renderer. |

### Timezone

The firewall log's `__timestamp__` has **no timezone**, and it is in the
firewall's local time. Parsed naively as UTC, every arc lands hours away from
now. IDS alerts are unaffected — they carry an explicit offset.

`FW_TZ_OFFSET=auto` (the default) infers the offset at startup by comparing a
fresh log line against the current time, snapped to 15 minutes. Pin it
(`+01:00`, `-05:00`, `Z`) if you prefer to be explicit. `scripts/smoke.js`
cross-checks the result against a live IDS alert and fails if the skew exceeds
five minutes.

## GeoIP

**Nothing to set up.** On first run the service downloads MaxMind's GeoLite2
databases (~62 MB City + ~12 MB ASN, about 15 seconds) from
[FyraLabs' mirror](https://github.com/FyraLabs/geolite2) of MaxMind's releases —
no account, no licence key. Lookups are then offline, instant, unlimited, and
carry the ASN/org names that make an attacker line readable
(`CHINANET-BACKBONE`, `DIGITALOCEAN-ASN`) rather than a bare address.

Downloads never block startup — the service comes up on the fallback below and
switches over the moment a database lands. Each file is opened and queried
before it is allowed to replace a working one, so a truncated download cannot
break a good copy.

`GEO_REFRESH_DAYS` (default 7) is both how stale a copy may get and how often
that is checked, so this costs roughly **74 MB per week, not per day** — nothing
is fetched while the local copy is younger than the window. The databases are
cached in a Docker named volume; they are public data, so losing them just means
downloading them again. `GEO_AUTO_DOWNLOAD=0` hands the files back to you.

### The ip-api.com fallback

Used while the first download is in flight, or if it fails. Free and keyless,
but rate-limited to ~15 requests/minute (so a first-seen address takes a few
seconds to place), it sends every address you look at to a third party, and
**IDS rulesets alert on the lookups themselves** — left alone,
`ET POLICY External IP Lookup ip-api.com` becomes your single most frequent
signature, generated entirely by this tool.

`SUPPRESS_GEO_ALERTS=1` (default) filters those out so the feed reflects your
network rather than itself; `/api/health` reports how many were dropped. It only
applies while the fallback is in use — a local database makes no lookups to
alert on. It does also hide genuine lookups to the same service from other
devices, so set it to `0` if that matters.

`/api/health` reports which mode is active: `mmdb+asn`, `mmdb`, or `ip-api`.

## How it works

Two independent pollers, and no configuration change on the firewall:

| Feed | Endpoint | Notes |
|---|---|---|
| Firewall log | `GET /api/diagnostics/firewall/log?limit=…&digest=…` | The `digest` filter returns an exact, gap-free delta. It is **inclusive** of the digest row, which `fwLogSince()` strips — otherwise the boundary event repeats on every poll. |
| IDS alerts | `POST /api/ids/service/queryAlerts` | Full eve.json records: signature, SID, action, TLS SNI, JA3/JA4, DNS queries, flow byte counts. |

The two loops are deliberately independent: the firewall log is the reliable
high-rate feed and must not stall because Suricata is slow, restarting or empty.

### Where the statistics come from

The rankings used to walk every raw event in a one-hour window, six times a
second. That is why the window was an hour — measured on real traffic, at 514
bytes per event:

| Window | Events held | Cost of one `stats()` | CPU at 1 Hz |
|---|---|---|---|
| 1h | 14k | 29 ms | 2.9% of a core |
| 24h | 346k | 634 ms | 63% |
| ~3d | 1M | 1705 ms | 170% — never finishes in time |

Events are now counted into **per-minute buckets** as they arrive, so cost scales
with the number of *distinct* attackers, ports and signatures rather than with
traffic volume. There are only a few hundred of those whether you look at an hour
or a day. Two tiers keep the bucket count down: minute resolution for the last
two hours, folded into hour buckets beyond that.

Measured after the change, holding 24 hours instead of 1:

| | CPU |
|---|---|
| 1h window only | **0.25%** of a core |
| both windows viewed at once | ~0.3% |

Rankings are cached and rebuilt on a schedule proportional to their window — 5 s
for 1h, longer for 24h — because a day-long ranking cannot visibly change in
between. The live header counters bypass all of this and are computed from a
90-second ring, so the page still reads as live.

**Seeding from the firewall log.** On startup the service walks the firewall log
backwards and counts `BACKFILL_HOURS` (24) into the statistics, so a fresh deploy
shows a full day immediately rather than minutes of data under a "24h" label.
After a restart only the gap since the last save is filled. Measured on OPNsense
26.7.1 that is ~27 pages and ~65 s of background work for 264k events; the log
retains about 72 h, so 24 h has headroom.

Two endpoints exist and only one of them can do this. `/api/diagnostics/firewall/log`
returns parsed rows but has **no cursor**, so reaching a day back means one
enormous request — and at 400k rows that exhausts PHP's 1 GB limit and the
request dies on the firewall. `/api/diagnostics/log/core/filter` pages properly
and costs ~3 MB per 10k rows however deep it goes; it returns raw syslog, which
`server/filterlog.js` parses back into the same shape. Pages get slower the
deeper they go (0.6 s at page 1, 3.6 s at page 26), so the walk runs in the
background and yields between pages rather than blocking startup.

Seeded **hostile** events also populate the threat log — up to 400 of them,
dimmed and date-stamped so a day-old attack is never mistaken for something
happening now. That is the difference between knowing 4,000 addresses attacked
you and being able to read what they did. Backfilled events never become arcs
(replaying yesterday's attacks across the map would be a lie) and never touch the
header counters, which mean "since this process started".

IDS alerts cannot be backfilled — `queryAlerts` retains only ~500 records, about
half an hour.

**Persistence.** History is written to `data/rollup.json` every five minutes and
on shutdown, so a redeploy does not reset the panels. **That file contains real,
unredacted addresses from your network** — `data/` is gitignored in full for
exactly that reason. Redaction still happens on the way out, so nothing about
what reaches a browser changes.

One caveat: the 24h window takes its most recent two hours from minute buckets
and the rest from hour buckets, so its boundary is accurate to about an hour.
Immaterial for a ranking, worth knowing before reading a total as exact.

### What the IDS feed can and cannot see

Worth understanding before you go tuning Suricata to catch inbound attacks,
because it probably cannot.

In OPNsense's default **IDS (non-inline) mode with netmap**, Suricata attaches
to the interface's *host-stack* ring — alerts arrive tagged `igc0^`, with the
caret. It deliberately does not seize the NIC rings, because netmap taking
exclusive ownership of the card would break forwarding. The consequence: it only
ever sees traffic that has already traversed the host stack, i.e. **post-firewall**.
Scans your firewall blocks never reach it, so they generate no alert.

If your WAN is PPPoE this is compounded. Suricata cannot capture on the `pppoe0`
pseudo-interface at all — selecting WAN in the IDS settings silently yields
nothing, with the service still reporting healthy. Assigning the physical parent
NIC as a separate interface does make capture work, but measured over ~49
minutes it produced **239 alerts, all outbound, and zero signatures that the LAN
interface had not already caught** — post-NAT, so strictly less informative than
watching LAN, at a ~14% increase in alert volume.

So:

- **Inbound attacks come from the firewall log**, which is complete and is what
  the map's block layer draws. The IDS layer is not the source for those.
- **IDS earns its place on LAN**, where it catches a compromised internal host
  talking out — with real internal addresses rather than your NAT address.
- Seeing raw pre-firewall traffic would need **IPS/inline** mode, so Suricata
  bridges the NIC and host rings. On an internet uplink that is a substantially
  riskier change, and most inbound scans are bare SYNs to closed ports that match
  no signature anyway.

If you do want to inspect raw WAN packets, assigning the physical parent
interface makes it selectable under **Interfaces → Diagnostics → Packet
Capture**, which is a better tool for that job than an IDS.

### Design notes

- **Volume.** Most events on a home connection are outbound passes. Drawing them
  all is the failure mode of most homemade attack maps, so the default view is
  inbound blocks plus IDS alerts, repeats inside a 10 s window collapse into one
  arc with a hit-count badge, and arcs are hard-capped.
- **Internal traffic.** LAN → LAN events (a host querying the firewall's own
  resolver) have no far end. They are classed `internal`, excluded from the
  attacker rankings, and never drawn as arcs. Without this your own hosts top the
  attacker list.
- **Flat map, flat arcs.** Arcs take the direct chord between two points. Routing
  “the short way” around the antimeridian is correct on a globe, but on a flat
  map it just looks like an attack flying off the wrong edge.
- **Mobile folds rather than hides.** Below 900px every panel is still there, but
  collapsed to a single heading carrying a count, with the plain-language threat
  log open by default because it answers the question you opened the page to ask.
  Tap a heading to expand it. An earlier version simply dropped those panels,
  which threw information away instead of deferring it; folding costs one row
  each, so the page is only as tall as what you have chosen to look at.
- **The threat log fills the map's dead band.** An equirectangular map is fixed
  at 2:1, so in a taller gap it letterboxes. Rather than leave that strip empty
  it carries the plain-language log, and the projection measures the console as
  a boundary so the map moves up instead of hiding behind it.
- **Layout.** The map is drawn at one uniform scale — stretching an axis to fill
  the box makes the continents visibly wrong — and positioned in the gap between
  the side panels so nothing on it hides behind the UI. The leftover space is not
  blank: the ocean and its gradient cover the whole viewport, so it reads as
  full-bleed. Land is drawn with copies offset by one map width, which is what
  carries rings across the antimeridian seam, and clipped to the map rectangle so
  the copy a whole width away cannot appear as a second set of continents.
- **Backgrounded tabs.** Browsers throttle `requestAnimationFrame` to zero in a
  hidden tab, so the canvas freezes on its last frame until you look at it again.
  That is normal; the server keeps ingesting throughout.

## Endpoints

- `/` — the map.
- `/ws` — event stream (`hello`, `snapshot`, `arc`, `bump`, `stats`, `health`).
- `/api/health` — feed status, geo mode, live stats. Redacted like everything
  else. Used by the container healthcheck.

## Troubleshooting

**IDS alerts are always empty.** `GET` on that endpoint always returns `[]`; it
must be a `POST`, which needs an API key. Check Suricata is enabled and bound to
the interfaces you expect — and note that adding an interface needs an
**Apply/reconfigure** before it takes effect.

**No IDS alerts for inbound attacks, even though the firewall is blocking them.**
Expected, not a fault. See
[What the IDS feed can and cannot see](#what-the-ids-feed-can-and-cannot-see) —
in netmap IDS mode Suricata only observes post-firewall traffic, and on a PPPoE
WAN it cannot capture on `pppoe0` at all.

**Everything is hours out of date.** Timezone — see above.

**My own LAN hosts are in the attacker list.** Internal events being
mis-classified: make sure `HOME_NETS` covers all your subnets.

**Map is blank but `/api/health` is fine.** The tab is backgrounded (see design
notes), or `public/world-110m.json` failed to load. Regenerate it with
`node scripts/build-world.js`.

**`smoke.js` fails on "fwLogSince returned 0 new rows".** That check samples six
seconds of live traffic, so it fails on an idle network rather than because
anything is wrong. Re-run it, or make a request through the firewall first. It
is the only check in the script that depends on live events.

## Licence

MIT — see [LICENSE](LICENSE).

Country outlines derive from [world-atlas](https://github.com/topojson/world-atlas)
(Natural Earth, public domain). Geolocation via
[MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
or [ip-api.com](https://ip-api.com), depending on configuration.
