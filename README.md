# Georgian ASN Interconnect Map: self-hosted version

Two ways to run it: free on GitHub (below), or on your own server (Install).

A static web page plus a daily job that refreshes the data from RIPE.

```
ge-asn-map/
├── site/                 ← the ONLY folder the web server should serve
│   ├── index.html        the map, graph, change log and table
│   └── data/
│       ├── net.json      map data (rewritten by the daily job)
│       └── changes.json  changes over the last 30 days
├── pipeline/
│   ├── fetch.py          downloads fresh data into cache/
│   └── build.py          turns cache/ into site/data/*.json
├── config/
│   ├── settings.json     thresholds, country, how long to keep history
│   ├── groups.json       corporate groups set by hand (Magticom + Delta Comm, ...)
│   └── asns.txt          your list of ASNs with preferred names (optional)
├── run_daily.sh          fetch + build, for cron
├── cache/                raw downloads (created by fetch.py)
└── history/              one compressed snapshot per day + changes.log
```

Requirements: **Python 3.8+** (standard library only) and outbound HTTPS. Outbound
port 43 (whois) is used if open; otherwise the job falls back to RIPEstat over HTTPS.

## Free hosting: GitHub Pages + GitHub Actions (no server needed)

GitHub hosts the page and runs the daily job for free in a **public** repository.

1. Create a new public repository on GitHub, e.g. `ge-asn-map`.
2. Upload the contents of this folder (including the hidden `.github/` folder) to its `main` branch:
   ```sh
   cd ge-asn-map
   git init -b main && git add . && git commit -m "Initial site"
   git remote add origin https://github.com/YOURNAME/ge-asn-map.git
   git push -u origin main
   ```
3. In the repository: **Settings → Pages → Build and deployment → Source: GitHub Actions**.
4. **Actions** tab → "Daily refresh and publish" → **Run workflow** for the first refresh (~15 min).
5. The site is live at `https://YOURNAME.github.io/ge-asn-map/`, refreshed every day at 05:17 Tbilisi time.

Your own domain later: Settings → Pages → Custom domain, plus one CNAME record at your DNS provider.
GitHub pauses scheduled jobs in repositories with no activity for 60 days. The daily data
commit normally keeps it active; if it ever pauses, re-enable it on the Actions tab.

## Install

**A VPS (recommended):**

```sh
# 1. copy the folder, e.g. to /opt/ge-asn-map
scp -r ge-asn-map user@server:/opt/

# 2. first run (takes ~10–15 minutes: 2 requests per ASN, 1 s apart)
/opt/ge-asn-map/run_daily.sh

# 3. serve only the site/ folder. nginx example:
#    server {
#        server_name asnmap.example.ge;
#        root /opt/ge-asn-map/site;
#        location /data/ { add_header Cache-Control "no-cache"; }
#    }

# 4. schedule it daily (crontab -e). 04:17 server time:
17 4 * * * /opt/ge-asn-map/run_daily.sh >> /opt/ge-asn-map/logs/daily.log 2>&1
```

**Shared hosting (cPanel or similar):** upload the folder *outside* `public_html`,
copy or symlink `site/` to `public_html/asnmap/`, and add the same cron line in
cPanel → Cron Jobs. Check that the host lets cron jobs make outbound HTTPS requests
and that `python3` is available (`python3 --version` in the cron command).
If `site/` is a copy rather than a symlink, add `&& cp site/data/*.json /home/USER/public_html/asnmap/data/`
to the end of `run_daily.sh`.

## Countries

`config/settings.json` → `"countries": ["GE", "AZ", "AM"]`. Every ASN registered in those countries
is discovered from RIPEstat each day. The page has a tab per country plus a **Whole region** view
(`#ge`, `#az`, `#am`, `#region` at the end of the address), and a table of cross-border links.
In a country tab, networks of the other two countries count as foreign neighbours.
To add a country, add its two-letter code (any RIPE-region country works).
`config/asns.txt` takes an optional country column: `AS12345<TAB>Preferred name<TAB>AZ`.

## Data sources and quality controls

| Layer | Source | Refresh |
|---|---|---|
| Live links (main) | RIPEstat `asn-neighbours` (RIPE RIS collectors) | daily |
| Second opinion | CAIDA AS relationships (RIS + RouteViews) | monthly file, checked daily |
| Declared policy | RIPE database `aut-num` objects | daily |
| Exchanges, data centers | PeeringDB | daily |
| Address space (node size) | RIPEstat `routing-status` | daily |
| Corrections | `config/overrides.json` (by hand) | on commit |

- **Confirmed changes:** a link is reported as added or lost only after it holds for
  `confirm_runs` daily runs (default 2). A link missing for one day stays on the map, drawn dashed.
  State lives in `history/linkstate.json`.
- **Backup links:** a weaker live sighting (≥ `min_backup_power` collector feeds) of an upstream
  that the network also declares in RIPE is shown as a thin "backup" link.
- **Sources per link:** each link lists which sources support it (RIS, CAIDA, RIPE, manual);
  the details panel shows them next to each neighbour.
- **Corrections:** add links confirmed by operators to `config/overrides.json` (`add`), or remove a
  wrong one (`hide`). The "Suggest a correction" link in the details panel opens a GitHub issue
  (Issues must be enabled in the repository settings).
- **PeeringDB API key (optional):** anonymous access is rate-limited. If PeeringDB data comes back
  incomplete in the log, create a free key at peeringdb.com (Profile → API keys) and add it as a
  repository secret named `PEERINGDB_API_KEY` (Settings → Secrets and variables → Actions).

## What the daily job does

1. **ASN list.** Asks RIPEstat for every ASN registered in Georgia and merges it with
   `config/asns.txt`. Names in `asns.txt` win. To track only your own list, set
   `"discover_country_asns": false` in `config/settings.json`.
2. **RIPE database.** For each ASN, downloads the `aut-num` object (routing policy) and
   its organisation (name). It skips person objects to stay well under RIPE's daily query limit.
3. **Live BGP.** For each ASN, downloads RIPEstat `asn-neighbours` (who it is seen
   connecting to in RIPE RIS route collectors).
4. **Foreign names.** Downloads the public ipverse ASN-name list from GitHub.
5. **Build.** Classifies every link as transit, mutual, peering or RIPE-only, assigns
   roles, compares with yesterday and writes `site/data/net.json` + `changes.json`.

Change detection covers transit links added or lost, new ASNs, and ASNs that start
or stop announcing routes. The full log is kept in `history/changes.log`.

The first run on the server will list many "New ASN" changes if discovery finds
more Georgian ASNs than the original 176. That's expected; the next day's run
shows only real changes.

## Tuning

`config/settings.json`:

| Setting | Default | Meaning |
|---|---|---|
| `min_upstream_power` | 20 | collector feeds that must see a transit link |
| `min_upstream_share` | 0.03 | and its share of the network's strongest upstream |
| `min_customer_power` | 15 | feeds that must see a customer link |
| `min_peer_power` | 3 | feeds for domestic peering |
| `changes_window_days` | 30 | how far back the page's change list goes |
| `history_days` | 365 | daily snapshots kept in `history/` |

`config/groups.json`: add sister companies the registry doesn't show, e.g.
`"System Net group": ["AS34797", "AS209183"]`.

## Checking a run

```sh
tail -n 20 /opt/ge-asn-map/logs/daily.log     # last line: "built: N ASNs, ... changes"
```

If a run fails halfway, the site keeps showing the previous day's data: `net.json`
is only replaced once a build completes.
