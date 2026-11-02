#!/bin/sh
# Daily refresh: fetch fresh RIPE data, rebuild site/data/*.json.
# cron example (04:17 every day):  17 4 * * * /path/to/ge-asn-map/run_daily.sh >> /path/to/ge-asn-map/logs/daily.log 2>&1
cd "$(dirname "$0")" || exit 1
mkdir -p logs
echo "=== $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="
python3 pipeline/fetch.py && python3 pipeline/build.py
