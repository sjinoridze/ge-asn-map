#!/usr/bin/env python3
"""
Step 1 of the daily job: download fresh source data into ../cache/

  cache/asn_list.txt        Georgian ASNs (RIPEstat country-resource-list, merged with config/asns.txt)
  cache/whois/ASxxx.txt     RIPE aut-num object + its organisation object (routing policy, org name)
  cache/live/ASxxx.json     RIPEstat asn-neighbours (live BGP adjacencies from RIPE RIS)
  cache/asinfo.csv          ASN -> name/country for foreign networks (ipverse snapshot on GitHub)

Standard library only. Polite rate: ~1 request/second to each RIPE service.
"""
import json, os, re, socket, sys, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
CONFIG = os.path.join(ROOT, "config")
UA = {"User-Agent": "ge-asn-map/1.0 (daily refresh)"}
STAT = "https://stat.ripe.net/data/{call}/data.json?resource={res}&sourceapp=ge-asn-map"
ASINFO = "https://raw.githubusercontent.com/ipverse/asn-info/master/as.csv"


def http_json(url, tries=3):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=90) as r:
                return json.load(r)
        except Exception as e:
            print(f"   ! {url[:80]}… {e} (retry {i + 1})", flush=True)
            time.sleep(5 * (i + 1))
    return None


def whois(query, host="whois.ripe.net", tries=3):
    for i in range(tries):
        try:
            with socket.create_connection((host, 43), timeout=60) as s:
                s.sendall((query + "\r\n").encode())
                buf = b""
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            return buf.decode("utf-8", "replace")
        except Exception as e:
            print(f"   ! whois {query}: {e} (retry {i + 1})", flush=True)
            time.sleep(5 * (i + 1))
    return ""


def whois_over_https(asn):
    """RIPEstat 'whois' data call -> RPSL-like text (aut-num + organisation objects)."""
    j = http_json(STAT.format(call="whois", res=asn))
    if not j:
        return ""
    blocks = []
    for rec in (j.get("data", {}).get("records") or []) + (j.get("data", {}).get("irr_records") or []):
        lines = [f"{kv.get('key')}: {kv.get('value')}" for kv in rec if kv.get("key")]
        if lines and lines[0].startswith(("aut-num:", "organisation:")):
            blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n"


def load_manual_list():
    """config/asns.txt: 'AS12345<TAB>Name' per line. Optional; names here override."""
    out = {}
    p = os.path.join(CONFIG, "asns.txt")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8", errors="replace"):
            m = re.match(r"\s*(AS\d+)\s*(.*)", line, re.I)
            if m:
                out[m.group(1).upper()] = re.sub(r",\s*GE$", "", m.group(2).strip())
    return out


def main():
    settings = json.load(open(os.path.join(CONFIG, "settings.json")))
    os.makedirs(os.path.join(CACHE, "whois"), exist_ok=True)
    os.makedirs(os.path.join(CACHE, "live"), exist_ok=True)

    # 1. the ASN list
    manual = load_manual_list()
    asns = set(manual)
    if settings.get("discover_country_asns", True):
        j = http_json(STAT.format(call="country-resource-list", res=settings.get("country", "GE")))
        if j:
            found = {"AS" + str(a) for a in j.get("data", {}).get("resources", {}).get("asn", [])}
            print(f"RIPEstat lists {len(found)} ASNs registered in {settings.get('country', 'GE')}")
            asns |= found
    asns = sorted(asns, key=lambda a: int(a[2:]))
    with open(os.path.join(CACHE, "asn_list.txt"), "w") as f:
        for a in asns:
            f.write(f"{a}\t{manual.get(a, '')}\n")
    print(f"{len(asns)} ASNs to refresh")

    # 2. foreign names
    try:
        with urllib.request.urlopen(urllib.request.Request(ASINFO, headers=UA), timeout=120) as r:
            open(os.path.join(CACHE, "asinfo.csv"), "wb").write(r.read())
    except Exception as e:
        print("   ! asinfo download failed, keeping previous copy:", e)

    # 3. per-ASN whois + live neighbours
    for n, a in enumerate(asns, 1):
        print(f"[{n}/{len(asns)}] {a}", flush=True)
        # -r: no personal (person/role) objects -> stays well under RIPE's daily personal-data limit
        text = whois(f"-r {a}")
        m = re.search(r"^org:\s*(\S+)", text, re.M)
        if m:
            text += "\n" + whois(f"-r {m.group(1)}")
        if "aut-num:" not in text:
            # port 43 blocked (common on shared hosting): fall back to RIPEstat's whois call over HTTPS
            text = whois_over_https(a)
        if "aut-num:" in text:
            open(os.path.join(CACHE, "whois", a + ".txt"), "w", encoding="utf-8").write(text)
        time.sleep(1)
        j = http_json(STAT.format(call="asn-neighbours", res=a))
        if j and j.get("status") == "ok":
            json.dump(j, open(os.path.join(CACHE, "live", a + ".json"), "w"))
        time.sleep(1)
    print("fetch done")


if __name__ == "__main__":
    sys.exit(main())
