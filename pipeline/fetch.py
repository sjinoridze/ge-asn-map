#!/usr/bin/env python3
"""
Step 1 of the daily job: download fresh source data into ../cache/

  cache/asn_list.txt        ASNs of every country in settings 'countries' (RIPEstat country-resource-list,
                            merged with config/asns.txt); columns: ASN, preferred name, country
  cache/whois/ASxxx.txt     RIPE aut-num object + its organisation object (routing policy, org name)
  cache/live/ASxxx.json     RIPEstat asn-neighbours (live BGP adjacencies from RIPE RIS)
  cache/asinfo.csv          ASN -> name/country for foreign networks (ipverse snapshot on GitHub)
  cache/rstatus/ASxxx.json  RIPEstat routing-status (announced IPv4/IPv6 address space)
  cache/peeringdb/*.json    PeeringDB: networks, exchange (IX) memberships, facilities
  cache/caida_rel.txt       CAIDA AS relationships (monthly), only lines touching our ASNs

Standard library only. Polite rate: ~1 request/second to each RIPE service.
"""
import bz2, json, os, re, socket, sys, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
CONFIG = os.path.join(ROOT, "config")
UA = {"User-Agent": "ge-asn-map/1.0 (daily refresh)"}
STAT = "https://stat.ripe.net/data/{call}/data.json?resource={res}&sourceapp=ge-asn-map"
ASINFO = "https://raw.githubusercontent.com/ipverse/asn-info/master/as.csv"
PDB = "https://www.peeringdb.com/api/"
CAIDA_DIR = "https://publicdata.caida.org/datasets/as-relationships/serial-2/"


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


def fetch_peeringdb(asns):
    """Networks, IX memberships and facilities for our ASNs. Anonymous access is rate-limited,
    so calls are spaced out; set the PEERINGDB_API_KEY secret for higher limits."""
    out_dir = os.path.join(CACHE, "peeringdb")
    os.makedirs(out_dir, exist_ok=True)
    hdr = dict(UA)
    key = os.environ.get("PEERINGDB_API_KEY", "").strip()
    if key:
        hdr["Authorization"] = "Api-Key " + key
    nums = [a[2:] for a in asns]

    def get(path):
        for i in range(4):
            try:
                with urllib.request.urlopen(urllib.request.Request(PDB + path, headers=hdr), timeout=90) as r:
                    return json.load(r).get("data", [])
            except Exception as e:
                print(f"   ! peeringdb {path[:60]}… {e} (retry {i + 1})", flush=True)
                time.sleep(20 * (i + 1))
        return None

    for name, field in (("net", "asn__in"), ("netixlan", "asn__in"), ("netfac", "local_asn__in")):
        rows, ok = [], True
        for i in range(0, len(nums), 40):
            chunk = get(f"{name}?{field}={','.join(nums[i:i + 40])}")
            if chunk is None:
                ok = False
                break
            rows += chunk
            time.sleep(4)
        if ok:
            json.dump(rows, open(os.path.join(out_dir, name + ".json"), "w"))
            print(f"PeeringDB {name}: {len(rows)} rows")
        else:
            print(f"   ! PeeringDB {name} incomplete, keeping previous copy")
    try:
        nl = json.load(open(os.path.join(out_dir, "netixlan.json")))
        ix_ids = sorted({str(r["ix_id"]) for r in nl})
        rows = []
        for i in range(0, len(ix_ids), 50):
            chunk = get(f"ix?id__in={','.join(ix_ids[i:i + 50])}")
            rows += chunk or []
            time.sleep(4)
        if rows:
            json.dump(rows, open(os.path.join(out_dir, "ix.json"), "w"))
    except Exception as e:
        print("   ! PeeringDB ix lookup skipped:", e)
    allfacs, ok = [], True
    for country in countries_of(json.load(open(os.path.join(CONFIG, "settings.json")))):
        facs = get(f"fac?country={country}")
        if facs is None:
            ok = False
            break
        allfacs += facs
        time.sleep(4)
    if ok:
        json.dump(allfacs, open(os.path.join(out_dir, "fac_country.json"), "w"))


def fetch_caida(asns):
    """Latest monthly CAIDA serial-2 file; keep only lines that touch our ASNs."""
    try:
        with urllib.request.urlopen(urllib.request.Request(CAIDA_DIR, headers=UA), timeout=60) as r:
            idx = r.read().decode("utf-8", "replace")
        files = sorted(set(re.findall(r"(\d{8})\.as-rel2\.txt\.bz2", idx)))
        if not files:
            print("   ! CAIDA: no files listed")
            return
        latest = files[-1]
        print("CAIDA as-rel2:", latest)
        with urllib.request.urlopen(urllib.request.Request(f"{CAIDA_DIR}{latest}.as-rel2.txt.bz2", headers=UA), timeout=300) as r:
            raw = bz2.decompress(r.read()).decode("utf-8", "replace")
        want = {a[2:] for a in asns}
        keep = [f"# source {latest}"]
        for line in raw.splitlines():
            if line.startswith("#"):
                continue
            p = line.split("|")
            if len(p) >= 3 and (p[0] in want or p[1] in want):
                keep.append(line)
        open(os.path.join(CACHE, "caida_rel.txt"), "w").write("\n".join(keep) + "\n")
        print(f"CAIDA: {len(keep) - 1} relationships touch our ASNs")
    except Exception as e:
        print("   ! CAIDA download failed, keeping previous copy:", e)


def countries_of(settings):
    c = settings.get("countries") or [settings.get("country", "GE")]
    return [x.upper() for x in c]


def load_manual_list():
    """config/asns.txt: 'AS12345<TAB>Name[<TAB>CC]' per line (or 'Name, CC'). Optional; names here override."""
    out = {}
    p = os.path.join(CONFIG, "asns.txt")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8", errors="replace"):
            m = re.match(r"\s*(AS\d+)\s*(.*)", line, re.I)
            if m:
                parts = m.group(2).split("\t")
                name = parts[0].strip()
                c = parts[1].strip().upper() if len(parts) > 1 and len(parts[1].strip()) == 2 else ""
                m2 = re.search(r",\s*([A-Z]{2})$", name)
                if m2 and not c:
                    c = m2.group(1)
                out[m.group(1).upper()] = (re.sub(r",\s*[A-Z]{2}$", "", name), c)
    return out


def main():
    settings = json.load(open(os.path.join(CONFIG, "settings.json")))
    os.makedirs(os.path.join(CACHE, "whois"), exist_ok=True)
    os.makedirs(os.path.join(CACHE, "live"), exist_ok=True)
    os.makedirs(os.path.join(CACHE, "rstatus"), exist_ok=True)

    # 1. the ASN list
    manual = load_manual_list()
    countries = countries_of(settings)
    cc = {}
    if settings.get("discover_country_asns", True):
        for country in countries:
            j = http_json(STAT.format(call="country-resource-list", res=country))
            if j:
                found = {"AS" + str(a) for a in j.get("data", {}).get("resources", {}).get("asn", [])}
                print(f"RIPEstat lists {len(found)} ASNs registered in {country}")
                for a in found:
                    cc.setdefault(a, country)
            time.sleep(0.5)
    for a, (name, c) in manual.items():
        if c:
            cc[a] = c
        else:
            cc.setdefault(a, countries[0])
    asns = sorted(cc, key=lambda a: int(a[2:]))
    with open(os.path.join(CACHE, "asn_list.txt"), "w") as f:
        for a in asns:
            f.write(f"{a}\t{manual.get(a, ('', ''))[0]}\t{cc[a]}\n")
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
        time.sleep(0.5)
        j = http_json(STAT.format(call="asn-neighbours", res=a))
        if j and j.get("status") == "ok":
            json.dump(j, open(os.path.join(CACHE, "live", a + ".json"), "w"))
        time.sleep(0.5)
        j = http_json(STAT.format(call="routing-status", res=a))
        if j and j.get("status") == "ok":
            json.dump(j.get("data", {}), open(os.path.join(CACHE, "rstatus", a + ".json"), "w"))
        time.sleep(0.5)

    # 4. exchanges and facilities, 5. second relationship source
    fetch_peeringdb(asns)
    fetch_caida(asns)
    print("fetch done")


if __name__ == "__main__":
    sys.exit(main())
