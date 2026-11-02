#!/usr/bin/env python3
"""
Step 2 of the daily job: turn ../cache/ into ../site/data/net.json (the map) and
../site/data/changes.json (what changed since the previous build).

Relationship rules
  Live (RIPEstat asn-neighbours, RIPE RIS collectors):
    upstream  = neighbour on the collector side ("left") seen by >= MIN_POWER feeds
                and >= 3% of the network's strongest upstream path
    customer  = neighbour on the far side ("right") seen by >= 15 feeds
    mutual    = both directions strong (sister networks passing each other's routes)
    peer      = 'uncertain' adjacency between two networks of the country list
  RIPE (aut-num import/export):
    links declared in RIPE but not seen live are kept as 'stale' (RIPE-only)
Standard library only.
"""
import csv, collections, datetime, glob, gzip, json, os, re, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
CONFIG = os.path.join(ROOT, "config")
OUT = os.path.join(ROOT, "site", "data")
HIST = os.path.join(ROOT, "history")

TIER1 = {"AS174", "AS1299", "AS3356", "AS6939", "AS2914", "AS3257", "AS6762", "AS6453", "AS3320",
         "AS5511", "AS6830", "AS7018", "AS701", "AS12956", "AS3491", "AS6461", "AS1239"}
ANYRE = re.compile(r"\b(ANY)\b|\{\s*0\.0\.0\.0/0[^}]*\}|\{\s*::/0[^}]*\}", re.I)
ASRE = re.compile(r"\bAS\d+\b", re.I)


# ---------------------------------------------------------------- RIPE whois parsing
def autnum_attrs(text):
    attrs, inside = [], False
    for raw in text.splitlines():
        if raw.startswith("aut-num:"):
            inside = True
        if not inside:
            continue
        if raw.strip() == "":
            if attrs:
                break
            continue
        if raw.startswith("%"):
            continue
        if raw[0] in " \t+" and attrs:
            attrs[-1][1] += " " + raw.lstrip("+").strip()
            continue
        m = re.match(r"([a-zA-Z0-9-]+):\s*(.*)", raw)
        if m:
            attrs.append([m.group(1).lower(), m.group(2)])
    return attrs


def org_attrs(text):
    m = re.search(r"^organisation:.*?(?=^\s*$|\Z)", text, re.M | re.S)
    o = {}
    if m:
        for l in m.group(0).splitlines():
            mm = re.match(r"([a-z-]+):\s*(.*)", l)
            if mm and mm.group(1) not in o:
                o[mm.group(1)] = mm.group(2).strip()
    return o


def parse_whois(asn, text):
    rec = {"as_name": "", "org_name": "", "created": "", "policy": collections.defaultdict(lambda: {"imp": [], "exp": [], "v6": False}), "lines": 0}
    o = org_attrs(text)
    rec["org_name"] = o.get("org-name", "")
    for k, v in autnum_attrs(text):
        v2 = re.sub(r"#.*", "", v).strip()
        if k == "as-name":
            rec["as_name"] = v2
        elif k == "created" and not rec["created"]:
            rec["created"] = v2[:10]
        elif k in ("import", "export", "mp-import", "mp-export", "default", "mp-default"):
            rec["lines"] += 1
            kind = "imp" if ("import" in k or "default" in k) else "exp"
            if "default" in k:
                m = re.search(r"\bto\s+(AS\d+)", v2, re.I)
                peers, body = ([m.group(1).upper()] if m else []), "ANY"
            else:
                kw = "from" if kind == "imp" else "to"
                m = re.search(r"\b%s\b(.*?)\b(accept|announce)\b(.*)" % kw, v2, re.I)
                if not m:
                    continue
                peerpart = re.sub(r"action.*", "", m.group(1), flags=re.I)
                body = m.group(3).strip()
                peers = [x.upper() for x in ASRE.findall(peerpart)]
            for p in peers:
                if p == asn:
                    continue
                rec["policy"][p][kind].append(body)
                if k.startswith("mp"):
                    rec["policy"][p]["v6"] = True
    return rec


def irr_relation(d):
    ia = any(ANYRE.search(b) for b in d["imp"])
    ea = any(ANYRE.search(b) for b in d["exp"])
    if ia and not ea:
        return "upstream"
    if ea and not ia:
        return "customer"
    if ia and ea:
        return "mutual"
    return "peer"


# ---------------------------------------------------------------- main build
def main():
    settings = json.load(open(os.path.join(CONFIG, "settings.json")))
    MIN_UP = settings.get("min_upstream_power", 20)
    MIN_UP_SHARE = settings.get("min_upstream_share", 0.03)
    MIN_DOWN = settings.get("min_customer_power", 15)
    MIN_PEER = settings.get("min_peer_power", 3)
    country = settings.get("country", "GE")

    names = {}
    for line in open(os.path.join(CACHE, "asn_list.txt"), encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if p[0]:
            names[p[0]] = p[1] if len(p) > 1 else ""

    info = {}
    if os.path.exists(os.path.join(CACHE, "asinfo.csv")):
        for r in csv.DictReader(open(os.path.join(CACHE, "asinfo.csv"), encoding="utf-8", errors="replace")):
            info["AS" + r["asn"]] = (r.get("handle", ""), r.get("description", ""), r.get("country-code", ""))

    # whois
    recs = {}
    for a in names:
        p = os.path.join(CACHE, "whois", a + ".txt")
        if os.path.exists(p):
            recs[a] = parse_whois(a, open(p, encoding="utf-8", errors="replace").read())
            if not names[a]:
                names[a] = recs[a]["org_name"] or info.get(a, ("", "", ""))[1] or recs[a]["as_name"]
        elif not names[a]:
            names[a] = info.get(a, ("", "", ""))[1]
    GE = set(names)

    # live
    def priv(a):
        n = int(a[2:])
        return 64512 <= n <= 65534 or n >= 4200000000 or n == 23456

    P = collections.defaultdict(int)
    seen = set()
    for a in names:
        p = os.path.join(CACHE, "live", a + ".json")
        if not os.path.exists(p):
            continue
        j = json.load(open(p))
        nbs = j.get("data", {}).get("neighbours", [])
        if nbs:
            seen.add(a)
        for nb in nbs:
            b = "AS" + str(nb["asn"])
            if priv(b) or b == a:
                continue
            k = (a, b, nb.get("type"))
            P[k] = max(P[k], int(nb.get("power") or 0))
    maxleft, maxright = collections.defaultdict(int), collections.defaultdict(int)
    for (a, b, p), v in P.items():
        if p == "left":
            maxleft[a] = max(maxleft[a], v)
        elif p == "right":
            maxright[a] = max(maxright[a], v)

    def up(a, b):
        v = P.get((a, b, "left"), 0)
        return v if (v >= MIN_UP and v >= MIN_UP_SHARE * maxleft[a]) else 0

    def down(a, b):
        v = P.get((a, b, "right"), 0)
        return v if (v >= MIN_DOWN and v >= 0.02 * maxright[a]) else 0

    rel = {}
    for x, y in {tuple(sorted((a, b))) for (a, b, _) in P}:
        xy = [v for v in (up(x, y), down(y, x)) if v]   # y is upstream of x
        yx = [v for v in (up(y, x), down(x, y)) if v]   # x is upstream of y
        if xy and yx:
            rel[(x, y)] = ("mutual", max(xy + yx))
        elif xy:
            rel[(y, x)] = ("transit", max(xy))
        elif yx:
            rel[(x, y)] = ("transit", max(yx))
        else:
            pv = max(P.get((x, y, "uncertain"), 0), P.get((y, x, "uncertain"), 0))
            if pv >= MIN_PEER and x in GE and y in GE:
                rel[(x, y)] = ("peer", pv)

    # RIPE-declared pairs
    irr = {}
    for a, r in recs.items():
        for b, d in r["policy"].items():
            k = tuple(sorted((a, b)))
            e = irr.setdefault(k, {"claims": {}, "policy": {}})
            rr = irr_relation(d)
            e["claims"][a] = (rr, b)
            e["policy"][a] = {"i": " / ".join(d["imp"])[:120], "e": " / ".join(d["exp"])[:120]}

    def irr_direction(k, e):
        """returns (src, dst, type) from RIPE claims"""
        a, b = k
        flip = {"upstream": "customer", "customer": "upstream", "peer": "peer", "mutual": "mutual"}
        rels = set()
        for by, (r, other) in e["claims"].items():
            rels.add(r if by == a else flip[r])     # relation of b with respect to a
        if rels == {"upstream", "customer"}:
            return a, b, "mutual"
        if "upstream" in rels:
            return b, a, "transit"
        if "customer" in rels:
            return a, b, "transit"
        return a, b, ("mutual" if "mutual" in rels else "peer")

    edges = []
    for (a, b), (t, pw) in rel.items():
        ie = irr.get(tuple(sorted((a, b))))
        edges.append(dict(src=a, dst=b, type=t, power=pw, live=True, irr=bool(ie), policy=ie["policy"] if ie else {}))
    livepairs = {tuple(sorted((e["src"], e["dst"]))) for e in edges}
    for k, e in irr.items():
        if k in livepairs or not (k[0] in seen or k[1] in seen):
            continue
        s, d, t = irr_direction(k, e)
        edges.append(dict(src=s, dst=d, type=t, power=0, live=False, irr=True, stale=True, policy=e["policy"]))

    # corporate groups: same registered name + config/groups.json
    by = collections.defaultdict(list)
    for a in GE:
        if names[a]:
            by[names[a].strip().lower()].append(a)
    groups = {names[v[0]]: sorted(v) for v in by.values() if len(v) > 1}
    gpath = os.path.join(CONFIG, "groups.json")
    if os.path.exists(gpath):
        for gname, members in json.load(open(gpath)).items():
            mem = set(members)
            for k in [k for k, v in groups.items() if set(v) & mem]:
                mem |= set(groups.pop(k))
            groups[gname] = sorted(mem)
    gof = {a: g for g, v in groups.items() for a in v}
    for g, v in groups.items():
        for i, a in enumerate(v):
            for b in v[i + 1:]:
                if tuple(sorted((a, b))) not in livepairs:
                    edges.append(dict(src=a, dst=b, type="group", power=0, live=True, irr=False, policy={}))

    # nodes
    nodes = {}

    def mk(x):
        if x in nodes:
            return
        if x in GE:
            r = recs.get(x, {})
            nodes[x] = dict(id=x, name=names[x] or x, grp="GE", cc=country, as_name=r.get("as_name", ""), created=r.get("created", ""), inbgp=x in seen)
        else:
            h, d, cc = info.get(x, ("", "", ""))
            nodes[x] = dict(id=x, name=d, as_name=h, grp=("T1" if x in TIER1 else "INT"), cc=cc)
            if cc == country:
                nodes[x]["grp"] = "GE"
    for a in GE:
        mk(a)
    for e in edges:
        mk(e["src"]), mk(e["dst"])
    for n in nodes.values():
        n.update(up=[], down=[], peers=[], stale_up=[], group=gof.get(n["id"], ""),
                 siblings=[x for x in groups.get(gof.get(n["id"], ""), []) if x != n["id"]])
    for e in edges:
        if e["type"] == "group":
            continue
        if e.get("stale"):
            if e["type"] == "transit":
                nodes[e["dst"]]["stale_up"].append(e["src"])
            continue
        if e["type"] == "transit":
            nodes[e["dst"]]["up"].append(e["src"])
            nodes[e["src"]]["down"].append(e["dst"])
        else:
            nodes[e["src"]]["peers"].append(e["dst"])
            nodes[e["dst"]]["peers"].append(e["src"])
    fpeers = collections.Counter(a for (a, b, p), v in P.items() if p == "uncertain" and v >= MIN_PEER and a in GE and b not in GE)
    for x in GE:
        n = nodes[x]
        sib = set(n["siblings"])
        nd = len([c for c in n["down"] if c not in sib])
        own = len([c for c in n["down"] if c in sib])
        nu = len(n["up"])
        mut = [p for p in n["peers"] if any(e["type"] == "mutual" and not e.get("stale") and {e["src"], e["dst"]} == {x, p} for e in edges)]
        n["mutual"], n["foreign_peers"] = mut, fpeers[x]
        if not n["inbgp"]:
            role = "Not visible in BGP"
        elif nd >= 10:
            role = "National backbone / major transit"
        elif nd >= 3:
            role = "Regional transit provider"
        elif nd >= 1:
            role = "Small transit / reseller"
        elif own:
            role = "Group edge (own ASNs only)"
        elif nu + len(mut) >= 2:
            role = "Multi-homed end network"
        elif nu + len(mut) == 1:
            role = "Single-homed end network"
        else:
            role = "Peering only"
        n["role"] = role
        nb = (set(n["up"]) | set(n["down"]) | set(n["peers"])) - sib
        n["ge_links"] = sum(1 for y in nb if nodes[y]["grp"] == "GE")
        n["offshore"] = bool(n["inbgp"] and nb and n["ge_links"] == 0)

    today = datetime.date.today().isoformat()
    out = dict(nodes=list(nodes.values()), edges=edges,
               meta=dict(built=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), date=today, country=country,
                         live_source="RIPEstat asn-neighbours (RIPE RIS route collectors)", groups=groups,
                         counts=dict(asns=len(GE), in_bgp=len(seen))))

    # ------------------------------------------------ changes vs previous build
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(HIST, exist_ok=True)
    prev_path = os.path.join(OUT, "net.json")
    changes = {"date": today, "since": None, "items": []}
    if os.path.exists(prev_path):
        prev = json.load(open(prev_path))
        changes["since"] = prev.get("meta", {}).get("date")
        pn = {n["id"]: n for n in prev["nodes"]}

        def tl(d):
            return {(e["src"], e["dst"]) for e in d["edges"] if e["type"] in ("transit", "mutual") and not e.get("stale")}
        old, new = tl(prev), tl(out)
        nm = lambda a: (nodes.get(a) or pn.get(a) or {}).get("name") or a
        for s, d in sorted(new - old):
            changes["items"].append(dict(kind="link_added", src=s, dst=d, text=f"{nm(d)} ({d}) now takes transit from {nm(s)} ({s})"))
        for s, d in sorted(old - new):
            changes["items"].append(dict(kind="link_removed", src=s, dst=d, text=f"{nm(d)} ({d}) no longer seen taking transit from {nm(s)} ({s})"))
        for a in sorted(GE):
            was = pn.get(a, {}).get("inbgp")
            if a not in pn:
                changes["items"].append(dict(kind="asn_new", src=a, text=f"New ASN in the list: {nm(a)} ({a})"))
            elif was is False and nodes[a]["inbgp"]:
                changes["items"].append(dict(kind="asn_up", src=a, text=f"{nm(a)} ({a}) started announcing routes"))
            elif was and not nodes[a]["inbgp"]:
                changes["items"].append(dict(kind="asn_down", src=a, text=f"{nm(a)} ({a}) stopped announcing routes"))
    tmp = prev_path + ".tmp"
    json.dump(out, open(tmp, "w"), separators=(",", ":"), ensure_ascii=False)
    os.replace(tmp, prev_path)

    # history: one compressed snapshot per day + append-only change log
    with gzip.open(os.path.join(HIST, f"net-{today}.json.gz"), "wt", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"), ensure_ascii=False)
    with open(os.path.join(HIST, "changes.log"), "a", encoding="utf-8") as f:
        for it in changes["items"]:
            f.write(f"{today}\t{it['kind']}\t{it['text']}\n")
    # changes.json for the page = everything logged in the last N days
    cutoff = (datetime.date.today() - datetime.timedelta(days=settings.get("changes_window_days", 30))).isoformat()
    recent = []
    for line in open(os.path.join(HIST, "changes.log"), encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) == 3 and p[0] >= cutoff:
            recent.append(dict(date=p[0], kind=p[1], text=p[2]))
    json.dump(dict(built=out["meta"]["built"], window_days=settings.get("changes_window_days", 30),
                   last_run=changes, recent=list(reversed(recent))),
              open(os.path.join(OUT, "changes.json"), "w"), ensure_ascii=False, indent=1)
    keep = settings.get("history_days", 365)
    snaps = sorted(glob.glob(os.path.join(HIST, "net-*.json.gz")))
    for old in snaps[:-keep]:
        os.remove(old)

    print(f"built: {len(GE)} ASNs, {len(seen)} in BGP, {sum(1 for e in edges if e['type'] == 'transit' and not e.get('stale'))} live transit links, "
          f"{sum(1 for e in edges if e.get('stale'))} RIPE-only, {len(changes['items'])} changes")


if __name__ == "__main__":
    sys.exit(main())
