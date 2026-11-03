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
    MIN_BACKUP = settings.get("min_backup_power", 10)
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

    # ---- CAIDA (second relationship source, monthly, RIS + RouteViews)
    caida, caida_src = {}, ""
    cp = os.path.join(CACHE, "caida_rel.txt")
    if os.path.exists(cp):
        for line in open(cp):
            if line.startswith("# source"):
                caida_src = line.split()[-1]
                continue
            q = line.strip().split("|")
            if len(q) < 3 or line.startswith("#"):
                continue
            a, b = "AS" + q[0], "AS" + q[1]
            if a not in GE and b not in GE:
                continue
            caida[tuple(sorted((a, b)))] = (a, b, "transit") if q[2] == "-1" else (a, b, "peer")

    def weak(child, parent):
        """weak live evidence that parent sells transit to child"""
        return max(P.get((child, parent, "left"), 0), P.get((parent, child, "right"), 0))

    edges, done = [], set()

    def add(src, dst, t, pw, sources, **kw):
        k = tuple(sorted((src, dst)))
        ie = irr.get(k)
        if ie:
            sources = sorted(set(sources) | {"ripe"})
        e = dict(src=src, dst=dst, type=t, power=pw, live=True, irr=bool(ie), sources=sources,
                 policy=ie["policy"] if ie else {})
        e.update(kw)
        edges.append(e)
        done.add(k)
        return e

    # 1) strong live adjacencies (RIS)
    for (a, b), (t, pw) in rel.items():
        src_ = ["ris"]
        c = caida.get(tuple(sorted((a, b))))
        if c and ((t == "transit" and c[2] == "transit" and c[0] == a) or (t != "transit" and c[2] == "peer")):
            src_.append("caida")
        add(a, b, t, pw, src_)
    # 2) CAIDA links RIS did not show strongly
    for k, (a, b, t) in caida.items():
        if k in done:
            continue
        if t == "peer" and not (a in GE and b in GE):
            continue
        w = weak(b, a) if t == "transit" else 0
        add(a, b, t, w, ["caida", "ris"] if w >= MIN_BACKUP else ["caida"], caida_only=w < MIN_BACKUP)
    # 3) weak live + declared in RIPE as upstream -> backup / lightly used transit
    for k, e in irr.items():
        if k in done:
            continue
        s_, d_, t_ = irr_direction(k, e)
        if t_ == "transit":
            w = weak(d_, s_)
            if w >= MIN_BACKUP:
                add(s_, d_, "transit", w, ["ris"], backup=True)
    # 4) hand-made corrections
    opath = os.path.join(CONFIG, "overrides.json")
    hidden = set()
    if os.path.exists(opath):
        ov = json.load(open(opath))
        for h in ov.get("hide", []):
            hidden.add(tuple(sorted((h["src"].upper(), h["dst"].upper()))))
        for l in ov.get("add", []):
            a, b = l["src"].upper(), l["dst"].upper()
            k = tuple(sorted((a, b)))
            if k in done:
                for e in edges:
                    if tuple(sorted((e["src"], e["dst"]))) == k:
                        e["sources"] = sorted(set(e["sources"]) | {"manual"})
                        e["note"] = l.get("note", "")
                continue
            add(a, b, l.get("type", "transit"), 0, ["manual"], manual=True, note=l.get("note", ""))
    if hidden:
        edges = [e for e in edges if tuple(sorted((e["src"], e["dst"]))) not in hidden]
        done -= hidden
    # 5) declared in RIPE only -> stale layer
    for k, e in irr.items():
        if k in done or k in hidden or not (k[0] in seen or k[1] in seen):
            continue
        s_, d_, t_ = irr_direction(k, e)
        edges.append(dict(src=s_, dst=d_, type=t_, power=0, live=False, irr=True, stale=True, sources=["ripe"], policy=e["policy"]))
    livepairs = {tuple(sorted((e["src"], e["dst"]))) for e in edges if not e.get("stale")}

    # ---- link-state memory: a change counts only after it holds for N runs
    os.makedirs(HIST, exist_ok=True)
    CONFIRM = settings.get("confirm_runs", 2)
    spath = os.path.join(HIST, "linkstate.json")
    state = json.load(open(spath)) if os.path.exists(spath) else None
    today = datetime.date.today().isoformat()
    link_changes = []
    cur = {f"{e['src']}|{e['dst']}": e for e in edges if e["type"] in ("transit", "mutual") and not e.get("stale")}
    if state is None:
        state = {k: dict(first=today, last=today, streak=CONFIRM, miss=0, on=True, edge=v) for k, v in cur.items()}
    else:
        for k, e in cur.items():
            st = state.setdefault(k, dict(first=today, streak=0, miss=0, on=False))
            if st.get("last") != today:
                st["streak"] = st.get("streak", 0) + 1
            st.update(last=today, miss=0, edge=e)
            if not st["on"] and st["streak"] >= CONFIRM:
                st["on"] = True
                link_changes.append(("link_added", k))
            if not st["on"]:
                e["pending"] = True          # new, not yet confirmed
        for k in list(state):
            if k in cur:
                continue
            st = state[k]
            if st.get("missed_on") != today:
                st["miss"] = st.get("miss", 0) + 1
                st["missed_on"] = today
            st["streak"] = 0
            if st["on"] and st["miss"] >= CONFIRM:
                st["on"] = False
                link_changes.append(("link_removed", k))
            elif st["on"]:
                g = dict(st["edge"])
                g["grace"] = True             # missing today, kept until confirmed gone
                gk = tuple(sorted((g["src"], g["dst"])))
                if gk not in livepairs:
                    edges[:] = [x for x in edges if not (x.get("stale") and tuple(sorted((x["src"], x["dst"]))) == gk)]
                    edges.append(g)
                    livepairs.add(tuple(sorted((g["src"], g["dst"]))))
            if not st["on"] and st["miss"] >= CONFIRM:
                del state[k]
    json.dump(state, open(spath, "w"), separators=(",", ":"))

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

    # ---- PeeringDB (exchanges, facilities) and announced address space
    pdir = os.path.join(CACHE, "peeringdb")
    def pload(n):
        f = os.path.join(pdir, n + ".json")
        return json.load(open(f)) if os.path.exists(f) else []
    pdb_net = {"AS" + str(r["asn"]): r for r in pload("net")}
    ixinfo = {r["id"]: r for r in pload("ix")}
    ix_members = collections.defaultdict(dict)
    for r in pload("netixlan"):
        a = "AS" + str(r["asn"])
        if a in GE:
            m = ix_members[r["ix_id"]].setdefault(a, dict(speed=0, rs=False))
            m["speed"] += int(r.get("speed") or 0)
            m["rs"] = m["rs"] or bool(r.get("is_rs_peer"))
    net_facs = collections.defaultdict(list)
    fac_members = collections.defaultdict(set)
    for r in pload("netfac"):
        a = "AS" + str(r.get("local_asn"))
        if a in GE:
            net_facs[a].append(dict(id=r.get("fac_id"), name=r.get("name", ""), city=r.get("city", ""), cc=r.get("country", "")))
            fac_members[r.get("fac_id")].add(a)
    country_facs = [dict(id=f["id"], name=f.get("name", ""), city=f.get("city", ""), website=f.get("website", ""),
                         members=sorted(fac_members.get(f["id"], set()))) for f in pload("fac_country")]
    country_facs.sort(key=lambda f: (-len(f["members"]), f["name"]))
    MIN_IX = settings.get("min_ix_members_on_graph", 2)
    for ixid, mem in ix_members.items():
        if len(mem) < MIN_IX:
            continue
        for a, m in mem.items():
            edges.append(dict(src=f"IX:{ixid}", dst=a, type="ix", power=0, live=True, irr=False, sources=["peeringdb"], policy={},
                              speed=m["speed"], rs=m["rs"]))
    space = {}
    for a in GE:
        f = os.path.join(CACHE, "rstatus", a + ".json")
        if os.path.exists(f):
            d = json.load(open(f)).get("announced_space", {})
            space[a] = dict(v4_24=round((d.get("v4", {}).get("ips") or 0) / 256), v6_48=d.get("v6", {}).get("48s") or 0)

    # nodes
    nodes = {}

    def mk(x):
        if x in nodes:
            return
        if x in GE:
            r = recs.get(x, {})
            nodes[x] = dict(id=x, name=names[x] or x, grp="GE", cc=country, as_name=r.get("as_name", ""), created=r.get("created", ""), inbgp=x in seen)
        elif x.startswith("IX:"):
            ix = ixinfo.get(int(x[3:]), {})
            nodes[x] = dict(id=x, name=ix.get("name", x), as_name="", grp="IX", cc=ix.get("country", ""), city=ix.get("city", ""),
                            members=sorted(ix_members.get(int(x[3:]), {})))
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
        n.update(up=[], down=[], peers=[], stale_up=[], backup_up=[], ixs=[], group=gof.get(n["id"], ""),
                 siblings=[x for x in groups.get(gof.get(n["id"], ""), []) if x != n["id"]])
    for e in edges:
        if e["type"] == "group":
            continue
        if e["type"] == "ix":
            nodes[e["dst"]]["ixs"].append(e["src"])
            continue
        if e.get("backup"):
            nodes[e["dst"]]["backup_up"].append(e["src"])
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
        n["space"] = space.get(x, {})
        n["facs"] = net_facs.get(x, [])
        n["all_ixs"] = sorted([dict(id=i, name=ixinfo.get(i, {}).get("name", f"IX {i}"), city=ixinfo.get(i, {}).get("city", ""),
                                    cc=ixinfo.get(i, {}).get("country", ""), speed=m[x]["speed"]) for i, m in ix_members.items() if x in m],
                              key=lambda r: -r["speed"])
        pn_ = pdb_net.get(x)
        if pn_:
            n["pdb"] = dict(id=pn_.get("id"), type=pn_.get("info_type", ""), website=pn_.get("website", ""))
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

    out = dict(nodes=list(nodes.values()), edges=edges,
               meta=dict(built=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), date=today, country=country,
                         live_source="RIPEstat asn-neighbours (RIPE RIS route collectors)", groups=groups,
                         counts=dict(asns=len(GE), in_bgp=len(seen)), caida=caida_src, repo=settings.get("repo_url", ""),
                         facilities=country_facs,
                         exchanges=sorted([dict(id=i, name=ixinfo.get(i, {}).get("name", f"IX {i}"), city=ixinfo.get(i, {}).get("city", ""),
                                                cc=ixinfo.get(i, {}).get("country", ""), members=sorted(m)) for i, m in ix_members.items()],
                                          key=lambda r: (-len(r["members"]), r["name"]))))

    # ------------------------------------------------ changes vs previous build
    os.makedirs(OUT, exist_ok=True)
    prev_path = os.path.join(OUT, "net.json")
    changes = {"date": today, "since": None, "items": []}
    if os.path.exists(prev_path):
        prev = json.load(open(prev_path))
        changes["since"] = prev.get("meta", {}).get("date")
        pn = {n["id"]: n for n in prev["nodes"]}

        nm = lambda a: (nodes.get(a) or pn.get(a) or {}).get("name") or a
        for kind, k in sorted(link_changes):
            s_, d_ = k.split("|")
            verb = "now takes transit from" if kind == "link_added" else "no longer takes transit from"
            changes["items"].append(dict(kind=kind, src=s_, dst=d_, text=f"{nm(d_)} ({d_}) {verb} {nm(s_)} ({s_}), confirmed over {CONFIRM} runs"))
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
          f"{sum(1 for e in edges if e.get('stale'))} RIPE-only, {sum(1 for e in edges if e.get('backup'))} backup, "
          f"{sum(1 for e in edges if e.get('caida_only'))} CAIDA-only, {sum(1 for e in edges if e['type'] == 'ix')} IX memberships, {len(changes['items'])} changes")


if __name__ == "__main__":
    sys.exit(main())
