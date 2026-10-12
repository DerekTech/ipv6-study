#!/usr/bin/env python3
"""
Turn the raw CSVs from both servers into the figures the article reports.

Usage:
  python3 analyze.py --data DATA_DIR --out results

DATA_DIR holds the files from BOTH servers in one folder (the file names carry the
server label, so they don't collide): sample.csv, sample_info.json, meta_<server>.json,
dns_<server>.csv, conn_<server>_pass<N>.csv, http_<server>_pass<N>.csv, passes_<server>.jsonl.
Pass 0 (the pilot) is ignored.

Definitions (also written into findings.md so the article and the data agree):
  connected  a host "accepted a connection" over a protocol on a server if a TCP connection and
             TLS handshake to port 443 succeeded in a majority of that server's passes. Every host
             in both samples gets this test; it sends no HTTP request.
  answered   a URL "answered" over a protocol on a server if its first page request got any
             HTTP response (any status code) in a majority of passes. Only full-mode URLs
             (Tranco homepages, and targets whose terms allow automated access) get page requests.
  site, Tranco    apex or www (either name counts).
  site, target    every tested host of the site (homepage host and scrape-page host).
  AAAA       the name published at least one AAAA record, as seen from either server.
  headline reachability (the chart) = accepted an IPv6 connection from every server.
  different  for a URL that answered over both protocols on a server, the same kind of
             difference (status class, block/challenge page on one side only, or body size
             beyond --size-ratio when both are 2xx) in a majority of paired passes.
"""
import argparse
import csv
import glob
import json
import os
import re
import statistics
from collections import Counter, defaultdict
from urllib.parse import urlsplit

CURL_ERRORS = {
    "6": "could not resolve host", "7": "could not connect (refused or unreachable)",
    "28": "timed out", "35": "TLS handshake failed", "52": "empty reply",
    "56": "connection reset while receiving", "60": "certificate problem",
    "47": "too many redirects", "16": "HTTP/2 error", "92": "HTTP/2 stream error",
}


# --------------------------------------------------------------------------- loading

def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def load(data):
    """data: one directory, or a list of directories (e.g. data/us data/eu)."""
    dirs = data if isinstance(data, list) else [data]
    data = dirs[0]
    sample = read_csv(os.path.join(data, "sample.csv"))
    info = {}
    if os.path.exists(os.path.join(data, "sample_info.json")):
        with open(os.path.join(data, "sample_info.json")) as f:
            info = json.load(f)

    def files(pattern):
        return [p for d in dirs for p in glob.glob(os.path.join(d, pattern))]

    servers = sorted(re.match(r"dns_(.+)\.csv$", os.path.basename(p)).group(1)
                     for p in files("dns_*.csv"))
    if not servers:
        raise SystemExit(f"no dns_<server>.csv files in {data}")

    dns = defaultdict(dict)              # dns[server][(host, rtype)] = row
    for s in servers:
        for r in read_csv(next(p for p in files(f"dns_{s}.csv"))):
            dns[s][(r["host"], r["rtype"])] = r

    http = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))  # http[s][url_id][proto][pass] = row
    passes = defaultdict(set)
    for p in files("http_*_pass*.csv"):
        m = re.match(r"http_(.+)_pass(\d+)\.csv$", os.path.basename(p))
        s, n = m.group(1), int(m.group(2))
        if n == 0 or s not in servers:
            continue
        passes[s].add(n)
        for r in read_csv(p):
            http[s][r["url_id"]][r["proto"]][n] = r

    conn = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))  # conn[s][(site, host)][proto][pass]
    for p in files("conn_*_pass*.csv"):
        m = re.match(r"conn_(.+)_pass(\d+)\.csv$", os.path.basename(p))
        s, n = m.group(1), int(m.group(2))
        if n == 0 or s not in servers:
            continue
        passes[s].add(n)
        for r in read_csv(p):
            conn[s][(r["site"], r["host"])][r["proto"]][n] = r

    meta, runs = {}, defaultdict(list)
    for s in servers:
        mp = next(iter(files(f"meta_{s}.json")), "")
        if mp and os.path.exists(mp):
            with open(mp) as f:
                meta[s] = json.load(f)
        jp = next(iter(files(f"passes_{s}.jsonl")), "")
        if jp and os.path.exists(jp):
            with open(jp) as f:
                runs[s] = [json.loads(l) for l in f if l.strip()]
    return sample, info, servers, dns, http, conn, passes, meta, runs


# --------------------------------------------------------------------------- helpers

def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def failure_label(row):
    stage, err = row.get("error_stage", ""), (row.get("error") or "").lower()
    if "timed out" in err:
        return f"{stage} timed out" if stage else "timed out"
    if "refused" in err:
        return "connection refused"
    if "unreachable" in err:
        return "network unreachable"
    if "reset" in err:
        return f"{stage} connection reset"
    if "certificate" in err:
        return "TLS certificate error"
    if stage == "dns":
        return "no IPv6 address resolved"
    if stage == "tls":
        return "TLS handshake failed"
    return err[:60] or "unknown"


def pct(n, d):
    return round(100.0 * n / d, 1) if d else None


def med(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 1) if xs else None


def majority(k, n):
    return n > 0 and k * 2 > n


def paired(v4, v6):
    both = [k for k in v4 if v4[k] is not None and v6.get(k) is not None]
    diffs = [v6[k] - v4[k] for k in both]
    return {"n": len(both), "median_ipv4": med([v4[k] for k in both]),
            "median_ipv6": med([v6[k] for k in both]),
            "median_difference_ipv6_minus_ipv4": med(diffs),
            "ipv6_faster_pct": pct(sum(1 for d in diffs if d < 0), len(diffs)),
            "within_10ms_pct": pct(sum(1 for d in diffs if abs(d) <= 10), len(diffs))}


class Study:
    def __init__(self, a):
        (self.sample, self.info, self.servers, self.dns, self.http, self.conn,
         self.passes, self.meta, self.runs) = load(a.data)
        self.size_ratio = a.size_ratio
        self.by_id = {r["url_id"]: r for r in self.sample}
        self.has_conn = any(self.conn[s] for s in self.servers)   # connection test is opt-in

    # ---- DNS
    def aaaa(self, host, server=None):
        servers = [server] if server else self.servers
        return any((self.dns[s].get((host, "AAAA")) or {}).get("addresses") for s in servers)

    def a_rec(self, host):
        return any((self.dns[s].get((host, "A")) or {}).get("addresses") for s in self.servers)

    # ---- connection test (TCP + TLS handshake, no HTTP)
    def crows(self, s, key, proto):
        return self.conn[s].get(key, {}).get(proto, {})

    def cmeasured(self, s, key):
        return bool(self.conn[s].get(key))

    def connected(self, s, key, proto):
        rows = self.crows(s, key, proto)
        ok = sum(1 for r in rows.values() if r.get("tls_ok") == "yes")
        return majority(ok, len(rows))

    def connected_all(self, key, proto):
        ms = [s for s in self.servers if self.cmeasured(s, key)]
        return bool(ms) and all(self.connected(s, key, proto) for s in ms)

    def connected_any(self, key, proto):
        return any(self.connected(s, key, proto) for s in self.servers if self.cmeasured(s, key))

    def ctiming(self, s, key, proto, field):
        return med([num(r.get(field)) for r in self.crows(s, key, proto).values() if r.get("tls_ok") == "yes"])

    # ---- HTTP
    def rows(self, s, uid, proto):
        return self.http[s].get(uid, {}).get(proto, {})

    def measured(self, s, uid):
        return bool(self.http[s].get(uid))

    def answered(self, s, uid, proto):
        rows = self.rows(s, uid, proto)
        ok = sum(1 for r in rows.values() if r.get("status"))
        return majority(ok, len(rows))

    def answered_all(self, uid, proto):
        ms = [s for s in self.servers if self.measured(s, uid)]
        return bool(ms) and all(self.answered(s, uid, proto) for s in ms)

    def answered_any(self, uid, proto):
        return any(self.answered(s, uid, proto) for s in self.servers if self.measured(s, uid))

    def loaded(self, s, uid, proto):
        """The final page arrived: the first response and every redirect hop succeeded (any status)."""
        rows = self.rows(s, uid, proto)
        ok = sum(1 for r in rows.values() if r.get("final_status") and str(r.get("final_exit_code")) == "0")
        return majority(ok, len(rows))

    def loaded_all(self, uid, proto):
        ms = [s for s in self.servers if self.measured(s, uid)]
        return bool(ms) and all(self.loaded(s, uid, proto) for s in ms)

    def timing(self, s, uid, proto, field):
        return med([num(r.get(field)) for r in self.rows(s, uid, proto).values() if r.get("status")])

    # ---- response comparison
    def compare(self, s, uid):
        """Return (consistent_flags, ever_flags, n_paired) for one URL on one server."""
        r4, r6 = self.rows(s, uid, "ipv4"), self.rows(s, uid, "ipv6")
        counts, n = Counter(), 0
        for p in sorted(set(r4) & set(r6)):
            a, b = r4[p], r6[p]
            if not (a.get("final_status") and b.get("final_status")):
                continue
            n += 1
            flags = set()
            # A redirect whose target can't be reached over this protocol (e.g. bbc.com has IPv6 but
            # www.bbc.com doesn't) is a dead end, not a different response: record it and stop.
            dead_a = str(a.get("final_exit_code")) != "0"
            dead_b = str(b.get("final_exit_code")) != "0"
            if dead_a or dead_b:
                if dead_b and not dead_a:
                    flags.add("ipv6_dead_end")
                elif dead_a and not dead_b:
                    flags.add("ipv4_dead_end")
                counts.update(flags)
                continue
            sa, sb = a["final_status"], b["final_status"]
            if sa[0] != sb[0]:
                flags.add("status_class")
            ma = set(filter(None, a.get("block_markers", "").split(";")))
            mb = set(filter(None, b.get("block_markers", "").split(";")))
            if mb - ma and not ma:
                flags.add("blocked_ipv6_only")
            if ma - mb and not mb:
                flags.add("blocked_ipv4_only")
            if sa.startswith("2") and sb.startswith("2"):
                xa, xb = num(a.get("final_size_bytes")), num(b.get("final_size_bytes"))
                if xa is not None and xb is not None:
                    lo, hi = min(xa, xb), max(xa, xb)
                    if hi - lo >= 1000 and (lo == 0 or hi / lo > self.size_ratio):
                        flags.add("size")
            fa, fb = urlsplit(a.get("final_url", "")), urlsplit(b.get("final_url", ""))
            if (fa.hostname, fa.path) != (fb.hostname, fb.path):
                flags.add("final_url")          # reported, not counted as "different"
            counts.update(flags)
        consistent = {f for f, k in counts.items() if majority(k, n)}
        return consistent, set(counts), n

    def size_noise(self, proto):
        """Within-protocol body-size variation across passes (max/min of 2xx bodies)."""
        ratios = []
        for s in self.servers:
            for uid in self.http[s]:
                sizes = [num(r.get("final_size_bytes")) for r in self.rows(s, uid, proto).values()
                         if r.get("final_status", "").startswith("2")]
                sizes = [x for x in sizes if x]
                if len(sizes) >= 2:
                    ratios.append(max(sizes) / min(sizes))
        if not ratios:
            return None
        ratios.sort()
        return {"urls": len(ratios), "median_ratio": round(statistics.median(ratios), 3),
                "p90_ratio": round(ratios[int(0.9 * (len(ratios) - 1))], 3),
                "share_above_threshold_pct": pct(sum(1 for x in ratios if x > self.size_ratio), len(ratios))}


# --------------------------------------------------------------------------- analysis

COUNTED = ("status_class", "blocked_ipv6_only", "blocked_ipv4_only", "size")


def analyse(st):
    out = {"servers": {}, "sample": st.info, "size_ratio_threshold": st.size_ratio}
    for s in st.servers:
        m = st.meta.get(s, {})
        runs = sorted(st.runs.get(s, []), key=lambda r: r.get("started_utc", ""))
        real = [r for r in runs if r.get("pass", 0) != 0]
        out["servers"][s] = {
            "location": m.get("location"), "provider": m.get("provider"),
            "public_ipv4": m.get("public_ipv4"), "public_ipv6": m.get("public_ipv6"),
            "passes": sorted(st.passes[s]),
            "first_pass_utc": real[0]["started_utc"] if real else None,
            "last_pass_utc": real[-1]["finished_utc"] if real else None,
            "user_agent": m.get("user_agent"), "curl": m.get("curl_version"),
            "warnings": m.get("warnings", []),
        }
        if len(st.passes[s]) < 5:
            out["servers"][s]["warnings"] = out["servers"][s]["warnings"] + [
                f"only {len(st.passes[s])} passes found (expected 5)"]

    # ---- group the sample
    tranco = defaultdict(dict)       # domain -> {"apex": row, "www": row}
    targets = defaultdict(dict)      # site -> {"homepage": row, "scrape": row}
    for r in st.sample:
        (tranco if r["source"] == "tranco" else targets)[r["site"]][r["variant"]] = r

    def any_measured(uid):
        return any(st.measured(s, uid) for s in st.servers)

    # ---- Tranco reachability (site level: apex or www)
    t = Counter()
    apex_www = []
    for d, v in tranco.items():
        rows = [x for x in v.values()]
        hosts = [x["host"] for x in rows]
        keys = [(d, h) for h in hosts if any(st.cmeasured(s, (d, h)) for s in st.servers)]
        uids = [x["url_id"] for x in rows if any_measured(x["url_id"])]
        t["domains"] += 1
        has6 = any(st.aaaa(h) for h in hosts)
        t["aaaa"] += has6
        if keys:
            t["conn_measured"] += 1
            c4 = any(st.connected_all(k, "ipv4") for k in keys)
            c6 = any(st.connected_all(k, "ipv6") for k in keys)
            t["conn_v4"] += c4
            t["conn_v6"] += c6
            t["conn_v6_any"] += any(st.connected_any(k, "ipv6") for k in keys)
            t["conn_v6_and_v4"] += (c4 and c6)
            t["aaaa_conn"] += has6
            if has6 and c4 and not c6:
                t["aaaa_but_no_v6"] += 1
        if not uids:
            t["not_measured"] += 1
            continue
        t["measured"] += 1
        v4 = any(st.answered_all(u, "ipv4") for u in uids)
        v6 = any(st.answered_all(u, "ipv6") for u in uids)
        v6_any = any(st.answered_any(u, "ipv6") for u in uids)
        t["v4"] += v4
        t["v6_all"] += v6
        t["v6_any"] += v6_any
        t["v6_and_v4"] += (v6 and v4)
        l4 = any(st.loaded_all(u, "ipv4") for u in uids)
        l6 = any(st.loaded_all(u, "ipv6") for u in uids)
        t["l4"] += l4
        t["l6"] += l6
        t["l6_and_l4"] += (l6 and l4)
        t["aaaa_web"] += (has6 and l4)
        t["dead_end"] += (v6 and not l6 and l4)
        if not st.has_conn:
            t["aaaa_conn"] += has6
            if has6 and v4 and not v6:
                t["aaaa_but_no_v6"] += 1
        # apex vs www
        if "apex" in v and "www" in v:
            a, w = v["apex"], v["www"]
            a6, w6 = st.aaaa(a["host"]), st.aaaa(w["host"])
            if st.has_conn:
                ka, kw = (d, a["host"]), (d, w["host"])
                ar, wr = st.connected_all(ka, "ipv6"), st.connected_all(kw, "ipv6")
                ar4, wr4 = st.connected_all(ka, "ipv4"), st.connected_all(kw, "ipv4")
            else:
                ar, wr = st.loaded_all(a["url_id"], "ipv6"), st.loaded_all(w["url_id"], "ipv6")
                ar4, wr4 = st.loaded_all(a["url_id"], "ipv4"), st.loaded_all(w["url_id"], "ipv4")
            kinds = []
            if a6 != w6 and st.a_rec(a["host"]) and st.a_rec(w["host"]):   # only names that both exist
                kinds.append("aaaa_apex_only" if a6 else "aaaa_www_only")
            if ar4 and wr4 and ar != wr:
                kinds.append("ipv6_reachable_apex_only" if ar else "ipv6_reachable_www_only")
            if kinds:
                apex_www.append({"rank": a["rank"], "domain": d, "differences": ";".join(kinds),
                                 "apex_aaaa": a6, "www_aaaa": w6, "apex_ipv6_reachable": ar,
                                 "www_ipv6_reachable": wr})
    both_served = sum(1 for d, v in tranco.items() if len(v) == 2 and all(
        (st.connected_all((d, x["host"]), "ipv4") if st.has_conn else st.loaded_all(x["url_id"], "ipv4"))
        for x in v.values()))
    out["tranco"] = {
        "domains": t["domains"], "measured": t["measured"], "conn_measured": t["conn_measured"],
        "aaaa_pct": pct(t["aaaa"], t["domains"]), "aaaa_n": t["aaaa"],
        "conn_ipv6_pct": pct(t["conn_v6"], t["conn_measured"]), "conn_ipv6_n": t["conn_v6"],
        "conn_ipv6_any_server_pct": pct(t["conn_v6_any"], t["conn_measured"]),
        "conn_ipv4_n": t["conn_v4"],
        "conn_ipv6_of_ipv4_sites_pct": pct(t["conn_v6_and_v4"], t["conn_v4"]),
        "answered_ipv4_n": t["v4"],
        "answered_ipv6_pct": pct(t["v6_all"], t["measured"]), "answered_ipv6_n": t["v6_all"],
        "answered_ipv6_any_server_pct": pct(t["v6_any"], t["measured"]),
        "answered_ipv6_of_ipv4_sites_pct": pct(t["v6_and_v4"], t["v4"]),
        "web_domains_n": t["l4"], "aaaa_web_pct": pct(t["aaaa_web"], t["l4"]),
        "loaded_ipv6_n": t["l6"], "loaded_ipv6_of_ipv4_sites_pct": pct(t["l6_and_l4"], t["l4"]),
        "ipv6_dead_end_domains_n": t["dead_end"],
        "aaaa_but_ipv6_failed_n": t["aaaa_but_no_v6"],
        "aaaa_but_ipv6_failed_pct_of_aaaa": pct(t["aaaa_but_no_v6"], t["aaaa_conn"]),
        "apex_www": {
            "domains_with_both_names_reachable_ipv4": both_served,
            "differ_n": len(apex_www),
            "aaaa_differs_n": sum(1 for x in apex_www if "aaaa_" in x["differences"]),
            "ipv6_reachability_differs_n": sum(1 for x in apex_www if "ipv6_reachable" in x["differences"]),
            "aaaa_www_only_n": sum(1 for x in apex_www if "aaaa_www_only" in x["differences"]),
            "aaaa_apex_only_n": sum(1 for x in apex_www if "aaaa_apex_only" in x["differences"]),
        },
    }
    out["tranco"]["apex_www"]["differ_pct_of_domains"] = pct(len(apex_www), t["domains"])

    # ---- targets: connection test on every host; page requests only for full-mode sites
    g = Counter()
    for site, v in targets.items():
        rows = list(v.values())
        keys = sorted({(site, x["host"]) for x in rows})
        g["sites"] += 1
        if not (any(st.cmeasured(s, k) for s in st.servers for k in keys) or
                any(any_measured(x["url_id"]) for x in rows)):
            g["not_measured"] += 1
            continue
        g["measured"] += 1
        g["aaaa"] += any(st.aaaa(x["host"]) for x in rows)
        g["conn_v6"] += all(st.connected_all(k, "ipv6") for k in keys)
        g["conn_v4"] += all(st.connected_all(k, "ipv4") for k in keys)
        g["multi_host"] += len(keys) > 1
        if len(keys) > 1:
            g["hosts_disagree_v6"] += len({st.connected_all(k, "ipv6") for k in keys}) > 1
        mode = rows[0].get("mode", "full")
        g[f"mode_{mode}"] += 1
        if mode != "full":
            continue
        measured = [x for x in rows if any_measured(x["url_id"])]
        if not measured:
            continue
        g["full_measured"] += 1
        v4_all = all(st.loaded_all(x["url_id"], "ipv4") for x in measured)
        v6_all = all(st.loaded_all(x["url_id"], "ipv6") for x in measured)
        g["dead_end"] += (all(st.answered_all(x["url_id"], "ipv6") for x in measured) and not v6_all and v4_all)
        g["full_v6_all_pages"] += v6_all
        g["full_v4_all_pages"] += v4_all
        g["full_v6_of_v4"] += (v4_all and v6_all)
        g["aaaa_web"] += (v4_all and any(st.aaaa(x["host"]) for x in measured))
        for kind in ("homepage", "scrape"):
            if kind in v and any_measured(v[kind]["url_id"]):
                g[f"{kind}_measured"] += 1
                g[f"{kind}_v6"] += st.answered_all(v[kind]["url_id"], "ipv6")
            elif kind in v:
                g[f"{kind}_skipped"] += 1
    cats = Counter(next(iter(v.values()))["category"] for v in targets.values())
    out["targets"] = {
        "sites": g["sites"], "measured": g["measured"], "categories": dict(cats),
        "full_mode_n": g["mode_full"], "connect_mode_n": g["mode_connect"],
        "aaaa_pct": pct(g["aaaa"], g["measured"]), "aaaa_n": g["aaaa"],
        "conn_ipv6_pct": pct(g["conn_v6"], g["measured"]), "conn_ipv6_n": g["conn_v6"],
        "conn_ipv4_n": g["conn_v4"],
        "sites_with_separate_scrape_host": g["multi_host"], "hosts_disagree_ipv6_n": g["hosts_disagree_v6"],
        "full_measured": g["full_measured"],
        "full_answered_ipv6_pct": pct(g["full_v6_all_pages"], g["full_measured"]),
        "web_sites_n": g["full_v4_all_pages"], "aaaa_web_pct": pct(g["aaaa_web"], g["full_v4_all_pages"]),
        "loaded_ipv6_of_ipv4_sites_pct": pct(g["full_v6_of_v4"], g["full_v4_all_pages"]),
        "ipv6_dead_end_sites_n": g["dead_end"],
        "homepage_answered_ipv6_pct": pct(g["homepage_v6"], g["homepage_measured"]),
        "scrape_answered_ipv6_pct": pct(g["scrape_v6"], g["scrape_measured"]),
        "scrape_pages_skipped_robots_n": g["scrape_skipped"],
    }

    # ---- speed, per server. Connect and TLS times from the connection test (every host that
    # connected over both protocols); time to first byte from page requests (full-mode URLs).
    speed = {}
    for s_ in st.servers:
        res = {}
        keys = [k for k in st.conn[s_] if st.connected(s_, k, "ipv4") and st.connected(s_, k, "ipv6")]
        uids = [u for u in st.http[s_] if st.answered(s_, u, "ipv4") and st.answered(s_, u, "ipv6")]
        for field in ("tcp_connect_ms", "tls_ms"):
            if st.has_conn:
                v4 = {k: st.ctiming(s_, k, "ipv4", field) for k in keys}
                v6 = {k: st.ctiming(s_, k, "ipv6", field) for k in keys}
            else:
                v4 = {u: st.timing(s_, u, "ipv4", field) for u in uids}
                v6 = {u: st.timing(s_, u, "ipv6", field) for u in uids}
            res[field] = paired(v4, v6)
        v4 = {u: st.timing(s_, u, "ipv4", "ttfb_ms") for u in uids}
        v6 = {u: st.timing(s_, u, "ipv6", "ttfb_ms") for u in uids}
        res["ttfb_ms"] = paired(v4, v6)
        speed[s_] = res
    out["speed"] = speed

    # ---- different responses
    diff_rows, per_url = [], {}
    for s in st.servers:
        for u in st.http[s]:
            if not (st.answered(s, u, "ipv4") and st.answered(s, u, "ipv6")):
                continue
            cons, ever, n = st.compare(s, u)
            rec = per_url.setdefault(u, {"consistent": set(), "ever": set(), "servers": set(), "dead": set()})
            rec["dead"] |= cons & {"ipv6_dead_end", "ipv4_dead_end"}
            counted = cons & set(COUNTED)
            rec["consistent"] |= counted
            rec["ever"] |= ever & set(COUNTED)
            rec["servers"].add(s)
            if counted or ("final_url" in cons) or rec["dead"]:
                r = st.by_id[u]
                diff_rows.append({"server": s, "url_id": u, "source": r["source"], "site": r["site"],
                                  "variant": r["variant"], "url": r["url"], "paired_passes": n,
                                  "consistent_differences": ";".join(sorted(cons)),
                                  "counted": "yes" if counted else ("no (dead end)" if cons & {"ipv6_dead_end", "ipv4_dead_end"} else "no (final URL only)")})
    compared = len(per_url)
    differing = [u for u, x in per_url.items() if x["consistent"]]
    by_type = Counter(f for u in differing for f in per_url[u]["consistent"])
    grp = Counter()
    for u in per_url:
        r = st.by_id[u]
        key = "tranco" if r["source"] == "tranco" else f"target_{r['variant']}"
        grp[f"{key}_compared"] += 1
        grp[f"{key}_different"] += bool(per_url[u]["consistent"])
    out["different"] = {
        "ipv6_dead_end_urls_n": sum(1 for x in per_url.values() if "ipv6_dead_end" in x["dead"]),
        "ipv4_dead_end_urls_n": sum(1 for x in per_url.values() if "ipv4_dead_end" in x["dead"]),
        "urls_compared": compared, "different_n": len(differing),
        "different_pct": pct(len(differing), compared),
        "ever_different_pct": pct(sum(1 for x in per_url.values() if x["ever"]), compared),
        "by_type": dict(by_type),
        "tranco_pct": pct(grp["tranco_different"], grp["tranco_compared"]),
        "target_homepage_pct": pct(grp["target_homepage_different"], grp["target_homepage_compared"]),
        "target_scrape_pct": pct(grp["target_scrape_different"], grp["target_scrape_compared"]),
        "blocked_ipv6_only_n": by_type.get("blocked_ipv6_only", 0),
        "blocked_ipv4_only_n": by_type.get("blocked_ipv4_only", 0),
    }
    out["size_noise"] = {"ipv4": st.size_noise("ipv4"), "ipv6": st.size_noise("ipv6")}
    # The chart's second bar: connection test if it was run, otherwise page requests (the brief's method).
    if st.has_conn:
        out["reach_basis"] = "Accepted an IPv6 connection from both servers"
        out["tranco"]["chart_v6_pct"] = out["tranco"]["conn_ipv6_pct"]
        out["targets"]["chart_v6_pct"] = out["targets"]["conn_ipv6_pct"]
        for k in ("tranco", "targets"):
            out[k]["chart_aaaa_pct"] = out[k]["aaaa_pct"]
            out[k]["chart_n"] = out[k]["conn_measured" if k == "tranco" else "measured"]
    else:
        out["reach_basis"] = "Loaded over IPv6 from both servers"
        # Tranco includes CDN, API and tracking domains that serve no website. Both bars use the
        # sites that answered over IPv4 from both servers, so the two shares share a denominator.
        for k in ("tranco", "targets"):
            out[k]["chart_aaaa_pct"] = out[k]["aaaa_web_pct"]
            out[k]["chart_v6_pct"] = out[k]["loaded_ipv6_of_ipv4_sites_pct"]
            out[k]["chart_n"] = out[k]["web_domains_n" if k == "tranco" else "web_sites_n"]

    # ---- why IPv6 failed where an AAAA record exists and IPv4 connected (connection test)
    fails = Counter()
    fail_rows = []
    for s_ in st.servers:
        for key in st.conn[s_]:
            site, host = key
            if st.aaaa(host, s_) and st.connected(s_, key, "ipv4") and not st.connected(s_, key, "ipv6"):
                errs = Counter(failure_label(x) for x in st.crows(s_, key, "ipv6").values()
                               if x.get("tls_ok") != "yes")
                label = errs.most_common(1)[0][0] if errs else "unknown"
                fails[label] += 1
                fail_rows.append({"server": s_, "site": site, "host": host, "failure": label})
    if not st.has_conn:
        for s_ in st.servers:
            for u in st.http[s_]:
                r = st.by_id[u]
                if st.aaaa(r["host"], s_) and st.loaded(s_, u, "ipv4") and not st.loaded(s_, u, "ipv6"):
                    if st.answered(s_, u, "ipv6"):
                        label = "redirected to a host without working IPv6"
                    else:
                        codes = Counter(str(x.get("exit_code")) for x in st.rows(s_, u, "ipv6").values()
                                        if not x.get("status"))
                        code = codes.most_common(1)[0][0] if codes else "?"
                        label = CURL_ERRORS.get(code, f"curl exit {code}")
                    fails[label] += 1
                    fail_rows.append({"server": s_, "site": r["site"], "host": r["host"], "url": r["url"],
                                      "failure": label})
    out["ipv6_failures"] = dict(fails.most_common())
    return out, apex_www, diff_rows, fail_rows


# --------------------------------------------------------------------------- outputs

def chart_svg(tr, tg, title_note, source_note="", basis="Answered over IPv6 from both servers"):
    """Grouped bar chart: Tranco vs targets, AAAA vs answered over IPv6. Static, light."""
    W, H = 720, 440
    left, right, top, bottom = 64, 24, 116, 64
    pw, ph = W - left - right, H - top - bottom
    c = {"surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781",
         "grid": "#e1e0d9", "base": "#c3c2b7", "s1": "#2a78d6", "s2": "#eb6834"}
    groups = [(f"Tranco top 1,000 ({tr['chart_n']} websites)", tr["chart_aaaa_pct"], tr["chart_v6_pct"]),
              (f"{tg['chart_n']} scraping targets", tg["chart_aaaa_pct"], tg["chart_v6_pct"])]
    bw, gap2 = 84, 2
    slot = pw / len(groups)

    def y(v):
        return top + ph - ph * (v or 0) / 100.0

    def bar(x, v, color):
        y0, yt, r = top + ph, y(v), 4
        h = y0 - yt
        if h <= 0:
            return ""
        r = min(r, h, bw / 2)
        d = (f"M{x:.1f},{y0:.1f} V{yt + r:.1f} Q{x:.1f},{yt:.1f} {x + r:.1f},{yt:.1f} "
             f"H{x + bw - r:.1f} Q{x + bw:.1f},{yt:.1f} {x + bw:.1f},{yt + r:.1f} V{y0:.1f} Z")
        return f'<path d="{d}" fill="{color}"/>'

    font = 'font-family="system-ui, -apple-system, Segoe UI, sans-serif"'
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         f'role="img" aria-labelledby="t d">',
         f'<title id="t">IPv6 reachability: Tranco top 1,000 vs 50 scraping targets</title>',
         f'<desc id="d">{alt_text(tr, tg, basis)}</desc>',
         f'<rect width="{W}" height="{H}" fill="{c["surface"]}"/>',
         f'<text x="{left - 40}" y="34" {font} font-size="19" font-weight="600" fill="{c["ink"]}">'
         f'IPv6 reachability: popular sites vs scraping targets</text>',
         f'<text x="{left - 40}" y="58" {font} font-size="13" fill="{c["ink2"]}">{title_note}</text>']
    # legend
    lx, ly = left - 40, 84
    for i, (label, col) in enumerate((("Publishes an IPv6 address (AAAA record)", c["s1"]),
                                      (basis, c["s2"]))):
        x = lx + i * 300
        s.append(f'<rect x="{x}" y="{ly - 10}" width="12" height="12" rx="3" fill="{col}"/>')
        s.append(f'<text x="{x + 18}" y="{ly}" {font} font-size="13" fill="{c["ink2"]}">{label}</text>')
    # grid + axis
    for v in (0, 25, 50, 75, 100):
        yy = y(v)
        s.append(f'<line x1="{left}" x2="{W - right}" y1="{yy:.1f}" y2="{yy:.1f}" '
                 f'stroke="{c["base"] if v == 0 else c["grid"]}" stroke-width="1"/>')
        s.append(f'<text x="{left - 10}" y="{yy + 4:.1f}" {font} font-size="12" fill="{c["muted"]}" '
                 f'text-anchor="end" style="font-variant-numeric: tabular-nums">{v}%</text>')
    # bars
    for gi, (label, v1, v2) in enumerate(groups):
        cx = left + slot * gi + slot / 2
        x1 = cx - bw - gap2 / 2
        x2 = cx + gap2 / 2
        for x, v, col in ((x1, v1, c["s1"]), (x2, v2, c["s2"])):
            s.append(bar(x, v, col))
            if v is not None:
                s.append(f'<text x="{x + bw / 2:.1f}" y="{y(v) - 8:.1f}" {font} font-size="14" '
                         f'font-weight="600" fill="{c["ink"]}" text-anchor="middle">{v:.1f}%</text>')
        s.append(f'<text x="{cx:.1f}" y="{top + ph + 26}" {font} font-size="14" fill="{c["ink"]}" '
                 f'text-anchor="middle">{label}</text>')
    if source_note:
        s.append(f'<text x="{left - 40}" y="{H - 14}" {font} font-size="12" fill="{c["muted"]}">{source_note}</text>')
    s.append("</svg>")
    return "\n".join(s)


def alt_text(tr, tg, basis="Answered over IPv6 from both servers"):
    b = basis[0].lower() + basis[1:]
    return (f"Bar chart of IPv6 reachability. Of the {tr['chart_n']} websites in the Tranco top 1,000, "
            f"{tr['chart_aaaa_pct']}% publish an IPv6 address and {tr['chart_v6_pct']}% {b}. "
            f"Of the {tg['chart_n']} commonly scraped sites, {tg['chart_aaaa_pct']}% publish an IPv6 address "
            f"and {tg['chart_v6_pct']}% {b}{' on every tested page' if 'Answered' in basis else ''}.")


def table_html(tr, tg, basis="Answered over IPv6 from both servers"):
    rows = [("Tranco top 1,000", tr["chart_n"], tr["chart_aaaa_pct"], tr["chart_v6_pct"]),
            ("Commonly scraped sites", tg["chart_n"], tg["chart_aaaa_pct"], tg["chart_v6_pct"])]
    body = "\n".join(f"    <tr><th scope=\"row\">{n}</th><td>{k}</td><td>{a}%</td><td>{b}%</td></tr>"
                     for n, k, a, b in rows)
    return ("<table>\n  <caption>IPv6 reachability by sample</caption>\n  <thead>\n    <tr><th scope=\"col\">"
            "Sample</th><th scope=\"col\">Websites tested</th><th scope=\"col\">Publish an IPv6 address (AAAA)</th>"
            f"<th scope=\"col\">{basis}</th></tr>\n  </thead>\n  <tbody>\n"
            f"{body}\n  </tbody>\n</table>\n")


def findings_md(o):
    tr, tg, df = o["tranco"], o["targets"], o["different"]
    lines = ["# Findings", "", "Generated by analyze.py. Every number in the article's test section comes from here.", ""]
    lines += ["## Placeholders for the draft", "", "| Placeholder | Value |", "|---|---|"]
    ph = {
        "TRANCO_LIST_ID": o["sample"].get("tranco_list_id"),
        "TRANCO_LIST_DATE": o["sample"].get("tranco_list_date"),
        "TRANCO_AAAA_PCT": tr["aaaa_pct"],
        "TRANCO_V6_PCT": tr["chart_v6_pct"], "TARGET_V6_PCT": tg["chart_v6_pct"], "REACH_BASIS": o["reach_basis"],
        "TRANCO_WEB_N": tr.get("web_domains_n"), "TRANCO_AAAA_WEB_PCT": tr.get("aaaa_web_pct"),
        "TARGET_WEB_N": tg.get("web_sites_n"), "TARGET_AAAA_WEB_PCT": tg.get("aaaa_web_pct"),
        "TRANCO_CONN_V6_PCT": tr["conn_ipv6_pct"], "TRANCO_CONN_V6_OF_V4_PCT": tr["conn_ipv6_of_ipv4_sites_pct"],
        "TRANCO_HTTP_V6_PCT": tr["answered_ipv6_pct"], "TRANCO_HTTP_V6_OF_V4_PCT": tr["answered_ipv6_of_ipv4_sites_pct"],
        "AAAA_BUT_FAILED_N": tr["aaaa_but_ipv6_failed_n"],
        "TARGET_SITES_MEASURED": tg["measured"], "TARGET_FULL_N": tg["full_mode_n"],
        "TARGET_CONNECT_N": tg["connect_mode_n"], "TARGET_AAAA_PCT": tg["aaaa_pct"],
        "TARGET_CONN_V6_PCT": tg["conn_ipv6_pct"],
        "TARGET_SEPARATE_HOST_N": tg["sites_with_separate_scrape_host"],
        "TARGET_HOSTS_DISAGREE_N": tg["hosts_disagree_ipv6_n"],
        "TARGET_FULL_HTTP_V6_PCT": tg["full_answered_ipv6_pct"],
        "SCRAPE_PAGES_SKIPPED_N": tg["scrape_pages_skipped_robots_n"],
        "DIFF_PCT": df["different_pct"], "DIFF_N": df["different_n"], "DIFF_COMPARED_N": df["urls_compared"],
        "BLOCKED_V6_ONLY_N": df["blocked_ipv6_only_n"], "BLOCKED_V4_ONLY_N": df["blocked_ipv4_only_n"],
        "APEX_WWW_N": tr["apex_www"]["differ_n"], "APEX_WWW_PCT": tr["apex_www"]["differ_pct_of_domains"],
        "AAAA_WWW_ONLY_N": tr["apex_www"]["aaaa_www_only_n"], "AAAA_APEX_ONLY_N": tr["apex_www"]["aaaa_apex_only_n"],
    }
    cats = tg.get("categories", {})
    ph["TARGET_CATEGORIES"] = ", ".join(f"{v} {k}" for k, v in sorted(cats.items(), key=lambda x: -x[1]))
    ph["TOP_FAILURE"] = next(iter(o["ipv6_failures"]), None)
    ph["TRANCO_LOADED_V6_OF_V4_PCT"] = tr.get("loaded_ipv6_of_ipv4_sites_pct")
    ph["TRANCO_V6_DEAD_END_N"] = tr.get("ipv6_dead_end_domains_n")
    ph["TARGET_V6_DEAD_END_N"] = tg.get("ipv6_dead_end_sites_n")
    ph["V6_DEAD_END_URLS_N"] = df.get("ipv6_dead_end_urls_n")
    if "conn_ipv6_pct" in tr and tr.get("conn_measured", 0) == 0:
        for k in [k for k in ph if "CONN" in k or k == "TARGET_HOSTS_DISAGREE_N"]:
            ph[k] = None                                  # connection test wasn't run
    ph["SIZE_RATIO"] = o["size_ratio_threshold"]
    dates = sorted(filter(None, [m["first_pass_utc"] for m in o["servers"].values()] +
                          [m["last_pass_utc"] for m in o["servers"].values()]))
    ph["TEST_DATES"] = f"{dates[0][:10]} to {dates[-1][:10]}" if dates else None
    for s, sp in o["speed"].items():
        S = s.upper()
        ph[f"{S}_CONNECT_V4_MS"] = sp["tcp_connect_ms"]["median_ipv4"]
        ph[f"{S}_CONNECT_V6_MS"] = sp["tcp_connect_ms"]["median_ipv6"]
        ph[f"{S}_CONNECT_V6_FASTER_PCT"] = sp["tcp_connect_ms"]["ipv6_faster_pct"]
        ph[f"{S}_CONNECT_PAIRED_HOSTS"] = sp["tcp_connect_ms"]["n"]
        ph[f"{S}_TTFB_V4_MS"] = sp["ttfb_ms"]["median_ipv4"]
        ph[f"{S}_TTFB_V6_MS"] = sp["ttfb_ms"]["median_ipv6"]
        ph[f"{S}_TTFB_V6_FASTER_PCT"] = sp["ttfb_ms"]["ipv6_faster_pct"]
        ph[f"{S}_TTFB_PAIRED_URLS"] = sp["ttfb_ms"]["n"]
    for s, m in o["servers"].items():
        S = s.upper()
        ph[f"{S}_LOCATION"] = m["location"]
        ph[f"{S}_FIRST_PASS"] = m["first_pass_utc"]
        ph[f"{S}_LAST_PASS"] = m["last_pass_utc"]
    for k, v in ph.items():
        lines.append(f"| [{k}] | {v} |")
    lines += ["", "## Alt text for the chart", "", alt_text(tr, tg, o["reach_basis"]), ""]
    lines += ["## IPv6 failure modes (AAAA published, IPv4 worked, IPv6 did not)", ""]
    for k, v in o["ipv6_failures"].items():
        lines.append(f"- {k}: {v} host-server pairs")
    lines += ["", "## Body-size noise within each protocol (sets the size threshold)", "",
              f"- Threshold used: {o['size_ratio_threshold']}x",
              f"- IPv4: {o['size_noise']['ipv4']}", f"- IPv6: {o['size_noise']['ipv6']}",
              "", "If the IPv4 p90 ratio is near or above the threshold, raise --size-ratio and rerun.", ""]
    lines += ["## Server details", ""]
    for s, m in o["servers"].items():
        lines.append(f"- **{s}**: {m['location']} ({m['provider']}), passes {m['passes']}, "
                     f"{m['first_pass_utc']} to {m['last_pass_utc']}. Warnings: {m['warnings'] or 'none'}")
    lines += ["", "Full numbers: summary.json. Case lists: apex_www_differences.csv, "
              "different_responses.csv, ipv6_failures.csv.", ""]
    return "\n".join(lines)


def write_csv(path, rows):
    if not rows:
        open(path, "w").close()
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", required=True, nargs="+",
                   help="data folder(s); pass both servers' folders, e.g. --data data/us data/eu")
    p.add_argument("--out", default="results")
    p.add_argument("--size-ratio", type=float, default=1.5)
    p.add_argument("--repo", default="", help="repo URL for the chart's source line, e.g. github.com/you/ipv6-study")
    a = p.parse_args()
    os.makedirs(a.out, exist_ok=True)
    st = Study(a)
    o, apex_www, diffs, fails = analyse(st)
    with open(os.path.join(a.out, "summary.json"), "w") as f:
        json.dump(o, f, indent=2)
    write_csv(os.path.join(a.out, "apex_www_differences.csv"), apex_www)
    write_csv(os.path.join(a.out, "different_responses.csv"), diffs)
    write_csv(os.path.join(a.out, "ipv6_failures.csv"), fails)
    dates = sorted(filter(None, [m["first_pass_utc"] for m in o["servers"].values()] +
                          [m["last_pass_utc"] for m in o["servers"].values()]))
    span = f"{dates[0][:10]} to {dates[-1][:10]}" if dates else "test dates"
    locs = " and ".join(filter(None, (m["location"] for m in o["servers"].values()))) or "two servers"
    note = f"Share of sites, tested from {locs}, {span}"
    with open(os.path.join(a.out, "reachability.svg"), "w") as f:
        src = f"Data and script: {a.repo}" if a.repo else ""
        f.write(chart_svg(o["tranco"], o["targets"], note, src, o["reach_basis"]))
    with open(os.path.join(a.out, "reachability_table.html"), "w") as f:
        f.write(table_html(o["tranco"], o["targets"], o["reach_basis"]))
    with open(os.path.join(a.out, "alt_text.txt"), "w") as f:
        f.write(alt_text(o["tranco"], o["targets"], o["reach_basis"]) + "\n")
    with open(os.path.join(a.out, "findings.md"), "w") as f:
        f.write(findings_md(o))
    print(f"wrote {a.out}/: findings.md, summary.json, reachability.svg, reachability_table.html, "
          f"alt_text.txt and three case lists")


if __name__ == "__main__":
    main()
