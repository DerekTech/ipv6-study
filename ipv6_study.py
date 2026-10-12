#!/usr/bin/env python3
"""
IPv4 vs IPv6 site test harness.

Stages (run on each dual-stack server):
  preflight  record the server's setup and confirm native IPv6 works
  sample     build the URL list: Tranco top N (apex + www) + your scrape targets
  discover   DNS (A/AAAA for every host, via dig) and robots.txt checks
  measure    one pass: request every URL with curl -4 and curl -6, log timings,
             status, size and challenge/block markers to CSV

Run `measure` five times per server at different times of day (see README).
Every row carries the server label, pass number and UTC timestamp, and the
sample file carries the Tranco list ID, so results can be rebuilt exactly.

Requires: Python 3.9+, curl >= 7.75, dig (dnsutils/bind-utils), `pip install tranco`.
"""
import argparse
import csv
import gzip
import hashlib
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.robotparser
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

VERSION = "1.0"
DEFAULT_UA = f"Mozilla/5.0 (compatible; ipv6-study/{VERSION}; +REPLACE_WITH_REPO_URL)"
ROBOTS_TOKEN = "ipv6-study"
BROWSER_HEADERS = [
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.9",
]


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    print(f"[{utcnow()}] {msg}", file=sys.stderr, flush=True)


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"{cmd[0]} not found"


# --------------------------------------------------------------------------- preflight

TUNNEL_PREFIXES = [ipaddress.ip_network("2001:470::/32")]  # Hurricane Electric tunnel broker
TUNNEL_IFACE = re.compile(r"\b(he-ipv6|sit\d*|tun\d*|6to4|teredo)\b")


def cmd_preflight(a):
    os.makedirs(a.out, exist_ok=True)
    meta = {
        "server_label": a.server,
        "location": a.location,
        "provider": a.provider,
        "recorded_utc": utcnow(),
        "script_version": VERSION,
        "hostname": platform.node(),
        "kernel": platform.release(),
        "curl_version": run(["curl", "--version"])[1].splitlines()[:1],
        "dig_version": (run(["dig", "-v"])[2] or "").strip(),
        "user_agent": a.user_agent,
        "warnings": [],
    }
    for proto, url in (("4", "https://api.ipify.org"), ("6", "https://api6.ipify.org")):
        rc, out, err = run(["curl", "-sS", "--noproxy", "*", f"-{proto}", "-m", "10", url])
        meta[f"public_ipv{proto}"] = out.strip() if rc == 0 else f"ERROR: {err.strip()}"
        if rc != 0:
            meta["warnings"].append(f"IPv{proto} connectivity check failed: {err.strip()}")

    v6 = meta.get("public_ipv6", "")
    try:
        addr = ipaddress.ip_address(v6)
        if any(addr in n for n in TUNNEL_PREFIXES):
            meta["warnings"].append("IPv6 address is in a tunnel-broker range; results would not reflect native IPv6.")
    except ValueError:
        pass
    rc, routes, _ = run(["ip", "-6", "route", "show", "default"])
    meta["ipv6_default_route"] = routes.strip()
    if TUNNEL_IFACE.search(routes):
        meta["warnings"].append("Default IPv6 route goes through a tunnel interface.")
    if not shutil.which("dig"):
        meta["warnings"].append("dig not installed (apt install dnsutils / dnf install bind-utils).")
    else:
        # ipv4only.arpa has only A records (RFC 7050). An AAAA answer means the resolver does DNS64,
        # which would make IPv4-only sites look IPv6-reachable through a NAT64 gateway.
        rc, out, _ = run(["dig", "+short", "ipv4only.arpa", "AAAA"])
        meta["dns64_detected"] = bool(out.strip())
        if out.strip():
            meta["warnings"].append("Resolver does DNS64 (AAAA returned for ipv4only.arpa); switch to a "
                                    "non-DNS64 resolver or results will overstate IPv6 reachability.")
    if "REPLACE_WITH" + "_REPO_URL" in a.user_agent:   # split so the README's sed doesn't rewrite it
        meta["warnings"].append("User-Agent still has the placeholder repo URL; pass --user-agent or edit DEFAULT_UA.")

    path = os.path.join(a.out, f"meta_{a.server}.json")
    with open(path, "w") as f:
        json.dump(meta, f, indent=2)
    log(f"wrote {path}")
    for w in meta["warnings"]:
        log(f"WARNING: {w}")
    if any("connectivity check failed" in w for w in meta["warnings"]):
        sys.exit(1)


# --------------------------------------------------------------------------- sample

SAMPLE_FIELDS = ["url_id", "source", "list_id", "rank", "category", "site", "host", "variant", "url", "mode"]


def load_targets(path):
    """Targets default to mode=full (curl -4 / curl -6 page requests, as the brief specifies).
    mode=connect limits a target to the optional TCP/TLS connection test, with no page request."""
    rows, downgraded = [], []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if not (r.get("site") or "").strip():
                continue
            mode = (r.get("mode") or "full").strip().lower()
            if mode not in ("full", "connect"):
                sys.exit(f"{r['site']}: mode must be 'full' or 'connect', not {mode!r}")
            r["mode"] = mode
            rows.append(r)
    return rows, downgraded


def cmd_sample(a):
    os.makedirs(a.out, exist_ok=True)
    if a.tranco_csv:
        if not a.list_id:
            sys.exit("--tranco-csv needs --list-id so the sample stays traceable")
        list_id, list_date = a.list_id, a.date or ""
        with open(a.tranco_csv) as f:
            domains = [line.strip().split(",", 1)[1] for line in f if "," in line][: a.top]
    else:
        from tranco import Tranco
        t = Tranco(cache=True, cache_dir=os.path.join(a.out, ".tranco"))
        lst = t.list(list_id=a.list_id) if a.list_id else t.list(date=a.date)
        list_id, list_date, domains = lst.list_id, getattr(lst, "date", "") or "", lst.top(a.top)

    rows = []
    for rank, d in enumerate(domains, 1):
        for variant, host in (("apex", d), ("www", f"www.{d}")):
            if variant == "www" and (a.no_www or d.startswith("www.")):
                continue
            rows.append({"source": "tranco", "list_id": list_id, "rank": rank, "category": "",
                         "site": d, "host": host, "variant": variant, "url": f"https://{host}/",
                         "mode": "full"})

    skipped = []
    if a.targets:
        targets, skipped = load_targets(a.targets)
        for t in targets:
            for variant, col in (("homepage", "homepage_url"), ("scrape", "scrape_url")):
                url = (t.get(col) or "").strip()
                if url:
                    rows.append({"source": "target", "list_id": "", "rank": "", "category": t.get("category", ""),
                                 "site": t["site"].strip(), "host": urlsplit(url).hostname, "variant": variant,
                                 "url": url, "mode": t["mode"]})
        modes = defaultdict(int)
        for t in targets:
            modes[t["mode"]] += 1
        log(f"{len(targets)} scrape targets: {modes['full']} full (page requests), {modes['connect']} connection-only")


    for i, r in enumerate(rows, 1):
        r["url_id"] = f"u{i:05d}"
    path = os.path.join(a.out, "sample.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SAMPLE_FIELDS)
        w.writeheader()
        w.writerows(rows)
    info = {"tranco_list_id": list_id, "tranco_list_date": list_date,
            "tranco_list_url": f"https://tranco-list.eu/list/{list_id}/",
            "top_n": a.top, "www_variants": not a.no_www, "created_utc": utcnow(),
            "url_count": len(rows)}
    with open(os.path.join(a.out, "sample_info.json"), "w") as f:
        json.dump(info, f, indent=2)
    log(f"wrote {path}: {len(rows)} URLs (Tranco list {list_id})")


def load_sample(out, limit=None):
    with open(os.path.join(out, "sample.csv"), newline="") as f:
        rows = list(csv.DictReader(f))
    return rows[:limit] if limit else rows


# --------------------------------------------------------------------------- discover

DNS_FIELDS = ["server", "timestamp_utc", "resolver", "host", "rtype", "dns_status", "addresses", "cname_chain", "error"]
ROBOTS_FIELDS = ["server", "timestamp_utc", "url_id", "host", "url", "robots_status", "robots_allowed"]
STATUS_RE = re.compile(r"status:\s*([A-Z]+)")


def parse_dig(output, rtype):
    """Return (status, addresses, cname_chain) from `dig +noall +answer +comments` output."""
    m = STATUS_RE.search(output)
    status = m.group(1) if m else ""
    addrs, cnames = [], []
    for line in output.splitlines():
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        t, data = parts[3].upper(), parts[4]
        if t == rtype:
            try:
                addrs.append(str(ipaddress.ip_address(data)))
            except ValueError:
                pass
        elif t == "CNAME":
            cnames.append(data.rstrip("."))
    return status, addrs, cnames


def dig(host, rtype, resolver=None):
    cmd = ["dig", "+noall", "+answer", "+comments", "+time=3", "+tries=2"]
    if resolver:
        cmd.append(f"@{resolver}")
    cmd += [host, rtype]
    rc, out, err = run(cmd, timeout=20)
    if rc != 0:
        return "", [], [], (err or out).strip()[:200] or f"dig exit {rc}"
    status, addrs, cnames = parse_dig(out, rtype)
    return status, addrs, cnames, ""


def origin(url):
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


def fetch_robots(base, ua):
    # robots.txt is fetched over whichever protocol works (IPv4 first); it gates both protocols equally.
    for proto in ("-4", "-6"):
        rc, out, err = run(["curl", "-sS", "--noproxy", "*", proto, "-L", "--max-redirs", "3", "-m", "15",
                            "-A", ua, "-w", "\n%{http_code}", f"{base}/robots.txt"], timeout=25)
        if rc == 0:
            body, _, code = out.rpartition("\n")
            return int(code or 0), body
    return 0, ""


def cmd_discover(a):
    if not shutil.which("dig"):
        sys.exit("dig is required for discover (apt install dnsutils)")
    sample = load_sample(a.out, a.limit)
    hosts = sorted({r["host"] for r in sample})
    ts = utcnow()

    dns_path = os.path.join(a.out, f"dns_{a.server}.csv")

    def do(host):
        rows = []
        for rtype in ("A", "AAAA"):
            status, addrs, cnames, err = dig(host, rtype, a.resolver)
            rows.append({"server": a.server, "timestamp_utc": ts, "resolver": a.resolver or "system",
                         "host": host, "rtype": rtype, "dns_status": status, "addresses": " ".join(addrs),
                         "cname_chain": " ".join(cnames), "error": err})
        return rows

    with ThreadPoolExecutor(a.workers) as ex:
        results = list(ex.map(do, hosts))          # map keeps host order, so the CSV stays sorted
    with open(dns_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=DNS_FIELDS)
        w.writeheader()
        for rows in results:
            w.writerows(rows)
    log(f"wrote {dns_path} ({len(hosts)} hosts)")

    robots_path = os.path.join(a.out, f"robots_{a.server}.csv")
    parsers = {}

    def get_parser(base):
        code, body = fetch_robots(base, a.user_agent)
        rp = urllib.robotparser.RobotFileParser()
        if code == 200:
            rp.parse(body.splitlines())
        elif code in (401, 403):
            rp.disallow_all = True       # same convention as Python's own robotparser.read()
        else:
            rp.allow_all = True          # missing or unreachable robots.txt = no restrictions stated
        return code, rp

    full = [r for r in sample if r.get("mode", "full") == "full"]   # connection-only sites get no HTTP at all
    bases = sorted({origin(r["url"]) for r in full})
    with ThreadPoolExecutor(a.workers) as ex:
        for base, res in zip(bases, ex.map(get_parser, bases)):
            parsers[base] = res
    with open(robots_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ROBOTS_FIELDS)
        w.writeheader()
        for r in full:
            code, rp = parsers[origin(r["url"])]
            w.writerow({"server": a.server, "timestamp_utc": ts, "url_id": r["url_id"], "host": r["host"],
                        "url": r["url"], "robots_status": code,
                        "robots_allowed": "yes" if rp.can_fetch(ROBOTS_TOKEN, r["url"]) else "no"})
    log(f"wrote {robots_path}")


# --------------------------------------------------------------------------- measure

HTTP_FIELDS = [
    "server", "pass", "timestamp_utc", "url_id", "source", "rank", "category", "site", "host", "variant", "url",
    "proto", "order", "exit_code", "error", "remote_ip", "http_version",
    "status", "redirect_url", "dns_ms", "tcp_connect_ms", "tls_ms", "ttfb_ms", "total_ms", "size_bytes",
    "final_status", "final_url", "num_redirects", "final_exit_code", "final_error", "final_remote_ip",
    "final_size_bytes", "body_sha256", "title", "block_markers", "captcha_widget", "pair_flags",
]

# (label, where, pattern). Matched case-insensitively against response headers or the first 256 KB of body.
BLOCK_MARKERS = [
    ("cloudflare_challenge", "headers", r"^cf-mitigated:\s*challenge"),
    ("cloudflare_challenge", "body", r"challenge-platform|<title>just a moment\.\.\.</title>|cf-chl-"),
    ("cloudflare_block", "body", r"cf-error-details|attention required! \| cloudflare|sorry, you have been blocked"),
    ("akamai_block", "body", r"errors\.edgesuite\.net|reference&#32;&#35;|reference #\d+\.[0-9a-f]+"),
    ("datadome", "headers", r"^x-datadome"),
    ("datadome", "body", r"captcha-delivery\.com|geo\.captcha-delivery"),
    ("perimeterx", "body", r"px-captcha|_pxappid|perimeterx"),
    ("imperva", "body", r"_incapsula_resource|incapsula incident id"),
    ("aws_waf", "headers", r"^x-amzn-waf-action"),
    ("aws_waf", "body", r"aws-waf-token|awswaf"),
    ("kasada", "headers", r"^x-kpsdk"),
    ("generic_denied", "body", r"<title>[^<]{0,40}(access denied|forbidden|blocked|unusual traffic)[^<]{0,40}</title>"),
]
CAPTCHA_WIDGET = re.compile(r"g-recaptcha|hcaptcha\.com|challenges\.cloudflare\.com/turnstile", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
WRITE_OUT = "%{json}"


def curl_once(url, proto, a, follow, workdir):
    body_path = os.path.join(workdir, f"b{proto}{'f' if follow else 'p'}")
    hdr_path = os.path.join(workdir, f"h{proto}{'f' if follow else 'p'}")
    cmd = ["curl", "-sS", "--noproxy", "*", f"-{proto}", "--compressed",
           "--connect-timeout", str(a.connect_timeout), "--max-time", str(a.max_time),
           "--max-filesize", str(10 * 1024 * 1024), "-A", a.user_agent,
           "-o", body_path, "-D", hdr_path, "-w", WRITE_OUT]
    for h in BROWSER_HEADERS:
        cmd += ["-H", h]
    if follow:
        cmd += ["-L", "--max-redirs", "5"]
    cmd.append(url)
    rc, out, err = run(cmd, timeout=a.max_time + 10)
    try:
        info = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        info = {}
    info.setdefault("exitcode", rc)
    if rc != 0 and not info.get("errormsg"):
        info["errormsg"] = err.strip()[:200]
    body = b""
    if os.path.exists(body_path):
        with open(body_path, "rb") as f:
            body = f.read()
    headers = ""
    if os.path.exists(hdr_path):
        with open(hdr_path, "rb") as f:
            headers = f.read().decode("latin-1", "replace")
    for p in (body_path, hdr_path):
        if os.path.exists(p):
            os.remove(p)
    return info, headers, body


def ms(v):
    try:
        return round(float(v) * 1000, 1)
    except (TypeError, ValueError):
        return ""


def analyse_body(headers, body, status):
    text = body[:262144].decode("utf-8", "replace").lower()
    hdr = headers.lower()
    found = []
    for label, where, pat in BLOCK_MARKERS:
        hay = hdr if where == "headers" else text
        if label not in found and re.search(pat, hay, re.M):
            found.append(label)
    if status == 429:
        found.append("rate_limited")
    m = TITLE_RE.search(body[:262144].decode("utf-8", "replace"))
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    return found, title, bool(CAPTCHA_WIDGET.search(text))


def measure_url(r, proto, order, a, workdir):
    row = {k: r.get(k, "") for k in ("url_id", "source", "rank", "category", "site", "host", "variant", "url")}
    row.update({"server": a.server, "pass": a.pass_no, "timestamp_utc": utcnow(), "proto": f"ipv{proto}",
                "order": order})
    info, headers, body = curl_once(r["url"], proto, a, follow=False, workdir=workdir)
    status = int(info.get("http_code") or 0)
    t_dns = info.get("time_namelookup") or 0
    row.update({
        "exit_code": info.get("exitcode", ""), "error": info.get("errormsg", "") or "",
        "remote_ip": info.get("remote_ip", ""), "http_version": info.get("http_version", ""),
        "status": status or "", "redirect_url": info.get("redirect_url", "") or "",
        "dns_ms": ms(t_dns) if status else "",
    })
    if status:
        # curl timings are cumulative from the start of the request; subtract earlier phases.
        tc, ta, ts_ = info.get("time_connect", 0), info.get("time_appconnect", 0), info.get("time_starttransfer", 0)
        row["tcp_connect_ms"] = ms(tc - t_dns)
        row["tls_ms"] = ms(ta - tc) if ta else ""
        row["ttfb_ms"] = ms(ts_ - t_dns)          # connect + TLS + server think time, DNS excluded
        row["total_ms"] = ms(info.get("time_total", 0) - t_dns)
        row["size_bytes"] = info.get("size_download", len(body))

    final_info, final_headers, final_body = info, headers, body
    if 300 <= status < 400 and row["redirect_url"]:
        time.sleep(a.delay)
        final_info, final_headers, final_body = curl_once(r["url"], proto, a, follow=True, workdir=workdir)
    final_status = int(final_info.get("http_code") or 0)
    markers, title, captcha = analyse_body(final_headers, final_body, final_status)
    row.update({
        "final_status": final_status or "", "final_url": final_info.get("url_effective", "") if final_status else "",
        "num_redirects": final_info.get("num_redirects", 0), "final_exit_code": final_info.get("exitcode", ""),
        "final_error": final_info.get("errormsg", "") or "", "final_remote_ip": final_info.get("remote_ip", ""),
        "final_size_bytes": final_info.get("size_download", len(final_body)) if final_status else "",
        "body_sha256": hashlib.sha256(final_body).hexdigest() if final_body else "",
        "title": title, "block_markers": ";".join(markers), "captcha_widget": "yes" if captcha else "",
    })
    return row, final_body


def pair_flags(r4, r6, size_ratio):
    """Quick per-pass flags for manual review. The analysis stage recomputes these across all passes."""
    flags = []
    s4, s6 = r4["final_status"], r6["final_status"]
    if bool(s4) != bool(s6):
        flags.append("ipv6_failed" if s4 else "ipv4_failed")
    elif s4 and s6:
        if str(s4)[0] != str(s6)[0]:
            flags.append("status_class_differs")
        elif s4 != s6:
            flags.append("status_differs")
        if r4["block_markers"] != r6["block_markers"]:
            flags.append("block_markers_differ")
        try:
            a4, a6 = int(r4["final_size_bytes"]), int(r6["final_size_bytes"])
            if min(a4, a6) == 0 and max(a4, a6) > 0 or (min(a4, a6) and max(a4, a6) / min(a4, a6) > size_ratio):
                flags.append("size_differs")
        except (TypeError, ValueError):
            pass
        if r4["final_url"] != r6["final_url"]:
            flags.append("final_url_differs")
    return ";".join(flags)


CONN_FIELDS = ["server", "pass", "timestamp_utc", "source", "site", "host", "proto", "order",
               "tcp_ok", "tls_ok", "error_stage", "error", "remote_ip", "tcp_connect_ms", "tls_ms",
               "tls_version", "alpn"]


def tls_probe(host, proto, a):
    """TCP connect + TLS handshake to host:443, then close. No HTTP request is sent."""
    fam = socket.AF_INET if proto == "4" else socket.AF_INET6
    row = {"host": host, "proto": f"ipv{proto}", "tcp_ok": "", "tls_ok": "", "error_stage": "", "error": "",
           "remote_ip": "", "tcp_connect_ms": "", "tls_ms": "", "tls_version": "", "alpn": ""}
    try:
        infos = socket.getaddrinfo(host, 443, fam, socket.SOCK_STREAM)
    except socket.gaierror as e:
        row.update(error_stage="dns", error=str(e)[:200])
        return row
    addr = infos[0][4]
    row["remote_ip"] = addr[0]
    sock = None
    try:
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(a.connect_timeout)
        t0 = time.perf_counter()
        sock.connect(addr)
        t1 = time.perf_counter()
        row.update(tcp_ok="yes", tcp_connect_ms=round((t1 - t0) * 1000, 1))
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        tls = ctx.wrap_socket(sock, server_hostname=host)   # handshake happens here
        t2 = time.perf_counter()
        row.update(tls_ok="yes", tls_ms=round((t2 - t1) * 1000, 1), tls_version=tls.version() or "",
                   alpn=tls.selected_alpn_protocol() or "")
        tls.close()
    except (socket.timeout, TimeoutError):
        row.update(error_stage="tls" if row["tcp_ok"] else "tcp", error="timed out")
    except ssl.SSLError as e:
        row.update(error_stage="tls", error=str(e)[:200])
    except OSError as e:
        row.update(error_stage="tls" if row["tcp_ok"] else "tcp", error=(e.strerror or str(e))[:200])
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return row


def cmd_measure(a):
    sample = load_sample(a.out, a.limit)
    robots = {}
    rpath = os.path.join(a.out, f"robots_{a.server}.csv")
    if a.respect_robots:
        if not os.path.exists(rpath):
            sys.exit(f"{rpath} missing: run discover first, or pass --ignore-robots")
        with open(rpath, newline="") as f:
            robots = {r["url_id"]: r["robots_allowed"] for r in csv.DictReader(f)}

    out_path = os.path.join(a.out, f"http_{a.server}_pass{a.pass_no}.csv")
    conn_path = os.path.join(a.out, f"conn_{a.server}_pass{a.pass_no}.csv")
    done, conn_done = set(), set()
    if os.path.exists(out_path):                      # resume an interrupted pass
        with open(out_path, newline="") as f:
            done = {(r["url_id"], r["proto"]) for r in csv.DictReader(f)}
    if os.path.exists(conn_path):
        with open(conn_path, newline="") as f:
            conn_done = {(r["site"], r["host"], r["proto"]) for r in csv.DictReader(f)}

    # Page requests: only "full"-mode URLs that robots.txt allows. Connection tests: every host.
    full = [r for r in sample if r.get("mode", "full") == "full"]
    skipped = [r for r in full if robots.get(r["url_id"]) == "no"]
    http_todo = [r for r in full if robots.get(r["url_id"]) != "no"
                 and ((r["url_id"], "ipv4") not in done or (r["url_id"], "ipv6") not in done)]
    if skipped:
        log(f"skipping page requests for {len(skipped)} URLs disallowed by robots.txt")

    # One worker owns all of a site's hosts and URLs, so a site never sees concurrent requests from us.
    by_site = defaultdict(lambda: {"hosts": [], "rows": [], "source": ""})
    for r in sample:
        g = by_site[r["site"]]
        g["source"] = r["source"]
        if a.conn_test and r["host"] not in g["hosts"] and \
                not all((r["site"], r["host"], p) in conn_done for p in ("ipv4", "ipv6")):
            g["hosts"].append(r["host"])
    for r in http_todo:
        by_site[r["site"]]["rows"].append(r)
    sites = [(k, v) for k, v in by_site.items() if v["hosts"] or v["rows"]]
    random.Random(f"{a.server}-{a.pass_no}").shuffle(sites)

    bodies_dir = os.path.join(a.out, "review_bodies", a.server, f"pass{a.pass_no}")
    lock = threading.Lock()
    files = {}
    outputs = [("http", out_path, HTTP_FIELDS)] + ([("conn", conn_path, CONN_FIELDS)] if a.conn_test else [])
    for key, path, fields in outputs:
        new = not os.path.exists(path)
        fh = open(path, "a", newline="")
        wr = csv.DictWriter(fh, fieldnames=fields)
        if new:
            wr.writeheader()
        files[key] = (fh, wr)
    counter = {"n": 0}
    started = time.time()

    def write(key, row):
        fh, wr = files[key]
        wr.writerow(row)
        fh.flush()

    def do_site(item):
        site, g = item
        first = True

        def pause():
            nonlocal first
            if not first:
                time.sleep(a.delay)
            first = False

        for host in g["hosts"]:
            order = ["4", "6"] if random.random() < 0.5 else ["6", "4"]
            for i, proto in enumerate(order):
                pause()
                row = tls_probe(host, proto, a)
                row.update(server=a.server, **{"pass": a.pass_no}, timestamp_utc=utcnow(), source=g["source"],
                           site=site, order=i + 1)
                with lock:
                    write("conn", row)
        with tempfile.TemporaryDirectory() as workdir:
            for r in g["rows"]:
                # Randomize which protocol goes first so CDN cache warm-up doesn't favour one.
                order = ["4", "6"] if random.random() < 0.5 else ["6", "4"]
                res = {}
                for i, proto in enumerate(order):
                    pause()
                    res[proto] = measure_url(r, proto, i + 1, a, workdir)
                (r4, b4), (r6, b6) = res["4"], res["6"]
                flags = pair_flags(r4, r6, a.size_ratio)
                r4["pair_flags"] = r6["pair_flags"] = flags
                if flags and a.save_review_bodies:
                    os.makedirs(bodies_dir, exist_ok=True)
                    for proto, body in (("ipv4", b4), ("ipv6", b6)):
                        with gzip.open(os.path.join(bodies_dir, f"{r['url_id']}_{proto}.html.gz"), "wb") as gz:
                            gz.write(body)
                with lock:
                    write("http", r4)
                    write("http", r6)
        with lock:
            counter["n"] += 1
            if counter["n"] % 50 == 0:
                log(f"{counter['n']}/{len(sites)} sites ({time.time() - started:.0f}s)")

    n_hosts = sum(len(g["hosts"]) for _, g in sites)
    log(f"pass {a.pass_no} on {a.server}: {len(sites)} sites, {n_hosts} hosts to connection-test, "
        f"{len(http_todo)} pages to request, {a.workers} workers")
    with ThreadPoolExecutor(a.workers) as ex:
        for fut in [ex.submit(do_site, s) for s in sites]:
            fut.result()
    for fh, _ in files.values():
        fh.close()

    meta_path = os.path.join(a.out, f"passes_{a.server}.jsonl")
    with open(meta_path, "a") as m:
        m.write(json.dumps({"server": a.server, "pass": a.pass_no, "finished_utc": utcnow(),
                            "started_utc": datetime.fromtimestamp(started, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "sites": len(sites), "hosts_connection_tested": n_hosts,
                            "pages_requested": len(http_todo), "pages_skipped_robots": len(skipped),
                            "delay_s": a.delay, "workers": a.workers, "user_agent": a.user_agent}) + "\n")
    log(f"wrote {out_path}" + (f" and {conn_path}" if a.conn_test else ""))


# --------------------------------------------------------------------------- cli

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="data", help="output directory (default: data)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, server=True):
        if server:
            sp.add_argument("--server", required=True, help="short label for this vantage point, e.g. us-east")
        sp.add_argument("--user-agent", default=DEFAULT_UA)
        sp.add_argument("--workers", type=int, default=8)
        sp.add_argument("--limit", type=int, help="only the first N sample URLs (for a pilot run)")

    sp = sub.add_parser("preflight", help="record server setup, check native IPv6")
    common(sp)
    sp.add_argument("--location", required=True, help='e.g. "Ashburn, Virginia, US"')
    sp.add_argument("--provider", default="", help="hosting provider, for the write-up")
    sp.set_defaults(fn=cmd_preflight)

    sp = sub.add_parser("sample", help="build sample.csv from Tranco + targets")
    sp.add_argument("--top", type=int, default=1000)
    sp.add_argument("--list-id", help="Tranco list ID (pin this so both servers test the same list)")
    sp.add_argument("--date", help="Tranco list for this date (YYYY-MM-DD) instead of an ID")
    sp.add_argument("--tranco-csv", help="use an already-downloaded Tranco CSV (needs --list-id)")
    sp.add_argument("--targets", help="CSV of scrape targets (see targets_template.csv)")
    sp.add_argument("--no-www", action="store_true", help="skip www.<domain> variants")
    sp.set_defaults(fn=cmd_sample)

    sp = sub.add_parser("discover", help="DNS A/AAAA via dig, and robots.txt")
    common(sp)
    sp.add_argument("--resolver", help="resolver IP for dig (default: system resolver)")
    sp.set_defaults(fn=cmd_discover)

    sp = sub.add_parser("measure", help="one pass of curl -4 / curl -6 over every URL")
    common(sp)
    sp.add_argument("--pass", dest="pass_no", type=int, required=True, help="pass number, 1-5")
    sp.add_argument("--delay", type=float, default=2.0, help="seconds between requests to the same site")
    sp.add_argument("--connect-timeout", type=int, default=8)
    sp.add_argument("--max-time", type=int, default=25)
    sp.add_argument("--size-ratio", type=float, default=1.5, help="flag pairs whose sizes differ by more than this")
    sp.add_argument("--ignore-robots", dest="respect_robots", action="store_false")
    sp.add_argument("--conn-test", action="store_true",
                    help="also run a TCP/TLS connection test (no HTTP) on every host; off by default")
    sp.add_argument("--save-review-bodies", action="store_true",
                    help="keep gzipped bodies of flagged IPv4/IPv6 pairs (off by default: only metadata is stored)")
    sp.set_defaults(fn=cmd_measure)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
