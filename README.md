# IPv4 vs IPv6: a 1,050-site test

This repository holds the script, raw data and results behind our test of how popular websites, and the sites people most often scrape, respond over IPv4 and IPv6.

## The test at a glance

| | |
|---|---|
| **Dates** | October 11–12, 2026: five passes per server, 23:10 UTC on October 11 to 01:07 UTC on October 12 |
| **Servers** | Two DigitalOcean Droplets with native IPv6 (Ubuntu 24.04, curl 8.5.0): **Atlanta, US** and **Frankfurt, Germany** |
| **Sample** | The top 1,000 domains on Tranco list [8PXYV](https://tranco-list.eu/list/8PXYV/) (generated October 10, 2026), each tested at the bare domain and at www, plus 50 commonly scraped sites, each tested at its homepage and one page a scraper would request |
| **Size** | 2,098 URLs on 2,022 hostnames, requested over IPv4 and IPv6 five times from each server (41,960 requests in total, plus redirects) |

## Results

| Measure | Tranco top 1,000 | Commonly scraped sites |
|---|---|---|
| Publish an IPv6 address (AAAA record) | 41.3% of all 1,000 domains; 54.1% of the 725 that served a website over IPv4 | 30.0% of all 50; 31.8% of the 44 that loaded over IPv4 |
| Loaded over IPv6 from both servers | 49.1% of the 725 | 29.5% of the 44 |

| Server | Pages | Median connect, IPv4 | Median connect, IPv6 | Median time to first byte, IPv4 | Median time to first byte, IPv6 |
|---|---|---|---|---|---|
| Atlanta | 636 | 1.3 ms | 1.3 ms | 49.8 ms | 49.2 ms |
| Frankfurt | 648 | 1.2 ms | 1.5 ms | 108.9 ms | 113.0 ms |

- **Different response over IPv6:** 16 of the 650 pages that answered over both protocols (2.5%). Eight were blocked or rate-limited only over IPv4, and two only over IPv6.
- **IPv6 dead ends:** 25 Tranco domains answered over IPv6 but redirected to a hostname with no IPv6 address. Another 14 published an IPv6 address that never answered.
- **Bare domain vs www:** the two names disagreed on IPv6 for 137 of the 1,000 domains (13.7%). Only www had an IPv6 address in 112 cases, and only the bare domain in 20.

Every figure, with its definition, is in [`results/findings.md`](results/findings.md) and [`results/summary.json`](results/summary.json). The individual sites are listed in the CSV files in `results/`.

## Method

1. **DNS.** Each server looked up the A and AAAA records for every hostname with `dig`, using a resolver checked not to synthesize IPv6 addresses (DNS64). Results: `data/<server>/dns_<server>.csv`.
2. **Requests.** Each server requested every URL with `curl -4` and `curl -6`, in random order per URL, in five consecutive passes. It recorded the status code, connect time, TLS time and time to first byte from the first response, measured after the DNS lookup. A second request followed any redirects to record the final page's status, size, title and any challenge or block-page signature. Page bodies were not stored.
3. **Comparison.** For each URL, the IPv4 and IPv6 responses in the same pass were compared for a different status class, a challenge or block page on one side only, or a body more than 1.5 times and at least 1 KB larger on one side. A URL counts as different only if the same difference appeared in at least three of five passes.

**Definitions used in the results:**

- **Loaded:** the final page, after any redirects, arrived over that protocol with any status code in at least three of five passes.
- **Website (Tranco):** a domain whose bare domain or www loaded over IPv4 from both servers. The remaining domains are mostly CDN, ad and tracking infrastructure that serves no website.
- **Dead end:** a URL whose first response arrived over IPv6, but whose redirect target couldn't be reached over IPv6.

**Load and conduct:** each site's pages were requested one at a time, at least two seconds apart, with a User-Agent that identifies the study and links here. Every URL in the sample was requested regardless of robots.txt; what each site's robots.txt said is recorded in `data/<server>/robots_<server>.csv`.

## Limitations

- **Two data-center vantage points.** Results may differ from home and mobile connections, and some sites treat cloud IP ranges with extra suspicion on both protocols.
- **One time window.** All five passes ran within about two hours, overnight in Europe and in the evening in the US.
- **curl, not a browser.** Requests came from curl with an identifying User-Agent, which some sites block regardless of protocol. "Loaded" counts any status code, including block pages.
- **A snapshot.** Sites change their configuration often.

## Files

| Path | Contents |
|---|---|
| `ipv6_study.py` | The test harness: `preflight`, `sample`, `discover` and `measure` |
| `analyze.py` | Turns the raw data into `results/` |
| `targets.csv` | The 50 commonly scraped sites, their homepage and scrape-page URLs, and notes on what each site's terms say about automated access |
| `data/us/`, `data/eu/` | Raw data from each server (below) |
| `results/` | Findings, summary, chart (SVG and PNG), HTML table, alt text, and case lists of IPv6 dead ends, response differences and apex/www differences |

In each `data/<server>/` folder:

| File | Contents |
|---|---|
| `meta_<server>.json` | Server location, provider, public IPv4 and IPv6 addresses, software versions |
| `sample.csv`, `sample_info.json` | Every URL tested; the Tranco list ID and date |
| `dns_<server>.csv` | A and AAAA lookups per hostname |
| `robots_<server>.csv` | What each URL's robots.txt said (recorded for reference, not used to skip URLs) |
| `http_<server>_pass<N>.csv` | One row per URL per protocol per pass. Pass 0 was a 40-URL pilot and is excluded from the analysis |
| `passes_<server>.jsonl` | Start and finish time of each pass |

**Key columns in the `http_*` files:**

- **`proto`** (ipv4/ipv6), **`status`**, **`tcp_connect_ms`**, **`tls_ms`** and **`ttfb_ms`**: from the first response, in milliseconds, with DNS lookup time excluded.
- **`final_status`**, **`final_url`**, **`final_size_bytes`** and **`title`**: from the final page after redirects. **`final_exit_code`** is curl's exit code for that request (0 means success).
- **`block_markers`**: the challenge or block signatures detected (Cloudflare, Akamai, DataDome, PerimeterX, Imperva, AWS WAF, Kasada, "access denied" page titles, HTTP 429).

## Reproduce the analysis

```bash
python3 analyze.py --data data/us data/eu --out results --repo github.com/DerekTech/ipv6-study
```

## Run the test yourself

On a Linux server with native IPv6 (`apt install curl dnsutils python3-pip`, then `pip install tranco --break-system-packages`):

```bash
python3 ipv6_study.py preflight --server us --location "City, Country" --provider "Host"
python3 ipv6_study.py sample --targets targets.csv --list-id 8PXYV
python3 ipv6_study.py discover --server us
for p in 1 2 3 4 5; do python3 ipv6_study.py measure --server us --pass $p --ignore-robots; done
```

Edit the `DEFAULT_UA` line in `ipv6_study.py` so the User-Agent points to your own contact page.

## Notes

- The US server's location was mistyped as "Atalanta" when the test ran. It has been corrected to "Atlanta, US" in `data/us/meta_us.json`; nothing else in the data was changed.
- The servers were destroyed after the test, so the IP addresses in the `meta_*.json` files no longer belong to this study.
