# Clouseau

A (heavily WIP) CLI tool for website analysis and reconnaissance. Runs a configurable set of
modules against a target URL and returns a human-readable report.

## Requirements

- Go 1.27+

## Build

```sh
go build -o clouseau .
```

Or run without building:

```sh
go run . https://example.com
```

## Usage

```sh
clouseau [url] [flags]
```

| Flag | Description |
| --- | --- |
| `-c`, `--config` | Path to the config file (default `config.yaml`) |
| `-o`, `--output` | Write the analysis report as JSON to this file |
| `--skip-whois` | Skip the `whois_lookup` module |
| `--skip-html` | Skip the `html_scan` module |
| `--skip-robots` | Skip the `robots_scan` module |
| `--skip-headers` | Skip the `headers_scan` module |
| `--skip-domain` | Skip the `domain_scan` module |
| `--skip-threat` | Skip the `threat_lookup` module |
| `--skip-infra` | Skip the `infra_scan` module |

Modules are driven by the config file; removing a task from it disables that
module (`ip_lookup` has no skip flag).

## Configuration

```yaml
tasks:
  - name: "whois_lookup"
    # server is optional; without it the server is discovered via IANA

  - name: "html_scan"
    params:
      max_depth: 3
      extract_links: true
      # skip_wordpress: true
      # skip_cloaking: true
      # evidence_dir: "./evidence"

  - name: "robots_scan"

  - name: "headers_scan"

  - name: "domain_scan"

  - name: "threat_lookup"
    params:
      # urlhaus_key: "..."   # optional, for higher rate limits

  - name: "infra_scan"

  - name: "ip_lookup"
    params:
      tls: true
      dnsbl: true
      tor: true
      netblock: true
      scan_ports: true
```

## Modules

### `whois_lookup`

Queries WHOIS over TCP/43. Without a `server` param it discovers the
authoritative server through IANA. The result includes the parsed field map
plus the raw response. When the creation date is parseable the result also
includes `domain_age_days` and flags domains registered less than 90 days ago
as `new_domain`.

### `html_scan`

Crawls the target (same host only) and reports status, title, size, SHA-256,
and links per page. Every page body gets a SHA-256 digest; with `evidence_dir`
set, the raw bodies are also saved to disk (chain of custody for
investigations).

- `max_depth` — crawl depth (default `1`, `0` fetches only the start page)
- `extract_links` — collect and print unique links (default `true`)
- `skip_wordpress` — disable the WordPress submodule (default `false`)
- `skip_cloaking` — disable the cloaking check (default `false`)
- `evidence_dir` — save fetched page bodies into this directory

Submodules:

- **Identifiers** — extracts analytics/tracker IDs (Google Analytics, GTM,
  AdSense, Facebook Pixel, Yandex Metrica), Telegram and WhatsApp contacts,
  crypto wallet addresses, and email addresses. Reused IDs and wallets are a
  strong clustering signal for phishing kits and disinformation networks.
- **Forms** — password forms, cross-origin form `action` targets, hidden
  field counts, and `<meta http-equiv="refresh">` redirects.
- **Cloaking** — fetches the start URL with browser, Googlebot, and curl
  profiles and compares status, final URL, title, and body size; differences
  are reported as suspected cloaking.
- **WordPress** — fingerprints the site from the HTML (`/wp-content/`,
  `/wp-admin/`, `/wp-json/`, `xmlrpc.php`, generator meta tag, plugin/theme
  asset paths) and, when detected, probes public endpoints:

  - version via meta generator, `readme.html`, or the RSS feed
  - `/wp-login.php`, `/xmlrpc.php`, `/wp-sitemap.xml`
  - REST API index (site name and namespaces, which reveal plugins)
  - user enumeration via `/wp-json/wp/v2/users`
  - author slugs via `/?author=1..3` redirects

### `robots_scan`

Fetches `/robots.txt` and reports the status, groups (with allowed/disallowed
counts), sitemaps, and disallowed paths that look sensitive (`admin`,
`backup`, `.env`, `staging`, ...). Up to 5 listed sitemaps are fetched and the
total number of URLs is reported.

### `headers_scan`

Fetches the target once and audits the response headers:

- HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and
  Permissions-Policy, each reported as `ok`, `weak`, or `missing`
- `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite`)
- CORS behavior, probing with a foreign `Origin` to detect reflection
- server banner and `X-Powered-By`
- the full redirect chain (status and URL per hop)

### `domain_scan`

Inspects the hostname itself for phishing signals:

- punycode (`xn--`) internationalized domains, decoded to their Unicode form
- mixed-script hosts (e.g. Cyrillic characters inside a Latin name), which
  indicate possible homoglyph domains

### `threat_lookup`

Checks the host against free, keyless threat intelligence sources:

- **OpenPhish** community feed — reports matching phishing URLs
- **URLhaus** host API — reports listed malware/phishing URLs
- **Wayback Machine** CDX API — reports the first archived capture, i.e. how
  long the site has existed

`urlhaus_key` supplies an optional API key for higher rate limits. The
`openphish_url`, `urlhaus_url`, and `wayback_url` params override the default
endpoints (mainly useful for testing).

### `infra_scan`

Clusters related infrastructure:

- **Certificate Transparency** (crt.sh) — sibling domains sharing a
  certificate with the target (capped at 100)
- **Favicon** — SHA-256 and Shodan-compatible mmh3 hash of `/favicon.ico` for
  pivoting on Shodan

### `ip_lookup`

Maps the target to its DNS and network footprint:

- **DNS records** — A/AAAA (IPv4/IPv6 addresses), CNAME (alias), NS
  (nameservers), MX (mail servers), and TXT
- **Reverse DNS** — the PTR name for each address, marked forward-confirmed
  when that name resolves back to the same IP
- **Network ownership** — ASN, announced prefix, country, and network name
  (Team Cymru)
- **Provider detection** — matches CNAME/PTR/ASN names against known CDNs and
  hosting providers (Cloudflare, Akamai, Fastly, CloudFront, ...)
- **Email security** — SPF (from TXT), DMARC and its policy (from
  `_dmarc.<domain>`), and BIMI (from `default._bimi.<domain>`), looked up on
  the registered (eTLD+1) domain

Optional extras, off unless enabled in the task params (the shipped
`config.yaml` turns all of them on):

| Param | Description |
| --- | --- |
| `tls: true` | Inspect the TLS certificate; `tls_port` overrides port 443 |
| `dnsbl: true` | Check public IPs against DNS blocklists |
| `tor: true` | Check whether an IP is a Tor exit node |
| `netblock: true` | Look up the RIR netblock and abuse contact |
| `scan_ports: true` | TCP port scan; `ports` overrides the default list, `port_timeout_ms` sets the timeout |

When the target resolves to Cloudflare, the Cloudflare submodule checks sibling
subdomains for origin leaks (IPs that are not in AS13335):

- `subdomains_file` — path to a wordlist (default `cloudflare_subdomains.txt`
  in the working directory), one subdomain prefix per line, `#` comments allowed
- `skip_origin_lookup: true` — disable the check

## Examples

Basic analysis using `config.yaml`:

```sh
go run . https://example.com
```

Write a JSON report:

```sh
go run . -o report.json https://example.com
```

Use a custom config and skip the WHOIS and HTML modules:

```sh
go run . -c minimal.yaml --skip-whois --skip-html https://example.com
```

Analyze only IP/infrastructure data (`minimal.yaml`):

```yaml
tasks:
  - name: "ip_lookup"
    params:
      tls: true
      dnsbl: true
      tor: true
      netblock: true
      scan_ports: true
```

```sh
go run . -c minimal.yaml https://example.com
```

WordPress-focused scan:

```yaml
tasks:
  - name: "html_scan"
    params:
      max_depth: 0
      extract_links: false
```

```sh
go run . -c wordpress-only.yaml https://example.com
```

Cloudflare origin check against a custom wordlist:

```yaml
tasks:
  - name: "ip_lookup"
    params:
      subdomains_file: "./lists/cloudflare.txt"
```

## JSON report

`-o` writes a single object containing the target, timestamp, and one entry per
task (with either `result` or `error`):

```json
{
  "target": "https://example.com",
  "generated_at": "2026-10-19T01:30:00Z",
  "results": [
    {
      "task": "whois_lookup",
      "result": { "domain": "example.com", "server": "whois.iana.org" }
    },
    {
      "task": "html_scan",
      "result": { "start_url": "https://example.com", "pages": [] }
    }
  ]
}
```

## Tests

```sh
go test ./...
```

## Project layout

```
cmd/                          CLI entry point and flags
internal/analyzer/            modules: whois, html, robots, headers, domain, threat, infra, ip
internal/analyzer/submodules/ shared submodules (cloudflare, wordpress, robots, identifiers, forms, cloak, favicon)
internal/config/              YAML config loading
tests/                        external package tests
```

