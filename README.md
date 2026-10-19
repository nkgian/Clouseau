# Clouseau

A CLI tool for website analysis and reconnaissance. Runs a configurable set of
modules against a target URL, prints a human-readable report

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

Modules are driven by the config file; removing a task from it disables that
module (`ip_lookup` has no skip flag).

## Configuration

```yaml
tasks:
  - name: "whois_lookup"
    params:
      server: "whois.verisign-grs.com"   # optional, "host:port" is accepted

  - name: "html_scan"
    params:
      max_depth: 3
      extract_links: true
      # skip_wordpress: true

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
plus the raw response.

### `html_scan`

Crawls the target (same host only) and reports status, title, size, and links
per page.

- `max_depth` — crawl depth (default `1`, `0` fetches only the start page)
- `extract_links` — collect and print unique links (default `true`)
- `skip_wordpress` — disable the WordPress submodule (default `false`)

The WordPress submodule fingerprints the site from the HTML
(`/wp-content/`, `/wp-admin/`, `/wp-json/`, `xmlrpc.php`, generator meta tag,
plugin/theme asset paths) and, when detected, probes public endpoints:

- version via meta generator, `readme.html`, or the RSS feed
- `/wp-login.php`, `/xmlrpc.php`, `/wp-sitemap.xml`
- REST API index (site name and namespaces, which reveal plugins)
- user enumeration via `/wp-json/wp/v2/users`
- author slugs via `/?author=1..3` redirects

Results appear under `wordpress` in the report.

### `ip_lookup`

Resolves A/AAAA/CNAME/NS/MX/TXT records, PTR and forward-confirmed PTR, ASN and
prefix (Team Cymru), provider/CDN fingerprints, and email security records
(SPF, DMARC, BIMI).

Optional extras, all disabled by default:

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
internal/analyzer/            modules: whois, html, ip
internal/analyzer/submodules/ provider/stack submodules (cloudflare, wordpress)
internal/config/              YAML config loading
tests/                        external package tests
```

