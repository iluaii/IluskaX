# IluskaX (luska)

A web security scanner written in Go. Crawls a target, finds URLs and forms, then runs a series of vulnerability checks — either as a full pipeline or selectively by phase.

It's two binaries: `luska` (crawler) and `pentest` (scanner). They can run together or separately.

```bash
git clone https://github.com/iluaii/IluskaX && cd IluskaX
go mod tidy
go build -o luska ./cmd/luska && go build -o pentest ./cmd/pentest
```

---

## Requirements

The scanner itself is pure Go, but the pentest phases depend on external tools being in your `$PATH`:

- `subfinder` — subdomain enumeration (Phase 0)
- `sqlmap` — deep SQL injection scanning (Phase 3)
- `nuclei` — template-based vulnerability detection (Phase 2)
- `dalfox` — XSS detection (Phase 4)

If a tool isn't installed, that phase will error out.

---

## Usage

### Crawl only

```bash
./luska -u https://example.com
```

### Crawl + pentest

```bash
./luska -u https://example.com -ps
```

### With options

```bash
./luska -u https://example.com -ps -r -rd 3 -sd -rate 5 -c 10 -cookie "session=abc123"
```

### Run pentest on an existing crawl file

```bash
./pentest -f output/example.com|2025-01-01_12-00-00.txt -host example.com
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | — | Target URL (required) |
| `-r` | false | Recursive crawling |
| `-rd` | 0 | Max recursion depth |
| `-ps` | false | Run pentest after crawl |
| `-sd` | false | Subdomain enumeration before crawl (requires subfinder) |
| `-rate` | 10 | Requests per second |
| `-c` | 5 | Concurrent goroutines |
| `-ignore-robots` | false | Skip robots.txt restrictions |
| `-timeout` | 0 | Crawl timeout in minutes (0 = no limit) |
| `-cookie` | — | Cookie header for authenticated scanning |
| `-burp` | — | Path to Burp Suite request file (used by SQLMap) |
| `-sqlmap-level` | auto | SQLMap level 1–5 |
| `-sqlmap-risk` | auto | SQLMap risk 1–3 |
| `-skip` | — | Comma-separated URL patterns to skip during crawl |
| `-skip-phase` | — | Comma-separated phases to skip (see below) |

---

## What the crawler does

Fetches pages, parses HTML, and collects:

- All links (`<a href>`)
- Forms — both GET and POST, including field names
- JS files (external and inline)

From JavaScript, it extracts endpoints found in `fetch()`, `axios`, XHR calls, template literals, and API variable assignments. It resolves relative paths against the page base URL.

Respects `robots.txt` by default — disallowed paths are skipped. Use `-ignore-robots` to bypass.

Scope is enforced by hostname. Out-of-scope URLs are logged but not followed.

Static assets (images, fonts, CSS, etc.) are filtered out automatically.

Output is written to `output/<hostname>|<datetime>.txt`.

---

## Pentest phases

### Phase 0 — Subdomain enumeration
Runs `subfinder` against the target hostname. Found subdomains are added to the crawl file as `https://<subdomain>/`. Enabled with `-sd`.

### Phase 1 — Quick SQLi test
Tests up to 20 URLs with parameters. Checks:
- **Time-based**: injects `SLEEP`/`WAITFOR DELAY` payloads, looks for ~2s delay
- **Boolean-based**: compares response sizes for true/false conditions (>20% difference triggers a flag)
- **POST forms**: time-based injection in POST body
- **Cookie injection**: discovers cookies from responses and tests them with sleep payloads

If anything is found, SQLMap (Phase 3) is automatically escalated to a higher level/risk.

### Phase 2 — Nuclei
Runs `nuclei` against all crawled URLs with severity `low,medium,high,critical`. Output is counted by severity and printed.

### Phase 3 — SQLMap
Runs `sqlmap` against all URLs with parameters. Uses `--technique=BEUSTQ` (all techniques). If Phase 1 found something, level and risk start higher. If this phase finds something, it escalates to the next level automatically (up to level 3 / risk 3).

Also tests POST forms separately.

Supports Burp Suite request files via `-burp` — passed directly to sqlmap with `-r`.

Cookie names discovered during crawl are passed to sqlmap as `--cookie-param`.

### Phase 4 — Dalfox
Runs `dalfox url` against each URL that has parameters. Detects reflected/stored XSS. Supports authenticated scanning via cookie.

### Phase 5 — Header & Cookie analysis
Checks each unique host (not every URL) for:

**Missing security headers:**
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `X-XSS-Protection`
- `Access-Control-Allow-Origin`

**CSP issues:** flags `unsafe-inline` and `unsafe-eval`

**CORS:** flags wildcard `Access-Control-Allow-Origin: *`

**HSTS:** flags missing `includeSubDomains` or `max-age`

**Information disclosure:** flags presence of `X-Powered-By`

**Cookies:** checks each cookie for missing `HttpOnly`, `Secure`, `SameSite`, and expiry

---

## Output

Crawl results go to `output/<hostname>|<datetime>.txt`.

Pentest report goes to `Poutput/<hostname>|<datetime>_report.txt`. The same output is printed to stdout while the scan runs.

SQLMap session files go to `Poutput/sqlmap/`.

---

## Skipping phases

```bash
./luska -u https://example.com -ps -skip-phase 2,4
```

Phase numbers: `0` = subdomains, `1` = quick SQLi, `2` = nuclei, `3` = sqlmap, `4` = dalfox, `5` = headers

---

## Build

Requires Go 1.21+. Check your version:

```bash
go version
```

Clone the repo and build both binaries:

```bash
git clone https://github.com/yourname/IluskaX
cd IluskaX
go build -o luska ./cmd/luska
go build -o pentest ./cmd/pentest
```

If your project structure has `main.go` at the root level for each binary, adjust accordingly:

```bash
go build -o luska .
```

Dependencies are managed via Go modules. Pull them before building:

```bash
go mod tidy
```

After that, `luska` and `pentest` are ready to use in the current directory.

---

## Legal

This tool is intended for use on systems you own or have explicit written permission to test. Running it against targets without authorization is illegal in most countries, regardless of intent.

The authors take no responsibility for how this tool is used. Use it only in scope — on bug bounty programs, your own infrastructure, or test environments you control.

---

## Notes

- The scanner identifies itself as `LuskaScanner/1.0` in the User-Agent
- HTTP client timeout is 10s per request during crawl, 8s during quick SQLi test
- Max 10MB per page during crawl, 5MB per JS file
- Max 5 redirects followed
- Deduplication during crawl is by path + query parameter names (not values), so `?id=1` and `?id=2` are treated as the same endpoint
