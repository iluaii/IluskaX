# IluskaX

Go-based web security scanner with two binaries:

- `luska` for crawl, JS parsing, sitemap generation, and optional handoff to pentest
- `pentest` for vulnerability checks against a crawl file

It can run as a simple CLI scanner or with a Bubble Tea TUI for the pentest phase.

## Build

```bash
git clone https://github.com/iluaii/IluskaX
cd IluskaX
go mod tidy
go build -o luska ./main.go
go build -o pentest ./cmd/pentest/main1.go
```

## Requirements

Core crawl logic is pure Go, but some pentest phases rely on external tools in `$PATH`:

- `subfinder` for subdomain enumeration
- `nuclei` for template-based checks
- `sqlmap` for SQL injection testing
- `dalfox` for XSS testing

If a tool is missing, only that phase will fail or be skipped.

## Quick Start

### Crawl only

```bash
./luska -u https://example.com
```

### Crawl and then run pentest

```bash
./luska -u https://example.com -ps
```

### Crawl and pentest with exported report

```bash
./luska -u https://example.com -ps -o report.txt
```

### Pentest an existing crawl file

```bash
./pentest -f 'output/example.com|2026-04-08_11-30-00.txt' -host example.com
```

### Run pentest in TUI mode

```bash
./pentest -f 'output/example.com|2026-04-08_11-30-00.txt' -host example.com -ui tui
```

### Run full flow and use TUI for pentest

```bash
./luska -u https://example.com -ps -ui tui
```

Note: when `luska` is started with `-ps -ui tui`, the crawl stays in normal CLI mode and only the child `pentest` process uses the TUI.

## `luska` Flags

| Flag | Default | Description |
|---|---|---|
| `-u` | required | Target URL |
| `-r` | `false` | Enable recursive crawl |
| `-rd` | `0` | Maximum recursion depth |
| `-ps` | `false` | Run pentest after crawl |
| `-sd` | `false` | Run subdomain enumeration before crawl |
| `-rate` | `10` | Requests per second |
| `-c` | `5` | Max concurrent goroutines |
| `-ignore-robots` | `false` | Ignore `robots.txt` restrictions |
| `-sqlmap-level` | `0` | SQLMap starting level, `0 = auto` |
| `-sqlmap-risk` | `0` | SQLMap starting risk, `0 = auto` |
| `-cookie` | empty | Cookie header for authenticated scanning |
| `-burp` | empty | Path to Burp request file for SQLMap |
| `-skip` | empty | Comma-separated path patterns to skip during crawl |
| `-skip-phase` | empty | Comma-separated phases to skip |
| `-timeout` | `0` | Total crawl timeout in minutes, `0 = no limit` |
| `-o` | empty | Output report path |
| `-ui` | `cli` | UI mode: `cli` or `tui` |

## `pentest` Flags

| Flag | Default | Description |
|---|---|---|
| `-f` | required | Crawl output file |
| `-host` | `target` | Host label for output/report naming |
| `-date` | current time | Date tag for output naming |
| `-skip-phase` | empty | Comma-separated phases to skip |
| `-sqlmap-level` | `0` | SQLMap starting level, `0 = auto` |
| `-sqlmap-risk` | `0` | SQLMap starting risk, `0 = auto` |
| `-cookie` | empty | Cookie header for authenticated scanning |
| `-burp` | empty | Path to Burp request file for SQLMap |
| `-rate` | `10` | Requests per second for HTTP probes |
| `-o` | empty | Export final report to a custom path |
| `-ui` | `cli` | UI mode: `cli` or `tui` |

## UI Modes

- `cli` prints plain terminal output and final tables
- `tui` uses Bubble Tea during pentest execution

In TUI mode:

- there is a global navigation layer with `Dashboard`, `Findings`, `Targets`, `History`, and `New Scan`
- selecting a scan opens a detail view with `Logs`, `Findings`, `Targets`, and `Control`
- live logs scroll in the viewport
- older lines disappear from the visible area when the screen fills up
- after the scan finishes, the TUI stays open and shows a completion message
- press `Esc` to leave the finished TUI and print the final findings tables and summary

## Crawl Output

The crawler collects:

- in-scope links
- GET and POST forms
- JS files and inline JS blocks
- endpoints extracted from JavaScript patterns like `fetch`, XHR, axios, template strings, and API assignments

It also:

- respects `robots.txt` by default
- keeps scope limited to the target hostname
- filters common static assets
- deduplicates endpoints by path and query parameter names

Crawl results are written to:

```text
output/<hostname>|<datetime>.txt
```

## Pentest Phases

### Phase 0: Subdomains

Uses `subfinder` and appends discovered subdomains to the crawl dataset.

### Phase 1: Quick SQLi Test

Tests parameterized URLs and forms with fast checks:

- time-based payloads
- boolean-based response comparison
- POST form checks
- cookie-based probes when cookies are present

If something suspicious is found, later SQLMap settings are escalated automatically.

### Phase 2: Nuclei

Runs `nuclei` against discovered URLs.

### Phase 3: SQLMap

Runs `sqlmap` against parameterized URLs and POST forms.

Supports:

- automatic escalation after suspicious Phase 1 results
- Burp request files via `-burp`
- cookie header forwarding via `-cookie`

### Phase 4: Dalfox

Runs `dalfox` against URLs with parameters to detect XSS.

### Phase 5: Header and Cookie Analysis

Checks security-related response headers and cookie settings.

Important:

- missing headers are treated as recommendations or informational findings
- real header or cookie misconfigurations are shown separately from confirmed vulnerabilities

## Reports

Default files:

```text
output/<hostname>|<datetime>.txt
Poutput/<hostname>|<datetime>_report.txt
Poutput/sqlmap/
```

If `-o` is provided, IluskaX also writes a custom export file with:

- sitemap
- findings tables
- final summary

## TUI Overview

### Dashboard

Shows the active scans list and current state for each scan:

- target
- status
- current phase
- progress percent
- finding counters

Press `Enter` on the selected scan to open its detail view.

### Findings

Shows discovered issues collected during the running scan, separated from raw logs.

### Targets

Shows discovered scan targets grouped by host, so the output is easier to read than a flat URL list.

Example:

```text
http://localhost:3000
├─ /
├─ /?q=1
└─ /xss?q=test
```

### History

Shows scans that were launched or finished during the current TUI session, plus queued items.

### New Scan

Lets you prepare a new command from inside the TUI.

You can:

- enter a target URL
- add extra flags
- choose `Run now` to launch a background `luska` process
- choose `Queue` to store a scan in the local session queue

`Run now` launches a new background process and writes its output to a log file in `Poutput/`.

## TUI Controls

- `Tab` and `Shift+Tab` switch tabs
- `Left` and `Right` also switch tabs
- `Up` and `Down` move selection or scroll
- `Enter` opens scan details or confirms the current action in `New Scan`
- `Esc` returns from scan details to the global tabs
- after a scan finishes, `Esc` exits the TUI and returns to normal terminal output
- `r` in `New Scan` runs immediately
- `q` in `New Scan` adds the prepared scan to the queue

## Skip Phases

Example:

```bash
./luska -u https://example.com -ps -skip-phase 2,4
```

Phase mapping:

- `0` = subdomain enumeration
- `1` = quick SQLi
- `2` = nuclei
- `3` = SQLMap
- `4` = dalfox
- `5` = header and cookie analysis

For direct `pentest`, supported skip values are `1` through `5`.

## Notes

- User-Agent: `LuskaScanner/1.0`
- crawl request timeout is short and optimized for scanning, not browsing
- JS parsing and endpoint extraction intentionally prefer breadth over perfect semantic accuracy
- TUI is intended for the pentest phase, not as a full-screen wrapper around the entire crawl pipeline

## Legal

Use this tool only on systems you own or on targets where you have explicit permission to test.

Unauthorized scanning may be illegal. You are responsible for how you use it.
