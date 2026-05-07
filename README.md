# IluskaX

Go-based web security scanner with two binaries:

- `luska` for crawl, JS parsing, sitemap generation, and optional handoff to pentest
- `pentest` for vulnerability checks against a crawl file

It can run as a simple CLI scanner or with a Bubble Tea TUI for the pentest phase.

## Authorized Use Only

IluskaX is created strictly for:

- authorized bug bounty research
- security testing in lab environments
- scanning networks, hosts, and applications that you own
- scanning targets where you have explicit written permission to test

Do not use IluskaX against third-party infrastructure, websites, APIs, or networks without authorization.

This project is not intended for unauthorized access, mass scanning of random targets, disruption, or illegal activity.

## Build

```bash
git clone https://github.com/iluaii/IluskaX
cd IluskaX
go mod tidy
go build -o luska ./main.go
go build -o pentest ./cmd/pentest/main1.go
```

## Requirements

Core crawl logic is pure Go, but some pentest phases rely on external tools in `$PATH` or at specific paths:

- `subfinder` for subdomain enumeration
- `httpx` at `~/go/bin/httpx` for subdomain probing (phase 0.1)
- `nuclei` for template-based checks
- `sqlmap` for SQL injection testing
- `dalfox` for XSS testing

If a tool is missing, only the affected phase will fail or be skipped.

## Quick Start

### Crawl only

```bash
./luska -u https://example.com
```

### Crawl with custom headers (bug bounty)

```bash
./luska -u https://example.com -H 'X-Bug-Bounty: yourhandle' -H 'X-Forwarded-For: 127.0.0.1'
```

### Crawl and then run pentest

```bash
./luska -u https://example.com -ps
```

### Crawl and pentest with custom headers

```bash
./luska -u https://example.com -ps -H 'X-Bug-Bounty: yourhandle' -cookie 'session=abc123'
```

### Crawl and pentest with exported report

```bash
./luska -u https://example.com -ps -o report.txt
```

### Crawl and pentest with separate internal and external rate limits

```bash
./luska -u https://example.com -ps -rate 10 -ext-rate 2
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

### Subdomain enumeration with httpx probe

```bash
./luska -u https://example.com -sd -ps
```

### Crawl validated subdomains too before pentest

```bash
./luska -u https://example.com -sd -ps -ps-subdomains
```

Note: when `luska` is started with `-ps -ui tui`, the crawl stays in normal CLI mode and only the child `pentest` process uses the TUI.

## `luska` Flags

| Flag | Default | Description |
|---|---|---|
| `-u` | required | Target URL |
| `-H` | empty | Custom header `Name: Value` (repeatable) |
| `-r` | `false` | Enable recursive crawl |
| `-rd` | `0` | Maximum recursion depth |
| `-ps` | `false` | Run pentest after crawl |
| `-sd` | `false` | Run subdomain enumeration before crawl |
| `-ps-subdomains` | `false` | Crawl validated subdomains too so pentest covers them |
| `-rate` | `10` | Requests per second for built-in crawl and pentest HTTP probes |
| `-ext-rate` | `0` | Requests per second for external tools, `0 = no limit` |
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
| `-json-out` | empty | Output JSON report path |
| `-graphql-schema-dir` | `Poutput/graphql` | Directory for GraphQL schema artifacts |
| `-graphql-schema-out` | empty | Single JSON file for GraphQL schema artifacts |
| `-graphql-endpoint` | empty | Manual GraphQL endpoint URL or path, repeatable, e.g. `/graphql/v1` |
| `-ui` | `cli` | UI mode: `cli` or `tui` |

## `pentest` Flags

| Flag | Default | Description |
|---|---|---|
| `-f` | required | Crawl output file |
| `-H` | empty | Custom header `Name: Value` (repeatable) |
| `-host` | `target` | Host label for output/report naming |
| `-date` | current time | Date tag for output naming |
| `-skip-phase` | empty | Comma-separated phases to skip |
| `-sqlmap-level` | `0` | SQLMap starting level, `0 = auto` |
| `-sqlmap-risk` | `0` | SQLMap starting risk, `0 = auto` |
| `-cookie` | empty | Cookie header for authenticated scanning |
| `-burp` | empty | Path to Burp request file for SQLMap |
| `-rate` | `10` | Requests per second for built-in pentest HTTP probes |
| `-ext-rate` | `0` | Requests per second for external tools, `0 = no limit` |
| `-o` | empty | Export final report to a custom path |
| `-json-out` | empty | Export final report to JSON |
| `-graphql-schema-dir` | `Poutput/graphql` | Directory for GraphQL schema artifacts |
| `-graphql-schema-out` | empty | Single JSON file for GraphQL schema artifacts |
| `-graphql-base-url` | empty | Base URL for resolving manual GraphQL endpoint paths |
| `-graphql-endpoint` | empty | Manual GraphQL endpoint URL or path, repeatable, e.g. `/graphql/v1` |
| `-ui` | `cli` | UI mode: `cli` or `tui` |

## Custom Headers

The `-H` flag injects headers into every HTTP request made by IluskaX's built-in scanner. This is important for bug bounty programs that require identification headers.

```bash
./luska -u https://example.com -ps \
  -H 'X-Bug-Bounty: yourhandle' \
  -H 'User-Agent: Mozilla/5.0 (custom)' \
  -H 'X-Forwarded-For: 127.0.0.1'
```

Custom headers apply to:

- crawler page fetches
- robots.txt fetch
- JS file fetching during endpoint discovery
- quick SQLi checks
- POST and cookie injection probes
- header and cookie analysis requests

Custom headers are automatically forwarded to `pentest` when launched via `luska -ps`.

## Rate Limits

- `-rate` controls built-in HTTP traffic generated directly by IluskaX
- `-ext-rate` controls external tools and defaults to `0`, which means no limit

Built-in traffic includes:

- crawler page fetches
- `robots.txt`
- JS fetching during endpoint discovery
- quick SQLi checks
- POST and cookie injection probes
- header and cookie analysis

External tool rate limiting is applied to:

- `subfinder`
- `httpx`
- `nuclei`
- `sqlmap`
- `dalfox`

## GraphQL Scan

Pentest phase `6` performs safe GraphQL checks:

- endpoint discovery from crawled URLs plus common paths such as `/graphql`, `/api`, `/api/graphql`, `/query`, `/gql`, and API prefixes inferred from crawled paths
- manual endpoint injection with `-graphql-endpoint`, useful for PortSwigger labs with hidden paths such as `/graphql/v1`
- safe probing of crawled non-static endpoints because GraphQL is not always hosted on a path named `/graphql`
- `POST` / `GET` transport probing with `__typename`; when `POST` is blocked, follow-up checks use the GET `query` parameter
- introspection detection and schema summary for queries, mutations, subscriptions, and types
- safe alternate introspection probes for blocked raw POST bodies: GET `query`, POST form `query`, compact alias query, `application/graphql`, JSON unicode-escaped introspection token, and newline/comma/comment after `__schema`
- JSON batching detection
- verbose validation error detection

Schema artifacts are written to `Poutput/graphql` by default and are not printed into the terminal. To write all detected GraphQL schemas into one file:

```bash
./pentest -f 'output/example.com|2026-04-08_11-30-00.txt' -host example.com -graphql-schema-out Poutput/graphql/example-schema.json
```

For a known PortSwigger GraphQL endpoint, inject it directly:

```bash
./luska -u https://YOUR-LAB.web-security-academy.net -ps -graphql-endpoint /graphql/v1
```

Mutations are never executed by this phase. To skip it:

```bash
./pentest -f 'output/example.com|2026-04-08_11-30-00.txt' -host example.com -skip-phase 6
```

Example:

```bash
./luska -u https://example.com -ps -rate 10 -ext-rate 2
./pentest -f 'output/example.com|2026-04-08_11-30-00.txt' -host example.com -rate 10 -ext-rate 1
```

## UI Modes

- `cli` prints plain terminal output and final tables
- `tui` uses Bubble Tea during pentest execution

In TUI mode:

- there is a global navigation layer with `Dashboard`, `Findings`, `Targets`, `History`, and `New Scan`
- selecting a scan opens a detail view with `Logs`, `Findings`, `Targets`, and `Control`
- live logs scroll in the viewport
- older lines disappear from the visible area when the screen fills up
- background scans launched from the TUI show their current phase and progress in real time by polling the log file
- after the scan finishes, the TUI stays open and shows a completion message
- press `Esc` to leave the finished TUI and print the final findings tables and summary

## Crawl Output

The crawler collects:

- in-scope links
- GET and POST forms
- JS files and inline JS blocks
- endpoints extracted from JavaScript patterns like `fetch`, XHR, axios, template strings, and API assignments
- JS signatures for exposed secrets, phishing behavior, anti-debugging, blocked browser shortcuts, and obvious exfiltration sinks

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

Uses `subfinder` to discover subdomains. Found subdomains are not written to the crawl file directly — they are passed to phase 0.1 for validation first.

If `-ext-rate` is set, it is forwarded to `subfinder`.

### Phase 0.1: httpx Probe

Runs `httpx` (at `~/go/bin/httpx`) against the subdomains found in phase 0. Only subdomains that respond with a valid HTTP response are written to the crawl file and added to the scan scope.

If `-ext-rate` is set, it is forwarded to `httpx`.

If `-ps-subdomains` is enabled, these validated subdomains are also crawled as separate in-scope targets before the final pentest starts. This gives later pentest phases more than just the root URL for each live subdomain.

### Phase 1: Quick SQLi Test

Tests parameterized URLs and forms with fast checks:

- time-based payloads
- boolean-based response comparison
- POST form checks
- cookie-based probes when cookies are present

If something suspicious is found, later SQLMap settings are escalated automatically.

### Phase 2: Nuclei

Runs `nuclei` against discovered URLs.

If `-ext-rate` is set, it is forwarded to `nuclei`.

### Phase 3: SQLMap

Runs `sqlmap` against parameterized URLs and POST forms.

Supports:

- automatic escalation after suspicious Phase 1 results
- Burp request files via `-burp`
- cookie header forwarding via `-cookie`
- optional external rate limiting via `-ext-rate`

### Phase 4: Dalfox

Runs `dalfox` against URLs with parameters to detect XSS.

If `-ext-rate` is set, IluskaX lowers Dalfox throughput to approximate that rate.

### Phase 5: Header and Cookie Analysis

Checks security-related response headers and cookie settings.

Important:

- missing headers are treated as recommendations or informational findings
- real header or cookie misconfigurations are shown separately from confirmed vulnerabilities

### Phase 6: GraphQL

Safely discovers GraphQL endpoints, checks whether `POST` or GET `query` parameters are accepted, detects enabled introspection, tries safe alternate introspection probes when the basic POST body is blocked, summarizes exposed schema operations, and checks for JSON batching and verbose validation errors.

This phase also probes crawled non-static endpoints, because GraphQL can live behind paths such as `/api`, `/gateway`, or `/v1`. Schema artifacts are saved to `Poutput/graphql` by default, or to `-graphql-schema-out` when a single custom JSON file is requested.

This phase does not execute mutations and does not print the schema body to the terminal.

### Phase 7: Open Redirect

Checks redirect-like query parameters such as `next`, `url`, `redirect`, `return`, `continue`, `callback`, `dest`, and `to`.

The check does not follow redirects. It injects a harmless external URL and reports a finding only when the target responds with a 3xx `Location` header pointing to that URL.

### Phase 8: OpenAPI and Sensitive File Discovery

Safely probes each discovered host for common exposed documentation or sensitive files:

- OpenAPI / Swagger JSON and UI paths
- `.env`
- `.git/config`
- common backup/config/archive/dump filenames
- `/.well-known/security.txt`

When OpenAPI JSON is found, IluskaX extracts path keys and adds those API routes to the sitemap for reporting.

### Phase 9: Parameter Reflection Map

Builds a lightweight map of reflected query parameters. IluskaX injects a unique harmless marker per parameter and records whether the marker is reflected in HTML text, HTML attributes, URL attributes, script blocks, or escaped output.

This phase is meant for triage: it helps identify which URLs are interesting for manual XSS or template-injection review without sending exploit payloads.

## Reports

Default files:

```text
output/<hostname>|<datetime>.txt
Poutput/<hostname>|<datetime>_report.txt
Poutput/sqlmap/
Poutput/graphql/
```

If `-o` is provided, IluskaX also writes a custom export file with:

- sitemap
- findings tables
- final summary

If `-json-out` is provided, IluskaX writes a machine-readable JSON report with:

- sitemap
- findings with level, type, url, payload, detail, and severity
- summary counts for vulnerabilities, warnings, info findings, and elapsed time

## TUI Overview

### Dashboard

Shows the active scans list and current state for each scan:

- target
- status badge
- current phase (polled from log for background scans)
- progress percent
- finding counters

Press `Enter` on the selected scan to open its detail view.

### Findings

Shows discovered issues collected during the running scan, separated from raw logs.

You can filter and search directly in the TUI:

- `0` all findings
- `1` vulnerabilities only
- `2` warnings only
- `3` info only
- `/` enter search mode

### Targets

In the global TUI view, `Targets` shows discovered targets grouped by scan, and inside each scan they are grouped by host.

In the scan detail view, `Targets` shows only the targets collected for the selected scan.

Example:

```text
localhost [FINISHED]
  http://localhost:3000
  ├─ /
  ├─ /?q=1
  └─ /xss?q=test
```

### History

Shows scans that were launched or finished during the current TUI session, plus queued items.

Finished and launched scan history is persisted to `Poutput/tui_history.json`, so it stays available between TUI launches.

Press `x` in the `History` tab to clear the saved history without deleting files manually.

### New Scan

Lets you prepare a new command from inside the TUI.

You can:

- enter a target URL
- add extra flags (including `-H 'X-Bug-Bounty: handle'`)
- choose `Run now` to launch a background `luska` process
- choose `Queue` to store a scan in the local session queue
- confirm the selected action before it executes

`Run now` launches a new background process and writes its output to a log file in `Poutput/`.

### Control

For background scans launched from the TUI, the `Control` tab can:

- pause or resume the selected scan
- restart the selected scan
- stop the selected scan
- show a confirmation prompt before the action is applied

## TUI Controls

- `Tab` and `Shift+Tab` switch tabs
- `Left` and `Right` also switch tabs
- `Up` and `Down` move selection or scroll
- `Enter` opens scan details or confirms the current action in `New Scan`
- `Esc` returns from scan details to the global tabs
- after a scan finishes, `Esc` exits the TUI and returns to normal terminal output
- `0`, `1`, `2`, `3` filter findings by severity in the `Findings` tab
- `/` enters findings search mode
- `x` clears saved history in the `History` tab
- in `New Scan`, use `Up` and `Down` to move focus between fields
- in `New Scan`, use `Left` and `Right` on the `Action` field to switch between `Run now` and `Queue`
- in `New Scan`, use `Enter` on the `Action` field to open a confirmation prompt
- use `Enter` or `y` to confirm actions, and `Esc` or `n` to cancel
- in `Control`, `p` pauses or resumes the selected background scan
- in `Control`, `r` restarts the selected background scan
- in `Control`, `s` stops the selected background scan

## Skip Phases

Example:

```bash
./luska -u https://example.com -ps -skip-phase 2,4
```

Phase mapping:

- `0` = subdomain enumeration
- `0.1` = httpx probe (runs automatically after phase 0, cannot be skipped independently)
- `1` = quick SQLi
- `2` = nuclei
- `3` = SQLMap
- `4` = dalfox
- `5` = header and cookie analysis
- `6` = GraphQL endpoint and schema scan
- `7` = open redirect check
- `8` = OpenAPI and sensitive file discovery
- `9` = parameter reflection map

For direct `pentest`, supported skip values are `1` through `9`.

## Notes

- User-Agent: `Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0`
- custom `-H` headers override the default User-Agent if `User-Agent` is specified
- crawl request timeout is short and optimized for scanning, not browsing
- JS parsing and endpoint extraction intentionally prefer breadth over perfect semantic accuracy
- TUI is intended for the pentest phase, not as a full-screen wrapper around the entire crawl pipeline
- phase display for background TUI scans is updated by polling the log file every 250ms

## Legal

IluskaX is intended only for authorized security work, including bug bounty programs, private labs, and infrastructure you own or are explicitly allowed to test.

You must not use this project to scan, probe, attack, stress, disrupt, or enumerate systems without permission.

The authors do not authorize illegal use of this software. The fact that this repository is public does not grant permission to test third-party targets.

By using IluskaX, you are solely responsible for ensuring that your activity complies with all applicable laws, platform rules, contracts, and program policies.
