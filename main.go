package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"IluskaX/internal/core"
	"IluskaX/internal/events"
	"IluskaX/internal/modules"
	"IluskaX/internal/ui"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[38;5;196m"
	colorGreen  = "\033[38;5;46m"
	colorYellow = "\033[38;5;226m"
	colorBlue   = "\033[38;5;39m"
	colorCyan   = "\033[38;5;51m"
	colorWhite  = "\033[38;5;15m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"

	clearLine  = "\033[2K"
	cursorUp   = "\033[1A"
	cursorHome = "\r"
	hideCursor = "\033[?25l"
	showCursor = "\033[?25h"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *multiFlag) Set(val string) error {
	*m = append(*m, val)
	return nil
}

type subdomainFlag struct {
	enabled bool
	pattern string
}

func (s *subdomainFlag) String() string {
	if s == nil || !s.enabled {
		return "false"
	}
	if s.pattern == "" {
		return "true"
	}
	return s.pattern
}

func (s *subdomainFlag) Set(val string) error {
	val = strings.TrimSpace(val)
	if val == "" || strings.EqualFold(val, "true") {
		s.enabled = true
		return nil
	}
	if strings.EqualFold(val, "false") {
		s.enabled = false
		s.pattern = ""
		return nil
	}
	s.enabled = true
	s.pattern = normalizeSubdomainPattern(val)
	return nil
}

func (s *subdomainFlag) IsBoolFlag() bool {
	return true
}

func (s subdomainFlag) Enabled() bool {
	return s.enabled
}

func (s subdomainFlag) Pattern() string {
	return s.pattern
}

func expandSubdomainFlagArgs(args []string) []string {
	if len(args) < 3 {
		return args
	}
	out := make([]string, 0, len(args))
	out = append(out, args[0])
	for i := 1; i < len(args); i++ {
		if args[i] == "-sd" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out = append(out, "-sd="+args[i+1])
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func withSubdomainScope(scopeList, host string, patterns ...string) string {
	subdomainRule := ""
	if len(patterns) > 0 {
		if pattern := normalizeSubdomainPattern(patterns[0]); pattern != "" {
			subdomainRule = pattern
		}
	}
	if subdomainRule == "" {
		if pattern := normalizeSubdomainPattern(host); strings.Contains(pattern, "*") {
			subdomainRule = pattern
		}
	}
	if subdomainRule == "" {
		host = discoveryHost(host)
		if host == "" {
			return strings.TrimSpace(scopeList)
		}
		subdomainRule = "*." + host
	}
	for _, item := range strings.Split(scopeList, ",") {
		if strings.TrimSpace(strings.ToLower(item)) == subdomainRule {
			return scopeList
		}
	}
	if strings.TrimSpace(scopeList) == "" {
		return subdomainRule
	}
	return scopeList + "," + subdomainRule
}

func discoveryHost(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if parsed, err := url.Parse("//" + raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.Trim(raw, "[] ")
	raw = strings.TrimSuffix(raw, ".")
	return strings.TrimPrefix(raw, "www.")
}

func normalizeSubdomainPattern(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if parsed, err := url.Parse("//" + raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.Trim(raw, "[] ")
	return strings.TrimSuffix(raw, ".")
}

func subdomainPatternForRun(flag subdomainFlag, targetHost string) string {
	if pattern := flag.Pattern(); pattern != "" {
		return pattern
	}
	pattern := normalizeSubdomainPattern(targetHost)
	if strings.Contains(pattern, "*") {
		return pattern
	}
	return ""
}

func subdomainEnumHost(targetHost, pattern string) string {
	if suffix := suffixAfterWildcard(pattern); suffix != "" {
		return suffix
	}
	return discoveryHost(targetHost)
}

func suffixAfterWildcard(pattern string) string {
	pattern = normalizeSubdomainPattern(pattern)
	if !strings.Contains(pattern, "*") {
		return ""
	}
	parts := strings.Split(pattern, ".")
	wildcardIndex := -1
	for i, part := range parts {
		if strings.Contains(part, "*") {
			wildcardIndex = i
		}
	}
	if wildcardIndex == -1 || wildcardIndex+1 >= len(parts) {
		return ""
	}
	return strings.Join(parts[wildcardIndex+1:], ".")
}

func isSameOrSubdomain(host, root string) bool {
	host = discoveryHost(host)
	root = discoveryHost(root)
	return host == root || strings.HasSuffix(host, "."+root)
}

func matchesSubdomainPattern(host, pattern string) bool {
	host = normalizeSubdomainPattern(host)
	pattern = normalizeSubdomainPattern(pattern)
	if host == "" || pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return discoveryHost(host) == discoveryHost(pattern)
	}
	hostParts := strings.Split(host, ".")
	patternParts := strings.Split(pattern, ".")
	if len(hostParts) != len(patternParts) {
		return false
	}
	for i := range patternParts {
		if patternParts[i] == "*" {
			continue
		}
		if hostParts[i] != patternParts[i] {
			return false
		}
	}
	return true
}

func sitemapURLForAliveSubdomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasSuffix(raw, "/") {
		return raw
	}
	return raw + "/"
}

func printBanner() {
	banner := []string{
		"",
		"  ██╗██╗     ██╗   ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗",
		"  ██║██║     ██║   ██║██╔════╝██║ ██╔╝██╔══██╗╚██╗██╔╝",
		"  ██║██║     ██║   ██║███████╗█████╔╝ ███████║ ╚███╔╝ ",
		"  ██║██║     ██║   ██║╚════██║██╔═██╗ ██╔══██║ ██╔██╗ ",
		"  ██║███████╗╚██████╔╝███████║██║  ██╗██║  ██║██╔╝ ██╗",
		"  ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝",
		"",
	}

	for _, line := range banner {
		fmt.Println(colorGreen + line + colorReset)
	}

	fmt.Println(colorYellow + "                   ╔══════════════════════╗" + colorReset)
	fmt.Println(colorYellow + "                   ║  web recon & pentest ║" + colorReset)
	fmt.Println(colorYellow + "                   ╚══════════════════════╝" + colorReset)
	fmt.Println()
}
func main() {
	printBanner()
	os.Args = expandSubdomainFlagArgs(os.Args)
	targetURL := flag.String("u", "", "Target URL to crawl")
	recursive := flag.Bool("r", false, "Enable recursive crawling")
	maxDepth := flag.Int("rd", 0, "Maximum recursion depth")
	pentest := flag.Bool("ps", false, "Run pentest scan after crawl")
	var subdomains subdomainFlag
	flag.Var(&subdomains, "sd", "Enable subdomain enumeration before crawl; optional host pattern (e.g. -sd or -sd www.*.example.com)")
	crawlSubdomains := flag.Bool("crawl-subdomains", false, "Crawl validated subdomains too after subdomain discovery")
	pentestSubdomains := flag.Bool("ps-subdomains", false, "Deprecated alias for -crawl-subdomains")
	rateLimit := flag.Int("rate", 10, "Requests per second")
	extRateLimit := flag.Int("ext-rate", 0, "Requests per second for external tools (0 = no limit)")
	concurrency := flag.Int("c", 5, "Max concurrent goroutines")
	ignoreRobots := flag.Bool("ignore-robots", false, "Ignore robots.txt restrictions")
	sqlmapLevel := flag.Int("sqlmap-level", 0, "SQLMap starting level (1-5), 0 = auto")
	sqlmapRisk := flag.Int("sqlmap-risk", 0, "SQLMap starting risk (1-3), 0 = auto")
	cookie := flag.String("cookie", "", "Cookie header for authenticated scanning")
	burpFile := flag.String("burp", "", "Path to Burp request file for SQLMap")
	skipFlag := flag.String("skip", "", "Comma-separated path patterns to skip")
	skipPhases := flag.String("skip-phase", "", "Comma-separated phases to skip (0-12)")
	phaseOnly := flag.String("phaseo", "", "Comma-separated pentest phases to run exclusively (1-12)")
	scopeFlag := flag.String("scope", "", "Comma-separated extra allowed hosts (supports *.example.com)")
	denyScopeFlag := flag.String("deny-scope", "", "Comma-separated denied hosts (deny wins, supports *.example.com)")
	crawlTimeout := flag.Int("timeout", 0, "Total crawl timeout in minutes (0 = no limit)")
	outFile := flag.String("o", "", "Output report file path (sitemap + vuln tables)")
	jsonOut := flag.String("json-out", "", "Output JSON report file path")
	graphqlSchemaDir := flag.String("graphql-schema-dir", "Poutput/graphql", "Directory for GraphQL schema artifacts")
	graphqlSchemaOut := flag.String("graphql-schema-out", "", "Single JSON file for GraphQL schema artifacts")
	uiMode := flag.String("ui", "cli", "UI mode: cli|tui")
	cookieFile := flag.String("cookiefile", "", "Path to file containing cookie header value")
	var headers multiFlag
	var graphqlEndpoints multiFlag
	flag.Var(&headers, "H", "Custom header in 'Name: Value' format (repeatable)")
	flag.Var(&graphqlEndpoints, "graphql-endpoint", "Manual GraphQL endpoint URL or path (repeatable, e.g. /graphql/v1)")
	oastServer := flag.String("oast-server", "oast.pro,oast.live", "Interactsh servers for pentest phase 11 (empty disables blind SSRF)")
	oastToken := flag.String("oast-token", "", "Optional Interactsh token for private servers")
	oastPoll := flag.Int("oast-poll-seconds", 40, "OAST poll duration for phase 11 (15-180)")
	flag.Parse()

	if *cookieFile != "" {
		data, err := os.ReadFile(*cookieFile)
		if err != nil {
			fmt.Printf("ERROR: Cannot read cookie file: %v\n", err)
			return
		}
		*cookie = strings.TrimSpace(string(data))
	}
	if *targetURL == "" {
		printUsage()
		return
	}

	modules.SetCustomHeaders(headers)

	var skipList []string
	if *skipFlag != "" {
		for _, s := range strings.Split(*skipFlag, ",") {
			skipList = append(skipList, strings.TrimSpace(s))
		}
	}

	os.MkdirAll("output", 0755)
	os.MkdirAll("Poutput", 0755)

	parsed, err := url.Parse(*targetURL)
	if err != nil {
		fmt.Printf("ERROR: Invalid URL: %v\n", err)
		return
	}
	allowScope := *scopeFlag
	subdomainPattern := subdomainPatternForRun(subdomains, parsed.Hostname())
	subdomainRoot := subdomainEnumHost(parsed.Hostname(), subdomainPattern)
	targetHasWildcard := strings.Contains(normalizeSubdomainPattern(parsed.Hostname()), "*")
	rootCrawlTarget := !targetHasWildcard && !(subdomains.Enabled() && subdomainPattern != "")
	if subdomains.Enabled() {
		allowScope = withSubdomainScope(allowScope, parsed.Hostname(), subdomainPattern)
	}
	defaultScopeHost := parsed.Hostname()
	if targetHasWildcard {
		defaultScopeHost = ""
	}
	scopeGuard := core.NewScopeGuard(defaultScopeHost, allowScope, *denyScopeFlag)
	if !scopeGuard.InScope(*targetURL) {
		fmt.Printf("ERROR: Target is denied by scope guard: %s\n", *targetURL)
		return
	}

	date := time.Now().Format("2006-01-02_15-04-05")
	crawlPath := "output/" + parsed.Hostname() + "|" + date + ".txt"

	f, err := os.Create(crawlPath)
	if err != nil {
		fmt.Printf("ERROR: Cannot create file: %v\n", err)
		return
	}
	defer f.Close()

	mode := ui.ParseMode(*uiMode)
	crawlMode := mode
	if *pentest && mode == ui.ModeTUI {
		crawlMode = ui.ModeCLI
	}
	session := ui.NewSession(crawlMode, os.Stdout)
	rc := session.Reports()
	sb := session.StatusBar()
	startTime := time.Now()
	sessionStopped := false
	stopSession := func() {
		if sessionStopped {
			return
		}
		sessionStopped = true
		session.Stop()
	}
	defer ui.RestoreTerminal(os.Stdout)
	defer stopSession()
	if em := session.Emitter(); em != nil {
		em.Publish(events.Event{
			Type:    events.EventScanStarted,
			Source:  "main",
			Message: *targetURL,
			Payload: map[string]string{"target": *targetURL, "mode": string(mode)},
		})
	}

	sep := strings.Repeat("=", 60)
	fmt.Println("\n" + sep)
	fmt.Printf("[*] CRAWLING STARTED: %s\n", *targetURL)
	fmt.Printf("[*] RATE LIMIT: %d req/s | CONCURRENCY: %d\n", *rateLimit, *concurrency)
	if *extRateLimit > 0 {
		fmt.Printf("[*] EXTERNAL TOOL RATE LIMIT: %d req/s\n", *extRateLimit)
	}
	if len(headers) > 0 {
		fmt.Printf("[*] CUSTOM HEADERS: %d set\n", len(headers))
		for _, h := range headers {
			fmt.Printf("    %s\n", h)
		}
	}
	if len(skipList) > 0 {
		fmt.Printf("[*] SKIPPING PATTERNS: %s\n", strings.Join(skipList, ", "))
	}
	fmt.Printf("[*] SCOPE ALLOW: %s\n", scopeGuard.AllowSummary())
	if *denyScopeFlag != "" {
		fmt.Printf("[*] SCOPE DENY: %s\n", scopeGuard.DenySummary())
	}
	if *crawlTimeout > 0 {
		fmt.Printf("[*] TIMEOUT: %d minutes\n", *crawlTimeout)
	}
	if targetHasWildcard {
		fmt.Println("[*] WILDCARD TARGET: root crawl skipped; use -crawl-subdomains to crawl matched live hosts")
	} else if !rootCrawlTarget {
		fmt.Println("[*] SD PATTERN TARGET: root crawl skipped; use -crawl-subdomains to crawl matched live hosts")
	}
	fmt.Println(sep)

	var aliveSubdomains []string
	if subdomains.Enabled() {
		found := modules.SubdomainEnum(subdomainRoot, f, session.Writer("subdomain"), *extRateLimit)
		if len(found) > 0 {
			var scoped []string
			for _, sub := range found {
				if !isSameOrSubdomain(sub, subdomainRoot) {
					fmt.Fprintf(session.Writer("subdomain"), "├─ [SCOPE] skipped out-of-scope subdomain: %s\n", sub)
					continue
				}
				if subdomainPattern != "" && !matchesSubdomainPattern(sub, subdomainPattern) {
					fmt.Fprintf(session.Writer("subdomain"), "├─ [SCOPE] skipped subdomain outside -sd pattern %s: %s\n", subdomainPattern, sub)
					continue
				}
				if *denyScopeFlag != "" && !scopeGuard.InScope("https://"+normalizeSubdomainPattern(sub)) {
					fmt.Fprintf(session.Writer("subdomain"), "├─ [SCOPE] skipped denied subdomain: %s\n", sub)
					continue
				}
				scoped = append(scoped, sub)
			}
			found = scoped
		}
		if len(found) > 0 {
			aliveSubdomains = modules.HTTPXProbe(found, f, session.Writer("httpx"), *extRateLimit, sb)
			for _, subURL := range aliveSubdomains {
				if sitemapURL := sitemapURLForAliveSubdomain(subURL); sitemapURL != "" {
					rc.AddSitemapURL(sitemapURL)
				}
			}
		}
	}

	var baseCtx context.Context
	var cancel context.CancelFunc
	if *crawlTimeout > 0 {
		baseCtx, cancel = context.WithTimeout(context.Background(), time.Duration(*crawlTimeout)*time.Minute)
	} else {
		baseCtx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	ctx, stopSignals := signal.NotifyContext(baseCtx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	sb.SetPhase("CRAWL", 0)
	session.Start()

	if *ignoreRobots {
		fmt.Println("[*] robots.txt ignored")
	}

	runCrawl := func(seedURL, scopeHost string) {
		crawlerTerm := ui.NewStatusWriter(sb)
		crawler := core.NewCrawler(*rateLimit, crawlerTerm, f, scopeHost)
		crawler.SetScopeGuard(scopeGuard)
		crawler.SetCustomHeaders(modules.CustomHeaders())
		defer crawler.Stop()
		crawler.WriteLine(seedURL)

		if !*ignoreRobots {
			if seedParsed, err := url.Parse(seedURL); err == nil {
				crawler.FetchRobots(seedParsed)
			}
		}

		sem := make(chan struct{}, *concurrency)
		var wg sync.WaitGroup
		wg.Add(1)
		sem <- struct{}{}
		go crawler.Pars(ctx, seedURL, *recursive, 0, *maxDepth, skipList, &wg, sem, rc, sb)
		wg.Wait()

		crawler.ScanJS(crawlerTerm, f, rc, sb)
		f.Sync()
	}

	if rootCrawlTarget {
		runCrawl(*targetURL, parsed.Host)
	}

	shouldCrawlSubdomains := *crawlSubdomains || *pentestSubdomains
	if shouldCrawlSubdomains && len(aliveSubdomains) > 0 {
		fmt.Printf("[*] Subdomain crawl enabled: crawling %d validated subdomains\n", len(aliveSubdomains))
		seenHosts := map[string]bool{
			parsed.Hostname(): true,
		}
		for _, subURL := range aliveSubdomains {
			subParsed, err := url.Parse(subURL)
			if err != nil || subParsed.Host == "" {
				fmt.Printf("[WARN] Skipping invalid subdomain URL: %s\n", subURL)
				continue
			}
			if seenHosts[subParsed.Hostname()] {
				continue
			}
			if !scopeGuard.InScope(subURL) {
				fmt.Printf("[SCOPE] Skipping out-of-scope subdomain crawl: %s\n", subURL)
				continue
			}
			seenHosts[subParsed.Hostname()] = true
			fmt.Printf("[*] Crawling validated subdomain: %s\n", subURL)
			runCrawl(subURL, subParsed.Host)
		}
	} else if shouldCrawlSubdomains && !subdomains.Enabled() {
		fmt.Println("[WARN] -crawl-subdomains requires -sd; flag ignored")
	}

	var completionSummary strings.Builder
	completionSummary.WriteString("\n" + sep + "\n")
	completionSummary.WriteString(fmt.Sprintf("[+] CRAWL COMPLETE: %s\n", crawlPath))
	completionSummary.WriteString(fmt.Sprintf("[+] URLs discovered: %d\n", len(rc.Sitemap())))
	completionSummary.WriteString(sep + "\n")

	var exportSummary strings.Builder
	if *outFile != "" && !*pentest {
		if err := ui.WriteReport(*outFile, rc.Sitemap(), rc.Findings(), startTime); err != nil {
			exportSummary.WriteString(fmt.Sprintf("[ERROR] Failed to write report: %v\n", err))
		} else {
			exportSummary.WriteString(fmt.Sprintf("[+] Report written: %s\n", *outFile))
			if em := session.Emitter(); em != nil {
				em.Publish(events.Event{
					Type:    events.EventReportWritten,
					Source:  "main",
					Message: *outFile,
					Payload: map[string]string{"path": *outFile},
				})
			}
		}
	}
	if *jsonOut != "" && !*pentest {
		if err := ui.WriteJSONReport(*jsonOut, rc.Sitemap(), rc.Findings(), startTime); err != nil {
			exportSummary.WriteString(fmt.Sprintf("[ERROR] Failed to write JSON report: %v\n", err))
		} else {
			exportSummary.WriteString(fmt.Sprintf("[+] JSON report written: %s\n", *jsonOut))
		}
	}

	if !*pentest {
		if em := session.Emitter(); em != nil {
			em.Publish(events.Event{
				Type:    events.EventScanFinished,
				Source:  "main",
				Message: *targetURL,
				Payload: map[string]string{"target": *targetURL},
			})
		}
		if mode == ui.ModeTUI {
			session.Wait()
		}
		stopSession()
		fmt.Print(completionSummary.String())
		if exportSummary.Len() > 0 {
			fmt.Print(exportSummary.String())
		}
		return
	}

	stopSession()
	fmt.Print(completionSummary.String())

	if *pentest {
		fmt.Println("\n[*] Starting pentest scan...")

		pentestArgs := []string{
			"-f", crawlPath,
			"-host", parsed.Hostname(),
			"-date", date,
			"-rate", fmt.Sprintf("%d", *rateLimit),
			"-ext-rate", fmt.Sprintf("%d", *extRateLimit),
		}
		for _, h := range headers {
			pentestArgs = append(pentestArgs, "-H", h)
		}
		if *skipPhases != "" {
			pentestArgs = append(pentestArgs, "-skip-phase", *skipPhases)
		}
		if *phaseOnly != "" {
			pentestArgs = append(pentestArgs, "-phaseo", *phaseOnly)
		}
		if allowScope != "" {
			pentestArgs = append(pentestArgs, "-scope", allowScope)
		}
		if *denyScopeFlag != "" {
			pentestArgs = append(pentestArgs, "-deny-scope", *denyScopeFlag)
		}
		if *sqlmapLevel > 0 {
			pentestArgs = append(pentestArgs, "-sqlmap-level", fmt.Sprintf("%d", *sqlmapLevel))
		}
		if *sqlmapRisk > 0 {
			pentestArgs = append(pentestArgs, "-sqlmap-risk", fmt.Sprintf("%d", *sqlmapRisk))
		}
		if *cookie != "" {
			pentestArgs = append(pentestArgs, "-cookie", *cookie)
		}
		if *burpFile != "" {
			pentestArgs = append(pentestArgs, "-burp", *burpFile)
		}
		if *outFile != "" {
			pentestArgs = append(pentestArgs, "-o", *outFile)
		}
		if *jsonOut != "" {
			pentestArgs = append(pentestArgs, "-json-out", *jsonOut)
		}
		if *graphqlSchemaDir != "" {
			pentestArgs = append(pentestArgs, "-graphql-schema-dir", *graphqlSchemaDir)
		}
		if *graphqlSchemaOut != "" {
			pentestArgs = append(pentestArgs, "-graphql-schema-out", *graphqlSchemaOut)
		}
		pentestArgs = append(pentestArgs, "-graphql-base-url", *targetURL)
		for _, endpoint := range graphqlEndpoints {
			pentestArgs = append(pentestArgs, "-graphql-endpoint", endpoint)
		}
		pentestArgs = append(pentestArgs, "-oast-server", *oastServer)
		if *oastToken != "" {
			pentestArgs = append(pentestArgs, "-oast-token", *oastToken)
		}
		pentestArgs = append(pentestArgs, "-oast-poll-seconds", fmt.Sprintf("%d", *oastPoll))
		if mode == ui.ModeTUI {
			pentestArgs = append(pentestArgs, "-ui", "tui")
		}

		cmd := exec.Command("./pentest", pentestArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			fmt.Printf("[ERROR] Pentest failed: %v\n", err)
		}
	}
	if em := session.Emitter(); em != nil {
		em.Publish(events.Event{
			Type:    events.EventScanFinished,
			Source:  "main",
			Message: *targetURL,
			Payload: map[string]string{"target": *targetURL},
		})
	}
}

func printUsage() {
	fmt.Println("ERROR: please provide URL with -u flag")
	fmt.Println("Usage: ./luska -u <URL> [-r] [-rd <depth>] [-ps] [-sd [pattern]] [-crawl-subdomains] [-scope <hosts>] [-deny-scope <hosts>] [-skip-phase <phases>] [-phaseo <phases>] [-rate <n>] [-ext-rate <n>] [-c <n>] [-H 'Name: Value'] [-o <report>] [-json-out <report.json>] [-graphql-endpoint <url-or-path>] [-ui <cli|tui>]")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -sd            Subdomain enumeration; optional pattern like www.*.example.com (default: *.target)")
	fmt.Println("  -H             Custom header 'Name: Value' (repeatable, e.g. -H 'X-Bug-Bounty: hunter')")
	fmt.Println("  -rate          Requests per second (default: 10)")
	fmt.Println("  -ext-rate      Requests per second for external tools (default: 0 = no limit)")
	fmt.Println("  -c             Concurrent crawl goroutines (default: 5)")
	fmt.Println("  -crawl-subdomains Crawl validated subdomains too after -sd")
	fmt.Println("  -ps-subdomains Deprecated alias for -crawl-subdomains")
	fmt.Println("  -scope         Extra allowed hosts, comma-separated; supports *.example.com")
	fmt.Println("  -deny-scope    Denied hosts, comma-separated; deny wins; supports *.example.com")
	fmt.Println("  -ignore-robots Skip robots.txt restrictions")
	fmt.Println("  -sqlmap-level  SQLMap starting level 1-5 (default: auto)")
	fmt.Println("  -sqlmap-risk   SQLMap starting risk 1-3 (default: auto)")
	fmt.Println("  -cookie        Cookie for authenticated scanning")
	fmt.Println("-cookiefile    Path to file with cookie header value (overrides -cookie)")
	fmt.Println("  -burp          Path to Burp request file for SQLMap")
	fmt.Println("  -skip-phase    Pentest phases to skip, comma-separated")
	fmt.Println("  -phaseo        Run only these pentest phases, comma-separated (e.g. -phaseo 4 or -phaseo 4,7)")
	fmt.Println("  -timeout       Total crawl timeout in minutes (default: no limit)")
	fmt.Println("  -o             Output report file (sitemap + vulnerability tables)")
	fmt.Println("  -json-out      Output JSON report file")
	fmt.Println("  -graphql-schema-dir Directory for GraphQL schema artifacts")
	fmt.Println("  -graphql-schema-out Single JSON file for GraphQL schema artifacts")
	fmt.Println("  -graphql-endpoint Manual GraphQL endpoint URL or path (repeatable, e.g. /graphql/v1)")
	fmt.Println("  -oast-server     Interactsh hosts for pentest phase 11 (default oast.pro,oast.live; empty disables OAST)")
	fmt.Println("  -oast-token       Optional Interactsh token")
	fmt.Println("  -oast-poll-seconds OAST poll duration (default 40)")
	fmt.Println("  -ui            UI mode: cli|tui (default: cli)")
	fmt.Println()
	fmt.Println("Phases (for -skip-phase / -phaseo):")
	fmt.Println("  0  = Subdomain Enumeration (subfinder)")
	fmt.Println("  0.1 = httpx probe (auto after phase 0)")
	fmt.Println("  1  = Header & Cookie Analysis")
	fmt.Println("  2  = OpenAPI & Sensitive File Discovery")
	fmt.Println("  3  = JavaScript Secret Scanner")
	fmt.Println("  4  = GraphQL Endpoint & Schema Scan")
	fmt.Println("  5  = Parameter Reflection Map")
	fmt.Println("  6  = Open Redirect Check")
	fmt.Println("  7  = Quick SQLi Test")
	fmt.Println("  8  = NUCLEI Template Scan")
	fmt.Println("  9  = Dalfox XSS Scan")
	fmt.Println("  10 = SQLMap Deep Scan")
	fmt.Println("  11 = CORS / session triage / blind SSRF (Interactsh)")
	fmt.Println("  12 = IDOR surface (static URL heuristics, no extra HTTP)")
}
