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

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *multiFlag) Set(val string) error {
	*m = append(*m, val)
	return nil
}

func main() {
	targetURL := flag.String("u", "", "Target URL to crawl")
	recursive := flag.Bool("r", false, "Enable recursive crawling")
	maxDepth := flag.Int("rd", 0, "Maximum recursion depth")
	pentest := flag.Bool("ps", false, "Run pentest scan after crawl")
	subdomains := flag.Bool("sd", false, "Enable subdomain enumeration before crawl (requires subfinder)")
	rateLimit := flag.Int("rate", 10, "Requests per second")
	extRateLimit := flag.Int("ext-rate", 0, "Requests per second for external tools (0 = no limit)")
	concurrency := flag.Int("c", 5, "Max concurrent goroutines")
	ignoreRobots := flag.Bool("ignore-robots", false, "Ignore robots.txt restrictions")
	sqlmapLevel := flag.Int("sqlmap-level", 0, "SQLMap starting level (1-5), 0 = auto")
	sqlmapRisk := flag.Int("sqlmap-risk", 0, "SQLMap starting risk (1-3), 0 = auto")
	cookie := flag.String("cookie", "", "Cookie header for authenticated scanning")
	burpFile := flag.String("burp", "", "Path to Burp request file for SQLMap")
	skipFlag := flag.String("skip", "", "Comma-separated path patterns to skip")
	skipPhases := flag.String("skip-phase", "", "Comma-separated phases to skip (0-5)")
	crawlTimeout := flag.Int("timeout", 0, "Total crawl timeout in minutes (0 = no limit)")
	outFile := flag.String("o", "", "Output report file path (sitemap + vuln tables)")
	jsonOut := flag.String("json-out", "", "Output JSON report file path")
	uiMode := flag.String("ui", "cli", "UI mode: cli|tui")
	cookieFile := flag.String("cookiefile", "", "Path to file containing cookie header value")
	var headers multiFlag
	flag.Var(&headers, "H", "Custom header in 'Name: Value' format (repeatable)")
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
	if *crawlTimeout > 0 {
		fmt.Printf("[*] TIMEOUT: %d minutes\n", *crawlTimeout)
	}
	fmt.Println(sep)

	if *subdomains {
		found := modules.SubdomainEnum(parsed.Hostname(), f, session.Writer("subdomain"), *extRateLimit)
		if len(found) > 0 {
			modules.HTTPXProbe(found, f, session.Writer("httpx"), *extRateLimit, sb)
		}
	}

	sb.SetPhase("CRAWL", 0)
	session.Start()

	crawlerTerm := ui.NewStatusWriter(sb)
	crawler := core.NewCrawler(*rateLimit, crawlerTerm, f, parsed.Host)
	crawler.SetCustomHeaders(modules.CustomHeaders())
	defer crawler.Stop()

	if !*ignoreRobots {
		crawler.FetchRobots(parsed)
	} else {
		fmt.Println("[*] robots.txt ignored")
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

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	wg.Add(1)
	sem <- struct{}{}
	go crawler.Pars(ctx, *targetURL, *recursive, 0, *maxDepth, skipList, &wg, sem, rc, sb)
	wg.Wait()

	crawler.ScanJS(crawlerTerm, f, rc, sb)
	f.Sync()

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
	fmt.Println("Usage: ./luska -u <URL> [-r] [-rd <depth>] [-ps] [-sd] [-rate <n>] [-ext-rate <n>] [-c <n>] [-H 'Name: Value'] [-o <report>] [-json-out <report.json>] [-ui <cli|tui>]")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -H             Custom header 'Name: Value' (repeatable, e.g. -H 'X-Bug-Bounty: hunter')")
	fmt.Println("  -rate          Requests per second (default: 10)")
	fmt.Println("  -ext-rate      Requests per second for external tools (default: 0 = no limit)")
	fmt.Println("  -c             Concurrent crawl goroutines (default: 5)")
	fmt.Println("  -ignore-robots Skip robots.txt restrictions")
	fmt.Println("  -sqlmap-level  SQLMap starting level 1-5 (default: auto)")
	fmt.Println("  -sqlmap-risk   SQLMap starting risk 1-3 (default: auto)")
	fmt.Println("  -cookie        Cookie for authenticated scanning")
	fmt.Println("  -burp          Path to Burp request file for SQLMap")
	fmt.Println("  -timeout       Total crawl timeout in minutes (default: no limit)")
	fmt.Println("  -o             Output report file (sitemap + vulnerability tables)")
	fmt.Println("  -json-out      Output JSON report file")
	fmt.Println("  -ui            UI mode: cli|tui (default: cli)")
	fmt.Println()
	fmt.Println("Phases (for -skip-phase):")
	fmt.Println("  0  = Subdomain Enumeration (subfinder)")
	fmt.Println("  0.1 = httpx probe (auto after phase 0)")
	fmt.Println("  1  = Quick SQLi Test")
	fmt.Println("  2  = NUCLEI Template Scan")
	fmt.Println("  3  = SQLMap Deep Scan")
	fmt.Println("  4  = Dalfox XSS Scan")
	fmt.Println("  5  = Header & Cookie Analysis")
	fmt.Println("-cookiefile    Path to file with cookie header value (overrides -cookie)")
}