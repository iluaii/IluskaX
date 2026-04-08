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

func main() {
	targetURL := flag.String("u", "", "Target URL to crawl")
	recursive := flag.Bool("r", false, "Enable recursive crawling")
	maxDepth := flag.Int("rd", 0, "Maximum recursion depth")
	pentest := flag.Bool("ps", false, "Run pentest scan after crawl")
	subdomains := flag.Bool("sd", false, "Enable subdomain enumeration before crawl (requires subfinder)")
	rateLimit := flag.Int("rate", 10, "Requests per second")
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
	uiMode := flag.String("ui", "cli", "UI mode: cli|tui")
	flag.Parse()

	if *targetURL == "" {
		printUsage()
		return
	}

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
	defer ui.RestoreTerminal(os.Stdout)
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
	if len(skipList) > 0 {
		fmt.Printf("[*] SKIPPING PATTERNS: %s\n", strings.Join(skipList, ", "))
	}
	if *crawlTimeout > 0 {
		fmt.Printf("[*] TIMEOUT: %d minutes\n", *crawlTimeout)
	}
	fmt.Println(sep)

	if *subdomains {
		modules.SubdomainEnum(parsed.Hostname(), f, session.Writer("subdomain"))
	}

	sb.SetPhase("CRAWL", 0)
	session.Start()
	defer session.Stop()

	crawlerTerm := ui.NewStatusWriter(sb)
	crawler := core.NewCrawler(*rateLimit, crawlerTerm, f, parsed.Host)
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

	session.Stop()

	fmt.Println("\n" + sep)
	fmt.Printf("[+] CRAWL COMPLETE: %s\n", crawlPath)
	fmt.Printf("[+] URLs discovered: %d\n", len(rc.Sitemap()))
	fmt.Println(sep)

	if *outFile != "" && !*pentest {
		if err := ui.WriteReport(*outFile, rc.Sitemap(), rc.Findings(), startTime); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to write report: %v\n", err)
		} else {
			fmt.Printf("[+] Report written: %s\n", *outFile)
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

	if *pentest {
		fmt.Println("\n[*] Starting pentest scan...")

		pentestArgs := []string{
			"-f", crawlPath,
			"-host", parsed.Hostname(),
			"-date", date,
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
	fmt.Println("Usage: ./luska -u <URL> [-r] [-rd <depth>] [-ps] [-sd] [-rate <n>] [-c <n>] [-o <report>] [-ui <cli|tui>]")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -rate          Requests per second (default: 10)")
	fmt.Println("  -c             Concurrent crawl goroutines (default: 5)")
	fmt.Println("  -ignore-robots Skip robots.txt restrictions")
	fmt.Println("  -sqlmap-level  SQLMap starting level 1-5 (default: auto)")
	fmt.Println("  -sqlmap-risk   SQLMap starting risk 1-3 (default: auto)")
	fmt.Println("  -cookie        Cookie for authenticated scanning")
	fmt.Println("  -burp          Path to Burp request file for SQLMap")
	fmt.Println("  -timeout       Total crawl timeout in minutes (default: no limit)")
	fmt.Println("  -o             Output report file (sitemap + vulnerability tables)")
	fmt.Println("  -ui            UI mode: cli|tui (default: cli)")
	fmt.Println()
	fmt.Println("Phases (for -skip-phase):")
	fmt.Println("  0 = Subdomain Enumeration (subfinder)")
	fmt.Println("  1 = Quick SQLi Test")
	fmt.Println("  2 = NUCLEI Template Scan")
	fmt.Println("  3 = SQLMap Deep Scan")
	fmt.Println("  4 = Dalfox XSS Scan")
	fmt.Println("  5 = Header & Cookie Analysis")
}
