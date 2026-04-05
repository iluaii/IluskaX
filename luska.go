package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

type Form struct {
	Action string
	Method string
	Inputs []string
}

type Crawler struct {
	mu           sync.Mutex
	visited      map[string]bool
	visitedPages []string
	disallowed   []string
	ticker       *time.Ticker
	limiter      <-chan time.Time
	client       *http.Client
	term         io.Writer
	file         io.Writer
	scopeHost    string
}

func newCrawler(ratePerSec int, term io.Writer, file io.Writer, scopeHost string) *Crawler {
	ticker := time.NewTicker(time.Second / time.Duration(ratePerSec))
	return &Crawler{
		visited:      make(map[string]bool),
		visitedPages: []string{},
		ticker:       ticker,
		limiter:      ticker.C,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		term:      term,
		file:      file,
		scopeHost: scopeHost,
	}
}

func (c *Crawler) stop() {
	c.ticker.Stop()
}

func (c *Crawler) inScope(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	host := strings.TrimPrefix(parsed.Host, "www.")
	scope := strings.TrimPrefix(c.scopeHost, "www.")
	return host == scope
}

func (c *Crawler) isVisited(uri string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.visited[uri]
}

func (c *Crawler) markVisited(uri string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.visited[uri] = true
}

func (c *Crawler) writeLine(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintln(c.file, line)
}

func (c *Crawler) log(format string, args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(c.term, format, args...)
}

func (c *Crawler) fetchRobots(base *url.URL) {
	robotsURL := base.Scheme + "://" + base.Host + "/robots.txt"
	resp, err := c.client.Get(robotsURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	fmt.Fprintf(c.term, "\n[ROBOTS] Fetched robots.txt from %s\n", base.Host)

	sc := bufio.NewScanner(resp.Body)
	userAgentMatch := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch strings.ToLower(key) {
		case "user-agent":
			userAgentMatch = val == "*"
		case "disallow":
			if userAgentMatch && val != "" {
				c.disallowed = append(c.disallowed, val)
				fmt.Fprintf(c.term, "├─ [DISALLOW] %s\n", val)
			}
		
		case "sitemap":
			fmt.Fprintf(c.term, "├─ [SITEMAP] %s\n", val)
		}
	}
	fmt.Fprintf(c.term, "└─ %d disallowed paths loaded\n", len(c.disallowed))
}

func (c *Crawler) isDisallowed(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	for _, d := range c.disallowed {
		if strings.HasPrefix(parsed.Path, d) {
			return true
		}
	}
	return false
}

func traverse(n *html.Node, base *url.URL, links *[]string, forms *[]Form) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "a":
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					link, err := url.Parse(attr.Val)
					if err == nil {
						resolved := base.ResolveReference(link)
						resolved.Fragment = ""
						*links = append(*links, resolved.String())
					}
				}
			}
	
		case "script", "iframe":
			for _, attr := range n.Attr {
				if attr.Key == "src" && attr.Val != "" {
					link, err := url.Parse(attr.Val)
					if err == nil {
						*links = append(*links, base.ResolveReference(link).String())
					}
				}
			}
		case "form":
			var f Form
			for _, attr := range n.Attr {
				switch attr.Key {
				case "action":
					link, err := url.Parse(attr.Val)
					if err == nil {
						f.Action = base.ResolveReference(link).String()
					}
				case "method":
					f.Method = strings.ToUpper(attr.Val)
				}
			}
			if f.Method == "" {
				f.Method = "GET"
			}
			if f.Action == "" {
				f.Action = base.String()
			}
			var collectInputs func(*html.Node)
			collectInputs = func(node *html.Node) {
				if node.Type == html.ElementNode {
					switch node.Data {
					case "input", "textarea", "select", "button":
						name, typ := "", node.Data
						for _, a := range node.Attr {
							if a.Key == "name" {
								name = a.Val
							}
							if a.Key == "type" && (node.Data == "input" || node.Data == "button") {
								typ = a.Val
							}
						}
						if name == "" {
							for _, a := range node.Attr {
								if a.Key == "id" {
									name = a.Val
									break
								}
							}
						}
						if name != "" {
							f.Inputs = append(f.Inputs, typ+"="+name)
						}
					}
				}
				for child := node.FirstChild; child != nil; child = child.NextSibling {
					collectInputs(child)
				}
			}
			collectInputs(n)
			*forms = append(*forms, f)
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		traverse(child, base, links, forms)
	}
}

func isSkipped(uri string, skipList []string) bool {
	for _, s := range skipList {
		if s != "" && strings.Contains(uri, s) {
			return true
		}
	}
	return false
}

func (c *Crawler) pars(ctx context.Context, uri string, recurs bool, depr, depth int, skipList []string, wg *sync.WaitGroup, sem chan struct{}) {
	if wg != nil {
		defer wg.Done()
	}
	if sem != nil {
		defer func() { <-sem }()
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	if c.isVisited(uri) {
		return
	}
	c.markVisited(uri)
	c.mu.Lock()
	c.visitedPages = append(c.visitedPages, uri)
	c.mu.Unlock()

	parsed0, err := url.Parse(uri)
	if err == nil && parsed0.Path == "" {
		parsed0.Path = "/"
		uri = parsed0.String()
	}

	if c.isDisallowed(uri) {
		c.log("  [ROBOTS] Skipped disallowed: %s\n", uri)
		return
	}

	<-c.limiter

	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		c.log("  [ERROR] Bad request %s: %v\n", uri, err)
		return
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")

	resp, err := c.client.Do(req)
	if err != nil {
		c.log("  [ERROR] Failed to fetch %s: %v\n", uri, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.log("  [WARN] HTTP %d: %s\n", resp.StatusCode, uri)
	}

	limitedBody := io.LimitReader(resp.Body, 10*1024*1024) 

	doc, err := html.Parse(limitedBody)
	if err != nil {
		c.log("  [ERROR] Failed to parse HTML: %v\n", err)
		return
	}

	base, err := url.Parse(uri)
	if err != nil {
		c.log("  [ERROR] Invalid URL: %v\n", err)
		return
	}

	var links []string
	var forms []Form
	traverse(doc, base, &links, &forms)

	c.log("\n[CRAWL] %s (Depth: %d)\n", base.Path, depr)
	c.log("├─ Status: %d, Forms: %d, Links: %d\n", resp.StatusCode, len(forms), len(links))

	if len(forms) > 0 {
		c.log("├─ FORMS:\n")
		for i, f := range forms {
			c.log("│  ├─ [%d] %s %s\n", i+1, f.Method, f.Action)
			var params []string
			for _, inp := range f.Inputs {
				parts := strings.Split(inp, "=")
				c.log("│  │  ├─ %s\n", inp)
				if len(parts) > 1 {
					params = append(params, parts[1]+"=1")
				}
			}
			if len(params) > 0 {
				if f.Method == "POST" {
					c.writeLine("POST|" + f.Action + "|" + strings.Join(params, "&"))
				} else {
					connector := "?"
					if strings.Contains(f.Action, "?") {
						connector = "&"
					}
					c.writeLine(f.Action + connector + strings.Join(params, "&"))
				}
			}
		}
	}

	if len(links) > 0 {
		c.log("├─ LINKS:\n")
		seenEndpoints := map[string]bool{}
		var childWg sync.WaitGroup
		for i, l := range links {
			parsed, _ := url.Parse(l)
			if parsed == nil || parsed.Path == "" || parsed.Host == "" {
				continue
			}
			lLower := strings.ToLower(parsed.Path)
			if isStaticAsset(lLower) {
				continue
			}
			if isSkipped(l, skipList) {
				c.log("│  ├─ [%d] %s [SKIPPED]\n", i+1, parsed.Path)
				continue
			}

			if !c.inScope(l) {
				c.log("│  ├─ [%d] %s [OUT OF SCOPE]\n", i+1, parsed.Host+parsed.Path)
				continue
			}

			endpointKey := parsed.Host + parsed.Path
			if parsed.RawQuery != "" {
				var paramNames []string
				for key := range parsed.Query() {
					paramNames = append(paramNames, key)
				}
				sort.Strings(paramNames) 
				endpointKey += "?" + strings.Join(paramNames, "&")
			}
			if seenEndpoints[endpointKey] {
				continue
			}
			seenEndpoints[endpointKey] = true

			c.log("│  ├─ [%d] %s\n", i+1, parsed.Path)
			if parsed.Scheme != "" && parsed.Host != "" {
				c.writeLine(parsed.Scheme + "://" + parsed.Host + parsed.Path)
			}

			if parsed.RawQuery != "" {
				for key, vals := range parsed.Query() {
					c.log("│  │  └─ param: %s=%s\n", key, vals[0])
				}
				if parsed.Scheme != "" && parsed.Host != "" {
					c.writeLine(parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + parsed.RawQuery)
				}
			}

			if recurs && depr < depth && !c.isVisited(l) {
				childWg.Add(1)
				sem <- struct{}{}
				go c.pars(ctx, l, recurs, depr+1, depth, skipList, &childWg, sem)
			}
		}
		childWg.Wait()
	}
}

func isStaticAsset(path string) bool {
	staticExts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
		".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz",
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func subdomainEnum(hostname string, crawlFile *os.File, term io.Writer) []string {
	fmt.Fprintln(term, "\n"+strings.Repeat("=", 60))
	fmt.Fprintf(term, "[PHASE 0] SUBDOMAIN ENUMERATION: %s\n", hostname)
	fmt.Fprintln(term, strings.Repeat("=", 60))

	cmd := exec.Command("subfinder", "-d", hostname, "-silent")
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(term, "[ERROR] subfinder failed: %v\n", err)
		fmt.Fprintln(term, "[WARN] Make sure subfinder is installed: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
		return nil
	}

	var found []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		sub := strings.TrimSpace(line)
		if sub == "" {
			continue
		}
		found = append(found, sub)
	}

	if len(found) == 0 {
		fmt.Fprintln(term, "├─ No subdomains found")
		fmt.Fprintln(term, "└─ Phase 0 complete")
		return nil
	}

	fmt.Fprintf(term, "├─ Found %d subdomains:\n", len(found))
	for _, sub := range found {
		fmt.Fprintf(term, "│  ├─ %s\n", sub)
		fmt.Fprintf(crawlFile, "https://%s/\n", sub)
	}
	fmt.Fprintln(term, "└─ Phase 0 complete, subdomains added to crawl file")

	return found
}

type JSEndpoint struct {
	URL    string
	Params []string
	Source string
}

var (
	reStrPath = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-/]{2,}(?:\?[a-zA-Z0-9_\-=&]*)?)["']`)
	reFetchQuoted   = regexp.MustCompile("(?:fetch|axios\\.(?:get|post|put|patch|delete)|http\\.(?:get|post|put|patch|delete))\\s*\\(\\s*[\"']([^\"'`]+)[\"']")
	reFetchTemplate = regexp.MustCompile("(?:fetch|axios\\.(?:get|post|put|patch|delete)|http\\.(?:get|post|put|patch|delete))\\s*\\(\\s*`([^`]+)`")
	reXHR           = regexp.MustCompile(`\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']`)
	reParam         = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_]*)=`)
	reTemplateVar   = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_.]*)\}`)
	reAPIVar = regexp.MustCompile(`(?:apiUrl|endpoint|baseURL|apiPath|path)\s*=\s*["']([^"']+)["']`)
)

func extractParams(path string) []string {
	matches := reParam.FindAllStringSubmatch(path, -1)
	seen := map[string]bool{}
	var params []string
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			params = append(params, m[1])
		}
	}
	return params
}

func parseJSBody(body, sourceURL string, base *url.URL) []JSEndpoint {
	seen := map[string]bool{}
	var results []JSEndpoint

	addEndpoint := func(rawPath, src string) {
		ref, err := url.Parse(rawPath)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref).String()
		if seen[resolved] {
			return
		}
		lower := strings.ToLower(resolved)
		for _, ext := range []string{".png", ".jpg", ".gif", ".svg", ".css", ".woff", ".ico", "data:"} {
			if strings.Contains(lower, ext) {
				return
			}
		}
		seen[resolved] = true
		params := extractParams(rawPath)
		results = append(results, JSEndpoint{URL: resolved, Params: params, Source: src})
	}

	for _, m := range reFetchQuoted.FindAllStringSubmatch(body, -1) {
		addEndpoint(m[1], "fetch/axios")
	}
	for _, m := range reFetchTemplate.FindAllStringSubmatch(body, -1) {
		raw := m[1]
		varMatches := reTemplateVar.FindAllStringSubmatch(raw, -1)
		var extraParams []string
		for _, vm := range varMatches {
			name := vm[1]
			if idx := strings.IndexAny(name, ".("); idx != -1 {
				name = name[:idx]
			}
			if name != "" {
				extraParams = append(extraParams, name)
			}
		}
		clean := reTemplateVar.ReplaceAllString(raw, "1")
		ref, err := url.Parse(clean)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref).String()
		lower := strings.ToLower(resolved)
		skip := false
		for _, ext := range []string{".png", ".jpg", ".gif", ".svg", ".css", ".woff", ".ico", "data:"} {
			if strings.Contains(lower, ext) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		params := extractParams(clean)
		seen2 := map[string]bool{}
		for _, p := range params {
			seen2[p] = true
		}
		for _, p := range extraParams {
			if !seen2[p] {
				seen2[p] = true
				params = append(params, p)
			}
		}
		key := resolved
		if !seen[key] {
			seen[key] = true
			results = append(results, JSEndpoint{URL: resolved, Params: params, Source: "fetch/template"})
		}
	}
	for _, m := range reXHR.FindAllStringSubmatch(body, -1) {
		addEndpoint(m[1], "XHR")
	}
	for _, m := range reStrPath.FindAllStringSubmatch(body, -1) {
		addEndpoint(m[1], "string")
	}

	for _, m := range reAPIVar.FindAllStringSubmatch(body, -1) {
		addEndpoint(m[1], "apiVar")
	}

	return results
}

func (c *Crawler) scanJS(term io.Writer, file io.Writer) {
	fmt.Fprintln(term, "\n"+strings.Repeat("═", 60))
	fmt.Fprintln(term, "  JS PARSER STARTED")
	fmt.Fprintln(term, strings.Repeat("═", 60))

	if len(c.visitedPages) == 0 {
		fmt.Fprintln(term, "└─ No pages to scan")
		return
	}

	type jsSource struct {
		body    string
		pageURL string
		srcURL  string
	}
	var jsSources []jsSource
	seenScripts := map[string]bool{}

	for _, pageURL := range c.visitedPages {
		<-c.limiter
		req, err := http.NewRequest("GET", pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")
		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		base, err := url.Parse(pageURL)
		if err != nil {
			continue
		}

		doc, err := html.Parse(strings.NewReader(string(body)))
		if err != nil {
			continue
		}

		var walkScripts func(*html.Node)
		walkScripts = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "script" {
				for _, attr := range n.Attr {
					if attr.Key == "src" && attr.Val != "" {
						ref, err := url.Parse(attr.Val)
						if err != nil {
							continue
						}
						scriptURL := base.ResolveReference(ref).String()
						if seenScripts[scriptURL] {
							break
						}
						seenScripts[scriptURL] = true
						<-c.limiter
						sr, err := c.client.Get(scriptURL)
						if err != nil {
							break
						}
						sb, err := io.ReadAll(io.LimitReader(sr.Body, 5*1024*1024))
						sr.Body.Close()
						if err != nil {
							break
						}
						jsSources = append(jsSources, jsSource{body: string(sb), pageURL: pageURL, srcURL: scriptURL})
						break
					}
				}
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					inline := strings.TrimSpace(n.FirstChild.Data)
					if inline != "" {
						key := pageURL + "#inline" + fmt.Sprintf("%d", len(jsSources))
						if !seenScripts[key] {
							seenScripts[key] = true
							jsSources = append(jsSources, jsSource{body: inline, pageURL: pageURL, srcURL: "inline"})
						}
					}
				}
			}
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				walkScripts(child)
			}
		}
		walkScripts(doc)
	}

	fmt.Fprintf(term, "├─ JS files/blocks found: %d\n", len(jsSources))

	if len(jsSources) == 0 {
		fmt.Fprintln(term, "└─ No JS to analyze")
		return
	}

	allEndpoints := map[string]JSEndpoint{}
	for _, js := range jsSources {
		base, _ := url.Parse(js.pageURL)
		endpoints := parseJSBody(js.body, js.srcURL, base)
		for _, ep := range endpoints {
			allEndpoints[ep.URL] = ep
		}
	}

	if len(allEndpoints) == 0 {
		fmt.Fprintln(term, "└─ No endpoints found in JS")
		return
	}

	fmt.Fprintf(term, "├─ Endpoints found: %d\n", len(allEndpoints))
	fmt.Fprintln(term, "│")
	fmt.Fprintf(term, "│  %-70s %-14s %s\n", "ENDPOINT", "SOURCE", "PARAMS")
	fmt.Fprintf(term, "│  %s\n", strings.Repeat("─", 100))

	for _, ep := range allEndpoints {
		params := "-"
		if len(ep.Params) > 0 {
			params = strings.Join(ep.Params, ", ")
		}
		fmt.Fprintf(term, "│  %-70s %-14s %s\n", ep.URL, ep.Source, params)
		fmt.Fprintln(file, ep.URL)
		if len(ep.Params) > 0 {
			if !strings.Contains(ep.URL, "?") {
				paramStr := make([]string, len(ep.Params))
				for i, p := range ep.Params {
					paramStr[i] = p + "=1"
				}
				fmt.Fprintln(file, ep.URL+"?"+strings.Join(paramStr, "&"))
			}
		}
	}

	fmt.Fprintln(term, "│")
	fmt.Fprintln(term, "└─ JS parse complete")
}

func main() {
	targetURL := flag.String("u", "", "Target URL to crawl")
	recursive := flag.Bool("r", false, "Enable recursive crawling")
	maxDepth := flag.Int("rd", 0, "Maximum recursion depth")
	pentest := flag.Bool("ps", false, "Run pentest scan after crawl")
	subdomains := flag.Bool("sd", false, "Enable subdomain enumeration before crawl (requires subfinder)")
	rateLimit := flag.Int("rate", 10, "Requests per second (rate limit)")
	concurrency := flag.Int("c", 5, "Max concurrent goroutines for crawling")
	ignoreRobots := flag.Bool("ignore-robots", false, "Ignore robots.txt restrictions")
	sqlmapLevel := flag.Int("sqlmap-level", 0, "SQLMap starting level (1-5), 0 = auto")
	sqlmapRisk := flag.Int("sqlmap-risk", 0, "SQLMap starting risk (1-3), 0 = auto")
	cookie := flag.String("cookie", "", "Cookie header for authenticated scanning (e.g. 'session=abc123')")
	burpFile := flag.String("burp", "", "Path to Burp request file for SQLMap (-r flag)")
	skipFlag := flag.String("skip", "", "Comma-separated list of path patterns to skip")
	skipPhases := flag.String("skip-phase", "", "Comma-separated phases to skip (0=Subdomains,1=SQLi,2=NUCLEI,3=SQLMap,4=XSS,5=Headers)")
	crawlTimeout := flag.Int("timeout", 0, "Total crawl timeout in minutes (0 = no limit)")
	flag.Parse()

	if *targetURL == "" {
		fmt.Println("ERROR: please provide URL with -u flag")
		fmt.Println("Usage: ./luska -u <URL> [-r] [-rd <depth>] [-ps] [-sd] [-rate <n>] [-c <n>] [-ignore-robots] [-sqlmap-level <1-5>] [-sqlmap-risk <1-3>] [-skip <patterns>] [-skip-phase <phases>] [-timeout <minutes>]")
		fmt.Println("\nFlags:")
		fmt.Println("  -rate          Requests per second (default: 10)")
		fmt.Println("  -c             Concurrent crawl goroutines (default: 5)")
		fmt.Println("  -ignore-robots Skip robots.txt restrictions")
		fmt.Println("  -sqlmap-level  SQLMap starting level 1-5 (default: auto)")
		fmt.Println("  -sqlmap-risk   SQLMap starting risk 1-3 (default: auto)")
		fmt.Println("  -cookie        Cookie for authenticated scanning (e.g. 'session=abc123')")
		fmt.Println("  -burp          Path to Burp request file for SQLMap")
		fmt.Println("  -timeout       Total crawl timeout in minutes (default: no limit)")
		fmt.Println("\nPhases:")
		fmt.Println("  0 = Subdomain Enumeration (subfinder)")
		fmt.Println("  1 = Quick SQLi Test")
		fmt.Println("  2 = NUCLEI Template Scan")
		fmt.Println("  3 = SQLMap Deep Scan")
		fmt.Println("  4 = Dalfox XSS Scan")
		fmt.Println("  5 = Header & Cookie Analysis")
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

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("[*] CRAWLING STARTED: %s\n", *targetURL)
	fmt.Printf("[*] RATE LIMIT: %d req/s | CONCURRENCY: %d\n", *rateLimit, *concurrency)
	if len(skipList) > 0 {
		fmt.Printf("[*] SKIPPING PATTERNS: %s\n", strings.Join(skipList, ", "))
	}
	if *crawlTimeout > 0 {
		fmt.Printf("[*] TIMEOUT: %d minutes\n", *crawlTimeout)
	}
	fmt.Println(strings.Repeat("=", 60))

	if *subdomains {
		subdomainEnum(parsed.Hostname(), f, os.Stdout)
	}

	crawler := newCrawler(*rateLimit, os.Stdout, f, parsed.Host)
	defer crawler.stop()

	if !*ignoreRobots {
		crawler.fetchRobots(parsed)
	} else {
		fmt.Println("[*] robots.txt ignored")
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if *crawlTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(*crawlTimeout)*time.Minute)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	wg.Add(1)
	sem <- struct{}{}
	go crawler.pars(ctx, *targetURL, *recursive, 0, *maxDepth, skipList, &wg, sem)
	wg.Wait()

	crawler.scanJS(os.Stdout, f)

	f.Sync()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("[+] CRAWL COMPLETE: %s\n", crawlPath)
	fmt.Println(strings.Repeat("=", 60))

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

		

		cmd := exec.Command("./pentest", pentestArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[ERROR] Pentest failed: %v\n", err)
		}
	}
}