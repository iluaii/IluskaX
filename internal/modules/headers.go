package modules

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var securityHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"X-XSS-Protection",
	"Access-Control-Allow-Origin",
}

func HeaderCookieScan(urls []string, w io.Writer, limiter <-chan time.Time) {
	fmt.Fprintln(w, "\n┌─ [PHASE 5] HEADER & COOKIE ANALYSIS")
	fmt.Fprintf(w, "├─ Scanning %d URLs\n", len(urls))

	client := &http.Client{Timeout: 10 * time.Second}
	uniqueURLs := uniqueHosts(urls)
	totalIssues := 0

	for i, targetURL := range uniqueURLs {
		fmt.Fprintf(w, "├─ [%d/%d] %s\n", i+1, len(uniqueURLs), targetURL)

		<-limiter
		req, _ := http.NewRequest("GET", targetURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(w, "│  [ERROR] %v\n", err)
			continue
		}
		resp.Body.Close()

		totalIssues += checkMissingHeaders(resp, w)
		totalIssues += checkCSP(resp, w)
		totalIssues += checkCORS(resp, w)
		totalIssues += checkHSTS(resp, w)
		printServerInfo(resp, w, &totalIssues)
		totalIssues += checkCookies(resp, w)
	}

	if totalIssues > 0 {
		fmt.Fprintf(w, "├─ [ALERT] Total issues found: %d\n", totalIssues)
	} else {
		fmt.Fprintln(w, "├─ No header/cookie issues detected")
	}
	fmt.Fprintln(w, "└─ Header & Cookie scan complete")
}

func uniqueHosts(urls []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		host := parsed.Scheme + "://" + parsed.Host
		if !seen[host] {
			seen[host] = true
			result = append(result, host)
		}
	}
	return result
}

func checkMissingHeaders(resp *http.Response, w io.Writer) int {
	var missing []string
	for _, h := range securityHeaders {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(w, "│  [HEADERS] Missing %d security headers:\n", len(missing))
		for _, h := range missing {
			fmt.Fprintf(w, "│     ✗ %s\n", h)
		}
		return len(missing)
	}
	fmt.Fprintf(w, "│  [HEADERS] ✓ All security headers present\n")
	return 0
}

func checkCSP(resp *http.Response, w io.Writer) int {
	issues := 0
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		return 0
	}
	if strings.Contains(csp, "'unsafe-inline'") {
		fmt.Fprintf(w, "│  [WARN] CSP contains 'unsafe-inline'\n")
		issues++
	}
	if strings.Contains(csp, "'unsafe-eval'") {
		fmt.Fprintf(w, "│  [WARN] CSP contains 'unsafe-eval'\n")
		issues++
	}
	return issues
}

func checkCORS(resp *http.Response, w io.Writer) int {
	if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
		fmt.Fprintf(w, "│  [WARN] CORS wildcard (*) — any origin allowed\n")
		return 1
	}
	return 0
}

func checkHSTS(resp *http.Response, w io.Writer) int {
	issues := 0
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		return 0
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		fmt.Fprintf(w, "│  [WARN] HSTS missing 'includeSubDomains'\n")
		issues++
	}
	if !strings.Contains(hsts, "max-age") {
		fmt.Fprintf(w, "│  [WARN] HSTS missing 'max-age'\n")
		issues++
	}
	return issues
}

func printServerInfo(resp *http.Response, w io.Writer, issues *int) {
	if server := resp.Header.Get("Server"); server != "" {
		fmt.Fprintf(w, "│  [INFO] Server: %s\n", server)
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		fmt.Fprintf(w, "│  [INFO] X-Powered-By: %s (information disclosure)\n", powered)
		*issues++
	}
}

func checkCookies(resp *http.Response, w io.Writer) int {
	issues := 0
	if len(resp.Cookies()) == 0 {
		fmt.Fprintf(w, "│  [COOKIE] No cookies set\n")
		return 0
	}
	for _, c := range resp.Cookies() {
		var probs []string
		if !c.HttpOnly {
			probs = append(probs, "missing HttpOnly")
		}
		if !c.Secure {
			probs = append(probs, "missing Secure")
		}
		if c.SameSite == http.SameSiteDefaultMode || c.SameSite == 0 {
			probs = append(probs, "SameSite not set")
		}
		if c.Expires.IsZero() && c.MaxAge == 0 {
			probs = append(probs, "no expiry set")
		}
		if len(probs) > 0 {
			fmt.Fprintf(w, "│  [COOKIE] %s → %s\n", c.Name, strings.Join(probs, ", "))
			issues += len(probs)
		} else {
			fmt.Fprintf(w, "│  [COOKIE] %s ✓ Secure\n", c.Name)
		}
	}
	return issues
}
