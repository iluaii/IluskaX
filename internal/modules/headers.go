package modules

import (
	"IluskaX/internal/ui"
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

func HeaderCookieScan(urls []string, w io.Writer, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 5] HEADER & COOKIE ANALYSIS")
	fmt.Fprintf(w, "├─ Scanning %d URLs\n", len(urls))

	client := &http.Client{Timeout: 10 * time.Second}
	uniqueURLs := uniqueHosts(urls)
	totalAlerts := 0
	totalRecommendations := 0

	if sb != nil {
		sb.SetPhase("HEADERS", int64(len(uniqueURLs)))
	}

	for i, targetURL := range uniqueURLs {
		if sb != nil {
			sb.Log("├─ [%d/%d] %s\n", i+1, len(uniqueURLs), ui.Truncate(targetURL, ui.MaxURLLen))
		} else {
			fmt.Fprintf(w, "├─ [%d/%d] %s\n", i+1, len(uniqueURLs), targetURL)
		}

		<-limiter
		req, _ := http.NewRequest("GET", targetURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(w, "│  [ERROR] %v\n", err)
			if sb != nil {
				sb.Tick(1)
			}
			continue
		}
		resp.Body.Close()

		totalRecommendations += checkMissingHeaders(resp, w, targetURL, rc)
		totalAlerts += checkCSP(resp, w, targetURL, rc)
		totalAlerts += checkCORS(resp, w, targetURL, rc)
		totalAlerts += checkHSTS(resp, w, targetURL, rc)
		totalRecommendations += printServerInfo(resp, w, targetURL, rc)
		totalAlerts += checkCookies(resp, w, targetURL, rc)

		if sb != nil {
			sb.Tick(1)
		}
	}

	if totalAlerts > 0 {
		msg := fmt.Sprintf("├─ %s\n", ui.Red(fmt.Sprintf("[ALERT] Total security issues found: %d", totalAlerts)))
		if sb != nil {
			sb.Log("%s", msg)
		} else {
			fmt.Fprint(w, msg)
		}
	} else {
		msg := "├─ " + ui.Green("No exploitable header/cookie issues detected") + "\n"
		if sb != nil {
			sb.Log("%s", msg)
		} else {
			fmt.Fprint(w, msg)
		}
	}
	if totalRecommendations > 0 {
		msg := fmt.Sprintf("├─ %s\n", ui.Yellow(fmt.Sprintf("[INFO] Recommendations / info findings: %d", totalRecommendations)))
		if sb != nil {
			sb.Log("%s", msg)
		} else {
			fmt.Fprint(w, msg)
		}
	}
	if sb != nil {
		sb.Log("└─ Header & Cookie scan complete\n")
	} else {
		fmt.Fprintln(w, "└─ Header & Cookie scan complete")
	}
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

func checkMissingHeaders(resp *http.Response, w io.Writer, targetURL string, rc *ui.ReportCollector) int {
	issues := 0 // Создаем локальный счетчик
	var missing []string
	for _, h := range securityHeaders {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h)
			issues++
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(w, "│  [HEADERS] Missing %d security headers\n", len(missing))
		return issues
	}
	return 0
}

func checkCSP(resp *http.Response, w io.Writer, targetURL string, rc *ui.ReportCollector) int {
	issues := 0
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		return 0
	}
	if strings.Contains(csp, "'unsafe-inline'") {
		fmt.Fprintf(w, "│  [WARN] CSP contains 'unsafe-inline'\n")
		if rc != nil {
			rc.AddFinding(ui.Finding{Type: ui.VulnHeader, Level: ui.LevelWarning, URL: targetURL, Payload: "CSP: unsafe-inline", Detail: "weak CSP"})
		}
		issues++
	}
	if strings.Contains(csp, "'unsafe-eval'") {
		fmt.Fprintf(w, "│  [WARN] CSP contains 'unsafe-eval'\n")
		if rc != nil {
			rc.AddFinding(ui.Finding{Type: ui.VulnHeader, Level: ui.LevelWarning, URL: targetURL, Payload: "CSP: unsafe-eval", Detail: "weak CSP"})
		}
		issues++
	}
	return issues
}

func checkCORS(resp *http.Response, w io.Writer, targetURL string, rc *ui.ReportCollector) int {
	if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
		fmt.Fprintf(w, "│  [WARN] CORS wildcard (*) — any origin allowed\n")
		if rc != nil {
			rc.AddFinding(ui.Finding{Type: ui.VulnHeader, Level: ui.LevelWarning, URL: targetURL, Payload: "CORS: Access-Control-Allow-Origin: *", Detail: "wildcard CORS"})
		}
		return 1
	}
	return 0
}

func checkHSTS(resp *http.Response, w io.Writer, targetURL string, rc *ui.ReportCollector) int {
	issues := 0
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		return 0
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		fmt.Fprintf(w, "│  [WARN] HSTS missing 'includeSubDomains'\n")
		if rc != nil {
			rc.AddFinding(ui.Finding{Type: ui.VulnHeader, Level: ui.LevelWarning, URL: targetURL, Payload: "HSTS: missing includeSubDomains", Detail: "weak HSTS"})
		}
		issues++
	}
	if !strings.Contains(hsts, "max-age") {
		fmt.Fprintf(w, "│  [WARN] HSTS missing 'max-age'\n")
		if rc != nil {
			rc.AddFinding(ui.Finding{Type: ui.VulnHeader, Level: ui.LevelWarning, URL: targetURL, Payload: "HSTS: missing max-age", Detail: "weak HSTS"})
		}
		issues++
	}
	return issues
}

func printServerInfo(resp *http.Response, w io.Writer, targetURL string, rc *ui.ReportCollector) int {
	recommendations := 0
	if server := resp.Header.Get("Server"); server != "" {
		fmt.Fprintf(w, "│  [INFO] Server: %s\n", server)
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		fmt.Fprintf(w, "│  [INFO] X-Powered-By: %s %s\n", powered, ui.Yellow("(information disclosure)"))
		if rc != nil {
			rc.AddFinding(ui.Finding{Type: ui.VulnHeader, Level: ui.LevelInfo, URL: targetURL, Payload: "X-Powered-By: " + powered, Detail: "info disclosure"})
		}
		recommendations++
	}
	return recommendations
}

func checkCookies(resp *http.Response, w io.Writer, targetURL string, rc *ui.ReportCollector) int {
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
			issue := strings.Join(probs, ", ")
			fmt.Fprintf(w, "│  [COOKIE] %s → %s\n", c.Name, ui.Yellow(issue))
			if rc != nil {
				rc.AddFinding(ui.Finding{
					Type:    ui.VulnCookie,
					Level:   ui.LevelWarning,
					URL:     targetURL,
					Payload: c.Name + ": " + issue,
					Detail:  "insecure cookie",
				})
			}
			issues += len(probs)
		} else {
			fmt.Fprintf(w, "│  [COOKIE] %s %s\n", c.Name, ui.Green("✓ Secure"))
		}
	}
	return issues
}
