package modules

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"IluskaX/internal/ui"
)

var redirectParamNames = map[string]bool{
	"next": true, "url": true, "redirect": true, "redirect_url": true,
	"return": true, "return_url": true, "continue": true, "callback": true,
	"dest": true, "destination": true, "to": true, "target": true,
}

func OpenRedirectScan(urls []string, w io.Writer, cookie string, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 6] OPEN REDIRECT CHECK")

	type candidate struct {
		raw   string
		param string
	}

	seen := map[string]bool{}
	var candidates []candidate
	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		for name := range parsed.Query() {
			if !redirectParamNames[strings.ToLower(name)] {
				continue
			}
			key := parsed.Scheme + "://" + parsed.Host + parsed.Path + "|" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, candidate{raw: raw, param: name})
		}
	}

	if len(candidates) == 0 {
		fmt.Fprintln(w, "└─ No redirect-like parameters found, skipping")
		return
	}

	limit := len(candidates)
	if limit > 60 {
		limit = 60
	}
	if sb != nil {
		sb.SetPhase("OPEN REDIRECT", int64(limit))
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	payload := "https://example.com/iluska-redirect-check"
	found := 0

	for i, c := range candidates[:limit] {
		testURL := injectSingleParam(c.raw, c.param, payload)
		if sb != nil {
			sb.Log("├─ [%d/%d] %s\n", i+1, limit, ui.Truncate(testURL, ui.MaxURLLen))
		} else {
			fmt.Fprintf(w, "├─ [%d/%d] %s\n", i+1, limit, testURL)
		}

		if limiter != nil {
			<-limiter
		}
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		ApplyHeaders(req, cookie)
		resp, err := client.Do(req)
		if err != nil {
			if sb != nil {
				sb.Tick(1)
			}
			continue
		}
		resp.Body.Close()

		location := resp.Header.Get("Location")
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(strings.ToLower(location), "https://example.com/iluska-redirect-check") {
			found++
			fmt.Fprintf(w, "│  [OPEN REDIRECT] param=%s status=%d location=%s\n", c.param, resp.StatusCode, location)
			if rc != nil {
				rc.AddFinding(ui.Finding{
					Type:     ui.VulnRedirect,
					Level:    ui.LevelVulnerability,
					URL:      c.raw,
					Payload:  c.param + "=" + payload,
					Detail:   fmt.Sprintf("HTTP %d Location: %s", resp.StatusCode, location),
					Severity: "high",
				})
			}
		}
		if sb != nil {
			sb.Tick(1)
		}
	}

	if found == 0 {
		fmt.Fprintln(w, "├─ Status: No open redirects detected")
	} else {
		fmt.Fprintf(w, "├─ %s\n", ui.Red(fmt.Sprintf("[ALERT] Found %d possible open redirects", found)))
	}
	fmt.Fprintln(w, "└─ Open redirect check complete")
}

func injectSingleParam(rawURL, param, payload string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
