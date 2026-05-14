package modules

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"IluskaX/internal/core"
	"IluskaX/internal/ui"

	"golang.org/x/net/html"
)

type jsSecretSource struct {
	url  string
	body string
}

func JSSecretScan(urls []string, w io.Writer, cookie string, limiter <-chan time.Time, guard *core.ScopeGuard, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 3] JAVASCRIPT SECRET SCANNER")

	pages := uniqueHTTPURLs(urls)
	if len(pages) == 0 {
		fmt.Fprintln(w, "└─ No URLs found, skipping")
		return
	}
	if sb != nil {
		sb.SetPhase("JS SECRETS", int64(len(pages)))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	seenScripts := map[string]bool{}
	seenFindings := map[string]bool{}
	totalSources := 0
	totalSecrets := 0

	for i, pageURL := range pages {
		if guard != nil && !guard.InScope(pageURL) {
			continue
		}
		if sb != nil {
			sb.Log("├─ [%d/%d] %s\n", i+1, len(pages), ui.Truncate(pageURL, ui.MaxURLLen))
		}

		body, contentType, err := fetchLimited(client, pageURL, cookie, limiter, 5*1024*1024)
		if err != nil {
			if sb != nil {
				sb.Tick(1)
			}
			continue
		}

		sources := []jsSecretSource{}
		if looksJavaScriptURL(pageURL) || strings.Contains(strings.ToLower(contentType), "javascript") {
			sources = append(sources, jsSecretSource{url: pageURL, body: body})
		} else {
			if looksSecretBearingResponse(pageURL, contentType, body) {
				sources = append(sources, jsSecretSource{url: pageURL, body: body})
			}
			sources = append(sources, extractJSSources(client, pageURL, body, cookie, limiter, guard, seenScripts)...)
		}

		for _, source := range sources {
			totalSources++
			for _, secret := range core.FindSecrets(source.body, source.url) {
				key := secret.Kind + "|" + secret.Source + "|" + secret.Match
				if seenFindings[key] {
					continue
				}
				seenFindings[key] = true
				totalSecrets++
				fmt.Fprintf(w, "│  [SECRET] %-20s %s\n", secret.Kind, ui.Truncate(secret.Source, ui.MaxURLLen))
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:    ui.VulnSecret,
						Level:   secret.Level,
						URL:     secret.Source,
						Payload: secret.Kind,
						Detail:  secret.Match + " | " + secret.Detail,
					})
				}
			}
		}

		if sb != nil {
			sb.Tick(1)
		}
	}

	if totalSecrets == 0 {
		fmt.Fprintf(w, "├─ Scanned JS sources: %d\n", totalSources)
		fmt.Fprintln(w, "├─ Status: No JavaScript secrets detected")
	} else {
		fmt.Fprintf(w, "├─ Scanned JS sources: %d\n", totalSources)
		fmt.Fprintf(w, "├─ Secrets found: %d\n", totalSecrets)
	}
	fmt.Fprintln(w, "└─ JavaScript secret scan complete")
}

func extractJSSources(client *http.Client, pageURL, body, cookie string, limiter <-chan time.Time, guard *core.ScopeGuard, seenScripts map[string]bool) []jsSecretSource {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var sources []jsSecretSource
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			src := attrValue(n, "src")
			if src != "" {
				if ref, err := url.Parse(src); err == nil {
					scriptURL := base.ResolveReference(ref).String()
					if (guard == nil || guard.InScope(scriptURL)) && !seenScripts[scriptURL] {
						seenScripts[scriptURL] = true
						if scriptBody, _, err := fetchLimited(client, scriptURL, cookie, limiter, 2*1024*1024); err == nil {
							sources = append(sources, jsSecretSource{url: scriptURL, body: scriptBody})
						}
					}
				}
			}
			if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				inline := strings.TrimSpace(n.FirstChild.Data)
				if inline != "" {
					sources = append(sources, jsSecretSource{url: pageURL + "#inline", body: inline})
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return sources
}

func fetchLimited(client *http.Client, targetURL, cookie string, limiter <-chan time.Time, maxBytes int64) (string, string, error) {
	if limiter != nil {
		<-limiter
	}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", "", err
	}
	ApplyHeaders(req, cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", resp.Header.Get("Content-Type"), err
	}
	return string(body), resp.Header.Get("Content-Type"), nil
}

func uniqueHTTPURLs(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range urls {
		if strings.HasPrefix(raw, "POST|") {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}
		parsed.Fragment = ""
		normalized := parsed.String()
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func attrValue(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}
	return ""
}

func looksJavaScriptURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(parsed.Path), ".js")
}

func looksSecretBearingResponse(raw, contentType, body string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.Contains(ct, "text/plain") {
		return true
	}
	parsed, err := url.Parse(raw)
	if err == nil && strings.Contains(strings.ToLower(parsed.Path), "/api/") && !strings.Contains(ct, "text/html") {
		return true
	}
	trimmed := strings.TrimSpace(body)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}
