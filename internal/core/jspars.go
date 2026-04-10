package core

import (
	"IluskaX/internal/ui"
	"context"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"net/url"
	"regexp"
	"strings"
)

type JSEndpoint struct {
	URL    string
	Params []string
	Source string
}

var (
	reStrPath     = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-/]{2,}(?:\?[a-zA-Z0-9_\-=&]*)?)["']`)
	reFetchQuoted = regexp.MustCompile("(?:fetch|axios\\.(?:get|post|put|patch|delete)|http\\.(?:get|post|put|patch|delete))\\s*\\(\\s*[\"']([^\"'`]+)[\"']")
	reFetchTmpl   = regexp.MustCompile("(?:fetch|axios\\.(?:get|post|put|patch|delete)|http\\.(?:get|post|put|patch|delete))\\s*\\(\\s*`([^`]+)`")
	reXHR         = regexp.MustCompile(`\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']`)
	reParam       = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_]*)=`)
	reTemplateVar = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_.]*)\}`)
	reAPIVar      = regexp.MustCompile(`(?:apiUrl|endpoint|baseURL|apiPath|path)\s*=\s*["']([^"']+)["']`)

	jsSkipExts = []string{".png", ".jpg", ".gif", ".svg", ".css", ".woff", ".ico", "data:"}
)

func (c *Crawler) ScanJS(term io.Writer, file io.Writer, rc *ui.ReportCollector, sb *ui.StatusBar) {
	logf := func(format string, args ...interface{}) {
		if sb != nil {
			sb.Log(format, args...)
		} else {
			fmt.Fprintf(term, format, args...)
		}
	}

	logf("%s\n  JS PARSER STARTED\n%s\n", strings.Repeat("═", 60), strings.Repeat("═", 60))

	if len(c.VisitedPages) == 0 {
		logf("└─ No pages to scan\n")
		return
	}

	type jsSource struct {
		body    string
		pageURL string
		srcURL  string
	}
	var jsSources []jsSource
	seenScripts := map[string]bool{}

	for _, pageURL := range c.VisitedPages {
		resp, err := c.Fetch(context.Background(), pageURL)
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
							break
						}
						scriptURL := base.ResolveReference(ref).String()
						if seenScripts[scriptURL] {
							break
						}
						seenScripts[scriptURL] = true
						sr, err := c.Fetch(context.Background(), scriptURL)
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
						key := fmt.Sprintf("%s#inline%d", pageURL, len(jsSources))
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

	logf("├─ JS files/blocks found: %d\n", len(jsSources))
	if len(jsSources) == 0 {
		logf("%s\n", "└─ No JS to analyze")
		return
	}

	allEndpoints := map[string]JSEndpoint{}
	for _, js := range jsSources {
		base, _ := url.Parse(js.pageURL)
		for _, ep := range parseJSBody(js.body, js.srcURL, base) {
			allEndpoints[ep.URL] = ep
		}
	}

	if len(allEndpoints) == 0 {
		logf("%s\n", "└─ No endpoints found in JS")
		return
	}

	logf("├─ Endpoints found: %d\n", len(allEndpoints))
	logf("%s\n", "│")
	logf("│  %-70s %-14s %s\n", "ENDPOINT", "SOURCE", "PARAMS")
	logf("│  %s\n", strings.Repeat("─", 100))

	for _, ep := range allEndpoints {
		params := "-"
		if len(ep.Params) > 0 {
			params = strings.Join(ep.Params, ", ")
		}
		displayURL := ui.Truncate(ep.URL, 70)
		logf("│  %-70s %-14s %s\n", displayURL, ep.Source, ui.Truncate(params, 40))
		fmt.Fprintln(file, ep.URL)
		if rc != nil {
			rc.AddSitemapURL(ep.URL)
		}
		if len(ep.Params) > 0 && !strings.Contains(ep.URL, "?") {
			parts := make([]string, len(ep.Params))
			for i, p := range ep.Params {
				parts[i] = p + "=1"
			}
			withParams := ep.URL + "?" + strings.Join(parts, "&")
			fmt.Fprintln(file, withParams)
			if rc != nil {
				rc.AddSitemapURL(withParams)
			}
		}
	}

	logf("%s\n", "│")
	logf("%s\n", "└─ JS parse complete")
}

func parseJSBody(body, sourceURL string, base *url.URL) []JSEndpoint {
	seen := map[string]bool{}
	var results []JSEndpoint

	add := func(rawPath, src string) {
		ref, err := url.Parse(rawPath)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref).String()
		if seen[resolved] {
			return
		}
		lower := strings.ToLower(resolved)
		for _, ext := range jsSkipExts {
			if strings.Contains(lower, ext) {
				return
			}
		}
		seen[resolved] = true
		params := extractParams(rawPath)
		results = append(results, JSEndpoint{URL: resolved, Params: params, Source: src})
	}

	for _, m := range reFetchQuoted.FindAllStringSubmatch(body, -1) {
		add(m[1], "fetch/axios")
	}
	for _, m := range reFetchTmpl.FindAllStringSubmatch(body, -1) {
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
		if func() bool {
			lower := strings.ToLower(resolved)
			for _, ext := range jsSkipExts {
				if strings.Contains(lower, ext) {
					return true
				}
			}
			return false
		}() {
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
		if !seen[resolved] {
			seen[resolved] = true
			results = append(results, JSEndpoint{URL: resolved, Params: params, Source: "fetch/template"})
		}
	}
	for _, m := range reXHR.FindAllStringSubmatch(body, -1) {
		add(m[1], "XHR")
	}
	for _, m := range reStrPath.FindAllStringSubmatch(body, -1) {
		add(m[1], "string")
	}
	for _, m := range reAPIVar.FindAllStringSubmatch(body, -1) {
		add(m[1], "apiVar")
	}
	return results
}

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
