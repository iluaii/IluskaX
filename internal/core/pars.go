package core

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/html"

	"IluskaX/internal/ui"
)

func (c *Crawler) TryMarkVisited(uri string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visited[uri] {
		return false
	}
	c.visited[uri] = true
	return true
}
func (c *Crawler) Pars(
	ctx context.Context,
	uri string,
	recurs bool,
	depr, depth int,
	skipList []string,
	wg *sync.WaitGroup,
	sem chan struct{},
	rc *ui.ReportCollector,
	sb *ui.StatusBar,
) {
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

	if !c.TryMarkVisited(uri) {
		return
	}
	c.mu.Lock()
	c.VisitedPages = append(c.VisitedPages, uri)
	c.mu.Unlock()

	if rc != nil {
		rc.AddSitemapURL(uri)
	}

	if parsed0, err := url.Parse(uri); err == nil && parsed0.Path == "" {
		parsed0.Path = "/"
		uri = parsed0.String()
	}

	if c.IsDisallowed(uri) {
		c.Log("  [ROBOTS] Skipped disallowed: %s\n", uri)
		return
	}

	resp, err := c.Fetch(ctx, uri)
	if err != nil {
		c.Log("  [ERROR] Failed to fetch %s: %v\n", uri, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.Log("  [WARN] HTTP %d: %s\n", resp.StatusCode, uri)
	}

	doc, err := html.Parse(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		c.Log("  [ERROR] Failed to parse HTML: %v\n", err)
		return
	}

	base, err := url.Parse(uri)
	if err != nil {
		c.Log("  [ERROR] Invalid URL: %v\n", err)
		return
	}

	var links []string
	var forms []Form
	Traverse(doc, base, &links, &forms)

	if sb != nil {
		sb.Log("\n[CRAWL] %s (Depth: %d)\n", ui.Truncate(base.Path, 80), depr)
		sb.Log("├─ Status: %d, Forms: %d, Links: %d\n", resp.StatusCode, len(forms), len(links))
		sb.Tick(1)
	} else {
		c.Log("\n[CRAWL] %s (Depth: %d)\n", base.Path, depr)
		c.Log("├─ Status: %d, Forms: %d, Links: %d\n", resp.StatusCode, len(forms), len(links))
	}

	c.writeForms(forms)
	c.writeLinks(ctx, links, base, recurs, depr, depth, skipList, wg, sem, rc, sb)
}

func (c *Crawler) writeForms(forms []Form) {
	if len(forms) == 0 {
		return
	}
	c.Log("├─ FORMS:\n")
	for i, f := range forms {
		c.Log("│  ├─ [%d] %s %s\n", i+1, f.Method, f.Action)
		var params []string
		for _, inp := range f.Inputs {
			parts := strings.Split(inp, "=")
			c.Log("│  │  ├─ %s\n", inp)
			if len(parts) > 1 {
				params = append(params, parts[1]+"=1")
			}
		}
		if len(params) > 0 {
			if f.Method == "POST" {
				c.WriteLine("POST|" + f.Action + "|" + strings.Join(params, "&"))
			} else {
				connector := "?"
				if strings.Contains(f.Action, "?") {
					connector = "&"
				}
				c.WriteLine(f.Action + connector + strings.Join(params, "&"))
			}
		}
	}
}

func (c *Crawler) writeLinks(
	ctx context.Context,
	links []string,
	base *url.URL,
	recurs bool,
	depr, depth int,
	skipList []string,
	wg *sync.WaitGroup,
	sem chan struct{},
	rc *ui.ReportCollector,
	sb *ui.StatusBar,
) {
	if len(links) == 0 {
		return
	}
	c.Log("├─ LINKS:\n")
	seenEndpoints := map[string]bool{}
	var childWg sync.WaitGroup

	for i, l := range links {
		parsed, _ := url.Parse(l)
		if parsed == nil || parsed.Path == "" || parsed.Host == "" {
			continue
		}
		lLower := strings.ToLower(parsed.Path)
		if IsStaticAsset(lLower) {
			continue
		}
		if IsSkipped(l, skipList) {
			c.Log("│  ├─ [%d] %s [SKIPPED]\n", i+1, ui.Truncate(parsed.Path, 60))
			continue
		}
		if !c.InScope(l) {
			c.Log("│  ├─ [%d] %s [OUT OF SCOPE]\n", i+1, ui.Truncate(parsed.Host+parsed.Path, 60))
			continue
		}

		endpointKey := dedupeKey(parsed)
		if seenEndpoints[endpointKey] {
			continue
		}
		seenEndpoints[endpointKey] = true

		c.Log("│  ├─ [%d] %s\n", i+1, ui.Truncate(parsed.Path, 70))
		if parsed.Scheme != "" && parsed.Host != "" {
			fullURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)
			c.WriteLine(fullURL)
			if rc != nil {
				rc.AddSitemapURL(fullURL)
			}
		}
		if parsed.RawQuery != "" {
			for key, vals := range parsed.Query() {
				c.Log("│  │  └─ param: %s=%s\n", key, ui.Truncate(vals[0], 40))
			}
			if parsed.Scheme != "" && parsed.Host != "" {
				withQuery := fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, parsed.RawQuery)
				c.WriteLine(withQuery)
				if rc != nil {
					rc.AddSitemapURL(withQuery)
				}
			}
		}

		if recurs && depr < depth {
			normalized := l
			if p2, err := url.Parse(l); err == nil {
				p2.Fragment = ""
				normalized = p2.String()
			}
			c.mu.Lock()
			alreadyVisited := c.visited[normalized]
			if !alreadyVisited {
				c.visited[normalized] = true
			}
			c.mu.Unlock()
			if !alreadyVisited {
				childWg.Add(1)
				sem <- struct{}{}
				go c.Pars(ctx, normalized, recurs, depr+1, depth, skipList, &childWg, sem, rc, sb)
			}
		}
	}
	childWg.Wait()
}

func dedupeKey(parsed *url.URL) string {
	key := parsed.Host + parsed.Path
	if parsed.RawQuery != "" {
		var names []string
		for k := range parsed.Query() {
			names = append(names, k)
		}
		sort.Strings(names)
		key += "?" + strings.Join(names, "&")
	}
	return key
}