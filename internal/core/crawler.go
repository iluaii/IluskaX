package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Crawler struct {
	mu           sync.Mutex
	visited      map[string]bool
	VisitedPages []string
	disallowed   []string
	ticker       *time.Ticker
	Limiter      <-chan time.Time
	Client       *http.Client
	Term         io.Writer
	File         io.Writer
	ScopeHost    string
}

func NewCrawler(ratePerSec int, term io.Writer, file io.Writer, scopeHost string) *Crawler {
	ticker := time.NewTicker(time.Second / time.Duration(ratePerSec))
	return &Crawler{
		visited: make(map[string]bool),
		ticker:  ticker,
		Limiter: ticker.C,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		Term:      term,
		File:      file,
		ScopeHost: scopeHost,
	}
}

func (c *Crawler) Stop() {
	c.ticker.Stop()
}

func (c *Crawler) InScope(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	host := strings.TrimPrefix(parsed.Host, "www.")
	scope := strings.TrimPrefix(c.ScopeHost, "www.")
	return host == scope
}

func (c *Crawler) IsVisited(uri string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.visited[uri]
}

func (c *Crawler) MarkVisited(uri string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.visited[uri] = true
}

func (c *Crawler) WriteLine(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintln(c.File, line)
}

func (c *Crawler) Log(format string, args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(c.Term, format, args...)
}

func (c *Crawler) FetchRobots(base *url.URL) {
	robotsURL := base.Scheme + "://" + base.Host + "/robots.txt"
	resp, err := c.Fetch(context.Background(), robotsURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	fmt.Fprintf(c.Term, "[ROBOTS] Fetched robots.txt from %s\n", base.Host)

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
				fmt.Fprintf(c.Term, "├─ [DISALLOW] %s\n", val)
			}
		case "sitemap":
			fmt.Fprintf(c.Term, "├─ [SITEMAP] %s\n", val)
		}
	}
	fmt.Fprintf(c.Term, "└─ %d disallowed paths loaded\n", len(c.disallowed))
}

func (c *Crawler) IsDisallowed(uri string) bool {
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

func (c *Crawler) Fetch(ctx context.Context, uri string) (*http.Response, error) {
	<-c.Limiter
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")
	return c.Client.Do(req)
}

func (c *Crawler) FetchWithHeaders(ctx context.Context, uri string, headers map[string]string) (*http.Response, error) {
	<-c.Limiter
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")
	for key, value := range headers {
		if key == "" || value == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	return c.Client.Do(req)
}
