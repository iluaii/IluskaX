package modules

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"IluskaX/internal/httpheaders"
)

type PostForm struct {
	URL  string
	Data string
}

func ReadURLs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	var urls []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !seen[line] {
			seen[line] = true
			urls = append(urls, line)
		}
	}
	return urls, sc.Err()
}

func ReadPostForms(path string) []PostForm {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var forms []PostForm
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "POST|") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) == 3 {
			forms = append(forms, PostForm{URL: parts[1], Data: parts[2]})
		}
	}
	return forms
}

func WriteTemp(urls []string, suffix string) (string, error) {
	f, err := os.CreateTemp("", "luska_*_"+suffix+".txt")
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, u := range urls {
		fmt.Fprintln(f, u)
	}
	return f.Name(), nil
}

func HasParams(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return len(u.RawQuery) > 0
}

func InjectPayload(rawURL, payload string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	newQ := url.Values{}
	for key := range q {
		newQ.Set(key, payload)
	}
	u.RawQuery = newQ.Encode()
	return u.String()
}

func InjectPostPayload(data, payload string) string {
	parts := strings.Split(data, "&")
	for i, p := range parts {
		if kv := strings.SplitN(p, "=", 2); len(kv) == 2 {
			parts[i] = kv[0] + "=" + url.QueryEscape(payload)
		}
	}
	return strings.Join(parts, "&")
}

func IsPhaseSkipped(phase string, skipPhases []string) bool {
	for _, s := range skipPhases {
		if s == phase {
			return true
		}
	}
	return false
}

func ParsePhaseList(raw string) []string {
	var phases []string
	seen := map[string]bool{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		phases = append(phases, p)
	}
	return phases
}

func PentestPhaseIDs() []string {
	return []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"}
}

func BuildPentestSkipPhases(skipRaw, onlyRaw string) []string {
	skipPhases := ParsePhaseList(skipRaw)
	onlyPhases := ParsePhaseList(onlyRaw)
	if len(onlyPhases) == 0 {
		return skipPhases
	}

	only := map[string]bool{}
	for _, phase := range onlyPhases {
		only[phase] = true
	}

	combined := make([]string, 0, len(PentestPhaseIDs())+len(skipPhases))
	seen := map[string]bool{}
	for _, phase := range PentestPhaseIDs() {
		if only[phase] {
			continue
		}
		combined = append(combined, phase)
		seen[phase] = true
	}
	for _, phase := range skipPhases {
		if seen[phase] {
			continue
		}
		combined = append(combined, phase)
		seen[phase] = true
	}
	return combined
}

func IsStaticAsset(path string) bool {
	staticExts := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz",
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func ApplyHeaders(req *http.Request, cookie string) {
	req.Header.Set("User-Agent", httpheaders.DefaultUserAgent)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}
}

func CollectCookieNames(urls []string, cookie string, client *http.Client, limiter <-chan time.Time) []string {
	seen := map[string]bool{}
	var names []string
	for _, u := range urls {
		if limiter != nil {
			<-limiter
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		ApplyHeaders(req, cookie)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		for _, c := range resp.Cookies() {
			if !seen[c.Name] {
				seen[c.Name] = true
				names = append(names, c.Name)
			}
		}
	}
	return names
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
