package modules

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"

	"IluskaX/internal/ui"
)

const (
	corsProbeOrigin     = "https://iluska-cors-probe.invalid"
	corsProbeOriginNull = "null"
)

var ssrfParamHints = []string{
	"url", "uri", "u", "link", "src", "source", "dest", "destination", "redirect",
	"return", "next", "continue", "target", "path", "file", "folder", "document",
	"load", "read", "fetch", "get", "proxy", "host", "hostname", "domain", "ip",
	"addr", "address", "site", "html", "page", "feed", "data", "reference", "ref",
	"callback", "cb", "webhook", "endpoint", "api", "request", "req", "image",
	"img", "picture", "avatar", "port", "socket", "connection", "go", "out",
	"view", "show", "open", "share", "to", "from",
}

var sessionCookieNames = []string{
	"jsessionid", "phpsessid", "session", "sessionid", "sess_id", "sid",
	"asp.net_sessionid", "connect.sid", "auth", "token", "jwt", "access_token",
}

type OASTOptions struct {
	ServerURL   string // comma-separated, e.g. "oast.pro,oast.live"; empty skips OAST
	Token       string // optional auth for private servers
	PollSeconds int    // time to wait for callbacks after probes
}

func CorsSessionSSRFScan(urls, paramURLs []string, cookie string, oast OASTOptions, w io.Writer, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 11] CORS, SESSION COOKIES & SSRF (OAST)")
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)

	hosts := uniqueHosts(urls)
	if sb != nil {
		sb.SetPhase("CORS/SESSION/SSRF", int64(len(hosts)+estimateSSRFProbes(paramURLs)))
	}

	corsReflectScan(hosts, cookie, w, limiter, sb, rc)
	sessionTriageScan(urls, cookie, w, limiter, sb, rc)

	if strings.TrimSpace(oast.ServerURL) == "" {
		msg := "├─ [OAST] Skipped (set -oast-server to enable blind SSRF, e.g. oast.pro,oast.live)\n"
		if sb != nil {
			sb.Log("%s", msg)
		} else {
			fmt.Fprint(w, msg)
		}
	} else {
		ssrfOASTScan(paramURLs, cookie, oast, w, limiter, sb, rc)
	}

	if sb != nil {
		sb.Log("└─ Phase 11 complete\n")
	} else {
		fmt.Fprintln(w, "└─ Phase 11 complete")
	}
}

func estimateSSRFProbes(paramURLs []string) int {
	n := 0
	for _, raw := range paramURLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for k := range u.Query() {
			if ssrfParamNameMatch(k) {
				n++
			}
		}
	}
	if n > 120 {
		return 120
	}
	return n
}

func corsReflectScan(hosts []string, cookie string, w io.Writer, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) {
	client := &http.Client{Timeout: 12 * time.Second}
	for _, targetURL := range hosts {
		for _, probe := range []struct {
			label  string
			origin string
		}{
			{"reflect-untrusted-origin", corsProbeOrigin},
			{"reflect-null-origin", corsProbeOriginNull},
		} {
			<-limiter
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				continue
			}
			ApplyHeaders(req, cookie)
			req.Header.Set("Origin", probe.origin)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			ac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
			acc := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
			resp.Body.Close()

			if ac == "*" && acc {
				msg := fmt.Sprintf("│  [CORS] %s — Allow-Credentials with wildcard ACAO\n", ui.Red(targetURL))
				logPhaseLine(w, sb, msg)
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:    ui.VulnCORS,
						Level:   ui.LevelVulnerability,
						URL:     targetURL,
						Payload: "ACAO: * + credentials: true",
						Detail:  "invalid CORS pair",
					})
				}
			} else if strings.EqualFold(ac, probe.origin) || (probe.origin == corsProbeOriginNull && strings.EqualFold(ac, "null")) {
				lvl := ui.LevelWarning
				detail := "reflected untrusted Origin"
				if acc {
					lvl = ui.LevelVulnerability
					detail = "reflected Origin with credentials enabled"
				}
				msg := fmt.Sprintf("│  [CORS] %s reflects Origin (%s) creds=%v\n", ui.Yellow(targetURL), probe.label, acc)
				logPhaseLine(w, sb, msg)
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:    ui.VulnCORS,
						Level:   lvl,
						URL:     targetURL,
						Payload: fmt.Sprintf("ACAO reflects %q", probe.origin),
						Detail:  detail,
					})
				}
			}

			<-limiter
			optReq, err := http.NewRequest("OPTIONS", targetURL, nil)
			if err != nil {
				continue
			}
			ApplyHeaders(optReq, cookie)
			optReq.Header.Set("Origin", corsProbeOrigin)
			optReq.Header.Set("Access-Control-Request-Method", "GET")
			optResp, err := client.Do(optReq)
			if err != nil {
				continue
			}
			oac := strings.TrimSpace(optResp.Header.Get("Access-Control-Allow-Origin"))
			optResp.Body.Close()
			if strings.EqualFold(oac, corsProbeOrigin) {
				msg := fmt.Sprintf("│  [CORS] %s OPTIONS reflects probe Origin\n", ui.Yellow(targetURL))
				logPhaseLine(w, sb, msg)
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:    ui.VulnCORS,
						Level:   ui.LevelWarning,
						URL:     targetURL,
						Payload: "OPTIONS ACAO reflects untrusted Origin",
						Detail:  "preflight misconfiguration",
					})
				}
			}
		}
		if sb != nil {
			sb.Tick(1)
		}
	}
}

func sessionTriageScan(urls []string, cookie string, w io.Writer, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) {
	httpClient := &http.Client{Timeout: 14 * time.Second}
	seen := map[string]bool{}
	n := 0
	const maxLoginURLs = 35
	for _, raw := range urls {
		if n >= maxLoginURLs {
			break
		}
		if !loginLikeURL(raw) {
			continue
		}
		if seen[raw] {
			continue
		}
		seen[raw] = true
		n++

		<-limiter
		c1 := fetchSessionSnapshot(httpClient, raw, "")
		if c1 == nil {
			c1 = map[string]string{}
		}
		<-limiter
		c2 := fetchSessionSnapshot(httpClient, raw, "")
		if c2 == nil {
			c2 = map[string]string{}
		}

		for name, v1 := range c1 {
			v2, ok := c2[name]
			if !ok || v1 == "" {
				continue
			}
			if v1 == v2 {
				msg := fmt.Sprintf("│  [SESSION] %s stable %s across back-to-back unauthenticated GETs\n", ui.Yellow(ui.Truncate(raw, ui.MaxURLLen)), name)
				logPhaseLine(w, sb, msg)
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:    ui.VulnSession,
						Level:   ui.LevelInfo,
						URL:     raw,
						Payload: fmt.Sprintf("%s unchanged between requests", name),
						Detail:  "possible fixation surface; verify post-auth rotation",
					})
				}
			}
		}

		<-limiter
		req, _ := http.NewRequest("GET", raw, nil)
		ApplyHeaders(req, cookie)
		resp, err := httpClient.Do(req)
		if err != nil {
			if sb != nil {
				sb.Tick(1)
			}
			continue
		}
		u, _ := url.Parse(raw)
		isHTTPS := u != nil && u.Scheme == "https"
		for _, c := range resp.Cookies() {
			if !sessionishName(c.Name) {
				continue
			}
			if isHTTPS && c.SameSite != http.SameSiteStrictMode {
				msg := fmt.Sprintf("│  [SESSION] %s cookie %s SameSite=%v on auth-like path\n", ui.Yellow(ui.Truncate(raw, ui.MaxURLLen)), c.Name, sameSiteLabel(c.SameSite))
				logPhaseLine(w, sb, msg)
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:    ui.VulnSession,
						Level:   ui.LevelInfo,
						URL:     raw,
						Payload: fmt.Sprintf("%s SameSite not Strict", c.Name),
						Detail:  "review CSRF/session binding on login flows",
					})
				}
			}
		}
		resp.Body.Close()
		if sb != nil {
			sb.Tick(1)
		}
	}
}

func ssrfOASTScan(paramURLs []string, cookie string, oast OASTOptions, w io.Writer, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) {
	poll := oast.PollSeconds
	if poll < 15 {
		poll = 15
	}
	if poll > 180 {
		poll = 180
	}

	ic, err := client.New(&client.Options{
		ServerURL: strings.TrimSpace(oast.ServerURL),
		Token:     strings.TrimSpace(oast.Token),
	})
	if err != nil {
		msg := fmt.Sprintf("├─ [OAST] Client init failed: %v\n", err)
		if sb != nil {
			sb.Log("%s", msg)
		} else {
			fmt.Fprint(w, msg)
		}
		return
	}
	polling := false
	defer func() {
		if polling {
			_ = ic.StopPolling()
		}
		_ = ic.Close()
	}()

	var pending sync.Map // host label -> probe description
	var seenID sync.Map

	if err := ic.StartPolling(2*time.Second, func(it *server.Interaction) {
		id := it.UniqueID + "|" + it.FullId + "|" + it.RawRequest
		if _, dup := seenID.LoadOrStore(id, true); dup {
			return
		}
		hostHint := strings.ToLower(it.RawRequest + "\n" + it.FullId)
		pending.Range(func(k, v interface{}) bool {
			h := k.(string)
			if strings.Contains(hostHint, strings.ToLower(h)) {
				desc := v.(string)
				msg := fmt.Sprintf("│  [SSRF] OAST hit (%s) for %s\n", ui.Red(it.Protocol), desc)
				logPhaseLine(w, sb, msg)
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:    ui.VulnSSRF,
						Level:   ui.LevelVulnerability,
						URL:     desc,
						Payload: "OAST interaction: " + it.Protocol,
						Detail:  ui.Truncate(strings.ReplaceAll(it.RawRequest, "\r", ""), 200),
					})
				}
				return false
			}
			return true
		})
	}); err != nil {
		msg := fmt.Sprintf("├─ [OAST] Polling failed: %v\n", err)
		if sb != nil {
			sb.Log("%s", msg)
		} else {
			fmt.Fprint(w, msg)
		}
		return
	}
	polling = true

	httpClient := &http.Client{Timeout: 15 * time.Second}
	probes := 0
	const maxProbes = 120

outer:
	for _, raw := range paramURLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		q := u.Query()
		for key := range q {
			if !ssrfParamNameMatch(key) {
				continue
			}
			if probes >= maxProbes {
				break outer
			}
			oastHost := ic.URL()
			if oastHost == "" {
				break outer
			}
			payload := "https://" + oastHost
			u2 := *u
			q2 := u2.Query()
			q2.Set(key, payload)
			u2.RawQuery = q2.Encode()
			target := u2.String()

			pending.Store(oastHost, target)
			<-limiter
			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				continue
			}
			ApplyHeaders(req, cookie)
			resp, err := httpClient.Do(req)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
			probes++
			if sb != nil {
				sb.Tick(1)
			}
		}
	}

	msg := fmt.Sprintf("├─ [OAST] Queued %d SSRF probes; polling %ds for callbacks\n", probes, poll)
	if sb != nil {
		sb.Log("%s", msg)
	} else {
		fmt.Fprint(w, msg)
	}
	time.Sleep(time.Duration(poll) * time.Second)
}

func logPhaseLine(w io.Writer, sb *ui.StatusBar, msg string) {
	if sb != nil {
		sb.Log("%s", msg)
	} else {
		fmt.Fprint(w, msg)
	}
}

func loginLikeURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	hints := []string{"/login", "/signin", "/sign-in", "/sign_in", "/auth", "/session", "/oauth", "/openid", "/account/login", "/user/login", "/wp-login", "/admin"}
	for _, h := range hints {
		if strings.Contains(p, h) {
			return true
		}
	}
	return false
}

func fetchSessionSnapshot(c *http.Client, pageURL, cookie string) map[string]string {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return nil
	}
	ApplyHeaders(req, cookie)
	resp, err := c.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	out := map[string]string{}
	for _, part := range resp.Header.Values("Set-Cookie") {
		name, val := cookieNameValue(part)
		if name == "" {
			continue
		}
		if sessionishName(name) {
			out[strings.ToLower(name)] = val
		}
	}
	return out
}

func cookieNameValue(setCookie string) (string, string) {
	setCookie = strings.TrimSpace(setCookie)
	if setCookie == "" {
		return "", ""
	}
	sem := strings.Index(setCookie, ";")
	first := setCookie
	if sem >= 0 {
		first = setCookie[:sem]
	}
	eq := strings.Index(first, "=")
	if eq <= 0 {
		return "", ""
	}
	return strings.TrimSpace(first[:eq]), strings.TrimSpace(first[eq+1:])
}

func sessionishName(name string) bool {
	n := strings.ToLower(name)
	for _, s := range sessionCookieNames {
		if n == s || strings.Contains(n, s) {
			return true
		}
	}
	return false
}

func sameSiteLabel(s http.SameSite) string {
	switch s {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "default/none"
	}
}

func ssrfParamNameMatch(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	for _, h := range ssrfParamHints {
		if k == h || strings.HasSuffix(k, "_"+h) || strings.HasPrefix(k, h+"_") {
			return true
		}
	}
	return false
}
