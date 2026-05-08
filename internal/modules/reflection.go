package modules

import (
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"IluskaX/internal/ui"
)

type reflectionCandidate struct {
	raw   string
	param string
}

func ReflectionMapScan(urls []string, w io.Writer, cookie string, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 5] PARAMETER REFLECTION MAP")

	candidates := reflectionCandidates(urls)
	if len(candidates) == 0 {
		fmt.Fprintln(w, "└─ No parameterized URLs found, skipping")
		return
	}

	limit := len(candidates)
	if limit > 80 {
		limit = 80
	}
	if sb != nil {
		sb.SetPhase("REFLECTION", int64(limit))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	found := 0
	for i, c := range candidates[:limit] {
		marker := reflectionMarker(c.raw, c.param)
		testURL := injectSingleParam(c.raw, c.param, marker)
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
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()

		contexts := classifyReflection(string(bodyBytes), marker)
		if len(contexts) > 0 {
			found++
			detail := strings.Join(contexts, ", ")
			fmt.Fprintf(w, "│  [REFLECTED] param=%s contexts=%s\n", c.param, detail)
			if rc != nil {
				rc.AddFinding(ui.Finding{
					Type:     ui.VulnReflection,
					Level:    ui.LevelInfo,
					URL:      c.raw,
					Payload:  c.param + "=" + marker,
					Detail:   detail,
					Severity: "info",
				})
			}
		}
		if sb != nil {
			sb.Tick(1)
		}
	}

	if found == 0 {
		fmt.Fprintln(w, "├─ Status: No reflected parameters detected")
	} else {
		fmt.Fprintf(w, "├─ Reflected parameters found: %d\n", found)
	}
	fmt.Fprintln(w, "└─ Reflection map complete")
}

func reflectionCandidates(urls []string) []reflectionCandidate {
	seen := map[string]bool{}
	var out []reflectionCandidate
	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		names := make([]string, 0, len(parsed.Query()))
		for name := range parsed.Query() {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			key := parsed.Scheme + "://" + parsed.Host + parsed.Path + "|" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, reflectionCandidate{raw: raw, param: name})
		}
	}
	return out
}

func reflectionMarker(rawURL, param string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(rawURL + "|" + param))
	return fmt.Sprintf("iluska_ref_%08x\"<>", h.Sum32())
}

func classifyReflection(body, marker string) []string {
	escaped := html.EscapeString(marker)
	contextSet := map[string]bool{}
	lowerBody := strings.ToLower(body)
	lowerMarker := strings.ToLower(marker)
	lowerEscaped := strings.ToLower(escaped)

	idx := strings.Index(lowerBody, lowerMarker)
	if idx == -1 && escaped != marker {
		idx = strings.Index(lowerBody, lowerEscaped)
	}
	if idx == -1 {
		return nil
	}

	if strings.Contains(lowerBody, lowerEscaped) && lowerEscaped != lowerMarker {
		contextSet["html-escaped"] = true
	}
	if strings.Contains(lowerBody, lowerMarker) {
		contextSet["raw"] = true
	}

	for searchFrom := 0; ; {
		pos := strings.Index(lowerBody[searchFrom:], lowerMarker)
		if pos == -1 {
			break
		}
		abs := searchFrom + pos
		contextSet[reflectionContextAt(lowerBody, abs)] = true
		searchFrom = abs + len(lowerMarker)
	}

	contexts := make([]string, 0, len(contextSet))
	for ctx := range contextSet {
		contexts = append(contexts, ctx)
	}
	sort.Strings(contexts)
	return contexts
}

func reflectionContextAt(lowerBody string, markerPos int) string {
	beforeStart := markerPos - 250
	if beforeStart < 0 {
		beforeStart = 0
	}
	afterEnd := markerPos + 250
	if afterEnd > len(lowerBody) {
		afterEnd = len(lowerBody)
	}
	before := lowerBody[beforeStart:markerPos]
	window := lowerBody[beforeStart:afterEnd]

	lastScriptOpen := strings.LastIndex(before, "<script")
	lastScriptClose := strings.LastIndex(before, "</script")
	if lastScriptOpen > lastScriptClose {
		return "script"
	}
	if strings.Contains(window, "href=\"") || strings.Contains(window, "src=\"") || strings.Contains(window, "action=\"") {
		return "url-attribute"
	}
	if strings.LastIndex(before, "<") > strings.LastIndex(before, ">") {
		return "html-attribute"
	}
	return "html-text"
}
