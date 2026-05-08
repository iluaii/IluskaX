package modules

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"unicode/utf8"

	"IluskaX/internal/ui"
)

func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func DalfoxScan(urls []string, w io.Writer, cookie string, extRateLimit int, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 9] DALFOX - XSS Detection")
	fmt.Fprintf(w, "├─ Scanning %d URLs\n", len(urls))

	if sb != nil {
		sb.SetPhase("DALFOX", int64(len(urls)))
	}

	vulnCount := 0
	for i, testURL := range urls {
		if !HasParams(testURL) {
			continue
		}

		if sb != nil {
			sb.Log("├─ [%d/%d] %s\n", i+1, len(urls), ui.Truncate(testURL, ui.MaxURLLen))
		} else {
			fmt.Fprintf(w, "├─ [%d/%d] %s\n", i+1, len(urls), testURL)
		}

		args := []string{"url", testURL, "--follow-redirects"}
		if cookie != "" {
			args = append(args, "--cookie", cookie)
		}
		if extRateLimit > 0 {
			delayMS := 1000 / extRateLimit
			if delayMS < 1 {
				delayMS = 1
			}
			args = append(args, "--worker", "1", "--delay", fmt.Sprintf("%d", delayMS))
		}
		out, err := exec.Command("dalfox", args...).CombinedOutput()
		outStr := string(out)

		isVuln := strings.Contains(outStr, "[V]") || strings.Contains(outStr, "poc =") ||
			strings.Contains(outStr, "INJECT") || strings.Contains(outStr, "Injected")

		if isVuln {
			msg := ui.Green("  ✓ [VULNERABLE] XSS found")
			if sb != nil {
				sb.Log("%s\n", msg)
			} else {
				fmt.Fprintln(w, msg)
			}
			vulnCount++
			payload := ""
			for _, line := range strings.Split(outStr, "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "poc =") || strings.Contains(line, "Payload") ||
					strings.Contains(line, "[V]") || strings.Contains(line, "Triggered") {
					payload = stripANSI(line)
					break
				}
			}
			if rc != nil {
				rc.AddFinding(ui.Finding{
					Type:    ui.VulnXSS,
					Level:   ui.LevelVulnerability,
					URL:     testURL,
					Payload: payload,
					Detail:  "XSS",
				})
			}
		} else if err != nil {
			fmt.Fprintf(w, "│  ? [ERROR] %v\n", err)
		} else {
			msg := ui.Dim("  ○ [SAFE]")
			if sb != nil {
				sb.Log("%s\n", msg)
			} else {
				fmt.Fprintln(w, msg)
			}
		}

		for _, line := range strings.Split(outStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && (strings.Contains(line, "[V]") || strings.Contains(line, "poc =") ||
				strings.Contains(line, "INJECT") || strings.Contains(line, "Injected") ||
				strings.Contains(line, "Parameter") || strings.Contains(line, "Payload")) {
				display := ui.Truncate(stripANSI(line), 100)
				fmt.Fprintf(w, "│     %s\n", display)
			}
		}

		if sb != nil {
			sb.Tick(1)
		}
	}

	if vulnCount > 0 {
		msg := fmt.Sprintf("├─ %s\n", ui.Red(fmt.Sprintf("[ALERT] Found %d vulnerable URLs", vulnCount)))
		if sb != nil {
			sb.Log("%s", msg)
		} else {
			fmt.Fprint(w, msg)
		}
	}
	if sb != nil {
		sb.Log("└─ Dalfox scan complete\n")
	} else {
		fmt.Fprintln(w, "└─ Dalfox scan complete")
	}
}
