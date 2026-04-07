package modules

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"IluskaX/internal/ui"
)

func SQLMapScan(urls []string, w io.Writer, level, risk, cookie, burpFile, phaseLabel string, flushSession bool, sb *ui.StatusBar, rc *ui.ReportCollector) bool {
	fmt.Fprintf(w, "\n┌─ [%s] SQLMAP - SQL Injection Detection\n", phaseLabel)

	baseArgs := []string{
		"--batch",
		"--level=" + level,
		"--risk=" + risk,
		"--technique=BEUSTQ",
		"--dbs",
		"-v", "1",
		"--flush-session",
		"--timeout=60",
		"--retries=3",
		"--time-sec=10",
	}
	if cookie != "" {
		baseArgs = append(baseArgs, "--cookie="+cookie)
		autoClient := &http.Client{Timeout: 15 * time.Second}
		autoCookies := CollectCookieNames(urls, cookie, autoClient)
		if len(autoCookies) > 0 {
			fmt.Fprintf(w, "├─ Auto-discovered cookies for injection: %s\n", strings.Join(autoCookies, ", "))
			baseArgs = append(baseArgs, "--cookie-param="+strings.Join(autoCookies, ","))
		}
	}

	run := func(args []string) (string, error) {
		out, err := exec.Command("sqlmap", args...).CombinedOutput()
		return string(out), err
	}

	printResult := func(outStr string, err error, targetURL string) bool {
		isVuln := strings.Contains(outStr, "Parameter:")
		if isVuln {
			msg := ui.Red("  ✓ [VULNERABLE] SQL Injection detected")
			if sb != nil {
				sb.Log("%s\n", msg)
			} else {
				fmt.Fprintln(w, msg)
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

		payload := ""
		paramName := ""
		for _, line := range strings.Split(outStr, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.Contains(line, "Parameter:") {
				paramName = line
			}
			if strings.Contains(line, "Payload:") {
				payload = strings.TrimPrefix(line, "Payload:")
				payload = strings.TrimSpace(payload)
			}
			if strings.Contains(line, "Parameter:") || strings.Contains(line, "Type:") ||
				strings.Contains(line, "Payload:") || strings.Contains(line, "[*]") || strings.Contains(line, "[+]") {
				display := ui.Truncate(line, 100)
				fmt.Fprintf(w, "│     %s\n", display)
			}
		}

		if isVuln && rc != nil && targetURL != "" {
			detail := paramName
			if detail == "" {
				detail = "SQLi"
			}
			rc.AddFinding(ui.Finding{
				Type:    ui.VulnSQLi,
				Level:   ui.LevelVulnerability,
				URL:     targetURL,
				Payload: payload,
				Detail:  detail,
			})
		}
		return isVuln
	}

	if burpFile != "" {
		fmt.Fprintf(w, "├─ Mode: Burp request file (%s) level=%s, risk=%s\n", burpFile, level, risk)
		out, err := run(append([]string{"-r", burpFile}, baseArgs...))
		result := printResult(out, err, burpFile)
		fmt.Fprintln(w, "└─ SQLMap scan complete")
		return result
	}

	seen := map[string]bool{}
	var dedupURLs []string
	for _, u := range urls {
		if !seen[u] && HasParams(u) {
			seen[u] = true
			dedupURLs = append(dedupURLs, u)
		}
	}

	if sb != nil {
		sb.SetPhase("SQLMAP", int64(len(dedupURLs)))
	}

	fmt.Fprintf(w, "├─ Scanning %d URLs with level=%s, risk=%s\n", len(dedupURLs), level, risk)
	vulnCount := 0
	for i, u := range dedupURLs {
		if sb != nil {
			sb.Log("├─ [%d/%d] %s\n", i+1, len(dedupURLs), ui.Truncate(u, ui.MaxURLLen))
		} else {
			fmt.Fprintf(w, "├─ [%d/%d] %s\n", i+1, len(dedupURLs), u)
		}
		out, err := run(append([]string{"-u", u}, baseArgs...))
		if printResult(out, err, u) {
			vulnCount++
		}
		if sb != nil {
			sb.Tick(1)
		}
	}

	if vulnCount > 0 {
		fmt.Fprintf(w, "├─ %s\n", ui.Red(fmt.Sprintf("[ALERT] Found %d vulnerable URLs", vulnCount)))
		fmt.Fprintln(w, "└─ Status: ESCALATING TO NEXT LEVEL ⚠️")
		return true
	}
	fmt.Fprintln(w, "└─ SQLMap scan complete")
	return false
}

func SQLMapPostForms(forms []PostForm, w io.Writer, level, risk, cookie string, sb *ui.StatusBar, rc *ui.ReportCollector) {
	if len(forms) == 0 {
		return
	}
	fmt.Fprintf(w, "\n┌─ [PHASE 3-POST] SQLMAP - POST Forms\n")
	fmt.Fprintf(w, "├─ Testing %d POST forms\n", len(forms))

	if sb != nil {
		sb.SetPhase("SQLMAP POST", int64(len(forms)))
	}

	for _, form := range forms {
		if sb != nil {
			sb.Log("├─ POST %s\n", ui.Truncate(form.URL, ui.MaxURLLen))
		} else {
			fmt.Fprintf(w, "├─ POST %s\n", form.URL)
		}
		args := []string{
			"-u", form.URL,
			"--data=" + form.Data,
			"--batch",
			"--level=" + level,
			"--risk=" + risk,
			"--technique=BEUSTQ",
			"--timeout=60",
			"--retries=3",
			"--time-sec=10",
			"--flush-session",
			"-v", "1",
		}
		if cookie != "" {
			args = append(args, "--cookie="+cookie)
		}
		out, err := exec.Command("sqlmap", args...).CombinedOutput()
		outStr := string(out)
		isVuln := strings.Contains(outStr, "Parameter:")
		if isVuln {
			msg := ui.Red("  ✓ [VULNERABLE] SQL Injection in POST")
			if sb != nil {
				sb.Log("%s\n", msg)
			} else {
				fmt.Fprintln(w, msg)
			}
			if rc != nil {
				rc.AddFinding(ui.Finding{
					Type:    ui.VulnSQLi,
					Level:   ui.LevelVulnerability,
					URL:     form.URL,
					Payload: form.Data,
					Detail:  "POST SQLi",
				})
			}
		} else if err != nil {
			fmt.Fprintf(w, "│  ? [ERROR] %v\n", err)
		} else {
			fmt.Fprintln(w, ui.Dim("  ○ [SAFE]"))
		}
		for _, line := range strings.Split(outStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && (strings.Contains(line, "Parameter:") || strings.Contains(line, "Type:") ||
				strings.Contains(line, "Payload:") || strings.Contains(line, "[*]") || strings.Contains(line, "[+]")) {
				fmt.Fprintf(w, "│     %s\n", ui.Truncate(line, 100))
			}
		}
		if sb != nil {
			sb.Tick(1)
		}
	}
	fmt.Fprintln(w, "└─ POST SQLMap complete")
}

func EscalateSQLMap(urls []string, w io.Writer, currentLevel, currentRisk, cookie, burpFile string, sb *ui.StatusBar, rc *ui.ReportCollector) {
	nextLevel := fmt.Sprintf("%d", minInt(atoi(currentLevel)+1, 3))
	nextRisk := fmt.Sprintf("%d", minInt(atoi(currentRisk)+1, 3))
	SQLMapScan(urls, w, nextLevel, nextRisk, cookie, burpFile, "PHASE 3.1", true, sb, rc)
}
