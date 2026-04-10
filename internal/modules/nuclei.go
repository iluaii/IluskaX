package modules

import (
	"fmt"
	"io"
	"os/exec"
	"strings"

	"IluskaX/internal/ui"
)

func NucleiScan(urlFile string, w io.Writer, extRateLimit int, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 2] NUCLEI - Template-Based Vulnerability Detection")

	if sb != nil {
		sb.SetPhase("NUCLEI", 1)
	}

	args := []string{
		"-l", urlFile,
		"-severity", "low,medium,high,critical",
		"-silent",
		"-timeout", "10",
		"-retries", "1",
	}
	if extRateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", extRateLimit))
	}
	cmd := exec.Command("nuclei", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "├─ [WARN] nuclei error: %v\n", err)
	}

	counts := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		lower := strings.ToLower(trimmed)
		severity := ""
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if strings.Contains(lower, sev) {
				severity = sev
				counts[sev]++
				break
			}
		}

		if sb != nil {
			sb.Log("├─ [FINDING] %s\n", ui.Truncate(trimmed, 80))
		} else {
			fmt.Fprintf(w, "├─ [FINDING] %s\n", trimmed)
		}

		if rc != nil && severity != "" {
			parts := strings.Fields(trimmed)
			url := ""
			template := ""
			if len(parts) > 0 {
				template = parts[0]
			}
			for _, p := range parts {
				if strings.HasPrefix(p, "http") {
					url = p
					break
				}
			}
			if url != "" {
				rc.AddFinding(ui.Finding{
					Type:     ui.VulnNuclei,
					Level:    ui.LevelVulnerability,
					URL:      url,
					Payload:  template,
					Detail:   severity,
					Severity: severity,
				})
			}
		}
	}

	total := counts["critical"] + counts["high"] + counts["medium"] + counts["low"]
	if total == 0 {
		fmt.Fprintln(w, "├─ Status: No vulnerabilities found")
	} else {
		fmt.Fprintf(w, "├─ Found: %d total (critical:%d high:%d medium:%d low:%d)\n",
			total, counts["critical"], counts["high"], counts["medium"], counts["low"])
	}
	fmt.Fprintln(w, "└─ NUCLEI scan complete")

	if sb != nil {
		sb.Tick(1)
	}
}
