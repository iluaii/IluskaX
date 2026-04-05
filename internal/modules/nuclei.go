package modules

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

func NucleiScan(urlFile string, w io.Writer) {
	fmt.Fprintln(w, "\n┌─ [PHASE 2] NUCLEI - Template-Based Vulnerability Detection")

	cmd := exec.Command("nuclei",
		"-l", urlFile,
		"-severity", "low,medium,high,critical",
		"-silent",
		"-timeout", "10",
		"-retries", "1",
	)
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
		fmt.Fprintf(w, "├─ [FINDING] %s\n", trimmed)
		lower := strings.ToLower(trimmed)
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if strings.Contains(lower, sev) {
				counts[sev]++
				break
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
}
