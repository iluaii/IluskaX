package modules

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

func DalfoxScan(urls []string, w io.Writer, cookie string) {
	fmt.Fprintln(w, "\n┌─ [PHASE 4] DALFOX - XSS Detection")
	fmt.Fprintf(w, "├─ Scanning %d URLs\n", len(urls))

	vulnCount := 0
	for i, testURL := range urls {
		if !HasParams(testURL) {
			continue
		}
		fmt.Fprintf(w, "├─ [%d/%d] %s\n", i+1, len(urls), testURL)

		args := []string{"url", testURL, "--follow-redirects"}
		if cookie != "" {
			args = append(args, "--cookie", cookie)
		}
		out, err := exec.Command("dalfox", args...).CombinedOutput()
		outStr := string(out)

		isVuln := strings.Contains(outStr, "[V]") || strings.Contains(outStr, "poc =") ||
			strings.Contains(outStr, "INJECT") || strings.Contains(outStr, "Injected")

		if isVuln {
			fmt.Fprintf(w, "│  ✓ [VULNERABLE] XSS found\n")
			vulnCount++
		} else if err != nil {
			fmt.Fprintf(w, "│  ? [ERROR] %v\n", err)
		} else {
			fmt.Fprintf(w, "│  ○ [SAFE] Not vulnerable\n")
		}

		for _, line := range strings.Split(outStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && (strings.Contains(line, "[V]") || strings.Contains(line, "poc =") ||
				strings.Contains(line, "INJECT") || strings.Contains(line, "Injected") ||
				strings.Contains(line, "Parameter") || strings.Contains(line, "Payload")) {
				fmt.Fprintf(w, "│     %s\n", line)
			}
		}
	}

	if vulnCount > 0 {
		fmt.Fprintf(w, "├─ [ALERT] Found %d vulnerable URLs\n", vulnCount)
	}
	fmt.Fprintln(w, "└─ Dalfox scan complete")
}
