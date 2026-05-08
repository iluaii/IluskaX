package modules

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func SubdomainEnum(hostname string, crawlFile *os.File, term io.Writer, extRateLimit int) []string {
	fmt.Fprintln(term, "\n"+strings.Repeat("=", 60))
	fmt.Fprintf(term, "[PHASE 0] SUBDOMAIN ENUMERATION: %s\n", hostname)
	fmt.Fprintln(term, strings.Repeat("=", 60))

	args := []string{"-d", hostname, "-silent"}
	if extRateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", extRateLimit))
	}
	cmd := exec.Command("subfinder", args...)
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(term, "[ERROR] subfinder failed: %v\n", err)
		fmt.Fprintln(term, "[WARN] Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
		return nil
	}

	var found []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if sub := strings.TrimSpace(line); sub != "" {
			found = append(found, sub)
		}
	}

	if len(found) == 0 {
		fmt.Fprintln(term, "├─ No subdomains found")
		fmt.Fprintln(term, "└─ Phase 0 complete")
		return nil
	}

	fmt.Fprintf(term, "├─ Found %d subdomains (will probe with httpx in phase 0.1)\n", len(found))
	fmt.Fprintln(term, "└─ Phase 0 complete")
	return found
}
