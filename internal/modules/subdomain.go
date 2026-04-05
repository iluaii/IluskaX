package modules

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func SubdomainEnum(hostname string, crawlFile *os.File, term io.Writer) []string {
	fmt.Fprintln(term, "\n"+strings.Repeat("=", 60))
	fmt.Fprintf(term, "[PHASE 0] SUBDOMAIN ENUMERATION: %s\n", hostname)
	fmt.Fprintln(term, strings.Repeat("=", 60))

	cmd := exec.Command("subfinder", "-d", hostname, "-silent")
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

	fmt.Fprintf(term, "├─ Found %d subdomains:\n", len(found))
	for _, sub := range found {
		fmt.Fprintf(term, "│  ├─ %s\n", sub)
		fmt.Fprintf(crawlFile, "https://%s/\n", sub)
	}
	fmt.Fprintln(term, "└─ Phase 0 complete, subdomains added to crawl file")
	return found
}
