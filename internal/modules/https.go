package modules

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"IluskaX/internal/ui"
)

func HTTPXProbe(subdomains []string, crawlFile *os.File, term io.Writer, extRateLimit int, sb *ui.StatusBar) []string {
	if len(subdomains) == 0 {
		return nil
	}

	logf := func(format string, args ...interface{}) {
		if sb != nil {
			sb.Log(format, args...)
		} else {
			fmt.Fprintf(term, format, args...)
		}
	}

	logf("┌─ [PHASE 0.1] HTTPX - Probing %d subdomains\n", len(subdomains))

	httpxPath := os.ExpandEnv("$HOME/go/bin/httpx")
	if _, err := os.Stat(httpxPath); err != nil {
		logf("├─ [WARN] httpx not found at %s, skipping probe\n", httpxPath)
		logf("└─ Phase 0.1 skipped\n")
		return nil
	}

	tmpFile, err := os.CreateTemp("", "luska_httpx_input_*.txt")
	if err != nil {
		logf("├─ [ERROR] Cannot create temp file: %v\n", err)
		logf("└─ Phase 0.1 skipped\n")
		return nil
	}
	defer os.Remove(tmpFile.Name())
	for _, sub := range subdomains {
		fmt.Fprintln(tmpFile, sub)
	}
	tmpFile.Close()

	args := []string{
		"-l", tmpFile.Name(),
		"-silent",
		"-no-color",
		"-timeout", "10",
		"-retries", "2",
	}
	if extRateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", extRateLimit))
	}

	cmd := exec.Command(httpxPath, args...)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		logf("├─ [WARN] httpx error: %v\n", err)
		logf("└─ Phase 0.1 failed\n")
		return nil
	}

	var alive []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		alive = append(alive, line)
		fmt.Fprintln(crawlFile, line+"/")
		logf("│  ├─ [ALIVE] %s\n", line)
	}

	logf("├─ %d/%d subdomains alive\n", len(alive), len(subdomains))
	logf("└─ Phase 0.1 complete\n")
	return alive
}
