package auth

import (
	"fmt"
	"os"
	"strings"
)

func ResolveCookie(raw, path string) (string, error) {
	parts := make([]string, 0, 2)
	if path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read cookie file: %w", err)
		}
		fileCookie := normalizeCookie(string(content))
		if fileCookie != "" {
			parts = append(parts, fileCookie)
		}
	}
	inlineCookie := normalizeCookie(raw)
	if inlineCookie != "" {
		parts = append(parts, inlineCookie)
	}
	return strings.Join(parts, "; "), nil
}

func normalizeCookie(value string) string {
	normalized := strings.ReplaceAll(value, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "cookie:") {
			line = strings.TrimSpace(line[len("cookie:"):])
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, ";"))
		if line != "" {
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, "; ")
}
