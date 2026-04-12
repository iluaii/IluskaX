package modules

import "strings"

var customHeaders map[string]string

func SetCustomHeaders(raw []string) {
	customHeaders = make(map[string]string, len(raw))
	for _, h := range raw {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				customHeaders[k] = v
			}
		}
	}
}

func CustomHeaders() map[string]string {
	return customHeaders
}

func ApplyCustomHeaders(existing map[string]string) map[string]string {
	if len(customHeaders) == 0 {
		return existing
	}
	merged := make(map[string]string, len(existing)+len(customHeaders))
	for k, v := range existing {
		merged[k] = v
	}
	for k, v := range customHeaders {
		merged[k] = v
	}
	return merged
}