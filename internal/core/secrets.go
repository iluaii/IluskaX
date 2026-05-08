package core

import (
	"regexp"
	"strings"

	"IluskaX/internal/ui"
)

type SecretFinding struct {
	Kind   string
	Source string
	Match  string
	Detail string
	Level  ui.FindingLevel
}

type secretPattern struct {
	kind       string
	re         *regexp.Regexp
	valueGroup int
	level      ui.FindingLevel
	detail     string
}

var secretPatterns = []secretPattern{
	{
		kind:       "AWS access key",
		re:         regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),
		valueGroup: 0,
		level:      ui.LevelWarning,
		detail:     "AWS-style access key id in client-side code",
	},
	{
		kind:       "AWS secret key",
		re:         regexp.MustCompile(`(?i)\b(aws_secret_access_key|awsSecretAccessKey)\b\s*[:=]\s*["'\x60]([A-Za-z0-9/+=]{32,})["'\x60]`),
		valueGroup: 2,
		level:      ui.LevelVulnerability,
		detail:     "AWS secret access key style value in client-side code",
	},
	{
		kind:       "GitHub token",
		re:         regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b`),
		valueGroup: 0,
		level:      ui.LevelVulnerability,
		detail:     "GitHub token format in client-side code",
	},
	{
		kind:       "Google API key",
		re:         regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		valueGroup: 0,
		level:      ui.LevelWarning,
		detail:     "Google API key format in client-side code",
	},
	{
		kind:       "Slack token",
		re:         regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{20,}\b`),
		valueGroup: 0,
		level:      ui.LevelVulnerability,
		detail:     "Slack token format in client-side code",
	},
	{
		kind:       "Stripe secret key",
		re:         regexp.MustCompile(`\bsk_(?:live|test)_[0-9A-Za-z]{20,}\b`),
		valueGroup: 0,
		level:      ui.LevelVulnerability,
		detail:     "Stripe secret key format in client-side code",
	},
	{
		kind:       "JWT",
		re:         regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		valueGroup: 0,
		level:      ui.LevelWarning,
		detail:     "JWT-like token in client-side code",
	},
	{
		kind:       "Bearer token",
		re:         regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})`),
		valueGroup: 1,
		level:      ui.LevelWarning,
		detail:     "Bearer token literal in client-side code",
	},
	{
		kind:       "Authorization header",
		re:         regexp.MustCompile(`(?i)\bauthorization\b\s*[:=]\s*["'\x60]([^"'\x60]{12,})["'\x60]`),
		valueGroup: 1,
		level:      ui.LevelWarning,
		detail:     "Authorization header value in client-side code",
	},
	{
		kind:       "Webhook URL",
		re:         regexp.MustCompile(`(?i)\bhttps://hooks\.(?:slack|zapier)\.com/[^\s"'\x60<>]+`),
		valueGroup: 0,
		level:      ui.LevelWarning,
		detail:     "Webhook URL in client-side code",
	},
	{
		kind:       "Discord webhook",
		re:         regexp.MustCompile(`(?i)\bhttps://(?:discord(?:app)?\.com)/api/webhooks/[0-9]{10,}/[A-Za-z0-9_-]{30,}`),
		valueGroup: 0,
		level:      ui.LevelWarning,
		detail:     "Discord webhook URL in client-side code",
	},
	{
		kind:       "Webhook-like URL",
		re:         regexp.MustCompile(`(?i)\bhttps?://[^\s"'\x60<>]{1,160}/(?:webhook|collect|gate|grab|steal|logger|log)[^\s"'\x60<>]*`),
		valueGroup: 0,
		level:      ui.LevelWarning,
		detail:     "Webhook or collection URL in client-side code",
	},
	{
		kind:       "Telegram bot token",
		re:         regexp.MustCompile(`\b[0-9]{6,}:[A-Za-z0-9_-]{25,}\b`),
		valueGroup: 0,
		level:      ui.LevelWarning,
		detail:     "Telegram bot token format in client-side code",
	},
	{
		kind:       "Private key",
		re:         regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		valueGroup: 0,
		level:      ui.LevelVulnerability,
		detail:     "Private key marker in client-side code",
	},
	{
		kind:       "Named secret",
		re:         regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|app[_-]?secret|secret|password|passwd|pwd)\b\s*[:=]\s*["'\x60]([^"'\x60]{8,})["'\x60]`),
		valueGroup: 2,
		level:      ui.LevelWarning,
		detail:     "Sensitive-looking assignment in client-side code",
	},
}

func FindSecrets(body, sourceURL string) []SecretFinding {
	seen := map[string]bool{}
	out := make([]SecretFinding, 0, 8)
	for _, pattern := range secretPatterns {
		matches := pattern.re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) == 0 {
				continue
			}
			value := match[0]
			if pattern.valueGroup > 0 && len(match) > pattern.valueGroup {
				value = match[pattern.valueGroup]
			}
			if isLikelyPlaceholder(value) {
				continue
			}
			masked := maskSecretValue(value)
			display := maskSecretInMatch(match[0], value, masked)
			key := pattern.kind + "|" + sourceURL + "|" + display
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, SecretFinding{
				Kind:   pattern.kind,
				Source: sourceURL,
				Match:  ui.Truncate(normalizeJSSnippet(display), 140),
				Detail: pattern.detail,
				Level:  pattern.level,
			})
		}
	}
	return out
}

func maskSecretInMatch(match, value, masked string) string {
	if value == "" {
		return "[redacted]"
	}
	return strings.Replace(match, value, masked, 1)
}

func maskSecretValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 8 {
		return "[redacted]"
	}
	if len(value) <= 16 {
		return value[:3] + "..." + value[len(value)-3:]
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func isLikelyPlaceholder(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return true
	}
	placeholders := []string{
		"example", "changeme", "change_me", "replace", "placeholder",
		"your_", "<", "xxx", "todo", "testtest", "dummy",
	}
	for _, marker := range placeholders {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}
