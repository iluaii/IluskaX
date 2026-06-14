package core

import (
	"net/url"
	"strings"
)

type scopeRule struct {
	host     string
	wildcard bool
	glob     bool
}

type ScopeGuard struct {
	allow []scopeRule
	deny  []scopeRule
}

func NewScopeGuard(defaultHost, allowList, denyList string) *ScopeGuard {
	g := &ScopeGuard{}
	if host := normalizeScopeHost(defaultHost); host != "" {
		g.allow = append(g.allow, scopeRule{host: host})
	}
	g.allow = append(g.allow, parseScopeRules(allowList)...)
	g.deny = append(g.deny, parseScopeRules(denyList)...)
	return g
}

func (g *ScopeGuard) InScope(raw string) bool {
	if g == nil {
		return true
	}
	host := hostFromURL(raw)
	if host == "" {
		return false
	}
	literalHost := hostFromURLLiteral(raw)
	for _, rule := range g.deny {
		if rule.matches(host, literalHost) {
			return false
		}
	}
	for _, rule := range g.allow {
		if rule.matches(host, literalHost) {
			return true
		}
	}
	return false
}

func (g *ScopeGuard) AllowSummary() string {
	return rulesSummary(g.allow)
}

func (g *ScopeGuard) DenySummary() string {
	return rulesSummary(g.deny)
}

func (r scopeRule) matches(host, literalHost string) bool {
	host = normalizeScopeHost(host)
	if host == "" || r.host == "" {
		return false
	}
	if r.glob {
		if literalHost == "" {
			literalHost = host
		}
		return hostGlobMatches(normalizeScopePattern(literalHost), r.host)
	}
	if host == r.host {
		return true
	}
	return r.wildcard && strings.HasSuffix(host, "."+r.host)
}

func hostGlobMatches(host, pattern string) bool {
	if host == "" || pattern == "" {
		return false
	}
	hostParts := strings.Split(host, ".")
	patternParts := strings.Split(pattern, ".")
	if len(hostParts) != len(patternParts) {
		return false
	}
	for i := range patternParts {
		if patternParts[i] == "*" {
			continue
		}
		if hostParts[i] != patternParts[i] {
			return false
		}
	}
	return true
}

func parseScopeRules(list string) []scopeRule {
	var rules []scopeRule
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "*") && !strings.HasPrefix(item, "*.") {
			host := normalizeScopePattern(item)
			if host == "" {
				continue
			}
			rules = append(rules, scopeRule{host: host, glob: true})
			continue
		}
		wildcard := false
		if strings.HasPrefix(item, "*.") {
			wildcard = true
			item = strings.TrimPrefix(item, "*.")
		} else if strings.HasPrefix(item, ".") {
			wildcard = true
			item = strings.TrimPrefix(item, ".")
		}
		host := normalizeScopeHost(item)
		if host == "" {
			continue
		}
		rules = append(rules, scopeRule{host: host, wildcard: wildcard})
	}
	return rules
}

func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "POST|") {
		parts := strings.SplitN(raw, "|", 3)
		if len(parts) >= 2 {
			raw = parts[1]
		}
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() != "" {
		return normalizeScopeHost(parsed.Hostname())
	}
	return normalizeScopeHost(raw)
}

func hostFromURLLiteral(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "POST|") {
		parts := strings.SplitN(raw, "|", 3)
		if len(parts) >= 2 {
			raw = parts[1]
		}
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() != "" {
		return normalizeScopePattern(parsed.Hostname())
	}
	return normalizeScopePattern(raw)
}

func normalizeScopeHost(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if parsed, err := url.Parse("//" + raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimPrefix(raw, "www.")
	raw = strings.Trim(raw, "[] ")
	return raw
}

func normalizeScopePattern(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if parsed, err := url.Parse("//" + raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.Trim(raw, "[] ")
	return strings.TrimSuffix(raw, ".")
}

func rulesSummary(rules []scopeRule) string {
	if len(rules) == 0 {
		return "-"
	}
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.glob {
			out = append(out, rule.host)
			continue
		}
		prefix := ""
		if rule.wildcard {
			prefix = "*."
		}
		out = append(out, prefix+rule.host)
	}
	return strings.Join(out, ", ")
}
