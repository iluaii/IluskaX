package main

import (
	"testing"

	"IluskaX/internal/core"
)

func TestWithSubdomainScopeAllowsDiscoveredSubdomains(t *testing.T) {
	allowScope := withSubdomainScope("", "example.com")
	guard := core.NewScopeGuard("example.com", allowScope, "")

	if !guard.InScope("https://api.example.com/health") {
		t.Fatal("expected -sd scope expansion to allow target subdomains")
	}
}

func TestWithSubdomainScopeKeepsDenyPrecedence(t *testing.T) {
	allowScope := withSubdomainScope("", "example.com")
	guard := core.NewScopeGuard("example.com", allowScope, "admin.example.com")

	if guard.InScope("https://admin.example.com/") {
		t.Fatal("expected deny rule to override -sd subdomain scope expansion")
	}
}

func TestWithSubdomainScopeDoesNotDuplicateExistingWildcard(t *testing.T) {
	allowScope := withSubdomainScope("api.example.com,*.example.com", "www.example.com")

	if allowScope != "api.example.com,*.example.com" {
		t.Fatalf("expected existing wildcard to be reused, got %q", allowScope)
	}
}

func TestIsSameOrSubdomainNormalizesDiscoveryHosts(t *testing.T) {
	tests := []string{
		"api.example.com",
		"https://api.example.com/path",
		"api.example.com.",
		"www.example.com",
	}

	for _, raw := range tests {
		if !isSameOrSubdomain(raw, "https://www.example.com") {
			t.Fatalf("expected %q to match target domain", raw)
		}
	}
}

func TestSitemapURLForAliveSubdomainMatchesCrawlFileEntry(t *testing.T) {
	tests := map[string]string{
		"https://api.example.com":  "https://api.example.com/",
		"https://api.example.com/": "https://api.example.com/",
		"  http://dev.example.com": "http://dev.example.com/",
		"":                         "",
	}

	for raw, want := range tests {
		if got := sitemapURLForAliveSubdomain(raw); got != want {
			t.Fatalf("sitemapURLForAliveSubdomain(%q) = %q, want %q", raw, got, want)
		}
	}
}
