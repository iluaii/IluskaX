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

func TestWithSubdomainScopeUsesPatternWhenProvided(t *testing.T) {
	allowScope := withSubdomainScope("", "example.com", "www.*.example.com")

	if allowScope != "www.*.example.com" {
		t.Fatalf("expected -sd pattern to be added to scope, got %q", allowScope)
	}
}

func TestWithSubdomainScopeUsesWildcardTargetAsPattern(t *testing.T) {
	allowScope := withSubdomainScope("", "www.*.gogo.com")

	if allowScope != "www.*.gogo.com" {
		t.Fatalf("expected wildcard target to be used as -sd pattern, got %q", allowScope)
	}
}

func TestSubdomainPatternForRunInfersWildcardTarget(t *testing.T) {
	pattern := subdomainPatternForRun(subdomainFlag{enabled: true}, "www.*.gogo.com")

	if pattern != "www.*.gogo.com" {
		t.Fatalf("expected wildcard target pattern, got %q", pattern)
	}
}

func TestSubdomainEnumHostUsesSuffixAfterWildcard(t *testing.T) {
	host := subdomainEnumHost("www.*.gogo.com", "www.*.gogo.com")

	if host != "gogo.com" {
		t.Fatalf("expected subfinder root gogo.com, got %q", host)
	}
}

func TestSubdomainEnumHostFallsBackToTargetHost(t *testing.T) {
	host := subdomainEnumHost("www.gogo.com", "")

	if host != "gogo.com" {
		t.Fatalf("expected normalized target host gogo.com, got %q", host)
	}
}

func TestExpandSubdomainFlagArgsAcceptsSeparatePattern(t *testing.T) {
	args := expandSubdomainFlagArgs([]string{"luska", "-u", "https://example.com", "-sd", "www.*.example.com", "-ps"})
	want := []string{"luska", "-u", "https://example.com", "-sd=www.*.example.com", "-ps"}

	if len(args) != len(want) {
		t.Fatalf("expected %v, got %v", want, args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, args)
		}
	}
}

func TestExpandSubdomainFlagArgsKeepsDefaultFlag(t *testing.T) {
	args := expandSubdomainFlagArgs([]string{"luska", "-u", "https://example.com", "-sd", "-ps"})
	want := []string{"luska", "-u", "https://example.com", "-sd", "-ps"}

	if len(args) != len(want) {
		t.Fatalf("expected %v, got %v", want, args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, args)
		}
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

func TestMatchesSubdomainPattern(t *testing.T) {
	if !matchesSubdomainPattern("www.dev.example.com", "www.*.example.com") {
		t.Fatal("expected wildcard label pattern to match")
	}
	if matchesSubdomainPattern("api.dev.example.com", "www.*.example.com") {
		t.Fatal("did not expect different prefix to match")
	}
	if matchesSubdomainPattern("www.deep.dev.example.com", "www.*.example.com") {
		t.Fatal("did not expect wildcard label to span multiple labels")
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
