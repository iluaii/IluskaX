package core

import "testing"

func TestScopeGuardAllowsDefaultHost(t *testing.T) {
	guard := NewScopeGuard("example.com", "", "")
	if !guard.InScope("https://example.com/path") {
		t.Fatal("expected default host to be in scope")
	}
	if !guard.InScope("https://www.example.com/path") {
		t.Fatal("expected www variant to normalize into scope")
	}
	if guard.InScope("https://api.example.com/path") {
		t.Fatal("did not expect subdomain without wildcard allow")
	}
}

func TestScopeGuardWildcardAndDeny(t *testing.T) {
	guard := NewScopeGuard("example.com", "*.example.com", "admin.example.com")
	if !guard.InScope("https://api.example.com/v1") {
		t.Fatal("expected wildcard subdomain to be in scope")
	}
	if guard.InScope("https://admin.example.com/") {
		t.Fatal("expected deny rule to override allow")
	}
}

func TestScopeGuardNormalizesURLsInRules(t *testing.T) {
	guard := NewScopeGuard("https://example.com:8443/base", "https://api.example.com/v1", "")
	if !guard.InScope("https://api.example.com/health") {
		t.Fatal("expected URL allow rule host to be normalized")
	}
}
