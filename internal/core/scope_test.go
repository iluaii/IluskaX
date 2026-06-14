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

func TestScopeGuardAllowsMiddleWildcardPattern(t *testing.T) {
	guard := NewScopeGuard("example.com", "www.*.example.com", "")
	if !guard.InScope("https://www.dev.example.com/") {
		t.Fatal("expected middle wildcard pattern to be in scope")
	}
	if guard.InScope("https://api.dev.example.com/") {
		t.Fatal("did not expect different prefix to match")
	}
	if guard.InScope("https://www.deep.dev.example.com/") {
		t.Fatal("did not expect wildcard label to span multiple labels")
	}
}

func TestScopeGuardNormalizesURLsInRules(t *testing.T) {
	guard := NewScopeGuard("https://example.com:8443/base", "https://api.example.com/v1", "")
	if !guard.InScope("https://api.example.com/health") {
		t.Fatal("expected URL allow rule host to be normalized")
	}
}
