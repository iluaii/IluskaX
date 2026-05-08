package core

import (
	"strings"
	"testing"

	"IluskaX/internal/ui"
)

func TestFindSecretsMasksNamedSecret(t *testing.T) {
	body := `window.apiKey = "super-secret-token-value";`
	findings := FindSecrets(body, "app.js")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Kind != "Named secret" {
		t.Fatalf("unexpected kind: %s", findings[0].Kind)
	}
	if strings.Contains(findings[0].Match, "super-secret-token-value") {
		t.Fatal("expected secret value to be masked")
	}
	if findings[0].Level != ui.LevelWarning {
		t.Fatalf("unexpected level: %s", findings[0].Level.String())
	}
}

func TestFindSecretsSkipsPlaceholders(t *testing.T) {
	body := `const token = "your_api_key_here";`
	findings := FindSecrets(body, "app.js")
	if len(findings) != 0 {
		t.Fatalf("expected placeholder to be skipped, got %d findings", len(findings))
	}
}

func TestFindSecretsDetectsHighConfidenceToken(t *testing.T) {
	body := `const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD";`
	findings := FindSecrets(body, "app.js")
	if len(findings) == 0 {
		t.Fatal("expected GitHub token finding")
	}
	foundGitHub := false
	for _, finding := range findings {
		if finding.Kind == "GitHub token" {
			foundGitHub = true
			if finding.Level != ui.LevelVulnerability {
				t.Fatalf("expected vulnerability level, got %s", finding.Level.String())
			}
			if strings.Contains(finding.Match, "abcdefghijklmnopqrstuvwxyz1234567890ABCD") {
				t.Fatal("expected GitHub token to be masked")
			}
		}
	}
	if !foundGitHub {
		t.Fatal("expected GitHub token finding")
	}
}
