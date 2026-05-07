package modules

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"IluskaX/internal/ui"
)

var openAPIPathRE = regexp.MustCompile(`"((?:\\/|/)[A-Za-z0-9._~!$&'()*+,;=:@%/\-{}]+)"\s*:`)

type exposureProbe struct {
	Path     string
	Name     string
	Severity string
	Match    func(status int, body string, contentType string) bool
}

func ExposureScan(urls []string, w io.Writer, cookie string, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector) {
	fmt.Fprintln(w, "┌─ [PHASE 8] OPENAPI & SENSITIVE FILE DISCOVERY")

	hosts := uniqueHosts(urls)
	if len(hosts) == 0 {
		fmt.Fprintln(w, "└─ No hosts found, skipping")
		return
	}

	probes := []exposureProbe{
		{Path: "/.env", Name: ".env file", Severity: "high", Match: matchEnv},
		{Path: "/.git/config", Name: ".git config", Severity: "high", Match: matchGitConfig},
		{Path: "/config.php~", Name: "backup config", Severity: "high", Match: matchAnyNonHTML},
		{Path: "/backup.zip", Name: "backup archive", Severity: "medium", Match: matchArchive},
		{Path: "/db.sql", Name: "database dump", Severity: "high", Match: matchSQLDump},
		{Path: "/swagger.json", Name: "Swagger JSON", Severity: "medium", Match: matchOpenAPI},
		{Path: "/openapi.json", Name: "OpenAPI JSON", Severity: "medium", Match: matchOpenAPI},
		{Path: "/api-docs", Name: "API docs", Severity: "medium", Match: matchOpenAPIOrDocs},
		{Path: "/v2/api-docs", Name: "Swagger v2 docs", Severity: "medium", Match: matchOpenAPI},
		{Path: "/v3/api-docs", Name: "OpenAPI v3 docs", Severity: "medium", Match: matchOpenAPI},
		{Path: "/swagger-ui/", Name: "Swagger UI", Severity: "low", Match: matchSwaggerUI},
		{Path: "/.well-known/security.txt", Name: "security.txt", Severity: "info", Match: matchSecurityTxt},
	}

	total := len(hosts) * len(probes)
	if sb != nil {
		sb.SetPhase("EXPOSURE", int64(total))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	found := 0
	for _, host := range hosts {
		for _, probe := range probes {
			target := strings.TrimRight(host, "/") + probe.Path
			if sb != nil {
				sb.Log("├─ %s\n", ui.Truncate(target, ui.MaxURLLen))
			}
			if limiter != nil {
				<-limiter
			}
			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				continue
			}
			ApplyHeaders(req, cookie)
			resp, err := client.Do(req)
			if err != nil {
				if sb != nil {
					sb.Tick(1)
				}
				continue
			}
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			resp.Body.Close()

			body := string(bodyBytes)
			contentType := resp.Header.Get("Content-Type")
			if probe.Match(resp.StatusCode, body, contentType) {
				found++
				level := ui.LevelWarning
				if probe.Severity == "high" {
					level = ui.LevelVulnerability
				} else if probe.Severity == "info" {
					level = ui.LevelInfo
				}
				fmt.Fprintf(w, "│  [FOUND] %s at %s (HTTP %d)\n", probe.Name, target, resp.StatusCode)
				if rc != nil {
					rc.AddFinding(ui.Finding{
						Type:     ui.VulnExposure,
						Level:    level,
						URL:      target,
						Payload:  probe.Name,
						Detail:   fmt.Sprintf("HTTP %d %s", resp.StatusCode, contentType),
						Severity: probe.Severity,
					})
				}
				if isOpenAPIProbe(probe.Path) {
					addOpenAPIEndpoints(target, body, rc)
				}
			}
			if sb != nil {
				sb.Tick(1)
			}
		}
	}

	if found == 0 {
		fmt.Fprintln(w, "├─ Status: No exposed API docs or sensitive files detected")
	} else {
		fmt.Fprintf(w, "├─ Found: %d exposure/API documentation items\n", found)
	}
	fmt.Fprintln(w, "└─ Exposure discovery complete")
}

func matchEnv(status int, body string, contentType string) bool {
	if status != http.StatusOK || looksHTML(contentType, body) {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "app_key=") || strings.Contains(lower, "db_password=") || strings.Contains(lower, "aws_secret") || strings.Contains(lower, "secret_key=")
}

func matchGitConfig(status int, body string, contentType string) bool {
	return status == http.StatusOK && strings.Contains(body, "[core]") && strings.Contains(body, "repositoryformatversion")
}

func matchAnyNonHTML(status int, body string, contentType string) bool {
	return status == http.StatusOK && !looksHTML(contentType, body) && len(strings.TrimSpace(body)) > 20
}

func matchArchive(status int, body string, contentType string) bool {
	ct := strings.ToLower(contentType)
	return status == http.StatusOK && (strings.Contains(ct, "zip") || strings.HasPrefix(body, "PK"))
}

func matchSQLDump(status int, body string, contentType string) bool {
	lower := strings.ToLower(body)
	return status == http.StatusOK && !looksHTML(contentType, body) && (strings.Contains(lower, "create table") || strings.Contains(lower, "insert into"))
}

func matchOpenAPI(status int, body string, contentType string) bool {
	if status != http.StatusOK {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, `"openapi"`) || strings.Contains(lower, `"swagger"`)
}

func matchOpenAPIOrDocs(status int, body string, contentType string) bool {
	return matchOpenAPI(status, body, contentType) || matchSwaggerUI(status, body, contentType)
}

func matchSwaggerUI(status int, body string, contentType string) bool {
	if status != http.StatusOK {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "swagger-ui") || strings.Contains(lower, "swagger ui") || strings.Contains(lower, "openapi")
}

func matchSecurityTxt(status int, body string, contentType string) bool {
	lower := strings.ToLower(body)
	return status == http.StatusOK && (strings.Contains(lower, "contact:") || strings.Contains(lower, "policy:"))
}

func looksHTML(contentType, body string) bool {
	lowerCT := strings.ToLower(contentType)
	lowerBody := strings.ToLower(strings.TrimSpace(body))
	return strings.Contains(lowerCT, "text/html") || strings.HasPrefix(lowerBody, "<!doctype html") || strings.HasPrefix(lowerBody, "<html")
}

func isOpenAPIProbe(path string) bool {
	return strings.Contains(path, "swagger") || strings.Contains(path, "openapi") || strings.Contains(path, "api-docs")
}

func addOpenAPIEndpoints(baseURL, body string, rc *ui.ReportCollector) {
	if rc == nil || body == "" {
		return
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	matches := openAPIPathRE.FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		path := strings.ReplaceAll(match[1], `\/`, `/`)
		if !strings.HasPrefix(path, "/") || seen[path] {
			continue
		}
		seen[path] = true
		u := *base
		u.Path = path
		u.RawQuery = ""
		rc.AddSitemapURL(u.String())
	}
}
