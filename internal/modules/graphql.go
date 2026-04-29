package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"IluskaX/internal/ui"
)

const graphqlIntrospectionQuery = `query IluskaXIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { name type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}`

type graphqlRequest struct {
	Query string `json:"query"`
}

type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type graphqlSchemaResponse struct {
	Data struct {
		Schema graphqlSchema `json:"__schema"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type graphqlSchema struct {
	QueryType        graphqlNamedType `json:"queryType"`
	MutationType     graphqlNamedType `json:"mutationType"`
	SubscriptionType graphqlNamedType `json:"subscriptionType"`
	Types            []graphqlType    `json:"types"`
}

type graphqlNamedType struct {
	Name string `json:"name"`
}

type graphqlType struct {
	Kind   string         `json:"kind"`
	Name   string         `json:"name"`
	Fields []graphqlField `json:"fields"`
}

type graphqlField struct {
	Name string         `json:"name"`
	Args []graphqlArg   `json:"args"`
	Type graphqlTypeRef `json:"type"`
}

type graphqlArg struct {
	Name string         `json:"name"`
	Type graphqlTypeRef `json:"type"`
}

type graphqlTypeRef struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	OfType *graphqlTypeRef `json:"ofType"`
}

type graphqlEndpointResult struct {
	URL                  string
	SupportsPOST         bool
	SupportsGET          bool
	IntrospectionEnabled bool
	BatchingEnabled      bool
	VerboseErrors        bool
	Schema               *graphqlSchema
}

type GraphQLScanOptions struct {
	SchemaDir  string
	SchemaFile string
}

type graphqlSchemaArtifact struct {
	Endpoint              string   `json:"endpoint"`
	Transport             string   `json:"transport"`
	IntrospectionEnabled  bool     `json:"introspection_enabled"`
	BatchingEnabled       bool     `json:"batching_enabled"`
	VerboseErrors         bool     `json:"verbose_errors"`
	Summary               string   `json:"summary"`
	OperationPreview      []string `json:"operation_preview"`
	Schema                any      `json:"schema,omitempty"`
	SchemaUnavailableNote string   `json:"schema_unavailable_note,omitempty"`
}

func GraphQLScan(urls []string, w io.Writer, cookie string, limiter <-chan time.Time, sb *ui.StatusBar, rc *ui.ReportCollector, opts GraphQLScanOptions) {
	fmt.Fprintln(w, "┌─ [PHASE 6] GRAPHQL - Safe endpoint, introspection and schema mapping")
	if opts.SchemaDir == "" {
		opts.SchemaDir = filepath.Join("Poutput", "graphql")
	}

	candidates := graphqlCandidates(urls)
	if len(candidates) == 0 {
		fmt.Fprintln(w, "└─ No GraphQL endpoint candidates found")
		return
	}

	fmt.Fprintf(w, "├─ Probing %d endpoint candidates\n", len(candidates))
	if sb != nil {
		sb.SetPhase("GRAPHQL", int64(len(candidates)))
	}

	client := &http.Client{Timeout: 12 * time.Second}
	var found []graphqlEndpointResult

	for i, endpoint := range candidates {
		if sb != nil {
			sb.Log("├─ [%d/%d] %s\n", i+1, len(candidates), ui.Truncate(endpoint, ui.MaxURLLen))
		} else {
			fmt.Fprintf(w, "├─ [%d/%d] %s\n", i+1, len(candidates), endpoint)
		}

		if limiter != nil {
			<-limiter
		}
		result, ok := probeGraphQLEndpoint(client, endpoint, cookie)
		if !ok {
			if sb != nil {
				sb.Tick(1)
			}
			continue
		}

		if limiter != nil {
			<-limiter
		}
		result.IntrospectionEnabled, result.Schema, result.VerboseErrors = probeGraphQLIntrospection(client, endpoint, cookie)

		if limiter != nil {
			<-limiter
		}
		result.VerboseErrors = result.VerboseErrors || probeGraphQLVerboseErrors(client, endpoint, cookie)

		if limiter != nil {
			<-limiter
		}
		result.BatchingEnabled = probeGraphQLBatching(client, endpoint, cookie)

		found = append(found, result)
		recordGraphQLFindings(result, rc)
		logGraphQLResult(w, result)

		if sb != nil {
			sb.Tick(1)
		}
	}

	if len(found) == 0 {
		fmt.Fprintln(w, "├─ No live GraphQL endpoints detected")
		fmt.Fprintln(w, "└─ GraphQL scan complete")
		return
	}

	fmt.Fprintf(w, "├─ Detected %d GraphQL endpoint(s)\n", len(found))
	if saved, err := saveGraphQLSchemas(found, opts); err != nil {
		fmt.Fprintf(w, "├─ [WARN] Could not save GraphQL schema artifacts: %v\n", err)
	} else if len(saved) > 0 {
		for _, path := range saved {
			fmt.Fprintf(w, "├─ Schema artifact saved: %s\n", path)
		}
	}
	fmt.Fprintln(w, "└─ GraphQL scan complete")
}

func graphqlCandidates(urls []string) []string {
	seen := map[string]bool{}
	add := func(raw string) {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return
		}
		parsed.Fragment = ""
		parsed.RawQuery = ""
		key := parsed.String()
		if !seen[key] {
			seen[key] = true
		}
	}

	hosts := map[string]*url.URL{}
	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		base := *parsed
		base.Path = ""
		base.RawQuery = ""
		base.Fragment = ""
		hosts[base.Scheme+"://"+base.Host] = &base

		if parsed.Path == "" || parsed.Path == "/" || !IsStaticAsset(strings.ToLower(parsed.Path)) {
			add(raw)
		}

		cleanPath := strings.ToLower(parsed.EscapedPath())
		switch {
		case strings.Contains(cleanPath, "graphql"):
			add(raw)
		case strings.HasSuffix(cleanPath, "/gql") || strings.HasSuffix(cleanPath, "/query"):
			add(raw)
		}
	}

	commonPaths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"}
	for _, base := range hosts {
		for _, p := range commonPaths {
			candidate := *base
			candidate.Path = p
			add(candidate.String())
		}
	}

	out := make([]string, 0, len(seen))
	for candidate := range seen {
		out = append(out, candidate)
	}
	sort.Strings(out)
	return out
}

func probeGraphQLEndpoint(client *http.Client, endpoint, cookie string) (graphqlEndpointResult, bool) {
	result := graphqlEndpointResult{URL: endpoint}
	body, status, err := doGraphQLPost(client, endpoint, cookie, graphqlRequest{Query: "query IluskaXProbe { __typename }"})
	if err == nil && status < 500 && looksLikeGraphQL(body) {
		result.SupportsPOST = true
	}

	getURL, err := url.Parse(endpoint)
	if err == nil {
		q := getURL.Query()
		q.Set("query", "query IluskaXProbe { __typename }")
		getURL.RawQuery = q.Encode()
		req, reqErr := http.NewRequest("GET", getURL.String(), nil)
		if reqErr == nil {
			ApplyHeaders(req, cookie)
			resp, doErr := client.Do(req)
			if doErr == nil {
				data, readErr := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				resp.Body.Close()
				if readErr == nil && resp.StatusCode < 500 && looksLikeGraphQL(data) {
					result.SupportsGET = true
				}
			}
		}
	}

	return result, result.SupportsPOST || result.SupportsGET
}

func probeGraphQLIntrospection(client *http.Client, endpoint, cookie string) (bool, *graphqlSchema, bool) {
	body, status, err := doGraphQLPost(client, endpoint, cookie, graphqlRequest{Query: graphqlIntrospectionQuery})
	if err != nil || status >= 500 {
		return false, nil, false
	}

	var parsed graphqlSchemaResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, nil, false
	}

	verbose := hasVerboseGraphQLErrors(parsed.Errors)
	if parsed.Data.Schema.QueryType.Name == "" || len(parsed.Data.Schema.Types) == 0 {
		return false, nil, verbose
	}
	return true, &parsed.Data.Schema, verbose
}

func probeGraphQLBatching(client *http.Client, endpoint, cookie string) bool {
	payload := []graphqlRequest{
		{Query: "query IluskaXBatchA { __typename }"},
		{Query: "query IluskaXBatchB { __typename }"},
	}
	body, status, err := doGraphQLPost(client, endpoint, cookie, payload)
	if err != nil || status >= 500 {
		return false
	}
	var batched []graphqlResponse
	if err := json.Unmarshal(body, &batched); err != nil {
		return false
	}
	return len(batched) == 2
}

func probeGraphQLVerboseErrors(client *http.Client, endpoint, cookie string) bool {
	body, status, err := doGraphQLPost(client, endpoint, cookie, graphqlRequest{Query: "query IluskaXInvalidField { profilee { id } }"})
	if err != nil || status >= 500 {
		return false
	}
	var parsed graphqlResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	return hasVerboseGraphQLErrors(parsed.Errors)
}

func doGraphQLPost(client *http.Client, endpoint, cookie string, payload interface{}) ([]byte, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	ApplyHeaders(req, cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return body, resp.StatusCode, err
}

func looksLikeGraphQL(body []byte) bool {
	var parsed graphqlResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	if len(parsed.Data) > 0 && string(parsed.Data) != "null" {
		return true
	}
	for _, e := range parsed.Errors {
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "graphql") ||
			strings.Contains(msg, "query") ||
			strings.Contains(msg, "field") ||
			strings.Contains(msg, "syntax") ||
			strings.Contains(msg, "cannot query") {
			return true
		}
	}
	return false
}

func hasVerboseGraphQLErrors(errors []struct {
	Message string `json:"message"`
}) bool {
	for _, e := range errors {
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "did you mean") ||
			strings.Contains(msg, "cannot query field") ||
			strings.Contains(msg, "unknown argument") {
			return true
		}
	}
	return false
}

func recordGraphQLFindings(result graphqlEndpointResult, rc *ui.ReportCollector) {
	if rc == nil {
		return
	}
	rc.AddFinding(ui.Finding{
		Type:    ui.VulnGraphQL,
		Level:   ui.LevelInfo,
		URL:     result.URL,
		Payload: graphqlTransportSummary(result),
		Detail:  "GraphQL endpoint",
	})
	if result.IntrospectionEnabled {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelWarning,
			URL:      result.URL,
			Payload:  "Introspection enabled",
			Detail:   graphqlSchemaSummary(result.Schema),
			Severity: "medium",
		})
	}
	if result.BatchingEnabled {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelWarning,
			URL:      result.URL,
			Payload:  "JSON batching enabled",
			Detail:   "rate-limit/DoS surface",
			Severity: "low",
		})
	}
	if result.VerboseErrors {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelWarning,
			URL:      result.URL,
			Payload:  "Verbose GraphQL validation errors",
			Detail:   "schema hints exposed",
			Severity: "low",
		})
	}
}

func logGraphQLResult(w io.Writer, result graphqlEndpointResult) {
	fmt.Fprintf(w, "│  [FOUND] %s (%s)\n", result.URL, graphqlTransportSummary(result))
	if result.IntrospectionEnabled {
		fmt.Fprintf(w, "│  [WARN] Introspection enabled: %s\n", graphqlSchemaSummary(result.Schema))
	} else {
		fmt.Fprintln(w, "│  [INFO] Introspection disabled or blocked")
	}
	if result.BatchingEnabled {
		fmt.Fprintln(w, "│  [WARN] JSON batching accepted")
	}
	if result.VerboseErrors {
		fmt.Fprintln(w, "│  [WARN] Verbose GraphQL validation errors exposed")
	}
}

func graphqlTransportSummary(result graphqlEndpointResult) string {
	var methods []string
	if result.SupportsPOST {
		methods = append(methods, "POST")
	}
	if result.SupportsGET {
		methods = append(methods, "GET")
	}
	if len(methods) == 0 {
		return "transport unknown"
	}
	return strings.Join(methods, "+")
}

func saveGraphQLSchemas(results []graphqlEndpointResult, opts GraphQLScanOptions) ([]string, error) {
	artifacts := make([]graphqlSchemaArtifact, 0, len(results))
	for _, result := range results {
		artifact := graphqlSchemaArtifact{
			Endpoint:             result.URL,
			Transport:            graphqlTransportSummary(result),
			IntrospectionEnabled: result.IntrospectionEnabled,
			BatchingEnabled:      result.BatchingEnabled,
			VerboseErrors:        result.VerboseErrors,
			Summary:              graphqlSchemaSummary(result.Schema),
			OperationPreview:     graphqlOperationLines(result.Schema, 100),
			Schema:               result.Schema,
		}
		if result.Schema == nil {
			artifact.SchemaUnavailableNote = "Introspection disabled, blocked, or returned no schema."
		}
		artifacts = append(artifacts, artifact)
	}

	var saved []string
	if opts.SchemaFile != "" {
		if err := os.MkdirAll(filepath.Dir(opts.SchemaFile), 0755); err != nil && filepath.Dir(opts.SchemaFile) != "." {
			return nil, err
		}
		if err := writeGraphQLJSON(opts.SchemaFile, artifacts); err != nil {
			return nil, err
		}
		saved = append(saved, opts.SchemaFile)
		return saved, nil
	}

	if err := os.MkdirAll(opts.SchemaDir, 0755); err != nil {
		return nil, err
	}
	for _, artifact := range artifacts {
		path := filepath.Join(opts.SchemaDir, graphqlArtifactFilename(artifact.Endpoint))
		if err := writeGraphQLJSON(path, artifact); err != nil {
			return saved, err
		}
		saved = append(saved, path)
	}
	return saved, nil
}

func writeGraphQLJSON(path string, value interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func graphqlArtifactFilename(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "graphql_schema.json"
	}
	raw := parsed.Host + parsed.EscapedPath()
	if raw == "" {
		raw = endpoint
	}
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" {
		name = "graphql"
	}
	return name + "_schema.json"
}

func graphqlSchemaSummary(schema *graphqlSchema) string {
	if schema == nil {
		return "schema unavailable"
	}
	q := countGraphQLFields(schema, schema.QueryType.Name)
	m := countGraphQLFields(schema, schema.MutationType.Name)
	s := countGraphQLFields(schema, schema.SubscriptionType.Name)
	return fmt.Sprintf("queries=%d mutations=%d subscriptions=%d types=%d", q, m, s, len(schema.Types))
}

func countGraphQLFields(schema *graphqlSchema, typeName string) int {
	if schema == nil || typeName == "" {
		return 0
	}
	for _, t := range schema.Types {
		if t.Name == typeName {
			return len(t.Fields)
		}
	}
	return 0
}

func graphqlOperationLines(schema *graphqlSchema, limit int) []string {
	if schema == nil {
		return nil
	}
	typeByName := map[string]graphqlType{}
	for _, t := range schema.Types {
		typeByName[t.Name] = t
	}

	var lines []string
	appendFields := func(label, typeName string) {
		if typeName == "" || len(lines) >= limit {
			return
		}
		t, ok := typeByName[typeName]
		if !ok {
			return
		}
		for _, f := range t.Fields {
			if len(lines) >= limit {
				return
			}
			lines = append(lines, fmt.Sprintf("%s %s%s: %s", label, f.Name, graphqlArgsString(f.Args), graphqlTypeString(f.Type)))
		}
	}
	appendFields("query", schema.QueryType.Name)
	appendFields("mutation", schema.MutationType.Name)
	appendFields("subscription", schema.SubscriptionType.Name)
	return lines
}

func graphqlArgsString(args []graphqlArg) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		parts = append(parts, arg.Name+": "+graphqlTypeString(arg.Type))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func graphqlTypeString(ref graphqlTypeRef) string {
	if ref.Kind == "NON_NULL" && ref.OfType != nil {
		return graphqlTypeString(*ref.OfType) + "!"
	}
	if ref.Kind == "LIST" && ref.OfType != nil {
		return "[" + graphqlTypeString(*ref.OfType) + "]"
	}
	if ref.Name != "" {
		return ref.Name
	}
	if ref.OfType != nil {
		return graphqlTypeString(*ref.OfType)
	}
	return ref.Kind
}
