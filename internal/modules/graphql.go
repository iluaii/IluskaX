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

const graphqlCompactIntrospectionQuery = `query IluskaXIntrospection{schema:__schema{queryType{name}mutationType{name}subscriptionType{name}types{kind name fields(includeDeprecated:true){name args{name type{kind name ofType{kind name ofType{kind name}}}}type{kind name ofType{kind name ofType{kind name}}}}}}}`

var graphqlIntrospectionBypassTokens = []struct {
	name  string
	token string
}{
	{name: "newline after __schema", token: "__schema\n"},
	{name: "comma after __schema", token: "__schema,"},
	{name: "comment after __schema", token: "__schema # IluskaX\n"},
}

type graphqlRequest struct {
	Query string `json:"query"`
}

type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Extensions map[string]json.RawMessage `json:"extensions"`
}

type graphqlSchemaResponse struct {
	Data struct {
		Schema      graphqlSchema `json:"__schema"`
		SchemaAlias graphqlSchema `json:"schema"`
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
	SupportsPOSTForm     bool
	SupportsGET          bool
	ProbeTransport       string
	IntrospectionProbe   string
	IntrospectionEnabled bool
	BatchingEnabled      bool
	VerboseErrors        bool
	BrowserSubmittable   bool
	PersistedQueryHint   bool
	FederationSDLExposed bool
	AliasAccepted        bool
	DebugSignals         []string
	IDEExposures         []string
	RiskyOperations      []string
	Schema               *graphqlSchema
}

type GraphQLScanOptions struct {
	SchemaDir  string
	SchemaFile string
	BaseURL    string
	Endpoints  []string
}

type graphqlSchemaArtifact struct {
	Endpoint              string   `json:"endpoint"`
	Transport             string   `json:"transport"`
	IntrospectionProbe    string   `json:"introspection_probe,omitempty"`
	IntrospectionEnabled  bool     `json:"introspection_enabled"`
	BatchingEnabled       bool     `json:"batching_enabled"`
	VerboseErrors         bool     `json:"verbose_errors"`
	BrowserSubmittable    bool     `json:"browser_submittable"`
	PersistedQueryHint    bool     `json:"persisted_query_hint"`
	FederationSDLExposed  bool     `json:"federation_sdl_exposed"`
	AliasAccepted         bool     `json:"alias_accepted"`
	DebugSignals          []string `json:"debug_signals,omitempty"`
	IDEExposures          []string `json:"ide_exposures,omitempty"`
	RiskyOperations       []string `json:"risky_operations,omitempty"`
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

	candidates := graphqlCandidates(graphqlScanInputs(urls, opts))
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
		result.IntrospectionEnabled, result.Schema, result.VerboseErrors, result.IntrospectionProbe = probeGraphQLIntrospection(client, result, cookie)

		if limiter != nil {
			<-limiter
		}
		result.VerboseErrors = result.VerboseErrors || probeGraphQLVerboseErrors(client, result, cookie)

		if limiter != nil {
			<-limiter
		}
		result.DebugSignals = probeGraphQLDebugSignals(client, result, cookie)

		if limiter != nil {
			<-limiter
		}
		result.PersistedQueryHint = probeGraphQLPersistedQuery(client, result.URL, cookie)

		if limiter != nil {
			<-limiter
		}
		result.FederationSDLExposed = probeGraphQLFederation(client, result, cookie)

		if limiter != nil {
			<-limiter
		}
		result.AliasAccepted = probeGraphQLAliases(client, result, cookie)

		if limiter != nil {
			<-limiter
		}
		result.IDEExposures = probeGraphQLIDEs(client, endpoint, cookie)

		if result.SupportsPOST {
			if limiter != nil {
				<-limiter
			}
			result.BatchingEnabled = probeGraphQLBatching(client, endpoint, cookie)
		}

		result.BrowserSubmittable = result.SupportsGET || result.SupportsPOSTForm
		result.RiskyOperations = graphqlRiskyOperations(result.Schema, 50)

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

func graphqlScanInputs(urls []string, opts GraphQLScanOptions) []string {
	inputs := append([]string{}, urls...)
	baseURLs := graphqlBaseURLs(opts.BaseURL, urls)
	for _, endpoint := range opts.Endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		parsed, err := url.Parse(endpoint)
		if err == nil && parsed.Scheme != "" && parsed.Host != "" {
			inputs = append(inputs, parsed.String())
			continue
		}
		for _, base := range baseURLs {
			ref, err := url.Parse(endpoint)
			if err != nil {
				continue
			}
			inputs = append(inputs, base.ResolveReference(ref).String())
		}
	}
	if len(inputs) == 0 {
		for _, base := range baseURLs {
			inputs = append(inputs, base.String())
		}
	}
	return inputs
}

func graphqlBaseURLs(baseURL string, urls []string) []*url.URL {
	seen := map[string]bool{}
	var bases []*url.URL
	add := func(raw string) {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return
		}
		parsed.Path = "/"
		parsed.RawQuery = ""
		parsed.Fragment = ""
		key := parsed.Scheme + "://" + parsed.Host
		if seen[key] {
			return
		}
		seen[key] = true
		bases = append(bases, parsed)
	}
	add(baseURL)
	for _, raw := range urls {
		add(raw)
	}
	return bases
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

		for _, apiCandidate := range graphqlAPIPrefixCandidates(parsed) {
			add(apiCandidate)
		}
	}

	commonPaths := []string{"/graphql", "/graphql/v1", "/api", "/api/graphql", "/api/graphql/v1", "/api/query", "/api/v1/graphql", "/v1", "/v1/graphql", "/query", "/gql", "/gateway"}
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

func graphqlAPIPrefixCandidates(parsed *url.URL) []string {
	if parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	var candidates []string
	for i, part := range parts {
		lower := strings.ToLower(part)
		if lower != "api" && lower != "graphql" && lower != "gql" && lower != "gateway" && lower != "query" && !isVersionPathSegment(lower) {
			continue
		}
		for end := i + 1; end <= len(parts) && end <= i+2; end++ {
			candidate := *parsed
			candidate.Path = "/" + strings.Join(parts[:end], "/")
			candidate.RawQuery = ""
			candidate.Fragment = ""
			candidates = append(candidates, candidate.String())
		}
	}
	return candidates
}

func isVersionPathSegment(segment string) bool {
	if len(segment) < 2 || segment[0] != 'v' {
		return false
	}
	for _, r := range segment[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func probeGraphQLEndpoint(client *http.Client, endpoint, cookie string) (graphqlEndpointResult, bool) {
	result := graphqlEndpointResult{URL: endpoint}
	body, status, err := doGraphQLPost(client, endpoint, cookie, graphqlRequest{Query: "query IluskaXProbe { __typename }"})
	if err == nil && status < 500 && looksLikeGraphQL(body) {
		result.SupportsPOST = true
		result.ProbeTransport = "POST"
	}

	body, status, err = doGraphQLPostForm(client, endpoint, cookie, "query IluskaXProbe { __typename }")
	if err == nil && status < 500 && looksLikeGraphQL(body) {
		result.SupportsPOST = true
		result.SupportsPOSTForm = true
		if result.ProbeTransport == "" {
			result.ProbeTransport = "POST_FORM"
		}
	}

	body, status, err = doGraphQLGet(client, endpoint, cookie, "query IluskaXProbe { __typename }")
	if err == nil && status < 500 && looksLikeGraphQL(body) {
		result.SupportsGET = true
		if result.ProbeTransport == "" {
			result.ProbeTransport = "GET"
		}
	}

	return result, result.SupportsPOST || result.SupportsGET
}

type graphqlIntrospectionProbe struct {
	Name        string
	Transport   string
	Query       string
	RawJSONBody string
	ContentType string
}

func probeGraphQLIntrospection(client *http.Client, result graphqlEndpointResult, cookie string) (bool, *graphqlSchema, bool, string) {
	verbose := false
	for _, probe := range graphqlIntrospectionProbes(result) {
		body, status, err := doGraphQLIntrospectionProbe(client, result.URL, cookie, probe)
		if err != nil || status >= 500 {
			continue
		}

		var parsed graphqlSchemaResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			continue
		}

		verbose = verbose || hasVerboseGraphQLErrors(parsed.Errors)
		schema := parsed.Data.Schema
		if schema.QueryType.Name == "" || len(schema.Types) == 0 {
			schema = parsed.Data.SchemaAlias
		}
		if schema.QueryType.Name == "" || len(schema.Types) == 0 {
			continue
		}
		return true, &schema, verbose, probe.Name
	}
	return false, nil, verbose, ""
}

func graphqlIntrospectionProbes(result graphqlEndpointResult) []graphqlIntrospectionProbe {
	var probes []graphqlIntrospectionProbe
	addPOST := func(name, query string) {
		probes = append(probes, graphqlIntrospectionProbe{
			Name:      name,
			Transport: "POST",
			Query:     query,
		})
	}
	addGET := func(name, query string) {
		probes = append(probes, graphqlIntrospectionProbe{
			Name:      name,
			Transport: "GET",
			Query:     query,
		})
	}
	addPOSTForm := func(name, query string) {
		probes = append(probes, graphqlIntrospectionProbe{
			Name:      name,
			Transport: "POST_FORM",
			Query:     query,
		})
	}

	if result.SupportsPOST {
		addPOST("POST JSON", graphqlIntrospectionQuery)
		for _, bypass := range graphqlIntrospectionBypassTokens {
			addPOST("POST JSON "+bypass.name, graphqlSchemaTokenQuery(graphqlIntrospectionQuery, bypass.token))
		}
		addPOST("POST JSON compact alias", graphqlCompactIntrospectionQuery)
		for _, bypass := range graphqlIntrospectionBypassTokens {
			addPOST("POST JSON compact alias "+bypass.name, graphqlSchemaTokenQuery(graphqlCompactIntrospectionQuery, bypass.token))
		}
		addPOSTForm("POST form query parameter", graphqlIntrospectionQuery)
		for _, bypass := range graphqlIntrospectionBypassTokens {
			addPOSTForm("POST form "+bypass.name, graphqlSchemaTokenQuery(graphqlIntrospectionQuery, bypass.token))
		}
		probes = append(probes, graphqlIntrospectionProbe{
			Name:        "POST application/graphql",
			Transport:   "POST_RAW",
			Query:       graphqlCompactIntrospectionQuery,
			ContentType: "application/graphql",
		})
		probes = append(probes, graphqlIntrospectionProbe{
			Name:        "POST JSON unicode escaped introspection token",
			Transport:   "POST_RAW",
			RawJSONBody: graphqlUnicodeEscapedRequest(graphqlIntrospectionQuery),
			ContentType: "application/json",
		})
	}
	if result.SupportsGET {
		addGET("GET query parameter", graphqlIntrospectionQuery)
		for _, bypass := range graphqlIntrospectionBypassTokens {
			addGET("GET query parameter "+bypass.name, graphqlSchemaTokenQuery(graphqlIntrospectionQuery, bypass.token))
		}
		addGET("GET compact alias query parameter", graphqlCompactIntrospectionQuery)
		for _, bypass := range graphqlIntrospectionBypassTokens {
			addGET("GET compact alias query parameter "+bypass.name, graphqlSchemaTokenQuery(graphqlCompactIntrospectionQuery, bypass.token))
		}
	}
	return probes
}

func graphqlSchemaTokenQuery(query, token string) string {
	if strings.Contains(query, "schema:__schema{") {
		return strings.Replace(query, "schema:__schema{", "schema:"+token+"{", 1)
	}
	if strings.Contains(query, "schema:__schema {") {
		return strings.Replace(query, "schema:__schema {", "schema:"+token+" {", 1)
	}
	if strings.Contains(query, "__schema{") {
		return strings.Replace(query, "__schema{", token+"{", 1)
	}
	return strings.Replace(query, "__schema {", token+" {", 1)
}

func doGraphQLIntrospectionProbe(client *http.Client, endpoint, cookie string, probe graphqlIntrospectionProbe) ([]byte, int, error) {
	switch probe.Transport {
	case "GET":
		return doGraphQLGet(client, endpoint, cookie, probe.Query)
	case "POST_FORM":
		return doGraphQLPostForm(client, endpoint, cookie, probe.Query)
	case "POST_RAW":
		body := probe.RawJSONBody
		if body == "" {
			body = probe.Query
		}
		return doGraphQLPostRaw(client, endpoint, cookie, []byte(body), probe.ContentType)
	default:
		return doGraphQLPost(client, endpoint, cookie, graphqlRequest{Query: probe.Query})
	}
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

func probeGraphQLVerboseErrors(client *http.Client, result graphqlEndpointResult, cookie string) bool {
	body, status, err := doGraphQLQuery(client, result, cookie, "query IluskaXInvalidField { profilee { id } }")
	if err != nil || status >= 500 {
		return false
	}
	var parsed graphqlResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	return hasVerboseGraphQLErrors(parsed.Errors)
}

func probeGraphQLDebugSignals(client *http.Client, result graphqlEndpointResult, cookie string) []string {
	body, status, err := doGraphQLQuery(client, result, cookie, "query IluskaXDebugProbe { __typename }")
	if err != nil || status >= 500 {
		return nil
	}

	var signals []string
	var parsed graphqlResponse
	if err := json.Unmarshal(body, &parsed); err == nil {
		for key := range parsed.Extensions {
			lower := strings.ToLower(key)
			switch {
			case strings.Contains(lower, "tracing"):
				signals = append(signals, "extensions."+key)
			case strings.Contains(lower, "cachecontrol") || strings.Contains(lower, "cache_control"):
				signals = append(signals, "extensions."+key)
			case strings.Contains(lower, "debug"):
				signals = append(signals, "extensions."+key)
			}
		}
	}

	lowerBody := strings.ToLower(string(body))
	for _, marker := range []string{"stacktrace", "stack trace", "\"exception\"", "\"debug\"", "extensions.tracing"} {
		if strings.Contains(lowerBody, marker) {
			signals = append(signals, marker)
		}
	}
	return uniqueStrings(signals)
}

func probeGraphQLPersistedQuery(client *http.Client, endpoint, cookie string) bool {
	payload := map[string]interface{}{
		"operationName": "IluskaXPersistedQueryProbe",
		"variables":     map[string]interface{}{},
		"extensions": map[string]interface{}{
			"persistedQuery": map[string]interface{}{
				"version":    1,
				"sha256Hash": strings.Repeat("0", 64),
			},
		},
	}
	body, status, err := doGraphQLPost(client, endpoint, cookie, payload)
	if err != nil || status >= 500 {
		return false
	}
	lowerBody := strings.ToLower(string(body))
	return strings.Contains(lowerBody, "persistedquerynotfound") ||
		strings.Contains(lowerBody, "persisted query not found") ||
		strings.Contains(lowerBody, "persistedquerynotsupported") ||
		strings.Contains(lowerBody, "persisted query")
}

func probeGraphQLFederation(client *http.Client, result graphqlEndpointResult, cookie string) bool {
	body, status, err := doGraphQLQuery(client, result, cookie, "query IluskaXFederationProbe { _service { sdl } }")
	if err != nil || status >= 500 {
		return false
	}

	var parsed struct {
		Data struct {
			Service struct {
				SDL string `json:"sdl"`
			} `json:"_service"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	return strings.TrimSpace(parsed.Data.Service.SDL) != ""
}

func probeGraphQLAliases(client *http.Client, result graphqlEndpointResult, cookie string) bool {
	body, status, err := doGraphQLQuery(client, result, cookie, "query IluskaXAliasProbe { a: __typename b: __typename c: __typename }")
	if err != nil || status >= 500 {
		return false
	}
	var parsed graphqlResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	return len(parsed.Data) > 0 && string(parsed.Data) != "null" && len(parsed.Errors) == 0
}

func probeGraphQLIDEs(client *http.Client, endpoint, cookie string) []string {
	var found []string
	for _, candidate := range graphqlIDEURLs(endpoint) {
		body, status, contentType, err := doGraphQLRawGet(client, candidate, cookie, "text/html,application/xhtml+xml")
		if err != nil || status >= 500 {
			continue
		}
		if !strings.Contains(strings.ToLower(contentType), "html") && !looksLikeGraphQLIDE(body) {
			continue
		}
		if name := graphqlIDEName(body); name != "" {
			found = append(found, fmt.Sprintf("%s at %s", name, candidate))
		}
	}
	return uniqueStrings(found)
}

func graphqlIDEURLs(endpoint string) []string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return []string{endpoint}
	}

	paths := []string{parsed.EscapedPath(), "/graphql", "/graphiql", "/playground", "/graphql/playground", "/graphql/console", "/altair", "/api/graphql"}
	var urls []string
	for _, p := range paths {
		if p == "" {
			p = "/"
		}
		u := *parsed
		u.Path = p
		u.RawQuery = ""
		u.Fragment = ""
		urls = append(urls, u.String())
	}
	return uniqueStrings(urls)
}

func looksLikeGraphQLIDE(body []byte) bool {
	return graphqlIDEName(body) != ""
}

func graphqlIDEName(body []byte) string {
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "apollo sandbox") || strings.Contains(lower, "embeddablesandbox"):
		return "Apollo Sandbox"
	case strings.Contains(lower, "graphql playground") || strings.Contains(lower, "graphql-playground"):
		return "GraphQL Playground"
	case strings.Contains(lower, "graphiql"):
		return "GraphiQL"
	case strings.Contains(lower, "altair"):
		return "Altair GraphQL Client"
	}
	return ""
}

func doGraphQLQuery(client *http.Client, result graphqlEndpointResult, cookie, query string) ([]byte, int, error) {
	if result.ProbeTransport == "GET" || (!result.SupportsPOST && result.SupportsGET) {
		return doGraphQLGet(client, result.URL, cookie, query)
	}
	if result.ProbeTransport == "POST_FORM" {
		return doGraphQLPostForm(client, result.URL, cookie, query)
	}
	return doGraphQLPost(client, result.URL, cookie, graphqlRequest{Query: query})
}

func doGraphQLPost(client *http.Client, endpoint, cookie string, payload interface{}) ([]byte, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	return doGraphQLPostRaw(client, endpoint, cookie, data, "application/json")
}

func doGraphQLPostRaw(client *http.Client, endpoint, cookie string, data []byte, contentType string) ([]byte, int, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	ApplyHeaders(req, cookie)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return body, resp.StatusCode, err
}

func doGraphQLPostForm(client *http.Client, endpoint, cookie, query string) ([]byte, int, error) {
	data := url.Values{}
	data.Set("query", query)
	return doGraphQLPostRaw(client, endpoint, cookie, []byte(data.Encode()), "application/x-www-form-urlencoded")
}

func graphqlUnicodeEscapedRequest(query string) string {
	data, err := json.Marshal(query)
	if err != nil {
		return `{"query":"query IluskaXIntrospection { \u005f\u005fschema { queryType { name } } }"}`
	}
	escapedQuery := strings.ReplaceAll(string(data), "__schema", `\u005f\u005fschema`)
	return `{"query":` + escapedQuery + `}`
}

func doGraphQLGet(client *http.Client, endpoint, cookie, query string) ([]byte, int, error) {
	getURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, 0, err
	}
	q := getURL.Query()
	q.Set("query", query)
	getURL.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", getURL.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	ApplyHeaders(req, cookie)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return body, resp.StatusCode, err
}

func doGraphQLRawGet(client *http.Client, endpoint, cookie, accept string) ([]byte, int, string, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, 0, "", err
	}
	ApplyHeaders(req, cookie)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return body, resp.StatusCode, resp.Header.Get("Content-Type"), err
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
			Payload:  graphqlIntrospectionPayload(result),
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
	if result.BrowserSubmittable {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelWarning,
			URL:      result.URL,
			Payload:  "Browser-submittable GraphQL transport",
			Detail:   "GET or form POST accepted",
			Severity: "low",
		})
	}
	if len(result.IDEExposures) > 0 {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelWarning,
			URL:      result.URL,
			Payload:  "GraphQL IDE exposed",
			Detail:   strings.Join(result.IDEExposures, "; "),
			Severity: "medium",
		})
	}
	if len(result.DebugSignals) > 0 {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelWarning,
			URL:      result.URL,
			Payload:  "GraphQL debug metadata exposed",
			Detail:   strings.Join(result.DebugSignals, ", "),
			Severity: "low",
		})
	}
	if result.PersistedQueryHint {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelInfo,
			URL:      result.URL,
			Payload:  "Persisted query support hinted",
			Detail:   "Apollo persisted query response observed",
			Severity: "info",
		})
	}
	if result.FederationSDLExposed {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelWarning,
			URL:      result.URL,
			Payload:  "Apollo Federation SDL exposed",
			Detail:   "_service { sdl } returned schema SDL",
			Severity: "medium",
		})
	}
	if len(result.RiskyOperations) > 0 {
		rc.AddFinding(ui.Finding{
			Type:     ui.VulnGraphQL,
			Level:    ui.LevelWarning,
			URL:      result.URL,
			Payload:  "Sensitive GraphQL operations in schema",
			Detail:   strings.Join(limitStrings(result.RiskyOperations, 8), "; "),
			Severity: "medium",
		})
	}
}

func logGraphQLResult(w io.Writer, result graphqlEndpointResult) {
	fmt.Fprintf(w, "│  [FOUND] %s (%s)\n", result.URL, graphqlTransportSummary(result))
	if result.IntrospectionEnabled {
		fmt.Fprintf(w, "│  [WARN] Introspection enabled: %s\n", graphqlSchemaSummary(result.Schema))
		if result.IntrospectionProbe != "" && result.IntrospectionProbe != "POST JSON" {
			fmt.Fprintf(w, "│  [WARN] Introspection bypass/alternate probe worked: %s\n", result.IntrospectionProbe)
		}
	} else {
		fmt.Fprintln(w, "│  [INFO] Introspection disabled or blocked")
	}
	if result.BatchingEnabled {
		fmt.Fprintln(w, "│  [WARN] JSON batching accepted")
	}
	if result.VerboseErrors {
		fmt.Fprintln(w, "│  [WARN] Verbose GraphQL validation errors exposed")
	}
	if result.BrowserSubmittable {
		fmt.Fprintln(w, "│  [WARN] Browser-submittable transport accepted (GET or form POST)")
	}
	if len(result.IDEExposures) > 0 {
		fmt.Fprintf(w, "│  [WARN] GraphQL IDE exposed: %s\n", strings.Join(result.IDEExposures, "; "))
	}
	if len(result.DebugSignals) > 0 {
		fmt.Fprintf(w, "│  [WARN] Debug metadata exposed: %s\n", strings.Join(result.DebugSignals, ", "))
	}
	if result.PersistedQueryHint {
		fmt.Fprintln(w, "│  [INFO] Persisted query support hinted")
	}
	if result.FederationSDLExposed {
		fmt.Fprintln(w, "│  [WARN] Apollo Federation SDL exposed via _service { sdl }")
	}
	if result.AliasAccepted {
		fmt.Fprintln(w, "│  [INFO] GraphQL aliases accepted")
	}
	if len(result.RiskyOperations) > 0 {
		fmt.Fprintf(w, "│  [WARN] Sensitive operations: %s\n", strings.Join(limitStrings(result.RiskyOperations, 6), "; "))
	}
}

func graphqlIntrospectionPayload(result graphqlEndpointResult) string {
	if result.IntrospectionProbe == "" || result.IntrospectionProbe == "POST JSON" {
		return "Introspection enabled"
	}
	return "Introspection enabled via " + result.IntrospectionProbe
}

func graphqlTransportSummary(result graphqlEndpointResult) string {
	var methods []string
	if result.SupportsPOST {
		methods = append(methods, "POST")
	}
	if result.SupportsPOSTForm {
		methods = append(methods, "POST_FORM")
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
			IntrospectionProbe:   result.IntrospectionProbe,
			IntrospectionEnabled: result.IntrospectionEnabled,
			BatchingEnabled:      result.BatchingEnabled,
			VerboseErrors:        result.VerboseErrors,
			BrowserSubmittable:   result.BrowserSubmittable,
			PersistedQueryHint:   result.PersistedQueryHint,
			FederationSDLExposed: result.FederationSDLExposed,
			AliasAccepted:        result.AliasAccepted,
			DebugSignals:         result.DebugSignals,
			IDEExposures:         result.IDEExposures,
			RiskyOperations:      result.RiskyOperations,
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

func graphqlRiskyOperations(schema *graphqlSchema, limit int) []string {
	if schema == nil {
		return nil
	}
	typeByName := map[string]graphqlType{}
	for _, t := range schema.Types {
		typeByName[t.Name] = t
	}

	keywords := []string{
		"admin", "apikey", "api_key", "auth", "backup", "changeemail", "changepassword",
		"create", "delete", "disablemfa", "export", "impersonate", "invite", "login",
		"password", "payment", "permission", "reset", "role", "secret",
		"token", "upload", "webhook",
	}
	var risky []string
	appendRisky := func(label, typeName string) {
		if typeName == "" || len(risky) >= limit {
			return
		}
		t, ok := typeByName[typeName]
		if !ok {
			return
		}
		for _, f := range t.Fields {
			if len(risky) >= limit {
				return
			}
			haystack := strings.ToLower(f.Name)
			if label == "mutation" {
				haystack += " mutation"
			}
			for _, keyword := range keywords {
				if strings.Contains(haystack, keyword) {
					risky = append(risky, fmt.Sprintf("%s %s%s: %s", label, f.Name, graphqlArgsString(f.Args), graphqlTypeString(f.Type)))
					break
				}
			}
		}
	}
	appendRisky("query", schema.QueryType.Name)
	appendRisky("mutation", schema.MutationType.Name)
	appendRisky("subscription", schema.SubscriptionType.Name)
	return uniqueStrings(risky)
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

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func limitStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	out := append([]string{}, values[:limit]...)
	out = append(out, fmt.Sprintf("+%d more", len(values)-limit))
	return out
}
