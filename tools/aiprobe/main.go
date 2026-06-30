package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	aiRequestIDPattern      = regexp.MustCompile(`(?i)\brequest_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	aiCitationIDPattern     = regexp.MustCompile(`(?i)\bcitation_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	aiOrganizationIDPattern = regexp.MustCompile(`(?i)\borganization_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	aiUserIDPattern         = regexp.MustCompile(`(?i)\buser_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	aiProviderPattern       = regexp.MustCompile(`(?i)\bAI_PROVIDER=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	aiChatModelPattern      = regexp.MustCompile(`(?i)\bAI_CHAT_MODEL=([A-Za-z0-9][A-Za-z0-9._:/-]*)\b`)
	aiHTTPEndpointPattern   = regexp.MustCompile(`(?i)\bAI_CHAT_ENDPOINT=(https://[^\s;,]+)\b`)
	aiHTTPTimeoutMSPattern  = regexp.MustCompile(`(?i)\bAI_HTTP_TIMEOUT_MS=([1-9][0-9]*)\b`)
	aiMaxRetriesPattern     = regexp.MustCompile(`(?i)\bAI_MAX_RETRIES=([0-9]+)\b`)
)

type config struct {
	ProviderArtifactURL    string
	GenerationArtifactURL  string
	DegradationArtifactURL string
	CitationArtifactURL    string
	AuditArtifactURL       string
	ReleaseCandidate       string
	ServiceVersion         string
	Timeout                time.Duration
}

type artifactTarget struct {
	Label string
	URL   string
}

type report struct {
	ObservedAt       string        `json:"observed_at"`
	ThresholdPass    bool          `json:"threshold_pass"`
	ReleaseCandidate string        `json:"release_candidate"`
	ServiceVersion   string        `json:"service_version"`
	Probes           []probeResult `json:"probes"`
	EvidenceItems    []string      `json:"evidence_items"`
}

type probeResult struct {
	Name            string `json:"name"`
	Target          string `json:"target"`
	Passed          bool   `json:"passed"`
	StatusCode      int    `json:"status_code,omitempty"`
	LatencyMS       int64  `json:"latency_ms,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	CitationID      string `json:"citation_id,omitempty"`
	OrganizationID  string `json:"organization_id,omitempty"`
	UserID          string `json:"user_id,omitempty"`
	AIProvider      string `json:"ai_provider,omitempty"`
	AIChatModel     string `json:"ai_chat_model,omitempty"`
	AIChatEndpoint  string `json:"ai_chat_endpoint,omitempty"`
	AIHTTPTimeout   string `json:"ai_http_timeout_ms,omitempty"`
	AIMaxRetries    string `json:"ai_max_retries,omitempty"`
	ProviderTimeout bool   `json:"provider_timeout,omitempty"`
	RetryExhausted  bool   `json:"retry_exhausted,omitempty"`
	FailClosed      bool   `json:"fail_closed,omitempty"`
	ResultSummary   string `json:"result_summary"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.ProviderArtifactURL, "provider-artifact-url", os.Getenv("STAGING_AI_PROVIDER_ARTIFACT_URL"), "AI provider/model/config readiness artifact URL")
	flag.StringVar(&cfg.GenerationArtifactURL, "generation-artifact-url", os.Getenv("STAGING_AI_GENERATION_ARTIFACT_URL"), "authenticated AI generation artifact URL")
	flag.StringVar(&cfg.DegradationArtifactURL, "degradation-artifact-url", os.Getenv("STAGING_AI_DEGRADATION_ARTIFACT_URL"), "AI provider-timeout/fail-closed degradation artifact URL")
	flag.StringVar(&cfg.CitationArtifactURL, "citation-artifact-url", os.Getenv("STAGING_AI_CITATION_ARTIFACT_URL"), "citation verification artifact URL")
	flag.StringVar(&cfg.AuditArtifactURL, "audit-artifact-url", os.Getenv("STAGING_AI_AUDIT_ARTIFACT_URL"), "ai_request_logs/citation_trails query artifact URL")
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("RELEASE_CANDIDATE"), "exact release candidate SHA being proven")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("SERVICE_VERSION"), "deployed service version being proven")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	return runWithClient(cfg, output, &http.Client{Timeout: cfg.Timeout})
}

func runWithClient(cfg config, output io.Writer, client *http.Client) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.ProviderArtifactURL == "" || cfg.GenerationArtifactURL == "" || cfg.DegradationArtifactURL == "" || cfg.CitationArtifactURL == "" || cfg.AuditArtifactURL == "" {
		return errors.New("AI proof requires provider, generation, degradation, citation, and audit artifact URLs")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" {
		return errors.New("AI proof requires -release-candidate and -service-version")
	}
	var err error
	cfg.ProviderArtifactURL, err = normalizeArtifactURL(cfg.ProviderArtifactURL, "provider-artifact-url")
	if err != nil {
		return err
	}
	cfg.GenerationArtifactURL, err = normalizeArtifactURL(cfg.GenerationArtifactURL, "generation-artifact-url")
	if err != nil {
		return err
	}
	cfg.DegradationArtifactURL, err = normalizeArtifactURL(cfg.DegradationArtifactURL, "degradation-artifact-url")
	if err != nil {
		return err
	}
	cfg.CitationArtifactURL, err = normalizeArtifactURL(cfg.CitationArtifactURL, "citation-artifact-url")
	if err != nil {
		return err
	}
	cfg.AuditArtifactURL, err = normalizeArtifactURL(cfg.AuditArtifactURL, "audit-artifact-url")
	if err != nil {
		return err
	}
	if err := requireDistinctArtifactURLs([]artifactTarget{
		{Label: "provider-artifact-url", URL: cfg.ProviderArtifactURL},
		{Label: "generation-artifact-url", URL: cfg.GenerationArtifactURL},
		{Label: "degradation-artifact-url", URL: cfg.DegradationArtifactURL},
		{Label: "citation-artifact-url", URL: cfg.CitationArtifactURL},
		{Label: "audit-artifact-url", URL: cfg.AuditArtifactURL},
	}); err != nil {
		return err
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	releaseMarkers := []string{
		fmt.Sprintf("release_candidate=%s", cfg.ReleaseCandidate),
		fmt.Sprintf("service_version=%s", cfg.ServiceVersion),
	}

	probes := []probeResult{
		probeArtifact(client, "ai-provider-config", cfg.ProviderArtifactURL, append([]string{"AI_PROVIDER", "AI_CHAT_MODEL", "AI_CHAT_ENDPOINT", "AI_HTTP_TIMEOUT_MS", "AI_MAX_RETRIES", "OPENAI_API_KEY redacted", "configured"}, releaseMarkers...), forbiddenArtifactMarkers(true)),
		probeArtifact(client, "ai-generation-route", cfg.GenerationArtifactURL, append([]string{"/api/v1/ai/generate/study", "authenticated", "JWT claims", "organization_id=", "user_id=", "request_id=", "200", "generated_curriculum", "[Genesis 1:1]"}, releaseMarkers...), forbiddenArtifactMarkers(true)),
		probeArtifact(client, "ai-timeout-degradation", cfg.DegradationArtifactURL, append([]string{"provider timeout", "degradation", "retry exhausted", "503", "fail closed", "AI_ORCHESTRATION_ENGINE_FAULT"}, releaseMarkers...), forbiddenArtifactMarkers(true)),
		probeArtifact(client, "ai-citation-verification", cfg.CitationArtifactURL, append([]string{"no-citation rejected", "hallucinated citation rejected", "verified citation accepted", "citation_trails", "citation_id="}, releaseMarkers...), forbiddenArtifactMarkers(false)),
		probeArtifact(client, "ai-audit-persistence", cfg.AuditArtifactURL, append([]string{"ai_request_logs", "citation_trails", "organization_id=", "user_id=", "request_id=", "citation_id=", "succeeded", "failed", "verified", "tenant rls", "cross-tenant hidden", "distinct_ai_artifacts=true"}, releaseMarkers...), forbiddenArtifactMarkers(false)),
	}
	enforceAIRequestIDLinkage(probes)
	enforceCitationIDLinkage(probes)
	enforceAITenantPrincipalLinkage(probes)

	result := report{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass:    true,
		ReleaseCandidate: cfg.ReleaseCandidate,
		ServiceVersion:   cfg.ServiceVersion,
		Probes:           probes,
		EvidenceItems:    []string{"EXT-AI-001"},
	}
	for _, probe := range probes {
		if !probe.Passed {
			result.ThresholdPass = false
			break
		}
	}

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	if !result.ThresholdPass {
		return errors.New("one or more AI probes failed")
	}
	return nil
}

func enforceAITenantPrincipalLinkage(probes []probeResult) {
	var generationOrganizationID string
	var generationUserID string
	var auditIndex = -1
	for i := range probes {
		switch probes[i].Name {
		case "ai-generation-route":
			generationOrganizationID = probes[i].OrganizationID
			generationUserID = probes[i].UserID
		case "ai-audit-persistence":
			auditIndex = i
		}
	}
	if generationOrganizationID == "" || generationUserID == "" || auditIndex < 0 {
		return
	}
	if probes[auditIndex].OrganizationID != generationOrganizationID {
		probes[auditIndex].Passed = false
		probes[auditIndex].ResultSummary += fmt.Sprintf("; organization_id %q does not match generation organization_id %q", probes[auditIndex].OrganizationID, generationOrganizationID)
	}
	if probes[auditIndex].UserID != generationUserID {
		probes[auditIndex].Passed = false
		probes[auditIndex].ResultSummary += fmt.Sprintf("; user_id %q does not match generation user_id %q", probes[auditIndex].UserID, generationUserID)
	}
}

func enforceCitationIDLinkage(probes []probeResult) {
	var citationID string
	var auditIndex = -1
	for i := range probes {
		switch probes[i].Name {
		case "ai-citation-verification":
			citationID = probes[i].CitationID
		case "ai-audit-persistence":
			auditIndex = i
		}
	}
	if citationID == "" || auditIndex < 0 {
		return
	}
	if probes[auditIndex].CitationID != citationID {
		probes[auditIndex].Passed = false
		probes[auditIndex].ResultSummary += fmt.Sprintf("; citation_id %q does not match citation verification citation_id %q", probes[auditIndex].CitationID, citationID)
	}
}

func enforceAIRequestIDLinkage(probes []probeResult) {
	var generationRequestID string
	var auditIndex = -1
	for i := range probes {
		switch probes[i].Name {
		case "ai-generation-route":
			generationRequestID = probes[i].RequestID
		case "ai-audit-persistence":
			auditIndex = i
		}
	}
	if generationRequestID == "" || auditIndex < 0 {
		return
	}
	if probes[auditIndex].RequestID != generationRequestID {
		probes[auditIndex].Passed = false
		probes[auditIndex].ResultSummary += fmt.Sprintf("; request_id %q does not match generation request_id %q", probes[auditIndex].RequestID, generationRequestID)
	}
}

func requireDistinctArtifactURLs(targets []artifactTarget) error {
	seen := map[string]string{}
	for _, target := range targets {
		normalized, err := canonicalArtifactURL(target.URL)
		if err != nil {
			return fmt.Errorf("%s artifact URL: %w", target.Label, err)
		}
		if normalized == "" {
			continue
		}
		if previous, ok := seen[normalized]; ok {
			return fmt.Errorf("%s must be a distinct artifact URL; duplicates %s", target.Label, previous)
		}
		seen[normalized] = target.Label
	}
	return nil
}

func canonicalArtifactURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if host == "" {
		return "", errors.New("missing host")
	}
	if scheme == "https" && port == "443" {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	} else {
		parsed.Host = host
	}
	parsed.Scheme = scheme
	parsed.Fragment = ""
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String(), nil
}

func probeArtifact(client *http.Client, name, target string, required []string, forbidden []string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-aiprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	text := string(body)
	requestID := ""
	citationID := ""
	organizationID := ""
	userID := ""
	if name == "ai-generation-route" || name == "ai-audit-persistence" {
		requestID = extractAIRequestID(text)
		organizationID = extractAIOrganizationID(text)
		userID = extractAIUserID(text)
	}
	if name == "ai-citation-verification" || name == "ai-audit-persistence" {
		citationID = extractAICitationID(text)
	}
	aiProvider := ""
	aiChatModel := ""
	aiChatEndpoint := ""
	aiHTTPTimeout := ""
	aiMaxRetries := ""
	if name == "ai-provider-config" {
		aiProvider = extractAIProvider(text)
		aiChatModel = extractAIChatModel(text)
		aiChatEndpoint = extractAIChatEndpoint(text)
		aiHTTPTimeout = extractAIHTTPTimeoutMS(text)
		aiMaxRetries = extractAIMaxRetries(text)
	}
	providerTimeout := false
	retryExhausted := false
	failClosed := false
	if name == "ai-timeout-degradation" {
		providerTimeout = containsAllFold(text, []string{"provider timeout"})
		retryExhausted = containsAllFold(text, []string{"retry exhausted"})
		failClosed = containsAllFold(text, []string{"fail closed", "AI_ORCHESTRATION_ENGINE_FAULT"})
	}
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && containsAllFold(text, required) && containsNoneFold(text, forbidden)
	if name == "ai-provider-config" && (aiProvider == "" || aiChatModel == "" || aiChatEndpoint == "" || aiHTTPTimeout == "" || aiMaxRetries == "") {
		passed = false
	}
	if name == "ai-timeout-degradation" && (!providerTimeout || !retryExhausted || !failClosed) {
		passed = false
	}
	if (name == "ai-generation-route" || name == "ai-audit-persistence") && requestID == "" {
		passed = false
	}
	if (name == "ai-generation-route" || name == "ai-audit-persistence") && (organizationID == "" || userID == "") {
		passed = false
	}
	if (name == "ai-citation-verification" || name == "ai-audit-persistence") && citationID == "" {
		passed = false
	}
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary += "; artifact missing required AI markers, leaks forbidden provider secret material, or is marked mock/placeholder"
	} else {
		summary += "; staging artifact; verified markers: " + strings.Join(required, ", ")
		exactMarkers := exactAIMarkers(name, requestID, citationID, organizationID, userID, aiProvider, aiChatModel, aiChatEndpoint, aiHTTPTimeout, aiMaxRetries, providerTimeout, retryExhausted, failClosed)
		if len(exactMarkers) > 0 {
			summary += "; " + strings.Join(exactMarkers, "; ")
		}
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, RequestID: requestID, CitationID: citationID, OrganizationID: organizationID, UserID: userID, AIProvider: aiProvider, AIChatModel: aiChatModel, AIChatEndpoint: aiChatEndpoint, AIHTTPTimeout: aiHTTPTimeout, AIMaxRetries: aiMaxRetries, ProviderTimeout: providerTimeout, RetryExhausted: retryExhausted, FailClosed: failClosed, ResultSummary: summary}
}

func exactAIMarkers(name, requestID, citationID, organizationID, userID, aiProvider, aiChatModel, aiChatEndpoint, aiHTTPTimeout, aiMaxRetries string, providerTimeout, retryExhausted, failClosed bool) []string {
	markers := []string{}
	if name == "ai-provider-config" {
		markers = append(markers, fmt.Sprintf("AI_PROVIDER=%s", aiProvider), fmt.Sprintf("AI_CHAT_MODEL=%s", aiChatModel), fmt.Sprintf("AI_CHAT_ENDPOINT=%s", aiChatEndpoint), fmt.Sprintf("AI_HTTP_TIMEOUT_MS=%s", aiHTTPTimeout), fmt.Sprintf("AI_MAX_RETRIES=%s", aiMaxRetries))
	}
	if name == "ai-timeout-degradation" {
		markers = append(markers, fmt.Sprintf("provider_timeout=%t", providerTimeout), fmt.Sprintf("retry_exhausted=%t", retryExhausted), fmt.Sprintf("fail_closed=%t", failClosed))
	}
	if name == "ai-generation-route" || name == "ai-audit-persistence" {
		markers = append(markers, fmt.Sprintf("organization_id=%s", organizationID), fmt.Sprintf("user_id=%s", userID), fmt.Sprintf("request_id=%s", requestID))
	}
	if name == "ai-citation-verification" || name == "ai-audit-persistence" {
		markers = append(markers, fmt.Sprintf("citation_id=%s", citationID))
	}
	return markers
}

func extractAIProvider(text string) string {
	match := aiProviderPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAIChatModel(text string) string {
	match := aiChatModelPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAIChatEndpoint(text string) string {
	match := aiHTTPEndpointPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAIHTTPTimeoutMS(text string) string {
	match := aiHTTPTimeoutMSPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAIMaxRetries(text string) string {
	match := aiMaxRetriesPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAIRequestID(text string) string {
	match := aiRequestIDPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAICitationID(text string) string {
	match := aiCitationIDPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAIOrganizationID(text string) string {
	match := aiOrganizationIDPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAIUserID(text string) string {
	match := aiUserIDPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func containsAllFold(text string, needles []string) bool {
	lowerText := strings.ToLower(text)
	for _, needle := range needles {
		if !strings.Contains(lowerText, strings.ToLower(needle)) {
			return false
		}
	}
	return true
}

func containsNoneFold(text string, needles []string) bool {
	lowerText := strings.ToLower(text)
	for _, needle := range needles {
		if strings.Contains(lowerText, strings.ToLower(needle)) {
			return false
		}
	}
	return true
}

func normalizeArtifactURL(raw, field string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("-%s must use https", field)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("-%s must include a host", field)
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not use a reserved placeholder artifact host", field)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must use a public staging artifact host", field)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func isReservedPlaceholderHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	return normalized == "example" ||
		strings.HasSuffix(normalized, ".example") ||
		normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		normalized == "example.org" ||
		strings.HasSuffix(normalized, ".example.org") ||
		normalized == "example.net" ||
		strings.HasSuffix(normalized, ".example.net") ||
		normalized == "test" ||
		strings.HasSuffix(normalized, ".test") ||
		normalized == "invalid" ||
		strings.HasSuffix(normalized, ".invalid")
}

func isLocalOrPrivateHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(host), "[]")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())
}

func forbiddenArtifactMarkers(includeSecrets bool) []string {
	markers := []string{
		"mock",
		"mocked",
		"placeholder",
		"sample artifact",
		"synthetic",
		"fake provider",
		"stubbed",
		"test-only",
		"dry-run",
		"local-only",
		"localhost",
		"127.0.0.1",
		"citation verification disabled",
		"citations disabled",
		"skip citation verification",
		"audit logging disabled",
		"audit persistence disabled",
		"ai_request_logs disabled",
		"citation_trails disabled",
	}
	if includeSecrets {
		markers = append(markers,
			"OPENAI_API_KEY=",
			"Authorization: Bearer",
			"sk-",
			"api_key=",
		)
	}
	return markers
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
