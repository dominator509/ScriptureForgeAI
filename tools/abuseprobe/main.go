package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"
)

type config struct {
	APIBase           string
	BearerToken       string
	Origin            string
	ConfigArtifactURL string
	ReleaseCandidate  string
	ServiceVersion    string
	Attempts          int
	Timeout           time.Duration
}

type report struct {
	ObservedAt             string        `json:"observed_at"`
	APITarget              string        `json:"api_target"`
	WebOrigin              string        `json:"web_origin"`
	ConfigArtifact         string        `json:"config_artifact_url"`
	ConfigArtifactVerified bool          `json:"config_artifact_verified"`
	ConfigArtifactSummary  string        `json:"config_artifact_summary"`
	ReleaseCandidate       string        `json:"release_candidate"`
	ServiceVersion         string        `json:"service_version"`
	ThresholdPass          bool          `json:"threshold_pass"`
	Probes                 []probeResult `json:"probes"`
	EvidenceItems          []string      `json:"evidence_items"`
}

type probeResult struct {
	Name                     string `json:"name"`
	Target                   string `json:"target"`
	Passed                   bool   `json:"passed"`
	Attempts                 int    `json:"attempts"`
	StatusCode               int    `json:"status_code,omitempty"`
	RetryAfter               string `json:"retry_after,omitempty"`
	RateLimit                string `json:"rate_limit,omitempty"`
	RateRemaining            string `json:"rate_limit_remaining,omitempty"`
	RateReset                string `json:"rate_limit_reset,omitempty"`
	AccountScoped            bool   `json:"account_scoped,omitempty"`
	RefreshTokenScoped       bool   `json:"refresh_token_scoped,omitempty"`
	ForwardedClientIPRotated bool   `json:"forwarded_client_ip_rotated,omitempty"`
	WebSocketUpgrade         bool   `json:"websocket_upgrade,omitempty"`
	ResultSummary            string `json:"result_summary"`
}

type endpointProbe struct {
	Name             string
	Method           string
	Path             string
	Body             []byte
	Auth             bool
	Origin           bool
	WebSocketUpgrade bool
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
	flag.StringVar(&cfg.APIBase, "api-base", "", "deployed API base URL, for example https://api.staging.example")
	flag.StringVar(&cfg.BearerToken, "bearer-token", os.Getenv("STAGING_ABUSE_BEARER_TOKEN"), "staging bearer token for protected abuse probes")
	flag.StringVar(&cfg.Origin, "origin", os.Getenv("STAGING_ABUSE_ORIGIN"), "allowed staging web origin for room stream probe")
	flag.StringVar(&cfg.ConfigArtifactURL, "config-artifact-url", os.Getenv("STAGING_ABUSE_CONFIG_ARTIFACT_URL"), "redacted staging ABUSE_LIMIT_* configuration artifact URL")
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("STAGING_RELEASE_CANDIDATE"), "exact git SHA or release candidate represented by this abuse evidence")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("STAGING_ABUSE_SERVICE_VERSION"), "exact API/service version represented by this abuse evidence")
	flag.IntVar(&cfg.Attempts, "attempts", 35, "maximum attempts per profile; set above deployed ABUSE_LIMIT_* values")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-request timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	return runWithClient(cfg, output, &http.Client{Timeout: cfg.Timeout})
}

func runWithClient(cfg config, output io.Writer, client *http.Client) error {
	if cfg.APIBase == "" {
		return errors.New("-api-base is required")
	}
	if cfg.BearerToken == "" {
		return errors.New("-bearer-token or STAGING_ABUSE_BEARER_TOKEN is required")
	}
	configArtifact, err := normalizeArtifactURL(cfg.ConfigArtifactURL)
	if err != nil {
		return err
	}
	if cfg.Attempts < 2 {
		return errors.New("-attempts must be at least 2")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if strings.TrimSpace(cfg.Origin) == "" {
		return errors.New("-origin or STAGING_ABUSE_ORIGIN is required for the WebSocket abuse probe")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" {
		return errors.New("abuse proof requires release-candidate and service-version")
	}
	apiBase, err := normalizeBaseURL(cfg.APIBase)
	if err != nil {
		return err
	}
	origin, err := normalizeOriginURL(cfg.Origin)
	if err != nil {
		return err
	}
	cfg.Origin = origin
	if err := requireDistinctArtifactHost(configArtifact, apiBase, origin); err != nil {
		return err
	}

	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	releaseMarkers := []string{
		"release_candidate=" + cfg.ReleaseCandidate,
		"service_version=" + cfg.ServiceVersion,
	}
	configArtifactSummary, err := validateConfigArtifact(client, configArtifact, releaseMarkers)
	if err != nil {
		return err
	}
	probes := []endpointProbe{
		{Name: "auth-rate-limit", Method: http.MethodPost, Path: "/api/v1/auth/login", Body: []byte(`{"email":"abuse-probe@example.invalid","password":"invalid"}`)},
		{Name: "auth-account-rate-limit", Method: http.MethodPost, Path: "/api/v1/auth/login", Body: []byte(`{"email":"abuse-account-probe@example.invalid","password":"invalid","organization_id":"abuse-probe-org"}`)},
		{Name: "auth-refresh-rate-limit", Method: http.MethodPost, Path: "/api/v1/auth/refresh", Body: []byte(`{"refresh_token":"abuse-refresh-token","organization_id":"abuse-probe-org"}`)},
		{Name: "ai-rate-limit", Method: http.MethodPost, Path: "/api/v1/ai/generate/study", Body: []byte(`{"topic":"abuse readiness probe"}`), Auth: true},
		{Name: "journal-rate-limit", Method: http.MethodPost, Path: "/api/v1/journal_entries", Body: []byte(`{"ciphertext":"YWJ1c2UtcHJvYmUtc2VhbGVkLXBheWxvYWQ=","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:abuse-probe","salt_version":1}`), Auth: true},
		{Name: "rooms-rate-limit", Method: http.MethodGet, Path: "/api/v1/rooms/active", Auth: true},
		{Name: "websocket-rate-limit", Method: http.MethodGet, Path: "/api/v1/rooms/stream/abuse-probe-room", Auth: true, Origin: true, WebSocketUpgrade: true},
	}

	results := make([]probeResult, 0, len(probes))
	for _, probe := range probes {
		results = append(results, runEndpointProbe(client, apiBase, cfg, probe))
	}

	result := report{
		ObservedAt:             time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		APITarget:              apiBase,
		WebOrigin:              cfg.Origin,
		ConfigArtifact:         configArtifact,
		ConfigArtifactVerified: true,
		ConfigArtifactSummary:  configArtifactSummary + "; distinct_abuse_artifacts=true",
		ReleaseCandidate:       cfg.ReleaseCandidate,
		ServiceVersion:         cfg.ServiceVersion,
		ThresholdPass:          true,
		Probes:                 results,
		EvidenceItems:          []string{"ABUSE-LIMIT-001"},
	}
	for _, probe := range results {
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
		return errors.New("one or more abuse probes failed")
	}
	return nil
}

func validateConfigArtifact(client *http.Client, target string, releaseMarkers []string) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return "", fmt.Errorf("config artifact request: %w", err)
	}
	req.Header.Set("User-Agent", "scriptureforge-abuseprobe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("config artifact fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("config artifact returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("config artifact read failed: %w", err)
	}
	text := string(body)
	required := append(abuseConfigArtifactMarkers(), releaseMarkers...)
	if !containsAllFold(text, required) {
		return "", fmt.Errorf("config artifact missing required staging markers: %s", strings.Join(required, ", "))
	}
	if err := requirePositiveAbuseConfigAssignments(text); err != nil {
		return "", err
	}
	if !containsNoneFold(text, forbiddenConfigArtifactMarkers()) {
		return "", errors.New("config artifact contains forbidden local/mock/secret markers")
	}
	return "config artifact verified markers: " + strings.Join(required, ", "), nil
}

func requirePositiveAbuseConfigAssignments(text string) error {
	for _, key := range abuseConfigAssignmentKeys() {
		value, ok := extractConfigAssignment(text, key)
		if !ok {
			return fmt.Errorf("config artifact missing required assignment %s=<positive integer>", key)
		}
		if value <= 0 {
			return fmt.Errorf("config artifact assignment %s must be a positive integer", key)
		}
	}
	return nil
}

func extractConfigAssignment(text, key string) (int, bool) {
	for _, field := range strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(field)), key+"=") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(field), key+"="))
		value, err := strconv.Atoi(raw)
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

func abuseConfigArtifactMarkers() []string {
	return []string{
		"staging artifact",
		"ABUSE_LIMIT_AUTH_REQUESTS=",
		"ABUSE_LIMIT_AUTH_WINDOW_SECONDS=",
		"ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=",
		"ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=",
		"ABUSE_LIMIT_AI_REQUESTS=",
		"ABUSE_LIMIT_JOURNAL_REQUESTS=",
		"ABUSE_LIMIT_ROOMS_REQUESTS=",
		"ABUSE_LIMIT_WEBSOCKET_REQUESTS=",
		"ABUSE_LIMIT_MAX_BUCKETS=",
		"TRUST_PROXY_HEADERS=true",
		"X-Forwarded-For",
		"X-Real-IP",
		"redacted",
	}
}

func abuseConfigAssignmentKeys() []string {
	return []string{
		"ABUSE_LIMIT_AUTH_REQUESTS",
		"ABUSE_LIMIT_AUTH_WINDOW_SECONDS",
		"ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS",
		"ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS",
		"ABUSE_LIMIT_AI_REQUESTS",
		"ABUSE_LIMIT_JOURNAL_REQUESTS",
		"ABUSE_LIMIT_ROOMS_REQUESTS",
		"ABUSE_LIMIT_WEBSOCKET_REQUESTS",
		"ABUSE_LIMIT_MAX_BUCKETS",
	}
}

func forbiddenConfigArtifactMarkers() []string {
	return []string{
		"mock",
		"placeholder",
		"synthetic",
		"stubbed",
		"test-only",
		"dry-run",
		"local-only",
		"localhost",
		"127.0.0.1",
		"::1",
		"DATABASE_URL=postgres://",
		"JWT_SECRET_KEY=",
		"OPENAI_API_KEY=sk-",
		"ZOOM_WEBHOOK_SECRET_TOKEN=",
		"client_secret",
		"bearer ",
	}
}

func containsAllFold(text string, markers []string) bool {
	lower := strings.ToLower(text)
	for _, marker := range markers {
		if !strings.Contains(lower, strings.ToLower(marker)) {
			return false
		}
	}
	return true
}

func containsNoneFold(text string, markers []string) bool {
	lower := strings.ToLower(text)
	for _, marker := range markers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return false
		}
	}
	return true
}

func runEndpointProbe(client *http.Client, apiBase string, cfg config, probe endpointProbe) probeResult {
	target := strings.TrimRight(apiBase, "/") + probe.Path
	result := probeResult{
		Name:               probe.Name,
		Target:             target,
		Attempts:           cfg.Attempts,
		AccountScoped:      probe.Name == "auth-account-rate-limit",
		RefreshTokenScoped: probe.Name == "auth-refresh-rate-limit",
		WebSocketUpgrade:   probe.WebSocketUpgrade,
	}
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		status, retryAfter, rateLimit, rateRemaining, rateReset, err := sendProbeRequest(client, target, cfg, probe, attempt)
		if err != nil {
			result.StatusCode = 0
			result.ResultSummary = err.Error()
			return result
		}
		result.StatusCode = status
		result.RetryAfter = retryAfter
		result.RateLimit = rateLimit
		result.RateRemaining = rateRemaining
		result.RateReset = rateReset
		if probe.Name == "auth-account-rate-limit" {
			result.ForwardedClientIPRotated = attempt >= 2
		}
		if status == http.StatusTooManyRequests {
			result.Attempts = attempt
			result.Passed = attempt >= 2 && hasRequiredHeadersAndValues(retryAfter, rateLimit, rateRemaining, rateReset)
			result.ResultSummary = fmt.Sprintf("got 429 with Retry-After=%q X-RateLimit-Limit=%q X-RateLimit-Remaining=%q X-RateLimit-Reset=%q after %d attempts", retryAfter, rateLimit, rateRemaining, rateReset, attempt)
			if !result.Passed {
				if attempt < 2 {
					result.ResultSummary = "got 429 before repeated attempts could prove rate-limit behavior"
				} else {
					result.ResultSummary = "got 429 without required rate-limit headers"
				}
			} else {
				markers := append(abuseSummaryMarkers(probe),
					"release_candidate="+cfg.ReleaseCandidate,
					"service_version="+cfg.ServiceVersion,
				)
				result.ResultSummary += "; verified markers: " + strings.Join(markers, ", ")
			}
			return result
		}
	}
	result.ResultSummary = fmt.Sprintf("no 429 observed after %d attempts; lower staging ABUSE_LIMIT_* values or raise -attempts", cfg.Attempts)
	return result
}

func abuseSummaryMarkers(probe endpointProbe) []string {
	markers := []string{
		"staging artifact",
		probe.Name,
		"429",
		"after",
		"attempts",
		"repeated_attempts_verified=true",
		"Retry-After",
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
	}
	if probe.WebSocketUpgrade {
		markers = append(markers, "websocket upgrade", "websocket_upgrade=true")
	}
	if probe.Name == "auth-account-rate-limit" {
		markers = append(markers, "account-scoped login", "account_scoped=true", "rotating forwarded client IP", "forwarded_client_ip_rotated=true")
	}
	if probe.Name == "auth-refresh-rate-limit" {
		markers = append(markers, "refresh token", "refresh_token_scoped=true")
	}
	return markers
}

func hasRequiredHeadersAndValues(retryAfter, limit, remaining, reset string) bool {
	if retryAfter == "" || limit == "" || remaining == "" || reset == "" {
		return false
	}
	retryAfterValue, err := strconv.Atoi(retryAfter)
	if err != nil || retryAfterValue <= 0 {
		return false
	}
	limitValue, err := strconv.Atoi(limit)
	if err != nil || limitValue <= 0 {
		return false
	}
	remainingValue, err := strconv.Atoi(remaining)
	if err != nil || remainingValue != 0 {
		return false
	}
	resetValue, err := strconv.Atoi(reset)
	if err != nil || resetValue <= 0 {
		return false
	}
	return true
}

func sendProbeRequest(client *http.Client, target string, cfg config, probe endpointProbe, attempt int) (int, string, string, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, probe.Method, target, bytes.NewReader(probe.Body))
	if err != nil {
		return 0, "", "", "", "", err
	}
	req.Header.Set("User-Agent", "scriptureforge-abuseprobe/1.0")
	req.Header.Set("X-ScriptureForge-Probe", probe.Name)
	if probe.Name == "auth-account-rate-limit" {
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d, 10.0.0.25", attempt))
		req.Header.Set("X-Real-IP", fmt.Sprintf("198.51.100.%d", attempt))
	}
	if len(probe.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if probe.Auth {
		req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	}
	if probe.Origin && cfg.Origin != "" {
		req.Header.Set("Origin", cfg.Origin)
	}
	if probe.WebSocketUpgrade {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", "", "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode,
		resp.Header.Get("Retry-After"),
		resp.Header.Get("X-RateLimit-Limit"),
		resp.Header.Get("X-RateLimit-Remaining"),
		resp.Header.Get("X-RateLimit-Reset"),
		nil
}

func normalizeBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", errors.New("api-base must use https")
	}
	if parsed.Host == "" {
		return "", errors.New("api-base must include a host")
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", errors.New("api-base must use a non-local, non-private staging host")
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", errors.New("api-base must not use a reserved placeholder staging host")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeOriginURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", errors.New("origin must use https")
	}
	if parsed.Host == "" {
		return "", errors.New("origin must include a host")
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", errors.New("origin must use a non-local, non-private staging host")
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", errors.New("origin must not use a reserved placeholder staging host")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeArtifactURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", errors.New("-config-artifact-url or STAGING_ABUSE_CONFIG_ARTIFACT_URL must use https")
	}
	if parsed.Host == "" {
		return "", errors.New("-config-artifact-url or STAGING_ABUSE_CONFIG_ARTIFACT_URL must include a host")
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", errors.New("-config-artifact-url or STAGING_ABUSE_CONFIG_ARTIFACT_URL must use a non-local, non-private staging host")
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", errors.New("-config-artifact-url or STAGING_ABUSE_CONFIG_ARTIFACT_URL must not use a reserved placeholder staging host")
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func requireDistinctArtifactHost(artifactURL, apiBase, origin string) error {
	artifact, err := url.Parse(artifactURL)
	if err != nil {
		return err
	}
	artifactHost := canonicalEvidenceHost(artifact.Hostname())
	for label, candidate := range map[string]string{
		"api-base": apiBase,
		"origin":   origin,
	} {
		parsed, err := url.Parse(candidate)
		if err != nil {
			return err
		}
		if artifactHost == canonicalEvidenceHost(parsed.Hostname()) {
			return fmt.Errorf("-config-artifact-url must use a distinct evidence host from %s", label)
		}
	}
	return nil
}

func canonicalEvidenceHost(host string) string {
	normalized := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	return strings.TrimRight(normalized, ".")
}

func isLocalOrPrivateHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(host), "[]")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())
}

func isReservedPlaceholderHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if normalized == "" {
		return false
	}
	return strings.HasSuffix(normalized, ".example") ||
		normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		normalized == "example.org" ||
		strings.HasSuffix(normalized, ".example.org") ||
		normalized == "example.net" ||
		strings.HasSuffix(normalized, ".example.net") ||
		strings.HasSuffix(normalized, ".test") ||
		strings.HasSuffix(normalized, ".invalid")
}
