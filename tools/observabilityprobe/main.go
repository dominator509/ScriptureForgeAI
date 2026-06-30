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

var alertDeliveryIDPattern = regexp.MustCompile(`(?i)\bdelivery_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)

type config struct {
	ProbeOTEL          bool
	ProbeAlerts        bool
	CollectorConfigURL string
	APIMetricsURL      string
	RustMetricsURL     string
	TraceQueryURL      string
	LogQueryURL        string
	TraceID            string
	ObservedRoute      string
	HTTPMethod         string
	TenantID           string
	UserID             string
	Role               string
	DashboardURL       string
	AlertRulesURL      string
	AlertmanagerURL    string
	AlertName          string
	AlertReceiver      string
	RetentionURL       string
	ReleaseCandidate   string
	ServiceVersion     string
	Timeout            time.Duration
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
	TraceID          string        `json:"trace_id,omitempty"`
	ObservedRoute    string        `json:"observed_route,omitempty"`
	HTTPMethod       string        `json:"http_method,omitempty"`
	TenantID         string        `json:"tenant_id,omitempty"`
	UserID           string        `json:"user_id,omitempty"`
	Role             string        `json:"role,omitempty"`
	AlertName        string        `json:"alert_name,omitempty"`
	AlertReceiver    string        `json:"alert_receiver,omitempty"`
	Probes           []probeResult `json:"probes"`
	EvidenceItems    []string      `json:"evidence_items"`
}

type probeResult struct {
	Name          string `json:"name"`
	Target        string `json:"target"`
	Passed        bool   `json:"passed"`
	StatusCode    int    `json:"status_code,omitempty"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	DeliveryID    string `json:"delivery_id,omitempty"`
	ResultSummary string `json:"result_summary"`
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
	flag.BoolVar(&cfg.ProbeOTEL, "probe-otel", false, "probe deployed OpenTelemetry collector, trace/log search, API metrics, and concrete Rust counter evidence")
	flag.BoolVar(&cfg.ProbeAlerts, "probe-alerts", false, "probe deployed dashboard, alert rules, alert manager, and retention evidence")
	flag.StringVar(&cfg.CollectorConfigURL, "collector-config-url", os.Getenv("STAGING_COLLECTOR_CONFIG_URL"), "URL exposing redacted collector or deployment config for OTLP proof")
	flag.StringVar(&cfg.APIMetricsURL, "api-metrics-url", os.Getenv("STAGING_API_METRICS_URL"), "deployed Go API Prometheus metrics URL")
	flag.StringVar(&cfg.RustMetricsURL, "rust-metrics-url", os.Getenv("STAGING_RUST_METRICS_URL"), "deployed Rust engine Prometheus metrics URL")
	flag.StringVar(&cfg.TraceQueryURL, "trace-query-url", os.Getenv("STAGING_TRACE_QUERY_URL"), "trace backend query URL expected to include -trace-id")
	flag.StringVar(&cfg.LogQueryURL, "log-query-url", os.Getenv("STAGING_LOG_QUERY_URL"), "log backend query URL expected to include -trace-id")
	flag.StringVar(&cfg.TraceID, "trace-id", os.Getenv("STAGING_TRACE_ID"), "trace ID to verify in trace and log backend query results")
	flag.StringVar(&cfg.ObservedRoute, "observed-route", os.Getenv("STAGING_OBSERVED_ROUTE"), "HTTP route path represented by the trace/log evidence, for example /api/v1/ai/generate/study")
	flag.StringVar(&cfg.HTTPMethod, "http-method", os.Getenv("STAGING_OBSERVED_HTTP_METHOD"), "HTTP method represented by the trace/log evidence, for example POST")
	flag.StringVar(&cfg.TenantID, "tenant-id", os.Getenv("STAGING_OBSERVED_TENANT_ID"), "tenant ID expected in log correlation evidence")
	flag.StringVar(&cfg.UserID, "user-id", os.Getenv("STAGING_OBSERVED_USER_ID"), "user ID expected in log correlation evidence")
	flag.StringVar(&cfg.Role, "role", os.Getenv("STAGING_OBSERVED_ROLE"), "role expected in log correlation evidence")
	flag.StringVar(&cfg.DashboardURL, "dashboard-url", os.Getenv("STAGING_DASHBOARD_URL"), "Grafana/dashboard URL or export URL for ScriptureForge overview")
	flag.StringVar(&cfg.AlertRulesURL, "alert-rules-url", os.Getenv("STAGING_ALERT_RULES_URL"), "deployed alert-rules URL or Prometheus rule API URL")
	flag.StringVar(&cfg.AlertmanagerURL, "alertmanager-url", os.Getenv("STAGING_ALERTMANAGER_URL"), "Alertmanager status or test-delivery evidence URL")
	flag.StringVar(&cfg.AlertName, "alert-name", os.Getenv("STAGING_ALERT_NAME"), "alert name represented by alert delivery evidence, for example ScriptureForgeHighErrorRate")
	flag.StringVar(&cfg.AlertReceiver, "alert-receiver", os.Getenv("STAGING_ALERT_RECEIVER"), "Alertmanager receiver represented by alert delivery evidence")
	flag.StringVar(&cfg.RetentionURL, "retention-url", os.Getenv("STAGING_RETENTION_URL"), "telemetry retention policy proof URL")
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("RELEASE_CANDIDATE"), "release candidate Git SHA or tag expected in observability evidence")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("SERVICE_VERSION"), "service version expected in observability evidence")
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
	if !cfg.ProbeOTEL && !cfg.ProbeAlerts {
		return errors.New("at least one of -probe-otel or -probe-alerts is required")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" {
		return errors.New("observability proof requires -release-candidate and -service-version")
	}
	if cfg.ProbeOTEL {
		if cfg.CollectorConfigURL == "" || cfg.APIMetricsURL == "" || cfg.RustMetricsURL == "" || cfg.TraceQueryURL == "" || cfg.LogQueryURL == "" || cfg.TraceID == "" {
			return errors.New("-probe-otel requires collector, API metrics, Rust counter metrics, trace query, log query, and trace ID inputs")
		}
		if !isValidTraceID(cfg.TraceID) {
			return errors.New("-trace-id must be a 32-character non-zero lowercase hex OpenTelemetry trace ID")
		}
		cfg.ObservedRoute = strings.TrimSpace(cfg.ObservedRoute)
		cfg.HTTPMethod = strings.ToUpper(strings.TrimSpace(cfg.HTTPMethod))
		if cfg.ObservedRoute == "" || !strings.HasPrefix(cfg.ObservedRoute, "/") {
			return errors.New("-observed-route must be an absolute HTTP route path")
		}
		if cfg.HTTPMethod == "" || strings.ContainsAny(cfg.HTTPMethod, " \t\r\n") {
			return errors.New("-http-method must be a single HTTP method token")
		}
		cfg.TenantID = strings.TrimSpace(cfg.TenantID)
		cfg.UserID = strings.TrimSpace(cfg.UserID)
		cfg.Role = strings.TrimSpace(cfg.Role)
		if cfg.TenantID == "" || strings.ContainsAny(cfg.TenantID, " \t\r\n") {
			return errors.New("-tenant-id must be a concrete tenant principal token for log correlation evidence")
		}
		if cfg.UserID == "" || strings.ContainsAny(cfg.UserID, " \t\r\n") {
			return errors.New("-user-id must be a concrete user principal token for log correlation evidence")
		}
		if cfg.Role == "" || strings.ContainsAny(cfg.Role, " \t\r\n") {
			return errors.New("-role must be a concrete role token for log correlation evidence")
		}
		var err error
		cfg.CollectorConfigURL, err = normalizeExternalStagingURL(cfg.CollectorConfigURL, "collector-config-url")
		if err != nil {
			return err
		}
		cfg.APIMetricsURL, err = normalizeExternalStagingURL(cfg.APIMetricsURL, "api-metrics-url")
		if err != nil {
			return err
		}
		cfg.RustMetricsURL, err = normalizeExternalStagingURL(cfg.RustMetricsURL, "rust-metrics-url")
		if err != nil {
			return err
		}
		cfg.TraceQueryURL, err = normalizeExternalStagingURL(cfg.TraceQueryURL, "trace-query-url")
		if err != nil {
			return err
		}
		cfg.LogQueryURL, err = normalizeExternalStagingURL(cfg.LogQueryURL, "log-query-url")
		if err != nil {
			return err
		}
		if err := requireDistinctArtifactURLs([]artifactTarget{
			{Label: "collector-config-url", URL: cfg.CollectorConfigURL},
			{Label: "api-metrics-url", URL: cfg.APIMetricsURL},
			{Label: "rust-metrics-url", URL: cfg.RustMetricsURL},
			{Label: "trace-query-url", URL: cfg.TraceQueryURL},
			{Label: "log-query-url", URL: cfg.LogQueryURL},
		}); err != nil {
			return err
		}
		if !urlCarriesTraceID(cfg.TraceQueryURL, cfg.TraceID) {
			return errors.New("-trace-query-url must include the supplied trace ID")
		}
		if !urlCarriesTraceID(cfg.LogQueryURL, cfg.TraceID) {
			return errors.New("-log-query-url must include the supplied trace ID")
		}
	}
	if cfg.ProbeAlerts {
		if cfg.DashboardURL == "" || cfg.AlertRulesURL == "" || cfg.AlertmanagerURL == "" || cfg.RetentionURL == "" {
			return errors.New("-probe-alerts requires dashboard, alert rules, alertmanager, and retention inputs")
		}
		cfg.AlertName = strings.TrimSpace(cfg.AlertName)
		cfg.AlertReceiver = strings.TrimSpace(cfg.AlertReceiver)
		if cfg.AlertName == "" || strings.ContainsAny(cfg.AlertName, " \t\r\n") {
			return errors.New("-probe-alerts requires -alert-name as a concrete alert token")
		}
		if cfg.AlertReceiver == "" || strings.ContainsAny(cfg.AlertReceiver, " \t\r\n") {
			return errors.New("-probe-alerts requires -alert-receiver as a concrete receiver token")
		}
		var err error
		cfg.DashboardURL, err = normalizeExternalStagingURL(cfg.DashboardURL, "dashboard-url")
		if err != nil {
			return err
		}
		cfg.AlertRulesURL, err = normalizeExternalStagingURL(cfg.AlertRulesURL, "alert-rules-url")
		if err != nil {
			return err
		}
		cfg.AlertmanagerURL, err = normalizeExternalStagingURL(cfg.AlertmanagerURL, "alertmanager-url")
		if err != nil {
			return err
		}
		cfg.RetentionURL, err = normalizeExternalStagingURL(cfg.RetentionURL, "retention-url")
		if err != nil {
			return err
		}
		if err := requireDistinctArtifactURLs([]artifactTarget{
			{Label: "dashboard-url", URL: cfg.DashboardURL},
			{Label: "alert-rules-url", URL: cfg.AlertRulesURL},
			{Label: "alertmanager-url", URL: cfg.AlertmanagerURL},
			{Label: "retention-url", URL: cfg.RetentionURL},
		}); err != nil {
			return err
		}
	}

	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	releaseMarkers := []string{
		"staging artifact",
		fmt.Sprintf("release_candidate=%s", cfg.ReleaseCandidate),
		fmt.Sprintf("service_version=%s", cfg.ServiceVersion),
	}
	probes := []probeResult{}
	evidenceItems := []string{}
	if cfg.ProbeOTEL {
		probes = append(probes,
			probeContainsAll(client, "collector-otlp-config", cfg.CollectorConfigURL, append([]string{"receivers", "otlp", "4317", "4318", "exporters", "service"}, releaseMarkers...)),
			probeContainsAll(client, "api-prometheus-metrics", cfg.APIMetricsURL, append([]string{"scriptureforge_http_requests_total", "scriptureforge_http_request_duration_seconds_sum", "scriptureforge_http_requests_total{", "status=", "websocket_active_connections_count", `scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped"`, "ai_inference_duration_seconds_sum", "ai_inference_duration_seconds_count", `scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"`, `scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"`}, releaseMarkers...)),
			probeContainsAll(client, "rust-prometheus-metrics", cfg.RustMetricsURL, append([]string{"scriptureforge_rust_engine_embedding_requests_total", "scriptureforge_rust_engine_embedding_failures_total", "scriptureforge_rust_engine_vector_search_requests_total", "scriptureforge_rust_engine_vector_search_failures_total"}, releaseMarkers...)),
			probeContainsAll(client, "trace-backend-search", cfg.TraceQueryURL, append([]string{cfg.TraceID, "scriptureforge-api", "scriptureforge-rust-engine", "route=" + cfg.ObservedRoute, "method=" + cfg.HTTPMethod}, releaseMarkers...)),
			probeContainsAll(client, "log-backend-trace-correlation", cfg.LogQueryURL, append([]string{cfg.TraceID, "trace_id", "scriptureforge-api", "scriptureforge-rust-engine", "route=" + cfg.ObservedRoute, "method=" + cfg.HTTPMethod, "service_version", "deployment_environment", "tenant_id=" + cfg.TenantID, "user_id=" + cfg.UserID, "role=" + cfg.Role, "distinct_otel_artifacts=true"}, releaseMarkers...)),
		)
		evidenceItems = append(evidenceItems, "OBS-OTEL-001")
	}
	if cfg.ProbeAlerts {
		probes = append(probes,
			probeContainsAll(client, "dashboard-import", cfg.DashboardURL, append([]string{"ScriptureForge", "scriptureforge_http_requests_total", "scriptureforge_http_request_duration_seconds_sum", "websocket_active_connections_count", "room_broadcast", "ai_inference_duration_seconds", "scriptureforge_rust_engine_", "trace_id"}, releaseMarkers...)),
			probeContainsAll(client, "alert-rules-loaded", cfg.AlertRulesURL, append([]string{"ScriptureForgeHighErrorRate", "ScriptureForgeTrafficAbsent", "ScriptureForgeAuthFailureSpike", "ScriptureForgeAbuseLimitSpike", "ScriptureForgeRouteLatencyElevated", "ScriptureForgeDependencyFailures", "ScriptureForgeAIInferenceLatencyElevated", "ScriptureForgeJournalWriteFailures", "ScriptureForgeRoomStreamFailures", "ScriptureForgeRoomBroadcastDrops", "ScriptureForgeRustEngineFailures", "scriptureforge_http_requests_total", "scriptureforge_dependency_operations_total", "ai_inference_duration_seconds"}, releaseMarkers...)),
			probeContainsAll(client, "alert-delivery-status", cfg.AlertmanagerURL, append([]string{"success", "delivered", "test alert", "alertmanager", "delivery_id=", "alertname=" + cfg.AlertName, "receiver=" + cfg.AlertReceiver}, releaseMarkers...)),
			probeContainsAll(client, "telemetry-retention-policy", cfg.RetentionURL, append([]string{"retention", "30 days", "trace", "logs", "metrics", "distinct_alert_artifacts=true"}, releaseMarkers...)),
		)
		evidenceItems = append(evidenceItems, "OBS-ALERT-001")
	}

	result := report{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass:    true,
		ReleaseCandidate: cfg.ReleaseCandidate,
		ServiceVersion:   cfg.ServiceVersion,
		TraceID:          traceIDForReport(cfg),
		ObservedRoute:    routeForReport(cfg),
		HTTPMethod:       methodForReport(cfg),
		TenantID:         tenantIDForReport(cfg),
		UserID:           userIDForReport(cfg),
		Role:             roleForReport(cfg),
		AlertName:        alertNameForReport(cfg),
		AlertReceiver:    alertReceiverForReport(cfg),
		Probes:           probes,
		EvidenceItems:    evidenceItems,
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
		return errors.New("one or more observability probes failed")
	}
	return nil
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

func traceIDForReport(cfg config) string {
	if !cfg.ProbeOTEL {
		return ""
	}
	return strings.TrimSpace(cfg.TraceID)
}

func routeForReport(cfg config) string {
	if !cfg.ProbeOTEL {
		return ""
	}
	return strings.TrimSpace(cfg.ObservedRoute)
}

func methodForReport(cfg config) string {
	if !cfg.ProbeOTEL {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(cfg.HTTPMethod))
}

func tenantIDForReport(cfg config) string {
	if !cfg.ProbeOTEL {
		return ""
	}
	return strings.TrimSpace(cfg.TenantID)
}

func userIDForReport(cfg config) string {
	if !cfg.ProbeOTEL {
		return ""
	}
	return strings.TrimSpace(cfg.UserID)
}

func roleForReport(cfg config) string {
	if !cfg.ProbeOTEL {
		return ""
	}
	return strings.TrimSpace(cfg.Role)
}

func alertNameForReport(cfg config) string {
	if !cfg.ProbeAlerts {
		return ""
	}
	return strings.TrimSpace(cfg.AlertName)
}

func alertReceiverForReport(cfg config) string {
	if !cfg.ProbeAlerts {
		return ""
	}
	return strings.TrimSpace(cfg.AlertReceiver)
}

func isValidTraceID(traceID string) bool {
	traceID = strings.TrimSpace(traceID)
	if len(traceID) != 32 {
		return false
	}
	allZero := true
	for _, char := range traceID {
		if char < '0' || (char > '9' && char < 'a') || char > 'f' {
			return false
		}
		if char != '0' {
			allZero = false
		}
	}
	return !allZero
}

func urlCarriesTraceID(rawURL, traceID string) bool {
	traceID = strings.TrimSpace(traceID)
	if traceID == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if strings.Contains(strings.ToLower(parsed.RawQuery), strings.ToLower(traceID)) {
		return true
	}
	for _, value := range parsed.Query() {
		for _, part := range value {
			if strings.Contains(strings.ToLower(part), strings.ToLower(traceID)) {
				return true
			}
		}
	}
	return strings.Contains(strings.ToLower(parsed.Path), strings.ToLower(traceID))
}

func normalizeStagingURL(raw, field string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("-%s must use http or https", field)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("-%s must include a host", field)
	}
	if isLocalHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must use a non-local staging host", field)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeExternalStagingURL(raw, field string) (string, error) {
	normalized, err := normalizeStagingURL(raw, field)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}
	if isPrivateNetworkHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must use a non-local, non-private staging host", field)
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not use a reserved placeholder staging host", field)
	}
	return normalized, nil
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

func isLocalHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(host), "[]")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && ip.IsLoopback()
}

func isPrivateNetworkHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(host), "[]")
	ip := net.ParseIP(normalized)
	return ip != nil && (ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())
}

func probeContainsAny(client *http.Client, name, target string, requiredAny []string) probeResult {
	return probeContains(client, name, target, requiredAny, false)
}

func probeContainsAll(client *http.Client, name, target string, requiredAll []string) probeResult {
	return probeContains(client, name, target, requiredAll, true)
}

func probeContains(client *http.Client, name, target string, required []string, requireAll bool) probeResult {
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-observabilityprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	text := string(body)
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300
	if requireAll {
		passed = passed && containsAllFold(text, required)
	} else {
		passed = passed && containsAnyFold(text, required)
	}
	deliveryID := ""
	if name == "alert-delivery-status" {
		deliveryID = extractMatch(text, alertDeliveryIDPattern)
		if deliveryID == "" {
			passed = false
		}
	}
	passed = passed && containsNoneFold(text, forbiddenObservabilityMarkers())
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if passed {
		summary = fmt.Sprintf("%s; verified markers: %s", summary, strings.Join(required, ", "))
		if name == "alert-delivery-status" {
			summary += fmt.Sprintf("; delivery_id=%s", deliveryID)
		}
	} else {
		summary = fmt.Sprintf("%s; missing required marker or contains forbidden mock/local-only marker", summary)
	}
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		DeliveryID:    deliveryID,
		ResultSummary: summary,
	}
}

func containsAnyFold(text string, needles []string) bool {
	lowerText := strings.ToLower(text)
	for _, needle := range needles {
		if strings.Contains(lowerText, strings.ToLower(needle)) {
			return true
		}
	}
	return false
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

func extractMatch(text string, pattern *regexp.Regexp) string {
	match := pattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func forbiddenObservabilityMarkers() []string {
	return []string{
		"mock",
		"mocked",
		"placeholder",
		"sample artifact",
		"synthetic",
		"stubbed",
		"test-only",
		"dry-run",
		"dry run",
		"local-only",
		"localhost",
		"127.0.0.1",
		"alert silenced",
		"alert muted",
		"alert inhibited",
		"notification suppressed",
		"delivery suppressed",
		"not delivered",
		"delivery failed",
		"delivery failure",
		"send failed",
	}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
