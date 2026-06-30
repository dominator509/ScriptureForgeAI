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
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var prometheusSamplePattern = regexp.MustCompile(`(?m)^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{[^}\n]*\})?\s+([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)\s*(?:\n|$)`)

type config struct {
	GRPCAddress      string
	MetricsURL       string
	APIMetricsURL    string
	ReleaseCandidate string
	ServiceVersion   string
	DeploymentEnv    string
	Timeout          time.Duration
	ServiceName      string
}

type report struct {
	ObservedAt       string        `json:"observed_at"`
	GRPCTarget       string        `json:"grpc_target"`
	MetricsTarget    string        `json:"metrics_target,omitempty"`
	APIMetricsURL    string        `json:"api_metrics_target,omitempty"`
	ThresholdPass    bool          `json:"threshold_pass"`
	ReleaseCandidate string        `json:"release_candidate"`
	ServiceVersion   string        `json:"service_version"`
	DeploymentEnv    string        `json:"deployment_environment"`
	Probes           []probeResult `json:"probes"`
	EvidenceItems    []string      `json:"evidence_items"`
}

type probeResult struct {
	Name                       string  `json:"name"`
	Target                     string  `json:"target"`
	Passed                     bool    `json:"passed"`
	Status                     string  `json:"status,omitempty"`
	StatusCode                 int     `json:"status_code,omitempty"`
	LatencyMS                  int64   `json:"latency_ms,omitempty"`
	EmbeddingRequests          float64 `json:"embedding_requests,omitempty"`
	VectorSearchRequests       float64 `json:"vector_search_requests,omitempty"`
	APIRustVectorSearchOps     float64 `json:"api_rust_vector_search_ops,omitempty"`
	APIRustVectorSearchSeconds float64 `json:"api_rust_vector_search_seconds,omitempty"`
	ResultSummary              string  `json:"result_summary"`
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
	flag.StringVar(&cfg.GRPCAddress, "grpc-address", "", "Rust gRPC address, for example scriptureforge-rust-engine:50051")
	flag.StringVar(&cfg.MetricsURL, "metrics-url", "", "optional Rust metrics URL, for example http://scriptureforge-rust-engine:9102/metrics")
	flag.StringVar(&cfg.APIMetricsURL, "api-metrics-url", "", "deployed Go API metrics URL after an API flow has invoked the Rust engine")
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("RELEASE_CANDIDATE"), "release candidate Git SHA or tag expected in Rust evidence")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("SERVICE_VERSION"), "service version expected in Rust evidence")
	flag.StringVar(&cfg.DeploymentEnv, "deployment-environment", os.Getenv("DEPLOYMENT_ENVIRONMENT"), "deployment environment expected in Rust evidence, for example staging")
	flag.StringVar(&cfg.ServiceName, "service-name", "scriptureforge.engine.ScriptureEngine", "gRPC health service name")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	return runWithDependencies(cfg, output, probeGRPCHealth, http.DefaultClient)
}

type grpcProbeFunc func(address, serviceName string, timeout time.Duration) probeResult

func runWithDependencies(cfg config, output io.Writer, grpcProbe grpcProbeFunc, metricsClient *http.Client) error {
	if cfg.GRPCAddress == "" {
		return errors.New("-grpc-address is required")
	}
	if cfg.MetricsURL == "" {
		return errors.New("-metrics-url is required")
	}
	if cfg.APIMetricsURL == "" {
		return errors.New("-api-metrics-url is required")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	cfg.DeploymentEnv = strings.TrimSpace(cfg.DeploymentEnv)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" || cfg.DeploymentEnv == "" {
		return errors.New("Rust proof requires -release-candidate, -service-version, and -deployment-environment")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	var err error
	cfg.GRPCAddress, err = normalizeGRPCAddress(cfg.GRPCAddress)
	if err != nil {
		return err
	}
	cfg.MetricsURL, err = normalizeMetricsURL(cfg.MetricsURL, "metrics-url", false)
	if err != nil {
		return err
	}
	cfg.APIMetricsURL, err = normalizeMetricsURL(cfg.APIMetricsURL, "api-metrics-url", true)
	if err != nil {
		return err
	}
	if canonicalMetricsURL(cfg.MetricsURL) == canonicalMetricsURL(cfg.APIMetricsURL) {
		return errors.New("Rust proof requires distinct -metrics-url and -api-metrics-url targets")
	}
	if grpcProbe == nil {
		grpcProbe = probeGRPCHealth
	}
	if metricsClient == nil {
		metricsClient = http.DefaultClient
	}

	releaseMarkers := []string{
		fmt.Sprintf("release_candidate=%s", cfg.ReleaseCandidate),
		fmt.Sprintf("service_version=%s", cfg.ServiceVersion),
		fmt.Sprintf("deployment_environment=%s", cfg.DeploymentEnv),
	}
	healthProbe := grpcProbe(cfg.GRPCAddress, cfg.ServiceName, cfg.Timeout)
	if healthProbe.Passed {
		healthProbe.ResultSummary += "; verified release markers: " + strings.Join(append([]string{"staging artifact"}, releaseMarkers...), ", ")
	}
	probes := []probeResult{
		healthProbe,
		probeMetrics(metricsClient, cfg.MetricsURL, cfg.Timeout, releaseMarkers),
		probeAPIRustIntegrationMetrics(metricsClient, cfg.APIMetricsURL, cfg.Timeout, releaseMarkers),
	}
	if probes[2].Passed {
		probes[2].ResultSummary += "; verified config markers: distinct_metrics_targets=true"
	}

	result := report{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		GRPCTarget:       cfg.GRPCAddress,
		MetricsTarget:    cfg.MetricsURL,
		APIMetricsURL:    cfg.APIMetricsURL,
		ThresholdPass:    true,
		ReleaseCandidate: cfg.ReleaseCandidate,
		ServiceVersion:   cfg.ServiceVersion,
		DeploymentEnv:    cfg.DeploymentEnv,
		Probes:           probes,
		EvidenceItems:    []string{"RUST-GRPC-001"},
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
		return errors.New("one or more Rust probes failed")
	}
	return nil
}

func probeGRPCHealth(address, serviceName string, timeout time.Duration) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	conn, err := grpc.DialContext(ctx, address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("rust-grpc-health", address, err.Error())
	}
	defer conn.Close()

	client := healthpb.NewHealthClient(conn)
	response, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: serviceName})
	latency = time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("rust-grpc-health", address, err.Error())
	}
	status := response.GetStatus().String()
	passed := response.GetStatus() == healthpb.HealthCheckResponse_SERVING
	return probeResult{
		Name:          "rust-grpc-health",
		Target:        address,
		Passed:        passed,
		Status:        status,
		LatencyMS:     latency,
		ResultSummary: fmt.Sprintf("gRPC health status %s in %dms; verified markers: grpc health, %s, SERVING", status, latency, serviceName),
	}
}

func probeMetrics(client *http.Client, metricsURL string, timeout time.Duration, releaseMarkers []string) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return failedProbe("rust-metrics", metricsURL, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-rustprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("rust-metrics", metricsURL, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	text := string(body)
	requiredMetrics := []string{
		"scriptureforge_rust_engine_embedding_requests_total",
		"scriptureforge_rust_engine_embedding_failures_total",
		"scriptureforge_rust_engine_vector_search_requests_total",
		"scriptureforge_rust_engine_vector_search_failures_total",
	}
	requiredMarkers := append(append([]string{}, requiredMetrics...), releaseMarkers...)
	samples := parsePrometheusSamples(text)
	passed := resp.StatusCode == http.StatusOK && containsAll(text, requiredMarkers)
	for _, metric := range requiredMetrics {
		if _, ok := samples[metric]; !ok {
			passed = false
			break
		}
	}
	embeddingRequestCount := maxSample(samples["scriptureforge_rust_engine_embedding_requests_total"])
	vectorSearchRequestCount := maxSample(samples["scriptureforge_rust_engine_vector_search_requests_total"])
	if embeddingRequestCount <= 0 || vectorSearchRequestCount <= 0 {
		passed = false
	}
	summary := fmt.Sprintf("metrics HTTP %d in %dms", resp.StatusCode, latency)
	if passed {
		summary += "; verified markers: " + strings.Join(append([]string{"staging artifact"}, append(requiredMarkers, "Prometheus metrics", "rust_metrics_samples_verified=true", "rust_embedding_requests_positive=true", "rust_vector_search_requests_positive=true")...), ", ")
	}
	return probeResult{
		Name:                 "rust-metrics",
		Target:               metricsURL,
		Passed:               passed,
		StatusCode:           resp.StatusCode,
		LatencyMS:            latency,
		EmbeddingRequests:    embeddingRequestCount,
		VectorSearchRequests: vectorSearchRequestCount,
		ResultSummary:        summary,
	}
}

func probeAPIRustIntegrationMetrics(client *http.Client, metricsURL string, timeout time.Duration, releaseMarkers []string) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return failedProbe("api-rust-integration-metrics", metricsURL, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-rustprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("api-rust-integration-metrics", metricsURL, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	text := string(body)
	requiredMarkers := []string{
		`scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"`,
		`scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"`,
	}
	requiredMarkers = append(requiredMarkers, releaseMarkers...)
	operationCount, hasOperationCount := findPrometheusSample(text, "scriptureforge_dependency_operations_total", map[string]string{
		"dependency": "rust_engine",
		"operation":  "vector_search",
		"status":     "success",
	})
	durationSum, hasDurationSum := findPrometheusSample(text, "scriptureforge_dependency_operation_duration_seconds_sum", map[string]string{
		"dependency": "rust_engine",
		"operation":  "vector_search",
		"status":     "success",
	})
	passed := resp.StatusCode == http.StatusOK && containsAll(text, requiredMarkers) && hasOperationCount && hasDurationSum && operationCount > 0 && durationSum > 0
	summary := fmt.Sprintf("API metrics HTTP %d in %dms", resp.StatusCode, latency)
	if passed {
		summary += "; verified markers: " + strings.Join(append([]string{"staging artifact", "Go API rust_engine vector_search success", "scriptureforge_dependency_operations_total", "scriptureforge_dependency_operation_duration_seconds_sum", "api_rust_metrics_samples_verified=true"}, releaseMarkers...), ", ")
	}
	return probeResult{
		Name:                       "api-rust-integration-metrics",
		Target:                     metricsURL,
		Passed:                     passed,
		StatusCode:                 resp.StatusCode,
		LatencyMS:                  latency,
		APIRustVectorSearchOps:     operationCount,
		APIRustVectorSearchSeconds: durationSum,
		ResultSummary:              summary,
	}
}

func containsAll(text string, needles []string) bool {
	for _, needle := range needles {
		if !strings.Contains(text, needle) {
			return false
		}
	}
	return true
}

func parsePrometheusSamples(text string) map[string][]float64 {
	samples := make(map[string][]float64)
	for _, match := range prometheusSamplePattern.FindAllStringSubmatch(text, -1) {
		value, err := strconv.ParseFloat(match[2], 64)
		if err != nil {
			continue
		}
		samples[match[1]] = append(samples[match[1]], value)
	}
	return samples
}

func maxSample(values []float64) float64 {
	var max float64
	for index, value := range values {
		if index == 0 || value > max {
			max = value
		}
	}
	return max
}

func findPrometheusSample(text, metric string, labels map[string]string) (float64, bool) {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, metric) {
			continue
		}
		if labelsMatch(trimmed, labels) {
			fields := strings.Fields(trimmed)
			if len(fields) < 2 {
				continue
			}
			value, err := strconv.ParseFloat(fields[1], 64)
			if err == nil {
				return value, true
			}
		}
	}
	return 0, false
}

func labelsMatch(line string, labels map[string]string) bool {
	for key, value := range labels {
		if !strings.Contains(line, fmt.Sprintf(`%s="%s"`, key, value)) {
			return false
		}
	}
	return true
}

func normalizeGRPCAddress(raw string) (string, error) {
	address := strings.TrimSpace(raw)
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("-grpc-address must be host:port for a non-local staging service: %w", err)
	}
	if strings.TrimSpace(port) == "" {
		return "", errors.New("-grpc-address must include a port")
	}
	if isLocalOrPrivateHost(host) {
		return "", errors.New("-grpc-address must use a public or routable staging service host")
	}
	if isReservedPlaceholderHost(host) {
		return "", errors.New("-grpc-address must not use a reserved placeholder staging service host")
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
}

func normalizeMetricsURL(raw, flagName string, requireHTTPS bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if requireHTTPS {
		if parsed.Scheme != "https" {
			return "", fmt.Errorf("-%s must use https", flagName)
		}
	} else if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("-%s must use http or https", flagName)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("-%s must include a host", flagName)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must use a public or routable staging metrics host", flagName)
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not use a reserved placeholder staging metrics host", flagName)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func canonicalMetricsURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	parsed.Scheme = scheme
	parsed.Host = host
	parsed.Fragment = ""
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String()
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
	normalized := strings.TrimSuffix(strings.Trim(strings.ToLower(host), "[]"), ".")
	return normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		strings.HasSuffix(normalized, ".example") ||
		normalized == "test" ||
		strings.HasSuffix(normalized, ".test") ||
		normalized == "invalid" ||
		strings.HasSuffix(normalized, ".invalid")
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
