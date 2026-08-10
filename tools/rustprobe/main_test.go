package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var requiredRustProbeSummaryMarkers = map[string][]string{
	"rust-grpc-health":             {"staging artifact", "grpc health", "scriptureforge.engine.ScriptureEngine", "SERVING", "grpc_transport_security=mTLS", "release_candidate=sha-rust", "service_version=scriptureforge-rust-engine:sha-rust", "deployment_environment=staging", "load_run_id=rust-run-123"},
	"rust-metrics":                 {"staging artifact", "scriptureforge_rust_engine_embedding_requests_total", "scriptureforge_rust_engine_embedding_failures_total", "scriptureforge_rust_engine_vector_search_requests_total", "scriptureforge_rust_engine_vector_search_failures_total", "Prometheus metrics", "rust_metrics_samples_verified=true", "rust_embedding_requests_positive=true", "rust_vector_search_requests_positive=true", "release_candidate=sha-rust", "service_version=scriptureforge-rust-engine:sha-rust", "deployment_environment=staging", "load_run_id=rust-run-123", "embedding_requests=1", "vector_search_requests=1"},
	"api-rust-integration-metrics": {"staging artifact", "Go API rust_engine vector_search success", "scriptureforge_dependency_operations_total", "scriptureforge_dependency_operation_duration_seconds_sum", "api_rust_metrics_samples_verified=true", "distinct_metrics_targets=true", "release_candidate=sha-rust", "service_version=scriptureforge-rust-engine:sha-rust", "deployment_environment=staging", "load_run_id=rust-run-123", "api_rust_vector_search_ops=1", "api_rust_vector_search_seconds=0.042"},
}

var rustReleaseMarkers = []string{"release_candidate=sha-rust", "service_version=scriptureforge-rust-engine:sha-rust", "deployment_environment=staging", "load_run_id=rust-run-123"}

func stagingRustConfig() config {
	return config{
		GRPCAddress:      "scriptureforge-rust-engine.staging.internal:50051",
		MetricsURL:       "http://scriptureforge-rust-engine.staging.internal:9102/metrics",
		APIMetricsURL:    "https://api.staging.scriptureforge.ai/metrics",
		ReleaseCandidate: "sha-rust",
		ServiceVersion:   "scriptureforge-rust-engine:sha-rust",
		DeploymentEnv:    "staging",
		LoadRunID:        "rust-run-123",
		Timeout:          time.Second,
		ServiceName:      "scriptureforge.engine.ScriptureEngine",
	}
}

func TestRunRequiresGRPCAddress(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "grpc-address") {
		t.Fatalf("expected missing grpc-address error, got %v", err)
	}
}

func TestRunProducesRustGRPCEvidenceReport(t *testing.T) {
	address, tlsConfig, stop := startMTLSHealthServer(t, "scriptureforge.engine.ScriptureEngine", healthpb.HealthCheckResponse_SERVING)
	defer stop()
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(completeRustMetrics() + "\n" + completeAPIRustIntegrationMetrics()))
	}))
	defer metricsServer.Close()

	var output bytes.Buffer
	err := runWithDependencies(stagingRustConfig(), &output, func(probeCfg config) probeResult {
		probeCfg.GRPCAddress = address
		probeCfg.GRPCCAFile = tlsConfig.GRPCCAFile
		probeCfg.GRPCClientCertFile = tlsConfig.GRPCClientCertFile
		probeCfg.GRPCClientKeyFile = tlsConfig.GRPCClientKeyFile
		probeCfg.GRPCServerName = tlsConfig.GRPCServerName
		return probeGRPCHealth(probeCfg)
	}, clientForHTTPServer(t, metricsServer))
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"RUST-GRPC-001"`) {
		t.Fatalf("report did not include RUST-GRPC-001:\n%s", output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.ThresholdPass || len(result.Probes) != 3 {
		t.Fatalf("unexpected report: %+v", result)
	}
	if result.ReleaseCandidate != "sha-rust" || result.ServiceVersion != "scriptureforge-rust-engine:sha-rust" {
		t.Fatalf("unexpected release identity: %+v", result)
	}
	if result.DeploymentEnv != "staging" || result.LoadRunID != "rust-run-123" {
		t.Fatalf("unexpected deployment environment: %+v", result)
	}
	if result.GRPCTransportSecurity != "mTLS" {
		t.Fatalf("unexpected gRPC transport security: %+v", result)
	}
	assertProbeSummariesIncludeMarkers(t, result.Probes, requiredRustProbeSummaryMarkers)
	rustMetrics := requireRustProbe(t, result.Probes, "rust-metrics")
	if rustMetrics.EmbeddingRequests != 1 || rustMetrics.VectorSearchRequests != 1 {
		t.Fatalf("rust metrics probe did not expose positive structured request samples: %+v", rustMetrics)
	}
	apiMetrics := requireRustProbe(t, result.Probes, "api-rust-integration-metrics")
	if apiMetrics.APIRustVectorSearchOps != 1 || apiMetrics.APIRustVectorSearchSeconds <= 0 {
		t.Fatalf("API rust integration probe did not expose positive structured samples: %+v", apiMetrics)
	}
}

func TestRunRequiresGRPCTLSConfiguration(t *testing.T) {
	var output bytes.Buffer
	err := run(stagingRustConfig(), &output)
	if err == nil || !strings.Contains(err.Error(), "mTLS configuration") {
		t.Fatalf("expected mTLS configuration error, got %v", err)
	}
}

func TestGRPCTransportCredentialsRejectsInvalidCA(t *testing.T) {
	dir := t.TempDir()
	caFile := dir + string(os.PathSeparator) + "ca.pem"
	certFile := dir + string(os.PathSeparator) + "client.pem"
	keyFile := dir + string(os.PathSeparator) + "client.key"
	for path, contents := range map[string]string{
		caFile:   "not pem",
		certFile: "not pem",
		keyFile:  "not pem",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := stagingRustConfig()
	cfg.GRPCCAFile = caFile
	cfg.GRPCClientCertFile = certFile
	cfg.GRPCClientKeyFile = keyFile
	cfg.GRPCServerName = "scriptureforge-rust-engine"
	if _, err := grpcTransportCredentials(cfg); err == nil || !strings.Contains(err.Error(), "valid PEM certificate") {
		t.Fatalf("expected invalid CA error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	cfg := stagingRustConfig()
	cfg.ReleaseCandidate = ""
	var output bytes.Buffer
	err := runWithDependencies(cfg, &output, nil, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "release-candidate") {
		t.Fatalf("expected release identity requirement error, got %v", err)
	}
}

func TestRunRequiresDeploymentEnvironment(t *testing.T) {
	cfg := stagingRustConfig()
	cfg.DeploymentEnv = ""
	var output bytes.Buffer
	err := runWithDependencies(cfg, &output, nil, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "deployment-environment") {
		t.Fatalf("expected deployment environment requirement error, got %v", err)
	}
}

func TestRunRequiresLoadRunID(t *testing.T) {
	cfg := stagingRustConfig()
	cfg.LoadRunID = ""
	var output bytes.Buffer
	err := runWithDependencies(cfg, &output, nil, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "load-run-id") {
		t.Fatalf("expected load-run-id requirement error, got %v", err)
	}
}

func assertProbeSummariesIncludeMarkers(t *testing.T, probes []probeResult, required map[string][]string) {
	t.Helper()
	seen := make(map[string]bool, len(probes))
	for _, probe := range probes {
		markers, ok := required[probe.Name]
		if !ok {
			t.Fatalf("unexpected probe %s", probe.Name)
		}
		seen[probe.Name] = true
		summary := strings.ToLower(probe.ResultSummary)
		for _, marker := range markers {
			if !strings.Contains(summary, strings.ToLower(marker)) {
				t.Fatalf("%s summary missing marker %q: %s", probe.Name, marker, probe.ResultSummary)
			}
		}
	}
	for name := range required {
		if !seen[name] {
			t.Fatalf("missing probe summary for %s", name)
		}
	}
}

func requireRustProbe(t *testing.T, probes []probeResult, name string) probeResult {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == name {
			if !probe.Passed {
				t.Fatalf("%s did not pass: %+v", name, probe)
			}
			return probe
		}
	}
	t.Fatalf("missing probe %s: %+v", name, probes)
	return probeResult{}
}

func TestRunFailsWhenHealthNotServing(t *testing.T) {
	address, tlsConfig, stop := startMTLSHealthServer(t, "scriptureforge.engine.ScriptureEngine", healthpb.HealthCheckResponse_NOT_SERVING)
	defer stop()

	var output bytes.Buffer
	err := runWithDependencies(stagingRustConfig(), &output, func(probeCfg config) probeResult {
		probeCfg.GRPCAddress = address
		probeCfg.GRPCCAFile = tlsConfig.GRPCCAFile
		probeCfg.GRPCClientCertFile = tlsConfig.GRPCClientCertFile
		probeCfg.GRPCClientKeyFile = tlsConfig.GRPCClientKeyFile
		probeCfg.GRPCServerName = tlsConfig.GRPCServerName
		return probeGRPCHealth(probeCfg)
	}, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(completeMetricsForURL(req.URL.String()))), Header: make(http.Header), Request: req}, nil
	})})
	if err == nil {
		t.Fatalf("expected not-serving health to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestMetricsProbeRequiresRustMetricPrefix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("some_other_metric 1\n"))
	}))
	defer server.Close()

	result := probeMetrics(server.Client(), server.URL, time.Second, nil)
	if result.Passed {
		t.Fatalf("metrics probe passed without Rust metric prefix: %+v", result)
	}
}

func TestMetricsProbeRequiresAllOperationalCounters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("scriptureforge_rust_engine_embedding_requests_total 1\nscriptureforge_rust_engine_vector_search_requests_total 1\n"))
	}))
	defer server.Close()

	result := probeMetrics(server.Client(), server.URL, time.Second, nil)
	if result.Passed {
		t.Fatalf("metrics probe passed without failure counters: %+v", result)
	}
}

func TestMetricsProbeRequiresRealPrometheusSamples(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Join([]string{
			"# HELP scriptureforge_rust_engine_embedding_requests_total Total embedding requests handled by the Rust scripture engine.",
			"# HELP scriptureforge_rust_engine_embedding_failures_total Total embedding request failures in the Rust scripture engine.",
			"# HELP scriptureforge_rust_engine_vector_search_requests_total Total vector search requests handled by the Rust scripture engine.",
			"# HELP scriptureforge_rust_engine_vector_search_failures_total Total vector search request failures in the Rust scripture engine.",
		}, "\n")))
	}))
	defer server.Close()

	result := probeMetrics(server.Client(), server.URL, time.Second, nil)
	if result.Passed {
		t.Fatalf("metrics probe passed without concrete Prometheus samples: %+v", result)
	}
}

func TestMetricsProbeRequiresPositiveRustRequestSamples(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Join([]string{
			"# HELP scriptureforge_rust_engine_embedding_requests_total Total embedding requests handled by the Rust scripture engine.",
			"# TYPE scriptureforge_rust_engine_embedding_requests_total counter",
			"scriptureforge_rust_engine_embedding_requests_total 0",
			"# HELP scriptureforge_rust_engine_embedding_failures_total Total embedding request failures in the Rust scripture engine.",
			"# TYPE scriptureforge_rust_engine_embedding_failures_total counter",
			"scriptureforge_rust_engine_embedding_failures_total 0",
			"# HELP scriptureforge_rust_engine_vector_search_requests_total Total vector search requests handled by the Rust scripture engine.",
			"# TYPE scriptureforge_rust_engine_vector_search_requests_total counter",
			"scriptureforge_rust_engine_vector_search_requests_total 0",
			"# HELP scriptureforge_rust_engine_vector_search_failures_total Total vector search request failures in the Rust scripture engine.",
			"# TYPE scriptureforge_rust_engine_vector_search_failures_total counter",
			"scriptureforge_rust_engine_vector_search_failures_total 0",
		}, "\n")))
	}))
	defer server.Close()

	result := probeMetrics(server.Client(), server.URL, time.Second, nil)
	if result.Passed {
		t.Fatalf("metrics probe passed without positive Rust request samples: %+v", result)
	}
}

func TestAPIRustIntegrationMetricsRequirePositiveSamples(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Join([]string{
			`scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"} 0`,
			`scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"} 0`,
		}, "\n")))
	}))
	defer server.Close()

	result := probeAPIRustIntegrationMetrics(server.Client(), server.URL, time.Second, nil)
	if result.Passed {
		t.Fatalf("API metrics probe passed without positive Rust integration samples: %+v", result)
	}
}

func completeRustMetrics() string {
	lines := []string{
		"# HELP scriptureforge_rust_engine_embedding_requests_total Total embedding requests handled by the Rust scripture engine.",
		"# TYPE scriptureforge_rust_engine_embedding_requests_total counter",
		"scriptureforge_rust_engine_embedding_requests_total 1",
		"# HELP scriptureforge_rust_engine_embedding_failures_total Total embedding request failures in the Rust scripture engine.",
		"# TYPE scriptureforge_rust_engine_embedding_failures_total counter",
		"scriptureforge_rust_engine_embedding_failures_total 0",
		"# HELP scriptureforge_rust_engine_vector_search_requests_total Total vector search requests handled by the Rust scripture engine.",
		"# TYPE scriptureforge_rust_engine_vector_search_requests_total counter",
		"scriptureforge_rust_engine_vector_search_requests_total 1",
		"# HELP scriptureforge_rust_engine_vector_search_failures_total Total vector search request failures in the Rust scripture engine.",
		"# TYPE scriptureforge_rust_engine_vector_search_failures_total counter",
		"scriptureforge_rust_engine_vector_search_failures_total 0",
	}
	lines = append(lines, rustReleaseMarkers...)
	return strings.Join(lines, "\n")
}

func completeAPIRustIntegrationMetrics() string {
	lines := []string{
		`scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"} 1`,
		`scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"} 0.042000`,
	}
	lines = append(lines, rustReleaseMarkers...)
	return strings.Join(lines, "\n")
}

func completeMetricsForURL(rawURL string) string {
	if strings.Contains(rawURL, "api.staging.scriptureforge.ai") {
		return completeAPIRustIntegrationMetrics()
	}
	return completeRustMetrics()
}

func TestRunRequiresMetricsURL(t *testing.T) {
	var output bytes.Buffer
	err := run(config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", Timeout: time.Second, ServiceName: "scriptureforge.engine.ScriptureEngine"}, &output)
	if err == nil || !strings.Contains(err.Error(), "metrics-url") {
		t.Fatalf("expected missing metrics-url error, got %v", err)
	}
}

func TestRunRequiresAPIMetricsURL(t *testing.T) {
	var output bytes.Buffer
	err := run(config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", Timeout: time.Second, ServiceName: "scriptureforge.engine.ScriptureEngine"}, &output)
	if err == nil || !strings.Contains(err.Error(), "api-metrics-url") {
		t.Fatalf("expected missing api-metrics-url error, got %v", err)
	}
}

func TestRunRejectsDuplicateMetricsTargets(t *testing.T) {
	cfg := stagingRustConfig()
	cfg.MetricsURL = "https://metrics.staging.scriptureforge.ai/rust"
	cfg.APIMetricsURL = cfg.MetricsURL
	var output bytes.Buffer
	err := runWithDependencies(cfg, &output, nil, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("expected duplicate metrics target error, got %v", err)
	}
}

func TestRunRejectsDuplicateMetricsTargetAliases(t *testing.T) {
	cfg := stagingRustConfig()
	cfg.MetricsURL = "https://metrics.staging.scriptureforge.ai:443/rust?b=2&a=1"
	cfg.APIMetricsURL = "https://METRICS.staging.scriptureforge.ai/rust?a=1&b=2#api"
	var output bytes.Buffer
	err := runWithDependencies(cfg, &output, nil, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("expected canonical duplicate metrics target error, got %v", err)
	}
}

func TestRunRejectsLocalOrMalformedTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config
		want string
	}{
		{
			name: "loopback grpc",
			cfg:  config{GRPCAddress: "127.0.0.1:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "grpc-address",
		},
		{
			name: "private grpc",
			cfg:  config{GRPCAddress: "10.0.0.15:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "grpc-address",
		},
		{
			name: "IPv4-mapped private grpc",
			cfg:  config{GRPCAddress: "[::ffff:10.0.0.15]:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "grpc-address",
		},
		{
			name: "unspecified grpc",
			cfg:  config{GRPCAddress: "0.0.0.0:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "grpc-address",
		},
		{
			name: "missing grpc port",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "grpc-address",
		},
		{
			name: "reserved grpc",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.example:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "reserved placeholder",
		},
		{
			name: "loopback metrics",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "http://localhost:9102/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "metrics-url",
		},
		{
			name: "link-local metrics",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "http://169.254.10.20:9102/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "metrics-url",
		},
		{
			name: "missing metrics host",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "http:///metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "metrics-url",
		},
		{
			name: "reserved metrics",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "https://rust-metrics.example.com/metrics", APIMetricsURL: "https://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "reserved placeholder",
		},
		{
			name: "loopback api metrics",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "http://localhost:8080/metrics", Timeout: time.Second},
			want: "metrics-url",
		},
		{
			name: "public http api metrics",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "http://api.staging.scriptureforge.ai/metrics", Timeout: time.Second},
			want: "api-metrics-url",
		},
		{
			name: "private api metrics",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "https://192.168.1.20/metrics", Timeout: time.Second},
			want: "metrics-url",
		},
		{
			name: "reserved api metrics",
			cfg:  config{GRPCAddress: "scriptureforge-rust-engine.staging.internal:50051", MetricsURL: "http://scriptureforge-rust-engine.staging.internal:9102/metrics", APIMetricsURL: "https://api.invalid/metrics", Timeout: time.Second},
			want: "reserved placeholder",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.ReleaseCandidate = "sha-rust"
			tc.cfg.ServiceVersion = "scriptureforge-rust-engine:sha-rust"
			tc.cfg.DeploymentEnv = "staging"
			tc.cfg.LoadRunID = "rust-run-123"
			var output bytes.Buffer
			err := runWithDependencies(tc.cfg, &output, nil, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q validation error, got %v", tc.want, err)
			}
		})
	}
}

func startMTLSHealthServer(t *testing.T, service string, status healthpb.HealthCheckResponse_ServingStatus) (string, config, func()) {
	t.Helper()
	caCert, caKey, caPEM, _ := issueTestCertificate(t, "ScriptureForge Test CA", nil, true, nil, nil)
	_, _, serverPEM, serverKeyPEM := issueTestCertificate(t, "scriptureforge-rust-engine", []string{"scriptureforge-rust-engine"}, false, caCert, caKey)
	_, _, clientPEM, clientKeyPEM := issueTestCertificate(t, "scriptureforge-rustprobe", nil, false, caCert, caKey)
	serverKeyPair, err := tls.X509KeyPair(append(serverPEM, caPEM...), serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverKeyPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	})))
	healthServer := health.NewServer()
	healthServer.SetServingStatus(service, status)
	healthpb.RegisterHealthServer(server, healthServer)
	go func() {
		_ = server.Serve(listener)
	}()
	dir := t.TempDir()
	caFile := dir + string(os.PathSeparator) + "ca.pem"
	clientCertFile := dir + string(os.PathSeparator) + "client.pem"
	clientKeyFile := dir + string(os.PathSeparator) + "client.key"
	for path, contents := range map[string][]byte{
		caFile:         caPEM,
		clientCertFile: clientPEM,
		clientKeyFile:  clientKeyPEM,
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	probeConfig := config{
		GRPCCAFile:         caFile,
		GRPCClientCertFile: clientCertFile,
		GRPCClientKeyFile:  clientKeyFile,
		GRPCServerName:     "scriptureforge-rust-engine",
		ServiceName:        service,
		Timeout:            time.Second,
	}
	return listener.Addr().String(), probeConfig, func() {
		server.GracefulStop()
		_ = listener.Close()
	}
}

func issueTestCertificate(t *testing.T, commonName string, dnsNames []string, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:              dnsNames,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	issuer := template
	issuerKey := key
	if parent != nil {
		issuer = parent
		issuerKey = parentKey
		if len(dnsNames) > 0 {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certificate, key, certificatePEM, keyPEM
}

func TestGRPCProbeFailsUnknownAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	<-ctx.Done()

	result := probeGRPCHealth(config{
		GRPCAddress:    address,
		GRPCServerName: "scriptureforge-rust-engine",
		Timeout:        50 * time.Millisecond,
	})
	if result.Passed {
		t.Fatalf("probe passed against closed listener: %+v", result)
	}
}

func clientForHTTPServer(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("invalid test server URL: %v", err)
	}
	baseClient := server.Client()
	baseTransport := baseClient.Transport
	return &http.Client{
		Timeout: baseClient.Timeout,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			cloned.URL.Scheme = serverURL.Scheme
			cloned.URL.Host = serverURL.Host
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
