package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func requiredOTELSummaryMarkers(traceID string) map[string][]string {
	return map[string][]string{
		"collector-otlp-config":         {"staging artifact", "receivers", "otlp", "4317", "4318", "exporters", "service", "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
		"api-prometheus-metrics":        {"staging artifact", "scriptureforge_http_requests_total", "scriptureforge_http_request_duration_seconds_sum", "scriptureforge_http_requests_total{", "status=", "websocket_active_connections_count", `scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped"`, "ai_inference_duration_seconds_sum", "ai_inference_duration_seconds_count", `scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"`, `scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"`, "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
		"rust-prometheus-metrics":       {"staging artifact", "scriptureforge_rust_engine_embedding_requests_total", "scriptureforge_rust_engine_embedding_failures_total", "scriptureforge_rust_engine_vector_search_requests_total", "scriptureforge_rust_engine_vector_search_failures_total", "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
		"trace-backend-search":          {"staging artifact", traceID, "scriptureforge-api", "scriptureforge-rust-engine", "route=/api/v1/ai/generate/study", "method=POST", "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
		"log-backend-trace-correlation": {"staging artifact", traceID, "trace_id", "scriptureforge-api", "scriptureforge-rust-engine", "route=/api/v1/ai/generate/study", "method=POST", "service_version", "deployment_environment", "tenant_id=org-staging", "user_id=user-staging", "role=admin", "distinct_otel_artifacts=true", "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
	}
}

var requiredAlertSummaryMarkers = map[string][]string{
	"dashboard-import":           {"staging artifact", "ScriptureForge", "scriptureforge_http_requests_total", "scriptureforge_http_request_duration_seconds_sum", "websocket_active_connections_count", "room_broadcast", "ai_inference_duration_seconds", "scriptureforge_rust_engine_", "trace_id", "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
	"alert-rules-loaded":         {"staging artifact", "ScriptureForgeHighErrorRate", "ScriptureForgeTrafficAbsent", "ScriptureForgeAuthFailureSpike", "ScriptureForgeAbuseLimitSpike", "ScriptureForgeRouteLatencyElevated", "ScriptureForgeDependencyFailures", "ScriptureForgeAIInferenceLatencyElevated", "ScriptureForgeJournalWriteFailures", "ScriptureForgeRoomStreamFailures", "ScriptureForgeRoomBroadcastDrops", "ScriptureForgeRustEngineFailures", "scriptureforge_http_requests_total", "scriptureforge_dependency_operations_total", "ai_inference_duration_seconds", "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
	"alert-delivery-status":      {"staging artifact", "success", "delivered", "test alert", "alertmanager", "delivery_id=am-delivery-123", "alertname=ScriptureForgeHighErrorRate", "receiver=staging-release", "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
	"telemetry-retention-policy": {"staging artifact", "retention", "30 days", "trace", "logs", "metrics", "distinct_alert_artifacts=true", "release_candidate=sha-obs", "service_version=scriptureforge-api:sha-obs"},
}

const completeAlertRulesArtifact = "alert: ScriptureForgeHighErrorRate alert: ScriptureForgeTrafficAbsent alert: ScriptureForgeAuthFailureSpike alert: ScriptureForgeAbuseLimitSpike alert: ScriptureForgeRouteLatencyElevated alert: ScriptureForgeDependencyFailures alert: ScriptureForgeAIInferenceLatencyElevated alert: ScriptureForgeJournalWriteFailures alert: ScriptureForgeRoomStreamFailures alert: ScriptureForgeRoomBroadcastDrops alert: ScriptureForgeRustEngineFailures expr scriptureforge_http_requests_total expr scriptureforge_dependency_operations_total expr ai_inference_duration_seconds"

const observabilityReleaseMarkers = " staging artifact release_candidate=sha-obs service_version=scriptureforge-api:sha-obs"

const completeRustMetricsArtifact = `scriptureforge_rust_engine_embedding_requests_total 1
scriptureforge_rust_engine_embedding_failures_total 0
scriptureforge_rust_engine_vector_search_requests_total 1
scriptureforge_rust_engine_vector_search_failures_total 0`

const completeAPIMetricsArtifact = `scriptureforge_http_requests_total{method="GET",path="/ready",status="200"} 1
scriptureforge_http_request_duration_seconds_sum 0.01
websocket_active_connections_count 2
scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped"} 1
ai_inference_duration_seconds_sum{profile="gpt-4.1",status="success"} 0.150000
ai_inference_duration_seconds_count{profile="gpt-4.1",status="success"} 2
scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"} 1
scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"} 0.042`

func observabilityReleaseConfig() config {
	return config{
		ReleaseCandidate: "sha-obs",
		ServiceVersion:   "scriptureforge-api:sha-obs",
		Timeout:          time.Second,
	}
}

func otelConfig() config {
	cfg := observabilityReleaseConfig()
	cfg.ProbeOTEL = true
	cfg.CollectorConfigURL = "https://observability-artifacts.staging.scriptureforge.ai/collector"
	cfg.APIMetricsURL = "https://api-observability.staging.scriptureforge.ai/api-metrics"
	cfg.RustMetricsURL = "https://rust-metrics.staging.scriptureforge.ai/rust-metrics"
	cfg.TraceQueryURL = "https://traces.staging.scriptureforge.ai/traces?trace_id=11112222333344445555666677778888"
	cfg.LogQueryURL = "https://logs.staging.scriptureforge.ai/logs?trace_id=11112222333344445555666677778888"
	cfg.TraceID = "11112222333344445555666677778888"
	cfg.ObservedRoute = "/api/v1/ai/generate/study"
	cfg.HTTPMethod = "POST"
	cfg.TenantID = "org-staging"
	cfg.UserID = "user-staging"
	cfg.Role = "admin"
	return cfg
}

func alertConfig() config {
	cfg := observabilityReleaseConfig()
	cfg.ProbeAlerts = true
	cfg.DashboardURL = "https://grafana.staging.scriptureforge.ai/dashboard"
	cfg.AlertRulesURL = "https://prometheus.staging.scriptureforge.ai/rules"
	cfg.AlertmanagerURL = "https://alertmanager.staging.scriptureforge.ai/alertmanager"
	cfg.AlertName = "ScriptureForgeHighErrorRate"
	cfg.AlertReceiver = "staging-release"
	cfg.RetentionURL = "https://observability-artifacts.staging.scriptureforge.ai/retention"
	return cfg
}

func TestRunRequiresProbeMode(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "probe-otel") {
		t.Fatalf("expected probe mode error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	cfg := otelConfig()
	cfg.ReleaseCandidate = ""
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "release-candidate") {
		t.Fatalf("expected release identity requirement error, got %v", err)
	}
}

func TestRunRequiresObservedRouteAndMethod(t *testing.T) {
	cfg := otelConfig()
	cfg.ObservedRoute = ""
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "observed-route") {
		t.Fatalf("expected observed route requirement error, got %v", err)
	}

	cfg = otelConfig()
	cfg.HTTPMethod = "POST GET"
	err = runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "http-method") {
		t.Fatalf("expected HTTP method requirement error, got %v", err)
	}
}

func TestRunRequiresConcreteLogPrincipal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*config)
		want   string
	}{
		{
			name: "tenant",
			mutate: func(cfg *config) {
				cfg.TenantID = ""
			},
			want: "tenant-id",
		},
		{
			name: "user",
			mutate: func(cfg *config) {
				cfg.UserID = "user staging"
			},
			want: "user-id",
		},
		{
			name: "role",
			mutate: func(cfg *config) {
				cfg.Role = "admin member"
			},
			want: "role",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := otelConfig()
			tc.mutate(&cfg)
			var output bytes.Buffer
			err := runWithClient(cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected concrete principal requirement for %s, got %v", tc.want, err)
			}
		})
	}
}

func TestRunRejectsDuplicateOTELArtifactURLs(t *testing.T) {
	cfg := otelConfig()
	cfg.LogQueryURL = cfg.TraceQueryURL
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "log-query-url must be a distinct artifact URL") {
		t.Fatalf("expected duplicate OTEL artifact URL error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateOTELArtifactURLs(t *testing.T) {
	cfg := otelConfig()
	cfg.TraceQueryURL = "https://OBSERVABILITY-ARTIFACTS.staging.scriptureforge.ai:443/observability/shared-trace?b=2&a=1"
	cfg.LogQueryURL = "https://observability-artifacts.staging.scriptureforge.ai/observability/shared-trace?a=1&b=2"
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "log-query-url must be a distinct artifact URL") {
		t.Fatalf("expected canonical duplicate OTEL artifact URL error, got %v", err)
	}
}

func TestRunRejectsDuplicateAlertArtifactURLs(t *testing.T) {
	cfg := alertConfig()
	cfg.RetentionURL = cfg.AlertmanagerURL
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "retention-url must be a distinct artifact URL") {
		t.Fatalf("expected duplicate alert artifact URL error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateAlertArtifactURLs(t *testing.T) {
	cfg := alertConfig()
	cfg.AlertmanagerURL = "https://OBSERVABILITY-ARTIFACTS.staging.scriptureforge.ai:443/observability/shared-alert?b=2&a=1"
	cfg.RetentionURL = "https://observability-artifacts.staging.scriptureforge.ai/observability/shared-alert?a=1&b=2"
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "retention-url must be a distinct artifact URL") {
		t.Fatalf("expected canonical duplicate alert artifact URL error, got %v", err)
	}
}

func TestRunRejectsInvalidTraceID(t *testing.T) {
	for _, traceID := range []string{
		"trace-abc",
		"1111222233334444555566667777888",
		"1111222233334444555566667777888G",
		"00000000000000000000000000000000",
	} {
		t.Run(traceID, func(t *testing.T) {
			cfg := otelConfig()
			cfg.TraceID = traceID
			cfg.TraceQueryURL = "https://traces.staging.scriptureforge.ai/traces?trace_id=" + traceID
			cfg.LogQueryURL = "https://logs.staging.scriptureforge.ai/logs?trace_id=" + traceID
			var output bytes.Buffer
			err := runWithClient(cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), "32-character non-zero lowercase hex") {
				t.Fatalf("expected invalid trace-id rejection, got %v", err)
			}
		})
	}
}

func TestRunEmitsOTELEvidenceWhenAllObservabilityProofsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers: otlp protocols: grpc endpoint 0.0.0.0:4317 http endpoint 0.0.0.0:4318 exporters: otlp service pipelines traces" + observabilityReleaseMarkers))
		case "/api-metrics":
			_, _ = w.Write([]byte(completeAPIMetricsArtifact + "\n" + observabilityReleaseMarkers))
		case "/rust-metrics":
			_, _ = w.Write([]byte(completeRustMetricsArtifact + "\n" + observabilityReleaseMarkers))
		case "/traces":
			_, _ = w.Write([]byte("trace 11112222333344445555666677778888 found service scriptureforge-api downstream scriptureforge-rust-engine route=/api/v1/ai/generate/study method=POST" + observabilityReleaseMarkers))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"11112222333344445555666677778888","service":"scriptureforge-api","downstream":"scriptureforge-rust-engine","route":"/api/v1/ai/generate/study","method":"POST","service_version":"staging-1","deployment_environment":"staging","tenant_id":"org-staging","user_id":"user-staging","role":"admin","message":"http_request","distinct_otel_artifacts":true} tenant_id=org-staging user_id=user-staging role=admin distinct_otel_artifacts=true route=/api/v1/ai/generate/study method=POST ` + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(otelConfig(), &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("observability probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if result.TraceID != "11112222333344445555666677778888" {
		t.Fatalf("expected report trace ID to be persisted, got %q", result.TraceID)
	}
	if result.TenantID != "org-staging" || result.UserID != "user-staging" || result.Role != "admin" {
		t.Fatalf("expected report log principal to be persisted, got tenant=%q user=%q role=%q", result.TenantID, result.UserID, result.Role)
	}
	for _, probe := range result.Probes {
		if probe.Name == "trace-backend-search" {
			if probe.TraceID != result.TraceID || probe.ObservedRoute != result.ObservedRoute || probe.HTTPMethod != result.HTTPMethod {
				t.Fatalf("trace probe structured binding mismatch: %+v report=%+v", probe, result)
			}
		}
		if probe.Name == "log-backend-trace-correlation" {
			if probe.TraceID != result.TraceID || probe.ObservedRoute != result.ObservedRoute || probe.HTTPMethod != result.HTTPMethod || probe.TenantID != result.TenantID || probe.UserID != result.UserID || probe.Role != result.Role {
				t.Fatalf("log probe structured binding mismatch: %+v report=%+v", probe, result)
			}
		}
	}
	if !containsItem(result.EvidenceItems, "OBS-OTEL-001") {
		t.Fatalf("report missing OBS-OTEL-001: %+v", result.EvidenceItems)
	}
	if result.ReleaseCandidate != "sha-obs" || result.ServiceVersion != "scriptureforge-api:sha-obs" {
		t.Fatalf("unexpected release identity: %+v", result)
	}
	assertProbeSummariesIncludeMarkers(t, result.Probes, requiredOTELSummaryMarkers("11112222333344445555666677778888"))
}

func TestRunRejectsBroadTraceAndLogQueries(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		ProbeOTEL:          true,
		CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/collector",
		APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/metrics",
		RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
		TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search",
		LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
		TraceID:            "11112222333344445555666677778888",
		ObservedRoute:      "/api/v1/ai/generate/study",
		HTTPMethod:         "POST",
		TenantID:           "org-staging",
		UserID:             "user-staging",
		Role:               "admin",
		ReleaseCandidate:   "sha-obs",
		ServiceVersion:     "scriptureforge-api:sha-obs",
		Timeout:            time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "trace-query-url") {
		t.Fatalf("expected broad trace query URL to fail, got %v", err)
	}

	err = run(config{
		ProbeOTEL:          true,
		CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/collector",
		APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/metrics",
		RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
		TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
		LogQueryURL:        "https://logs.staging.scriptureforge.ai/search",
		TraceID:            "11112222333344445555666677778888",
		ObservedRoute:      "/api/v1/ai/generate/study",
		HTTPMethod:         "POST",
		TenantID:           "org-staging",
		UserID:             "user-staging",
		Role:               "admin",
		ReleaseCandidate:   "sha-obs",
		ServiceVersion:     "scriptureforge-api:sha-obs",
		Timeout:            time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "log-query-url") {
		t.Fatalf("expected broad log query URL to fail, got %v", err)
	}
}

func TestRunEmitsAlertEvidenceWhenAlertProofsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard":
			_, _ = w.Write([]byte("ScriptureForge production overview dashboard scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id" + observabilityReleaseMarkers))
		case "/rules":
			_, _ = w.Write([]byte(completeAlertRulesArtifact + observabilityReleaseMarkers))
		case "/alertmanager":
			_, _ = w.Write([]byte(`{"status":"success","alertname":"ScriptureForgeHighErrorRate","receiver":"staging-release","delivery_id":"am-delivery-123","delivered":true,"message":"test alert delivered by alertmanager"} alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123 ` + observabilityReleaseMarkers))
		case "/retention":
			_, _ = w.Write([]byte("retention: trace logs metrics 30 days distinct_alert_artifacts=true" + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(alertConfig(), &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("alert probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !containsItem(result.EvidenceItems, "OBS-ALERT-001") {
		t.Fatalf("report missing OBS-ALERT-001: %+v", result.EvidenceItems)
	}
	if result.ReleaseCandidate != "sha-obs" || result.ServiceVersion != "scriptureforge-api:sha-obs" {
		t.Fatalf("unexpected release identity: %+v", result)
	}
	if result.AlertName != "ScriptureForgeHighErrorRate" || result.AlertReceiver != "staging-release" {
		t.Fatalf("unexpected alert identity: %+v", result)
	}
	for _, probe := range result.Probes {
		if probe.Name == "alert-delivery-status" && probe.DeliveryID != "am-delivery-123" {
			t.Fatalf("alert delivery_id = %q, want %q", probe.DeliveryID, "am-delivery-123")
		}
	}
	assertProbeSummariesIncludeMarkers(t, result.Probes, requiredAlertSummaryMarkers)
}

func TestRunRejectsContradictoryAlertDeliveryEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard":
			_, _ = w.Write([]byte("ScriptureForge production overview dashboard scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id" + observabilityReleaseMarkers))
		case "/rules":
			_, _ = w.Write([]byte(completeAlertRulesArtifact + observabilityReleaseMarkers))
		case "/alertmanager":
			_, _ = w.Write([]byte(`{"status":"success","alertname":"ScriptureForgeHighErrorRate","receiver":"staging-release","delivery_id":"am-delivery-123","delivered":true,"message":"test alert delivered by alertmanager; alert silenced and not delivered"} alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123 ` + observabilityReleaseMarkers))
		case "/retention":
			_, _ = w.Write([]byte("retention: trace logs metrics 30 days distinct_alert_artifacts=true" + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(alertConfig(), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected contradictory alert delivery evidence to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "alert-delivery-status") {
		t.Fatalf("report missing alert delivery probe:\n%s", output.String())
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

func TestRunFailsWhenTraceIDIsNotFoundInLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers otlp 4317 4318 exporters service" + observabilityReleaseMarkers))
		case "/api-metrics":
			_, _ = w.Write([]byte(completeAPIMetricsArtifact + observabilityReleaseMarkers))
		case "/rust-metrics":
			_, _ = w.Write([]byte(completeRustMetricsArtifact + observabilityReleaseMarkers))
		case "/traces":
			_, _ = w.Write([]byte("trace abcdefabcdefabcdefabcdefabcdefab scriptureforge-api scriptureforge-rust-engine found route=/api/v1/ai/generate/study method=POST" + observabilityReleaseMarkers))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"different"} ` + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeOTEL:          true,
		CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/collector",
		APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/api-metrics",
		RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/rust-metrics",
		TraceQueryURL:      "https://traces.staging.scriptureforge.ai/traces?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		LogQueryURL:        "https://logs.staging.scriptureforge.ai/logs?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		TraceID:            "abcdefabcdefabcdefabcdefabcdefab",
		ObservedRoute:      "/api/v1/ai/generate/study",
		HTTPMethod:         "POST",
		TenantID:           "org-staging",
		UserID:             "user-staging",
		Role:               "admin",
		ReleaseCandidate:   "sha-obs",
		ServiceVersion:     "scriptureforge-api:sha-obs",
		Timeout:            time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing log trace ID to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenRustMetricsMissFailureCounters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers otlp 4317 4318 exporters service" + observabilityReleaseMarkers))
		case "/api-metrics":
			_, _ = w.Write([]byte(completeAPIMetricsArtifact + observabilityReleaseMarkers))
		case "/rust-metrics":
			_, _ = w.Write([]byte("scriptureforge_rust_engine_embedding_requests_total 1\nscriptureforge_rust_engine_vector_search_requests_total 1" + observabilityReleaseMarkers))
		case "/traces":
			_, _ = w.Write([]byte("trace abcdefabcdefabcdefabcdefabcdefab scriptureforge-api scriptureforge-rust-engine found route=/api/v1/ai/generate/study method=POST" + observabilityReleaseMarkers))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"abcdefabcdefabcdefabcdefabcdefab","service":"scriptureforge-api","downstream":"scriptureforge-rust-engine","service_version":"staging-1","deployment_environment":"staging","tenant_id":"org","user_id":"user","role":"admin","route":"/api/v1/ai/generate/study","method":"POST"} tenant_id=org user_id=user role=admin ` + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeOTEL:          true,
		CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/collector",
		APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/api-metrics",
		RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/rust-metrics",
		TraceQueryURL:      "https://traces.staging.scriptureforge.ai/traces?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		LogQueryURL:        "https://logs.staging.scriptureforge.ai/logs?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		TraceID:            "abcdefabcdefabcdefabcdefabcdefab",
		ObservedRoute:      "/api/v1/ai/generate/study",
		HTTPMethod:         "POST",
		TenantID:           "org-staging",
		UserID:             "user-staging",
		Role:               "admin",
		ReleaseCandidate:   "sha-obs",
		ServiceVersion:     "scriptureforge-api:sha-obs",
		Timeout:            time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing Rust failure counters to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "rust-prometheus-metrics") {
		t.Fatalf("report missing Rust metrics probe:\n%s", output.String())
	}
}

func TestRunFailsWhenAPIMetricsMissRustEngineDependencyMarkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers otlp 4317 4318 exporters service" + observabilityReleaseMarkers))
		case "/api-metrics":
			_, _ = w.Write([]byte(`scriptureforge_http_requests_total{status="200"} 1
scriptureforge_http_request_duration_seconds_sum 0.01` + observabilityReleaseMarkers))
		case "/rust-metrics":
			_, _ = w.Write([]byte(completeRustMetricsArtifact + observabilityReleaseMarkers))
		case "/traces":
			_, _ = w.Write([]byte("trace abcdefabcdefabcdefabcdefabcdefab scriptureforge-api scriptureforge-rust-engine found route=/api/v1/ai/generate/study method=POST" + observabilityReleaseMarkers))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"abcdefabcdefabcdefabcdefabcdefab","service":"scriptureforge-api","downstream":"scriptureforge-rust-engine","service_version":"staging-1","deployment_environment":"staging","tenant_id":"org","user_id":"user","role":"admin","route":"/api/v1/ai/generate/study","method":"POST"} tenant_id=org user_id=user role=admin ` + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeOTEL:          true,
		CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/collector",
		APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/api-metrics",
		RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/rust-metrics",
		TraceQueryURL:      "https://traces.staging.scriptureforge.ai/traces?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		LogQueryURL:        "https://logs.staging.scriptureforge.ai/logs?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		TraceID:            "abcdefabcdefabcdefabcdefabcdefab",
		ObservedRoute:      "/api/v1/ai/generate/study",
		HTTPMethod:         "POST",
		TenantID:           "org-staging",
		UserID:             "user-staging",
		Role:               "admin",
		ReleaseCandidate:   "sha-obs",
		ServiceVersion:     "scriptureforge-api:sha-obs",
		Timeout:            time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing API rust_engine dependency metrics to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "api-prometheus-metrics") {
		t.Fatalf("report missing API metrics probe:\n%s", output.String())
	}
}

func TestRunFailsWhenAPIMetricsMissArchitectureMetricProfiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers otlp 4317 4318 exporters service" + observabilityReleaseMarkers))
		case "/api-metrics":
			_, _ = w.Write([]byte(`scriptureforge_http_requests_total{status="200"} 1
scriptureforge_http_request_duration_seconds_sum 0.01
scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"} 1
scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"} 0.042` + observabilityReleaseMarkers))
		case "/rust-metrics":
			_, _ = w.Write([]byte(completeRustMetricsArtifact + observabilityReleaseMarkers))
		case "/traces":
			_, _ = w.Write([]byte("trace abcdefabcdefabcdefabcdefabcdefab scriptureforge-api scriptureforge-rust-engine found route=/api/v1/ai/generate/study method=POST" + observabilityReleaseMarkers))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"abcdefabcdefabcdefabcdefabcdefab","service":"scriptureforge-api","downstream":"scriptureforge-rust-engine","service_version":"staging-1","deployment_environment":"staging","tenant_id":"org","user_id":"user","role":"admin","route":"/api/v1/ai/generate/study","method":"POST"} tenant_id=org user_id=user role=admin ` + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeOTEL:          true,
		CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/collector",
		APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/api-metrics",
		RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/rust-metrics",
		TraceQueryURL:      "https://traces.staging.scriptureforge.ai/traces?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		LogQueryURL:        "https://logs.staging.scriptureforge.ai/logs?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		TraceID:            "abcdefabcdefabcdefabcdefabcdefab",
		ObservedRoute:      "/api/v1/ai/generate/study",
		HTTPMethod:         "POST",
		TenantID:           "org-staging",
		UserID:             "user-staging",
		Role:               "admin",
		ReleaseCandidate:   "sha-obs",
		ServiceVersion:     "scriptureforge-api:sha-obs",
		Timeout:            time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing architecture metric profiles to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "api-prometheus-metrics") {
		t.Fatalf("report missing API metrics probe:\n%s", output.String())
	}
}

func TestRunFailsWhenLogsMissTenantPrincipalFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers otlp 4317 4318 exporters service" + observabilityReleaseMarkers))
		case "/api-metrics":
			_, _ = w.Write([]byte(completeAPIMetricsArtifact + observabilityReleaseMarkers))
		case "/rust-metrics":
			_, _ = w.Write([]byte(completeRustMetricsArtifact + observabilityReleaseMarkers))
		case "/traces":
			_, _ = w.Write([]byte("trace abcdefabcdefabcdefabcdefabcdefab scriptureforge-api scriptureforge-rust-engine found route=/api/v1/ai/generate/study method=POST" + observabilityReleaseMarkers))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"abcdefabcdefabcdefabcdefabcdefab","service":"scriptureforge-api","downstream":"scriptureforge-rust-engine","service_version":"staging-1","deployment_environment":"staging"} ` + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeOTEL:          true,
		CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/collector",
		APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/api-metrics",
		RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/rust-metrics",
		TraceQueryURL:      "https://traces.staging.scriptureforge.ai/traces?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		LogQueryURL:        "https://logs.staging.scriptureforge.ai/logs?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		TraceID:            "abcdefabcdefabcdefabcdefabcdefab",
		ObservedRoute:      "/api/v1/ai/generate/study",
		HTTPMethod:         "POST",
		TenantID:           "org-staging",
		UserID:             "user-staging",
		Role:               "admin",
		ReleaseCandidate:   "sha-obs",
		ServiceVersion:     "scriptureforge-api:sha-obs",
		Timeout:            time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing tenant/user log fields to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "log-backend-trace-correlation") {
		t.Fatalf("report missing log correlation probe:\n%s", output.String())
	}
}

func TestRunFailsWhenLogsContainWrongTenantPrincipalValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers otlp 4317 4318 exporters service" + observabilityReleaseMarkers))
		case "/api-metrics":
			_, _ = w.Write([]byte(completeAPIMetricsArtifact + observabilityReleaseMarkers))
		case "/rust-metrics":
			_, _ = w.Write([]byte(completeRustMetricsArtifact + observabilityReleaseMarkers))
		case "/traces":
			_, _ = w.Write([]byte("trace abcdefabcdefabcdefabcdefabcdefab scriptureforge-api scriptureforge-rust-engine found route=/api/v1/ai/generate/study method=POST" + observabilityReleaseMarkers))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"abcdefabcdefabcdefabcdefabcdefab","service":"scriptureforge-api","downstream":"scriptureforge-rust-engine","service_version":"staging-1","deployment_environment":"staging","tenant_id":"org-other","user_id":"user-other","role":"member","route":"/api/v1/ai/generate/study","method":"POST"} tenant_id=org-other user_id=user-other role=member distinct_otel_artifacts=true route=/api/v1/ai/generate/study method=POST ` + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := otelConfig()
	cfg.TraceID = "abcdefabcdefabcdefabcdefabcdefab"
	cfg.TraceQueryURL = "https://traces.staging.scriptureforge.ai/search?trace_id=abcdefabcdefabcdefabcdefabcdefab"
	cfg.LogQueryURL = "https://logs.staging.scriptureforge.ai/search?trace_id=abcdefabcdefabcdefabcdefabcdefab"
	var output bytes.Buffer
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected wrong log principal values to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "log-backend-trace-correlation") {
		t.Fatalf("report missing log correlation probe:\n%s", output.String())
	}
}

func TestRunFailsWhenDashboardMissingTraceCorrelationPanel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard":
			_, _ = w.Write([]byte("ScriptureForge dashboard scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_" + observabilityReleaseMarkers))
		case "/rules":
			_, _ = w.Write([]byte(completeAlertRulesArtifact + observabilityReleaseMarkers))
		case "/alertmanager":
			_, _ = w.Write([]byte("success delivered test alert alertmanager alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123" + observabilityReleaseMarkers))
		case "/retention":
			_, _ = w.Write([]byte("retention trace logs metrics 30 days" + observabilityReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeAlerts:      true,
		DashboardURL:     "https://grafana.staging.scriptureforge.ai/dashboard",
		AlertRulesURL:    "https://prometheus.staging.scriptureforge.ai/rules",
		AlertmanagerURL:  "https://alertmanager.staging.scriptureforge.ai/alertmanager",
		AlertName:        "ScriptureForgeHighErrorRate",
		AlertReceiver:    "staging-release",
		RetentionURL:     "https://observability-artifacts.staging.scriptureforge.ai/retention",
		ReleaseCandidate: "sha-obs",
		ServiceVersion:   "scriptureforge-api:sha-obs",
		Timeout:          time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected dashboard without trace_id panel to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "dashboard-import") {
		t.Fatalf("report missing dashboard probe:\n%s", output.String())
	}
}

func TestRunFailsWhenAlertRulesMissOperationalCoverage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard":
			_, _ = w.Write([]byte("ScriptureForge dashboard scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id" + observabilityReleaseMarkers))
		case "/rules":
			_, _ = w.Write([]byte("alert: ScriptureForgeHighErrorRate alert: ScriptureForgeRouteLatencyElevated alert: ScriptureForgeRustEngineFailures expr scriptureforge_http_requests_total" + observabilityReleaseMarkers))
		case "/alertmanager":
			_, _ = w.Write([]byte("success delivered test alert alertmanager alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123" + observabilityReleaseMarkers))
		case "/retention":
			_, _ = w.Write([]byte("retention trace logs metrics 30 days" + observabilityReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeAlerts:      true,
		DashboardURL:     "https://grafana.staging.scriptureforge.ai/dashboard",
		AlertRulesURL:    "https://prometheus.staging.scriptureforge.ai/rules",
		AlertmanagerURL:  "https://alertmanager.staging.scriptureforge.ai/alertmanager",
		AlertName:        "ScriptureForgeHighErrorRate",
		AlertReceiver:    "staging-release",
		RetentionURL:     "https://observability-artifacts.staging.scriptureforge.ai/retention",
		ReleaseCandidate: "sha-obs",
		ServiceVersion:   "scriptureforge-api:sha-obs",
		Timeout:          time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected incomplete alert rules artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "alert-rules-loaded") {
		t.Fatalf("report missing alert-rules probe:\n%s", output.String())
	}
}

func TestRunFailsWhenAlertDeliveryOnlyReportsReady(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard":
			_, _ = w.Write([]byte("ScriptureForge dashboard scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id" + observabilityReleaseMarkers))
		case "/rules":
			_, _ = w.Write([]byte(completeAlertRulesArtifact + observabilityReleaseMarkers))
		case "/alertmanager":
			_, _ = w.Write([]byte("ready receiver alertmanager" + observabilityReleaseMarkers))
		case "/retention":
			_, _ = w.Write([]byte("retention trace logs metrics 30 days" + observabilityReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeAlerts:      true,
		DashboardURL:     "https://grafana.staging.scriptureforge.ai/dashboard",
		AlertRulesURL:    "https://prometheus.staging.scriptureforge.ai/rules",
		AlertmanagerURL:  "https://alertmanager.staging.scriptureforge.ai/alertmanager",
		AlertName:        "ScriptureForgeHighErrorRate",
		AlertReceiver:    "staging-release",
		RetentionURL:     "https://observability-artifacts.staging.scriptureforge.ai/retention",
		ReleaseCandidate: "sha-obs",
		ServiceVersion:   "scriptureforge-api:sha-obs",
		Timeout:          time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected alertmanager readiness-only artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "alert-delivery-status") {
		t.Fatalf("report missing alert delivery probe:\n%s", output.String())
	}
}

func TestRunFailsWhenAlertDeliveryOmitsConcreteDeliveryID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard":
			_, _ = w.Write([]byte("ScriptureForge dashboard scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id" + observabilityReleaseMarkers))
		case "/rules":
			_, _ = w.Write([]byte(completeAlertRulesArtifact + observabilityReleaseMarkers))
		case "/alertmanager":
			_, _ = w.Write([]byte("success delivered test alert alertmanager alertname=ScriptureForgeHighErrorRate receiver=staging-release" + observabilityReleaseMarkers))
		case "/retention":
			_, _ = w.Write([]byte("retention trace logs metrics 30 days distinct_alert_artifacts=true" + observabilityReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(alertConfig(), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected alertmanager delivery without delivery_id to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "alert-delivery-status") {
		t.Fatalf("report missing alert delivery probe:\n%s", output.String())
	}
}

func TestRunRejectsMockMarkedObservabilityArtifacts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers otlp 4317 4318 exporters service" + observabilityReleaseMarkers))
		case "/api-metrics":
			_, _ = w.Write([]byte(completeAPIMetricsArtifact + "\nmock artifact" + observabilityReleaseMarkers))
		case "/rust-metrics":
			_, _ = w.Write([]byte(completeRustMetricsArtifact + observabilityReleaseMarkers))
		case "/traces":
			_, _ = w.Write([]byte("trace abcdefabcdefabcdefabcdefabcdefab scriptureforge-api scriptureforge-rust-engine found route=/api/v1/ai/generate/study method=POST" + observabilityReleaseMarkers))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"abcdefabcdefabcdefabcdefabcdefab","service":"scriptureforge-api","downstream":"scriptureforge-rust-engine","service_version":"staging-1","deployment_environment":"staging","tenant_id":"org","user_id":"user","role":"admin","route":"/api/v1/ai/generate/study","method":"POST"} tenant_id=org user_id=user role=admin ` + observabilityReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeOTEL:          true,
		CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/collector",
		APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/api-metrics",
		RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/rust-metrics",
		TraceQueryURL:      "https://traces.staging.scriptureforge.ai/traces?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		LogQueryURL:        "https://logs.staging.scriptureforge.ai/logs?trace_id=abcdefabcdefabcdefabcdefabcdefab",
		TraceID:            "abcdefabcdefabcdefabcdefabcdefab",
		ObservedRoute:      "/api/v1/ai/generate/study",
		HTTPMethod:         "POST",
		TenantID:           "org-staging",
		UserID:             "user-staging",
		Role:               "admin",
		ReleaseCandidate:   "sha-obs",
		ServiceVersion:     "scriptureforge-api:sha-obs",
		Timeout:            time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mock-marked observability artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "api-prometheus-metrics") {
		t.Fatalf("report missing API metrics probe:\n%s", output.String())
	}
}

func TestRunRejectsDryRunAlertArtifacts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard":
			_, _ = w.Write([]byte("ScriptureForge dashboard scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id" + observabilityReleaseMarkers))
		case "/rules":
			_, _ = w.Write([]byte(completeAlertRulesArtifact + observabilityReleaseMarkers))
		case "/alertmanager":
			_, _ = w.Write([]byte("success delivered test alert alertmanager alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123" + observabilityReleaseMarkers))
		case "/retention":
			_, _ = w.Write([]byte("retention trace logs metrics 30 days dry-run" + observabilityReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		ProbeAlerts:      true,
		DashboardURL:     "https://grafana.staging.scriptureforge.ai/dashboard",
		AlertRulesURL:    "https://prometheus.staging.scriptureforge.ai/rules",
		AlertmanagerURL:  "https://alertmanager.staging.scriptureforge.ai/alertmanager",
		AlertName:        "ScriptureForgeHighErrorRate",
		AlertReceiver:    "staging-release",
		RetentionURL:     "https://observability-artifacts.staging.scriptureforge.ai/retention",
		ReleaseCandidate: "sha-obs",
		ServiceVersion:   "scriptureforge-api:sha-obs",
		Timeout:          time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected dry-run alert artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "telemetry-retention-policy") {
		t.Fatalf("report missing retention probe:\n%s", output.String())
	}
}

func containsItem(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}

func TestRunRejectsLocalTelemetryTargets(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cfg         config
		want        string
		wantMessage string
	}{
		{
			name: "collector",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://localhost:4318/config",
				APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/metrics",
				RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
				TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "collector-config-url",
			wantMessage: "non-local staging host",
		},
		{
			name: "api metrics",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/config",
				APIMetricsURL:      "https://127.0.0.1:8443/metrics",
				RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
				TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "api-metrics-url",
			wantMessage: "non-local staging host",
		},
		{
			name: "private api metrics",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/config",
				APIMetricsURL:      "https://10.0.0.25:8443/metrics",
				RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
				TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "api-metrics-url",
			wantMessage: "non-private staging host",
		},
		{
			name: "IPv4-mapped private api metrics",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/config",
				APIMetricsURL:      "https://[::ffff:10.0.0.25]:8443/metrics",
				RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
				TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "api-metrics-url",
			wantMessage: "non-private staging host",
		},
		{
			name: "private rust metrics",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/config",
				APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/metrics",
				RustMetricsURL:     "https://10.0.0.30:9102/metrics",
				TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "rust-metrics-url",
			wantMessage: "non-private staging host",
		},
		{
			name: "private log query",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/config",
				APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/metrics",
				RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
				TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://172.16.20.5/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "log-query-url",
			wantMessage: "non-private staging host",
		},
		{
			name: "reserved example collector",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://observability.staging.example/config",
				APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/metrics",
				RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
				TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "collector-config-url",
			wantMessage: "reserved placeholder staging host",
		},
		{
			name: "reserved example.com api metrics",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/config",
				APIMetricsURL:      "https://api.example.com/metrics",
				RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
				TraceQueryURL:      "https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "api-metrics-url",
			wantMessage: "reserved placeholder staging host",
		},
		{
			name: "reserved test trace query",
			cfg: config{
				ProbeOTEL:          true,
				CollectorConfigURL: "https://observability-artifacts.staging.scriptureforge.ai/config",
				APIMetricsURL:      "https://api-observability.staging.scriptureforge.ai/metrics",
				RustMetricsURL:     "https://rust-metrics.staging.scriptureforge.ai/metrics",
				TraceQueryURL:      "https://traces.staging.test/search?trace_id=11112222333344445555666677778888",
				LogQueryURL:        "https://logs.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888",
				TraceID:            "11112222333344445555666677778888",
				ObservedRoute:      "/api/v1/ai/generate/study",
				HTTPMethod:         "POST",
				TenantID:           "org-staging",
				UserID:             "user-staging",
				Role:               "admin",
				ReleaseCandidate:   "sha-obs",
				ServiceVersion:     "scriptureforge-api:sha-obs",
				Timeout:            time.Second,
			},
			want:        "trace-query-url",
			wantMessage: "reserved placeholder staging host",
		},
		{
			name: "alert dashboard",
			cfg: config{
				ProbeAlerts:      true,
				DashboardURL:     "https://[::1]/dashboard",
				AlertRulesURL:    "https://prometheus.staging.scriptureforge.ai/rules",
				AlertmanagerURL:  "https://alertmanager.staging.scriptureforge.ai/status",
				AlertName:        "ScriptureForgeHighErrorRate",
				AlertReceiver:    "staging-release",
				RetentionURL:     "https://observability-artifacts.staging.scriptureforge.ai/retention",
				ReleaseCandidate: "sha-obs",
				ServiceVersion:   "scriptureforge-api:sha-obs",
				Timeout:          time.Second,
			},
			want:        "dashboard-url",
			wantMessage: "non-local staging host",
		},
		{
			name: "private alert rules",
			cfg: config{
				ProbeAlerts:      true,
				DashboardURL:     "https://observability-artifacts.staging.scriptureforge.ai/dashboard",
				AlertRulesURL:    "https://192.168.100.30/rules",
				AlertmanagerURL:  "https://alertmanager.staging.scriptureforge.ai/status",
				AlertName:        "ScriptureForgeHighErrorRate",
				AlertReceiver:    "staging-release",
				RetentionURL:     "https://observability-artifacts.staging.scriptureforge.ai/retention",
				ReleaseCandidate: "sha-obs",
				ServiceVersion:   "scriptureforge-api:sha-obs",
				Timeout:          time.Second,
			},
			want:        "alert-rules-url",
			wantMessage: "non-private staging host",
		},
		{
			name: "reserved invalid retention",
			cfg: config{
				ProbeAlerts:      true,
				DashboardURL:     "https://observability-artifacts.staging.scriptureforge.ai/dashboard",
				AlertRulesURL:    "https://prometheus.staging.scriptureforge.ai/rules",
				AlertmanagerURL:  "https://alertmanager.staging.scriptureforge.ai/status",
				AlertName:        "ScriptureForgeHighErrorRate",
				AlertReceiver:    "staging-release",
				RetentionURL:     "https://observability.invalid/retention",
				ReleaseCandidate: "sha-obs",
				ServiceVersion:   "scriptureforge-api:sha-obs",
				Timeout:          time.Second,
			},
			want:        "retention-url",
			wantMessage: "reserved placeholder staging host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := runWithClient(tc.cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("expected non-local %s error, got %v", tc.want, err)
			}
		})
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
