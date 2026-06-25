package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresProbeMode(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "probe-otel") {
		t.Fatalf("expected probe mode error, got %v", err)
	}
}

func TestRunEmitsOTELEvidenceWhenAllObservabilityProofsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("receivers: otlp protocols: http endpoint: 0.0.0.0:4318"))
		case "/api-metrics":
			_, _ = w.Write([]byte("scriptureforge_http_requests_total 1\nscriptureforge_http_request_duration_seconds_sum 0.01"))
		case "/rust-metrics":
			_, _ = w.Write([]byte("scriptureforge_rust_engine_embedding_requests_total 1"))
		case "/traces":
			_, _ = w.Write([]byte("trace 11112222333344445555666677778888 found"))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"11112222333344445555666677778888","message":"http_request"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeOTEL:          true,
		CollectorConfigURL: server.URL + "/collector",
		APIMetricsURL:      server.URL + "/api-metrics",
		RustMetricsURL:     server.URL + "/rust-metrics",
		TraceQueryURL:      server.URL + "/traces",
		LogQueryURL:        server.URL + "/logs",
		TraceID:            "11112222333344445555666677778888",
		Timeout:            time.Second,
	}, &output)
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
	if !containsItem(result.EvidenceItems, "OBS-OTEL-001") {
		t.Fatalf("report missing OBS-OTEL-001: %+v", result.EvidenceItems)
	}
}

func TestRunEmitsAlertEvidenceWhenAlertProofsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard":
			_, _ = w.Write([]byte("ScriptureForge production overview dashboard"))
		case "/rules":
			_, _ = w.Write([]byte("alert: ScriptureForgeHighErrorRate"))
		case "/alertmanager":
			_, _ = w.Write([]byte(`{"status":"success","receiver":"staging-release"}`))
		case "/retention":
			_, _ = w.Write([]byte("retention: traces logs metrics 30 days"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeAlerts:     true,
		DashboardURL:    server.URL + "/dashboard",
		AlertRulesURL:   server.URL + "/rules",
		AlertmanagerURL: server.URL + "/alertmanager",
		RetentionURL:    server.URL + "/retention",
		Timeout:         time.Second,
	}, &output)
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
}

func TestRunFailsWhenTraceIDIsNotFoundInLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("otlp"))
		case "/api-metrics":
			_, _ = w.Write([]byte("scriptureforge_http_requests_total 1"))
		case "/rust-metrics":
			_, _ = w.Write([]byte("scriptureforge_rust_engine_embedding_requests_total 1"))
		case "/traces":
			_, _ = w.Write([]byte("trace abcdefabcdefabcdefabcdefabcdefab found"))
		case "/logs":
			_, _ = w.Write([]byte(`{"trace_id":"different"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeOTEL:          true,
		CollectorConfigURL: server.URL + "/collector",
		APIMetricsURL:      server.URL + "/api-metrics",
		RustMetricsURL:     server.URL + "/rust-metrics",
		TraceQueryURL:      server.URL + "/traces",
		LogQueryURL:        server.URL + "/logs",
		TraceID:            "abcdefabcdefabcdefabcdefabcdefab",
		Timeout:            time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected missing log trace ID to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
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
