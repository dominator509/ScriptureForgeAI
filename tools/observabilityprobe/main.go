package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type config struct {
	ProbeOTEL          bool
	ProbeAlerts        bool
	CollectorConfigURL string
	APIMetricsURL      string
	RustMetricsURL     string
	TraceQueryURL      string
	LogQueryURL        string
	TraceID            string
	DashboardURL       string
	AlertRulesURL      string
	AlertmanagerURL    string
	RetentionURL       string
	Timeout            time.Duration
}

type report struct {
	ObservedAt    string        `json:"observed_at"`
	ThresholdPass bool          `json:"threshold_pass"`
	Probes        []probeResult `json:"probes"`
	EvidenceItems []string      `json:"evidence_items"`
}

type probeResult struct {
	Name          string `json:"name"`
	Target        string `json:"target"`
	Passed        bool   `json:"passed"`
	StatusCode    int    `json:"status_code,omitempty"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
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
	flag.BoolVar(&cfg.ProbeOTEL, "probe-otel", false, "probe deployed OpenTelemetry collector, trace/log search, and API/Rust metrics evidence")
	flag.BoolVar(&cfg.ProbeAlerts, "probe-alerts", false, "probe deployed dashboard, alert rules, alert manager, and retention evidence")
	flag.StringVar(&cfg.CollectorConfigURL, "collector-config-url", os.Getenv("STAGING_COLLECTOR_CONFIG_URL"), "URL exposing redacted collector or deployment config for OTLP proof")
	flag.StringVar(&cfg.APIMetricsURL, "api-metrics-url", os.Getenv("STAGING_API_METRICS_URL"), "deployed Go API Prometheus metrics URL")
	flag.StringVar(&cfg.RustMetricsURL, "rust-metrics-url", os.Getenv("STAGING_RUST_METRICS_URL"), "deployed Rust engine Prometheus metrics URL")
	flag.StringVar(&cfg.TraceQueryURL, "trace-query-url", os.Getenv("STAGING_TRACE_QUERY_URL"), "trace backend query URL expected to include -trace-id")
	flag.StringVar(&cfg.LogQueryURL, "log-query-url", os.Getenv("STAGING_LOG_QUERY_URL"), "log backend query URL expected to include -trace-id")
	flag.StringVar(&cfg.TraceID, "trace-id", os.Getenv("STAGING_TRACE_ID"), "trace ID to verify in trace and log backend query results")
	flag.StringVar(&cfg.DashboardURL, "dashboard-url", os.Getenv("STAGING_DASHBOARD_URL"), "Grafana/dashboard URL or export URL for ScriptureForge overview")
	flag.StringVar(&cfg.AlertRulesURL, "alert-rules-url", os.Getenv("STAGING_ALERT_RULES_URL"), "deployed alert-rules URL or Prometheus rule API URL")
	flag.StringVar(&cfg.AlertmanagerURL, "alertmanager-url", os.Getenv("STAGING_ALERTMANAGER_URL"), "Alertmanager status or test-delivery evidence URL")
	flag.StringVar(&cfg.RetentionURL, "retention-url", os.Getenv("STAGING_RETENTION_URL"), "telemetry retention policy proof URL")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if !cfg.ProbeOTEL && !cfg.ProbeAlerts {
		return errors.New("at least one of -probe-otel or -probe-alerts is required")
	}
	if cfg.ProbeOTEL {
		if cfg.CollectorConfigURL == "" || cfg.APIMetricsURL == "" || cfg.RustMetricsURL == "" || cfg.TraceQueryURL == "" || cfg.LogQueryURL == "" || cfg.TraceID == "" {
			return errors.New("-probe-otel requires collector, API metrics, Rust metrics, trace query, log query, and trace ID inputs")
		}
	}
	if cfg.ProbeAlerts {
		if cfg.DashboardURL == "" || cfg.AlertRulesURL == "" || cfg.AlertmanagerURL == "" || cfg.RetentionURL == "" {
			return errors.New("-probe-alerts requires dashboard, alert rules, alertmanager, and retention inputs")
		}
	}

	client := &http.Client{Timeout: cfg.Timeout}
	probes := []probeResult{}
	evidenceItems := []string{}
	if cfg.ProbeOTEL {
		probes = append(probes,
			probeContainsAll(client, "collector-otlp-config", cfg.CollectorConfigURL, []string{"receivers", "otlp", "4317", "4318", "exporters", "service"}),
			probeContainsAll(client, "api-prometheus-metrics", cfg.APIMetricsURL, []string{"scriptureforge_http_requests_total", "scriptureforge_http_request_duration_seconds_sum", "scriptureforge_http_requests_total{", "status="}),
			probeContainsAll(client, "rust-prometheus-metrics", cfg.RustMetricsURL, []string{"scriptureforge_rust_engine_", "scriptureforge_rust_engine_requests_total", "scriptureforge_rust_engine_request_failures_total"}),
			probeContainsAll(client, "trace-backend-search", cfg.TraceQueryURL, []string{cfg.TraceID, "scriptureforge-api", "scriptureforge-rust-engine"}),
			probeContainsAll(client, "log-backend-trace-correlation", cfg.LogQueryURL, []string{cfg.TraceID, "trace_id", "scriptureforge-api", "scriptureforge-rust-engine", "SERVICE_VERSION", "DEPLOYMENT_ENVIRONMENT"}),
		)
		evidenceItems = append(evidenceItems, "OBS-OTEL-001")
	}
	if cfg.ProbeAlerts {
		probes = append(probes,
			probeContainsAll(client, "dashboard-import", cfg.DashboardURL, []string{"ScriptureForge", "scriptureforge_http_requests_total", "scriptureforge_http_request_duration_seconds_sum", "scriptureforge_rust_engine_", "trace_id"}),
			probeContainsAll(client, "alert-rules-loaded", cfg.AlertRulesURL, []string{"ScriptureForgeHighErrorRate", "ScriptureForgeRouteLatencyElevated", "ScriptureForgeRustEngineFailures", "scriptureforge_http_requests_total"}),
			probeContainsAll(client, "alert-delivery-status", cfg.AlertmanagerURL, []string{"success", "receiver", "delivered", "test alert", "alertmanager"}),
			probeContainsAll(client, "telemetry-retention-policy", cfg.RetentionURL, []string{"retention", "30 days", "trace", "logs", "metrics"}),
		)
		evidenceItems = append(evidenceItems, "OBS-ALERT-001")
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: evidenceItems,
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
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary = fmt.Sprintf("%s; missing required marker", summary)
	}
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
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

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
