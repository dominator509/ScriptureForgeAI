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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type config struct {
	GRPCAddress string
	MetricsURL  string
	Timeout     time.Duration
	ServiceName string
}

type report struct {
	ObservedAt    string        `json:"observed_at"`
	GRPCTarget    string        `json:"grpc_target"`
	MetricsTarget string        `json:"metrics_target,omitempty"`
	ThresholdPass bool          `json:"threshold_pass"`
	Probes        []probeResult `json:"probes"`
	EvidenceItems []string      `json:"evidence_items"`
}

type probeResult struct {
	Name          string `json:"name"`
	Target        string `json:"target"`
	Passed        bool   `json:"passed"`
	Status        string `json:"status,omitempty"`
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
	flag.StringVar(&cfg.GRPCAddress, "grpc-address", "", "Rust gRPC address, for example scriptureforge-rust-engine:50051")
	flag.StringVar(&cfg.MetricsURL, "metrics-url", "", "optional Rust metrics URL, for example http://scriptureforge-rust-engine:9102/metrics")
	flag.StringVar(&cfg.ServiceName, "service-name", "scriptureforge.engine.ScriptureEngine", "gRPC health service name")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.GRPCAddress == "" {
		return errors.New("-grpc-address is required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	probes := []probeResult{probeGRPCHealth(cfg.GRPCAddress, cfg.ServiceName, cfg.Timeout)}
	if cfg.MetricsURL != "" {
		probes = append(probes, probeMetrics(cfg.MetricsURL, cfg.Timeout))
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		GRPCTarget:    cfg.GRPCAddress,
		MetricsTarget: cfg.MetricsURL,
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: []string{"RUST-GRPC-001"},
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
		ResultSummary: fmt.Sprintf("gRPC health status %s in %dms", status, latency),
	}
}

func probeMetrics(metricsURL string, timeout time.Duration) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return failedProbe("rust-metrics", metricsURL, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-rustprobe/1.0")
	resp, err := http.DefaultClient.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("rust-metrics", metricsURL, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	passed := resp.StatusCode == http.StatusOK && strings.Contains(string(body), "scriptureforge_rust_engine_")
	return probeResult{
		Name:          "rust-metrics",
		Target:        metricsURL,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		ResultSummary: fmt.Sprintf("metrics HTTP %d in %dms", resp.StatusCode, latency),
	}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
