package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestRunRequiresGRPCAddress(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "grpc-address") {
		t.Fatalf("expected missing grpc-address error, got %v", err)
	}
}

func TestRunProducesRustGRPCEvidenceReport(t *testing.T) {
	address, stop := startHealthServer(t, "scriptureforge.engine.ScriptureEngine", healthpb.HealthCheckResponse_SERVING)
	defer stop()
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("scriptureforge_rust_engine_embedding_requests_total 1\n"))
	}))
	defer metricsServer.Close()

	var output bytes.Buffer
	err := run(config{
		GRPCAddress: address,
		MetricsURL:  metricsServer.URL,
		Timeout:     time.Second,
		ServiceName: "scriptureforge.engine.ScriptureEngine",
	}, &output)
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
	if !result.ThresholdPass || len(result.Probes) != 2 {
		t.Fatalf("unexpected report: %+v", result)
	}
}

func TestRunFailsWhenHealthNotServing(t *testing.T) {
	address, stop := startHealthServer(t, "scriptureforge.engine.ScriptureEngine", healthpb.HealthCheckResponse_NOT_SERVING)
	defer stop()

	var output bytes.Buffer
	err := run(config{GRPCAddress: address, Timeout: time.Second, ServiceName: "scriptureforge.engine.ScriptureEngine"}, &output)
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

	result := probeMetrics(server.URL, time.Second)
	if result.Passed {
		t.Fatalf("metrics probe passed without Rust metric prefix: %+v", result)
	}
}

func startHealthServer(t *testing.T, service string, status healthpb.HealthCheckResponse_ServingStatus) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus(service, status)
	healthpb.RegisterHealthServer(server, healthServer)
	go func() {
		_ = server.Serve(listener)
	}()
	return listener.Addr().String(), func() {
		server.GracefulStop()
		_ = listener.Close()
	}
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

	result := probeGRPCHealth(address, "scriptureforge.engine.ScriptureEngine", 50*time.Millisecond)
	if result.Passed {
		t.Fatalf("probe passed against closed listener: %+v", result)
	}
}
