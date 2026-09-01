package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

func TestOTelConfigFromEnvUsesProductionDefaults(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("SERVICE_VERSION", "2026.06.25")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "staging")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.local:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	t.Setenv("OTEL_SDK_DISABLED", "")

	cfg := OTelConfigFromEnv()
	if cfg.ServiceName != "scriptureforge-api" {
		t.Fatalf("service name = %q", cfg.ServiceName)
	}
	if cfg.ServiceVersion != "2026.06.25" || cfg.Environment != "staging" || cfg.Endpoint != "http://collector.local:4318" || !cfg.Insecure || cfg.Disabled {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestInitOpenTelemetryDisabledIsNoop(t *testing.T) {
	shutdown, err := InitOpenTelemetry(context.Background(), OTelConfig{Disabled: true})
	if err != nil {
		t.Fatalf("disabled init failed: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown hook was nil")
	}
	if _, ok := otel.GetTracerProvider().(trace.TracerProvider); !ok {
		t.Fatal("global tracer provider was not installed")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestInitOpenTelemetryRequiresServiceNameWhenEnabled(t *testing.T) {
	_, err := InitOpenTelemetry(context.Background(), OTelConfig{Endpoint: "localhost:4318"})
	if err == nil {
		t.Fatal("enabled init without service name unexpectedly succeeded")
	}
}

func TestInitOpenTelemetryAcceptsHTTPExporterEndpoint(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer collector.Close()

	shutdown, err := InitOpenTelemetry(context.Background(), OTelConfig{
		ServiceName:    "scriptureforge-api-test",
		ServiceVersion: "test",
		Environment:    "test",
		Endpoint:       collector.URL,
		Insecure:       true,
	})
	if err != nil {
		t.Fatalf("enabled init failed: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestNormalizeOTLPEndpoint(t *testing.T) {
	tests := map[string]string{
		"localhost:4318":            "localhost:4318",
		"http://localhost:4318":     "localhost:4318",
		"https://collector:4318/v1": "collector:4318",
		"collector.namespace:4318/": "collector.namespace:4318",
	}
	for input, want := range tests {
		got, err := normalizeOTLPEndpoint(input)
		if err != nil {
			t.Fatalf("normalize %q failed: %v", input, err)
		}
		if got != want {
			t.Fatalf("normalize %q = %q, want %q", input, got, want)
		}
	}
}
