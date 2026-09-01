package observability

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

type OTelConfig struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	Endpoint       string
	Insecure       bool
	Disabled       bool
}

func OTelConfigFromEnv() OTelConfig {
	return OTelConfig{
		ServiceName:    envOrDefault("OTEL_SERVICE_NAME", "scriptureforge-api"),
		ServiceVersion: os.Getenv("SERVICE_VERSION"),
		Environment:    os.Getenv("DEPLOYMENT_ENVIRONMENT"),
		Endpoint:       strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
		Insecure:       strings.EqualFold(os.Getenv("OTEL_EXPORTER_OTLP_INSECURE"), "true"),
		Disabled:       strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true"),
	}
}

func InitOpenTelemetry(ctx context.Context, cfg OTelConfig) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if cfg.Disabled || strings.TrimSpace(cfg.Endpoint) == "" {
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		return func(context.Context) error { return nil }, nil
	}
	if strings.TrimSpace(cfg.ServiceName) == "" {
		return nil, errors.New("otel service name is required")
	}
	endpoint, err := normalizeOTLPEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	options := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if cfg.Insecure {
		options = append(options, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, options...)
	if err != nil {
		return nil, err
	}
	resource, err := sdkresource.New(ctx,
		sdkresource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			attribute.String("service.version", cfg.ServiceVersion),
			attribute.String("deployment.environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(resource),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

func normalizeOTLPEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if !strings.Contains(endpoint, "://") {
		return strings.TrimSuffix(endpoint, "/"), nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" {
		if parsed.Host == "" && parsed.Path != "" {
			return strings.TrimSuffix(parsed.Path, "/"), nil
		}
		return strings.TrimSuffix(parsed.Host, "/"), nil
	}
	if parsed.Host == "" {
		return "", errors.New("otel endpoint host is required")
	}
	return parsed.Host, nil
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}
