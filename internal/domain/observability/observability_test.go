package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestObserverCapsHTTPMetricSeries(t *testing.T) {
	observer := NewObserver(Options{})
	for index := 0; index < maxHTTPMetricSeries+100; index++ {
		observer.record(http.MethodGet, "/unmatched/"+strconv.Itoa(index), http.StatusNotFound, time.Millisecond)
	}

	observer.mu.Lock()
	seriesCount := len(observer.requests)
	observer.mu.Unlock()
	if seriesCount > maxHTTPMetricSeries+1 {
		t.Fatalf("HTTP metric series grew to %d, want at most %d", seriesCount, maxHTTPMetricSeries+1)
	}
	if !strings.Contains(observer.Snapshot(), `path="/:other"`) {
		t.Fatal("HTTP metric overflow series was not recorded")
	}
}

func TestMiddlewareAddsTraceIDStructuredLogAndMetrics(t *testing.T) {
	var logs bytes.Buffer
	now := time.Date(2026, 6, 25, 13, 0, 0, 0, time.UTC)
	generatedTraceID := "11112222333344445555666677778888"
	observer := NewObserver(Options{
		Writer:                &logs,
		Now:                   func() time.Time { return now },
		GenerateID:            func() string { return generatedTraceID },
		ServiceVersion:        "test-version",
		DeploymentEnvironment: "test",
	})

	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := TraceIDFromContext(r.Context()); got != generatedTraceID {
			t.Fatalf("trace id in context = %q, want %s", got, generatedTraceID)
		}
		EnrichRequestLogFields(r.Context(), "tenant-123", "user-456", "admin")
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/journal_entries", nil)
	request.RemoteAddr = "203.0.113.5:5000"
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get(HeaderTraceID); got != generatedTraceID {
		t.Fatalf("response trace header = %q, want %s", got, generatedTraceID)
	}
	if got := recorder.Header().Get(HeaderTraceparent); got != "00-"+generatedTraceID+"-0000000000000001-01" {
		t.Fatalf("response traceparent = %q", got)
	}

	var entry accessLog
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("decode structured access log: %v", err)
	}
	if entry.TraceID != generatedTraceID || entry.Method != http.MethodPost || entry.Path != "/api/v1/journal_entries" || entry.Status != http.StatusAccepted {
		t.Fatalf("unexpected access log entry: %#v", entry)
	}
	if entry.Timestamp != "2026-06-25T13:00:00Z" || entry.At != entry.Timestamp {
		t.Fatalf("access log missing canonical timestamp field: %#v", entry)
	}
	if entry.Severity != "info" || entry.Level != entry.Severity {
		t.Fatalf("access log missing canonical severity field: %#v", entry)
	}
	if entry.Component != "scriptureforge-api" || entry.Service != "scriptureforge-api" || entry.ServiceVersion != "test-version" || entry.DeploymentEnvironment != "test" {
		t.Fatalf("access log missing service identity fields: %#v", entry)
	}
	if entry.TenantID != "tenant-123" || entry.UserID != "user-456" || entry.Role != "admin" {
		t.Fatalf("access log missing verified principal fields: %#v", entry)
	}

	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_http_requests_total{method="POST",path="/api/v1/journal_entries",status="202"} 1`) {
		t.Fatalf("metrics did not include request count, got:\n%s", metrics)
	}
	if !strings.Contains(metrics, "scriptureforge_http_request_duration_seconds_sum") {
		t.Fatalf("metrics did not include duration sum, got:\n%s", metrics)
	}
	if !strings.Contains(metrics, `scriptureforge_http_request_duration_seconds_bucket{method="POST",path="/api/v1/journal_entries",status="202",le="+Inf"} 1`) {
		t.Fatalf("metrics did not include request duration histogram bucket, got:\n%s", metrics)
	}
	if !strings.Contains(metrics, `scriptureforge_http_request_duration_seconds_count{method="POST",path="/api/v1/journal_entries",status="202"} 1`) {
		t.Fatalf("metrics did not include request duration histogram count, got:\n%s", metrics)
	}
}

func TestMiddlewareProvidesObserverForDependencyMetrics(t *testing.T) {
	observer := NewObserver(Options{})
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ObserveDependencyFromContext(r.Context(), "Postgres", "Room Membership", "success", 20*time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/rooms/active", nil))

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="postgres",operation="room_membership",status="success"} 1`) {
		t.Fatalf("metrics missing context dependency operation:\n%s", metrics)
	}
}

func TestMiddlewarePreservesInboundTraceIDAndNormalizesIDs(t *testing.T) {
	var logs bytes.Buffer
	observer := NewObserver(Options{Writer: &logs})
	inboundTraceID := "aaaabbbbccccddddeeeeffff00001111"
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/journal_entries/018fe13d-9a4b-7d1a-a5b2-04ad8f98a333", nil)
	request.Header.Set(HeaderTraceID, inboundTraceID)
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get(HeaderTraceID); got != inboundTraceID {
		t.Fatalf("response trace header = %q, want inbound trace", got)
	}

	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `path="/api/v1/journal_entries/:id"`) {
		t.Fatalf("metrics did not normalize high-cardinality id path, got:\n%s", metrics)
	}
}

func TestMiddlewarePropagatesW3CTraceparent(t *testing.T) {
	var logs bytes.Buffer
	traceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	observer := NewObserver(Options{Writer: &logs})
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := TraceIDFromContext(r.Context()); got != traceID {
			t.Fatalf("trace id in context = %q, want %s", got, traceID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/active", nil)
	request.Header.Set(HeaderTraceparent, "00-"+traceID+"-00f067aa0ba902b7-01")
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get(HeaderTraceID); got != traceID {
		t.Fatalf("response trace id = %q, want %s", got, traceID)
	}
	if got := recorder.Header().Get(HeaderTraceparent); got != "00-"+traceID+"-0000000000000001-01" {
		t.Fatalf("response traceparent = %q", got)
	}

	var entry accessLog
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("decode structured access log: %v", err)
	}
	if entry.TraceID != traceID {
		t.Fatalf("log trace id = %q, want %s", entry.TraceID, traceID)
	}
}

func TestMiddlewareBindsOTelSpanToAcceptedXTraceID(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
	})

	var logs bytes.Buffer
	traceID := "1234567890abcdef1234567890abcdef"
	observer := NewObserver(Options{Writer: &logs})
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := TraceIDFromContext(r.Context()); got != traceID {
			t.Fatalf("trace id in context = %q, want %s", got, traceID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/active", nil)
	request.Header.Set(HeaderTraceID, traceID)
	handler.ServeHTTP(recorder, request)

	var requestSpan tracetest.SpanStub
	for _, span := range exporter.GetSpans() {
		if span.Name == "GET /api/v1/rooms/active" {
			requestSpan = span
			break
		}
	}
	if requestSpan.Name == "" {
		t.Fatalf("request span not exported: %#v", exporter.GetSpans())
	}
	if got := requestSpan.SpanContext.TraceID().String(); got != traceID {
		t.Fatalf("exported span trace id = %q, want accepted X-Trace-ID %s", got, traceID)
	}
	var entry accessLog
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("decode structured access log: %v", err)
	}
	if entry.TraceID != traceID || recorder.Header().Get(HeaderTraceID) != traceID {
		t.Fatalf("trace id was not consistent across log/header: log=%q header=%q want=%s", entry.TraceID, recorder.Header().Get(HeaderTraceID), traceID)
	}
}

func TestMiddlewareFallsBackToXTraceIDWhenTraceparentInvalid(t *testing.T) {
	fallbackTraceID := "22223333444455556666777788889999"
	observer := NewObserver(Options{GenerateID: func() string { return fallbackTraceID }})
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := TraceIDFromContext(r.Context()); got != fallbackTraceID {
			t.Fatalf("trace id in context = %q, want %s", got, fallbackTraceID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	request.Header.Set(HeaderTraceparent, "00-not-a-valid-trace-id-00f067aa0ba902b7-01")
	request.Header.Set(HeaderTraceID, fallbackTraceID)
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get(HeaderTraceID); got != fallbackTraceID {
		t.Fatalf("response trace id = %q, want %s", got, fallbackTraceID)
	}
}

func TestMiddlewareRejectsInvalidXTraceIDAndGeneratorFallbacks(t *testing.T) {
	var logs bytes.Buffer
	observer := NewObserver(Options{
		Writer:     &logs,
		GenerateID: func() string { return "not-a-valid-trace-id" },
	})
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := TraceIDFromContext(r.Context()); len(got) != 32 || got == "not-a-valid-trace-id" {
			t.Fatalf("trace id in context = %q, want generated 32-hex fallback", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	request.Header.Set(HeaderTraceID, "client-trace-789")
	handler.ServeHTTP(recorder, request)

	traceID := recorder.Header().Get(HeaderTraceID)
	if len(traceID) != 32 || traceID == "client-trace-789" {
		t.Fatalf("response trace id = %q, want generated 32-hex fallback", traceID)
	}
	if got := recorder.Header().Get(HeaderTraceparent); !strings.HasPrefix(got, "00-"+traceID+"-0000000000000001-") {
		t.Fatalf("response traceparent = %q", got)
	}
	var entry accessLog
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("decode structured access log: %v", err)
	}
	if entry.TraceID != traceID {
		t.Fatalf("log trace id = %q, want response trace id %q", entry.TraceID, traceID)
	}
}

func TestMetricsHandlerServesPrometheusText(t *testing.T) {
	observer := NewObserver(Options{})
	observer.record(http.MethodGet, "/ready", http.StatusOK, 25*time.Millisecond)

	recorder := httptest.NewRecorder()
	observer.MetricsHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("metrics content type = %q, want text/plain", got)
	}
	if !strings.Contains(recorder.Body.String(), "scriptureforge_http_requests_total") {
		t.Fatalf("metrics body missing request counter:\n%s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `scriptureforge_http_request_duration_seconds_bucket{method="GET",path="/ready",status="200",le="0.025"} 1`) {
		t.Fatalf("metrics body missing request duration histogram bucket:\n%s", recorder.Body.String())
	}
}

func TestMetricsHandlerRestrictsMethods(t *testing.T) {
	observer := NewObserver(Options{})

	head := httptest.NewRecorder()
	observer.MetricsHandler().ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/metrics", nil))
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD /metrics status = %d, want 200", head.Code)
	}
	if head.Body.Len() != 0 {
		t.Fatalf("HEAD /metrics body length = %d, want 0", head.Body.Len())
	}
	if got := head.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("HEAD /metrics content type = %q, want text/plain", got)
	}

	post := httptest.NewRecorder()
	observer.MetricsHandler().ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics status = %d, want 405", post.Code)
	}
	if got := post.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("POST /metrics Allow = %q, want GET, HEAD", got)
	}
	if strings.Contains(post.Body.String(), "scriptureforge_http_requests_total") {
		t.Fatalf("POST /metrics should not expose metrics body:\n%s", post.Body.String())
	}
}

func TestMiddlewareDoesNotRecordMetricsScrapes(t *testing.T) {
	var logs bytes.Buffer
	observer := NewObserver(Options{Writer: &logs})
	handler := observer.Middleware(observer.MetricsHandler())

	for range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("/metrics status = %d, want 200", recorder.Code)
		}
	}

	if logs.Len() != 0 {
		t.Fatalf("metrics scrapes should not create access logs, got %s", logs.String())
	}
	if snapshot := observer.Snapshot(); strings.Contains(snapshot, `path="/metrics"`) {
		t.Fatalf("metrics scrapes should not be counted as application traffic:\n%s", snapshot)
	}
}

func TestMiddlewarePreservesStreamingResponseWriterCapabilities(t *testing.T) {
	observer := NewObserver(Options{})
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			t.Fatal("observability status recorder should preserve http.Flusher")
		}
		if unwrapped := http.NewResponseController(w).Flush(); unwrapped != nil {
			t.Fatalf("response controller flush through observability wrapper failed: %v", unwrapped)
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/rooms/state/018fe13d-9a4b-7d1a-a5b2-04ad8f98a333", nil))

	if !recorder.Flushed {
		t.Fatal("underlying response recorder was not flushed through observability wrapper")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want implicit 200 committed by flush", recorder.Code)
	}
	if metrics := observer.Snapshot(); !strings.Contains(metrics, `path="/api/v1/rooms/state/:id"`) || !strings.Contains(metrics, `status="200"`) {
		t.Fatalf("streaming-capable wrapped response should still record normalized metrics:\n%s", metrics)
	}
}

func TestObserveDependencyAddsLowCardinalityMetrics(t *testing.T) {
	observer := NewObserver(Options{})

	observer.ObserveDependency("Zoom API", "Create Meeting", "5xx", 1500*time.Millisecond)
	observer.ObserveDependency("Zoom API", "Create Meeting", "5xx", -10*time.Millisecond)

	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="zoom_api",operation="create_meeting",status="5xx"} 2`) {
		t.Fatalf("metrics missing dependency operation count:\n%s", metrics)
	}
	if !strings.Contains(metrics, `scriptureforge_dependency_operation_duration_seconds_sum{dependency="zoom_api",operation="create_meeting",status="5xx"} 1.500000`) {
		t.Fatalf("metrics missing dependency duration sum:\n%s", metrics)
	}
}

func TestObserveDependencyFromContextAddsTraceSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
	})

	ctx, parent := otel.Tracer("scriptureforge-test").Start(context.Background(), "request")
	observer := NewObserver(Options{})
	ctx = WithObserver(ctx, observer)
	ObserveDependencyFromContext(ctx, "Zoom API", "Create Meeting", "timeout_or_network_error", 1500*time.Millisecond)
	parent.End()

	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("exported spans = %d, want request plus dependency span: %#v", len(spans), spans)
	}
	var dependencySpan tracetest.SpanStub
	for _, span := range spans {
		if span.Name == "dependency.zoom_api.create_meeting" {
			dependencySpan = span
			break
		}
	}
	if dependencySpan.Name == "" {
		t.Fatalf("dependency span not exported: %#v", spans)
	}
	if dependencySpan.Parent.SpanID() != spans[0].SpanContext.SpanID() && dependencySpan.Parent.SpanID() != spans[1].SpanContext.SpanID() {
		t.Fatalf("dependency span parent = %s, want one exported request span", dependencySpan.Parent.SpanID())
	}
	if dependencySpan.Status.Code != codes.Error {
		t.Fatalf("dependency span status = %#v, want error for timeout/network status", dependencySpan.Status)
	}
	for key, want := range map[string]string{
		"scriptureforge.dependency":           "zoom_api",
		"scriptureforge.dependency.operation": "create_meeting",
		"scriptureforge.dependency.status":    "timeout_or_network_error",
	} {
		if got := spanAttributeString(dependencySpan, key); got != want {
			t.Fatalf("dependency span attr %s = %q, want %q; attrs=%#v", key, got, want, dependencySpan.Attributes)
		}
	}
	if got := spanAttributeFloat64(dependencySpan, "scriptureforge.dependency.duration_ms"); got != 1500 {
		t.Fatalf("dependency duration attr = %f, want 1500", got)
	}
	if metrics := observer.Snapshot(); !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="zoom_api",operation="create_meeting",status="timeout_or_network_error"} 1`) {
		t.Fatalf("dependency span path should preserve existing metric:\n%s", metrics)
	}
}

func TestMockDependencyStatusIsError(t *testing.T) {
	if !dependencyStatusIsError("mock_success") {
		t.Fatal("mock dependency status must not be normalized as a production success")
	}
}

func TestDroppedRejectedAndUnavailableDependencyStatusesAreErrors(t *testing.T) {
	for _, status := range []string{"dropped", "room_broadcast_dropped", "rejected", "provider_unavailable"} {
		if !dependencyStatusIsError(status) {
			t.Fatalf("dependency status %q must mark the span as an error", status)
		}
	}
}

func TestArchitectureMetricProfilesExposeWebSocketAndAIInference(t *testing.T) {
	observer := NewObserver(Options{})
	ctx := WithObserver(context.Background(), observer)

	releaseFirst := ObserveWebSocketActiveConnectionFromContext(ctx)
	releaseSecond := ObserveWebSocketActiveConnectionFromContext(ctx)
	ObserveAIInferenceFromContext(ctx, "gpt-4.1", "success", 120*time.Millisecond)
	ObserveAIInferenceFromContext(ctx, "gpt-4.1", "success", 30*time.Millisecond)

	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `websocket_active_connections_count 2`) {
		t.Fatalf("metrics missing active WebSocket gauge:\n%s", metrics)
	}
	if !strings.Contains(metrics, `ai_inference_duration_seconds_sum{profile="gpt-4.1",status="success"} 0.150000`) {
		t.Fatalf("metrics missing AI inference duration sum:\n%s", metrics)
	}
	if !strings.Contains(metrics, `ai_inference_duration_seconds_count{profile="gpt-4.1",status="success"} 2`) {
		t.Fatalf("metrics missing AI inference count:\n%s", metrics)
	}

	releaseFirst()
	releaseSecond()
	releaseSecond()
	if metrics := observer.Snapshot(); !strings.Contains(metrics, `websocket_active_connections_count 0`) {
		t.Fatalf("active WebSocket gauge should not go below zero:\n%s", metrics)
	}
}

func spanAttributeString(span tracetest.SpanStub, key string) string {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsString()
		}
	}
	return ""
}

func spanAttributeFloat64(span tracetest.SpanStub, key string) float64 {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsFloat64()
		}
	}
	return 0
}
