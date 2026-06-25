package observability

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMiddlewareAddsTraceIDStructuredLogAndMetrics(t *testing.T) {
	var logs bytes.Buffer
	now := time.Date(2026, 6, 25, 13, 0, 0, 0, time.UTC)
	observer := NewObserver(Options{
		Writer:     &logs,
		Now:        func() time.Time { return now },
		GenerateID: func() string { return "trace-local-123" },
	})

	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := TraceIDFromContext(r.Context()); got != "trace-local-123" {
			t.Fatalf("trace id in context = %q, want trace-local-123", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/journal_entries", nil)
	request.RemoteAddr = "203.0.113.5:5000"
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get(HeaderTraceID); got != "trace-local-123" {
		t.Fatalf("response trace header = %q, want trace-local-123", got)
	}

	var entry accessLog
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("decode structured access log: %v", err)
	}
	if entry.TraceID != "trace-local-123" || entry.Method != http.MethodPost || entry.Path != "/api/v1/journal_entries" || entry.Status != http.StatusAccepted {
		t.Fatalf("unexpected access log entry: %#v", entry)
	}

	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_http_requests_total{method="POST",path="/api/v1/journal_entries",status="202"} 1`) {
		t.Fatalf("metrics did not include request count, got:\n%s", metrics)
	}
	if !strings.Contains(metrics, "scriptureforge_http_request_duration_seconds_sum") {
		t.Fatalf("metrics did not include duration sum, got:\n%s", metrics)
	}
}

func TestMiddlewarePreservesInboundTraceIDAndNormalizesIDs(t *testing.T) {
	var logs bytes.Buffer
	observer := NewObserver(Options{Writer: &logs})
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/journal_entries/018fe13d-9a4b-7d1a-a5b2-04ad8f98a333", nil)
	request.Header.Set(HeaderTraceID, "client-trace-456")
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get(HeaderTraceID); got != "client-trace-456" {
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
	if got := recorder.Header().Get(HeaderTraceparent); got != "00-"+traceID+"-0000000000000000-01" {
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

func TestMiddlewareFallsBackToXTraceIDWhenTraceparentInvalid(t *testing.T) {
	observer := NewObserver(Options{GenerateID: func() string { return "generated-fallback" }})
	handler := observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := TraceIDFromContext(r.Context()); got != "client-trace-789" {
			t.Fatalf("trace id in context = %q, want client-trace-789", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	request.Header.Set(HeaderTraceparent, "00-not-a-valid-trace-id-00f067aa0ba902b7-01")
	request.Header.Set(HeaderTraceID, "client-trace-789")
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get(HeaderTraceID); got != "client-trace-789" {
		t.Fatalf("response trace id = %q, want client-trace-789", got)
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
}
