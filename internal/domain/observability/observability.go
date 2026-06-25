package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
)

const (
	HeaderTraceID     = "X-Trace-ID"
	HeaderTraceparent = "Traceparent"
)

type traceContextKey string

const contextKeyTraceID traceContextKey = "trace_id"

type Observer struct {
	mu          sync.Mutex
	writer      io.Writer
	now         func() time.Time
	generateID  func() string
	requests    map[metricKey]int64
	durationSum map[metricKey]float64
}

type metricKey struct {
	Method string
	Path   string
	Status int
}

type Options struct {
	Writer     io.Writer
	Now        func() time.Time
	GenerateID func() string
}

type accessLog struct {
	Level      string `json:"level"`
	Message    string `json:"message"`
	TraceID    string `json:"trace_id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	RemoteAddr string `json:"remote_addr"`
	At         string `json:"at"`
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func NewDefaultObserver() *Observer {
	return NewObserver(Options{Writer: os.Stdout})
}

func NewObserver(options Options) *Observer {
	writer := options.Writer
	if writer == nil {
		writer = io.Discard
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	generateID := options.GenerateID
	if generateID == nil {
		generateID = newTraceID
	}
	return &Observer{
		writer:      writer,
		now:         now,
		generateID:  generateID,
		requests:    map[metricKey]int64{},
		durationSum: map[metricKey]float64{},
	}
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, contextKeyTraceID, traceID)
}

func TraceIDFromContext(ctx context.Context) string {
	if traceID, ok := ctx.Value(contextKeyTraceID).(string); ok {
		return traceID
	}
	return ""
}

func (o *Observer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := o.now()
		traceID := traceIDFromHeaders(r.Header)
		if traceID == "" {
			traceID = o.generateID()
		}

		spanCtx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		spanCtx, span := otel.Tracer("scriptureforge-api").Start(spanCtx, r.Method+" "+routeLabel(r.URL.Path))
		defer span.End()

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		recorder.Header().Set(HeaderTraceID, traceID)
		recorder.Header().Set(HeaderTraceparent, formatTraceparent(traceID))
		next.ServeHTTP(recorder, r.WithContext(WithTraceID(spanCtx, traceID)))

		duration := o.now().Sub(start)
		if duration < 0 {
			duration = 0
		}
		route := routeLabel(r.URL.Path)
		span.SetAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("url.path", route),
			attribute.Int("http.response.status_code", recorder.status),
			attribute.String("scriptureforge.trace_id", traceID),
		)
		o.record(r.Method, route, recorder.status, duration)
		o.writeAccessLog(accessLog{
			Level:      "info",
			Message:    "http_request",
			TraceID:    traceID,
			Method:     r.Method,
			Path:       route,
			Status:     recorder.status,
			DurationMS: duration.Milliseconds(),
			RemoteAddr: r.RemoteAddr,
			At:         start.UTC().Format(time.RFC3339Nano),
		})
	})
}

func traceIDFromHeaders(headers http.Header) string {
	if traceID := traceIDFromTraceparent(headers.Get(HeaderTraceparent)); traceID != "" {
		return traceID
	}
	return strings.TrimSpace(headers.Get(HeaderTraceID))
}

func traceIDFromTraceparent(header string) string {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) != 4 {
		return ""
	}
	traceID := strings.ToLower(parts[1])
	if len(traceID) != 32 || traceID == "00000000000000000000000000000000" {
		return ""
	}
	if _, err := hex.DecodeString(traceID); err != nil {
		return ""
	}
	return traceID
}

func formatTraceparent(traceID string) string {
	traceID = strings.ToLower(strings.TrimSpace(traceID))
	if len(traceID) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(traceID); err != nil {
		return ""
	}
	return "00-" + traceID + "-0000000000000000-01"
}

func (o *Observer) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, o.Snapshot())
	})
}

func (o *Observer) Snapshot() string {
	o.mu.Lock()
	defer o.mu.Unlock()

	var builder strings.Builder
	builder.WriteString("# HELP scriptureforge_http_requests_total Total HTTP requests by method, path, and status.\n")
	builder.WriteString("# TYPE scriptureforge_http_requests_total counter\n")
	for key, count := range o.requests {
		builder.WriteString(fmt.Sprintf(
			"scriptureforge_http_requests_total{method=%q,path=%q,status=%q} %d\n",
			key.Method,
			escapeLabel(key.Path),
			strconv.Itoa(key.Status),
			count,
		))
	}
	builder.WriteString("# HELP scriptureforge_http_request_duration_seconds_sum Total HTTP request duration seconds by method, path, and status.\n")
	builder.WriteString("# TYPE scriptureforge_http_request_duration_seconds_sum counter\n")
	for key, sum := range o.durationSum {
		builder.WriteString(fmt.Sprintf(
			"scriptureforge_http_request_duration_seconds_sum{method=%q,path=%q,status=%q} %.6f\n",
			key.Method,
			escapeLabel(key.Path),
			strconv.Itoa(key.Status),
			sum,
		))
	}
	return builder.String()
}

func (o *Observer) record(method, path string, status int, duration time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := metricKey{Method: method, Path: path, Status: status}
	o.requests[key]++
	o.durationSum[key] += duration.Seconds()
}

func (o *Observer) writeAccessLog(entry accessLog) {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = o.writer.Write(append(encoded, '\n'))
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func newTraceID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(bytes)
}

var volatilePathSegment = regexp.MustCompile(`/[0-9a-fA-F-]{12,}`)

func routeLabel(path string) string {
	if path == "" {
		return "/"
	}
	return volatilePathSegment.ReplaceAllString(path, "/:id")
}

func escapeLabel(value string) string {
	return strings.ReplaceAll(value, "\\", "\\\\")
}
