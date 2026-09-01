package observability

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	HeaderTraceID     = "X-Trace-ID"
	HeaderTraceparent = "Traceparent"
)

type traceContextKey string

const contextKeyTraceID traceContextKey = "trace_id"

type observerContextKey string

const contextKeyObserver observerContextKey = "observer"

type Observer struct {
	mu                 sync.Mutex
	writer             io.Writer
	now                func() time.Time
	generateID         func() string
	component          string
	serviceName        string
	serviceVersion     string
	environment        string
	requests           map[metricKey]int64
	durationSum        map[metricKey]float64
	durationBuckets    map[metricBucketKey]int64
	dependencies       map[dependencyMetricKey]int64
	dependencyDuration map[dependencyMetricKey]float64
	websocketActive    int64
	aiInferenceCount   map[aiInferenceMetricKey]int64
	aiInferenceSum     map[aiInferenceMetricKey]float64
}

const maxHTTPMetricSeries = 2048

type metricKey struct {
	Method string
	Path   string
	Status int
}

type metricBucketKey struct {
	metricKey
	Le string
}

type durationBucket struct {
	label      string
	upperBound float64
}

var httpDurationBuckets = []durationBucket{
	{label: "0.005", upperBound: 0.005},
	{label: "0.01", upperBound: 0.01},
	{label: "0.025", upperBound: 0.025},
	{label: "0.05", upperBound: 0.05},
	{label: "0.1", upperBound: 0.1},
	{label: "0.2", upperBound: 0.2},
	{label: "0.5", upperBound: 0.5},
	{label: "1", upperBound: 1},
	{label: "2.5", upperBound: 2.5},
	{label: "5", upperBound: 5},
	{label: "+Inf", upperBound: math.Inf(1)},
}

type dependencyMetricKey struct {
	Dependency string
	Operation  string
	Status     string
}

type aiInferenceMetricKey struct {
	Profile string
	Status  string
}

type Options struct {
	Writer                io.Writer
	Now                   func() time.Time
	GenerateID            func() string
	Component             string
	ServiceName           string
	ServiceVersion        string
	DeploymentEnvironment string
}

type accessLog struct {
	Level                 string `json:"level"`
	Severity              string `json:"severity"`
	Message               string `json:"message"`
	TraceID               string `json:"trace_id"`
	Component             string `json:"component"`
	Service               string `json:"service"`
	ServiceVersion        string `json:"service_version,omitempty"`
	DeploymentEnvironment string `json:"deployment_environment,omitempty"`
	TenantID              string `json:"tenant_id,omitempty"`
	UserID                string `json:"user_id,omitempty"`
	Role                  string `json:"role,omitempty"`
	Method                string `json:"method"`
	Path                  string `json:"path"`
	Status                int    `json:"status"`
	DurationMS            int64  `json:"duration_ms"`
	RemoteAddr            string `json:"remote_addr"`
	At                    string `json:"at"`
	Timestamp             string `json:"timestamp"`
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

type requestLogFields struct {
	TenantID string
	UserID   string
	Role     string
}

type requestLogFieldsContextKey string

const contextKeyRequestLogFields requestLogFieldsContextKey = "request_log_fields"

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
	component := firstNonEmpty(options.Component, "scriptureforge-api")
	serviceName := firstNonEmpty(options.ServiceName, os.Getenv("OTEL_SERVICE_NAME"), "scriptureforge-api")
	serviceVersion := firstNonEmpty(options.ServiceVersion, os.Getenv("SERVICE_VERSION"))
	environment := firstNonEmpty(options.DeploymentEnvironment, os.Getenv("DEPLOYMENT_ENVIRONMENT"))
	return &Observer{
		writer:             writer,
		now:                now,
		generateID:         generateID,
		component:          component,
		serviceName:        serviceName,
		serviceVersion:     serviceVersion,
		environment:        environment,
		requests:           map[metricKey]int64{},
		durationSum:        map[metricKey]float64{},
		durationBuckets:    map[metricBucketKey]int64{},
		dependencies:       map[dependencyMetricKey]int64{},
		dependencyDuration: map[dependencyMetricKey]float64{},
		aiInferenceCount:   map[aiInferenceMetricKey]int64{},
		aiInferenceSum:     map[aiInferenceMetricKey]float64{},
	}
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, contextKeyTraceID, traceID)
}

func WithObserver(ctx context.Context, observer *Observer) context.Context {
	if observer == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKeyObserver, observer)
}

func ObserverFromContext(ctx context.Context) *Observer {
	if observer, ok := ctx.Value(contextKeyObserver).(*Observer); ok {
		return observer
	}
	return nil
}

func EnrichRequestLogFields(ctx context.Context, tenantID, userID, role string) {
	fields, ok := ctx.Value(contextKeyRequestLogFields).(*requestLogFields)
	if !ok || fields == nil {
		return
	}
	fields.TenantID = strings.TrimSpace(tenantID)
	fields.UserID = strings.TrimSpace(userID)
	fields.Role = strings.TrimSpace(role)
}

func TraceIDFromContext(ctx context.Context) string {
	if traceID, ok := ctx.Value(contextKeyTraceID).(string); ok {
		return traceID
	}
	return ""
}

func ObserveDependencyFromContext(ctx context.Context, dependency, operation, status string, duration time.Duration) {
	recordDependencySpan(ctx, dependency, operation, status, duration)
	if observer := ObserverFromContext(ctx); observer != nil {
		observer.ObserveDependency(dependency, operation, status, duration)
	}
}

func ObserveAIInferenceFromContext(ctx context.Context, profile, status string, duration time.Duration) {
	if observer := ObserverFromContext(ctx); observer != nil {
		observer.ObserveAIInference(profile, status, duration)
	}
}

func ObserveWebSocketActiveConnectionFromContext(ctx context.Context) func() {
	observer := ObserverFromContext(ctx)
	if observer == nil {
		return func() {}
	}
	observer.AddWebSocketActiveConnection(1)
	return func() {
		observer.AddWebSocketActiveConnection(-1)
	}
}

func recordDependencySpan(ctx context.Context, dependency, operation, status string, duration time.Duration) {
	dependency = lowCardinalityLabel(dependency)
	operation = lowCardinalityLabel(operation)
	status = lowCardinalityLabel(status)
	if duration < 0 {
		duration = 0
	}
	_, span := otel.Tracer("scriptureforge-api").Start(ctx, "dependency."+dependency+"."+operation)
	defer span.End()
	span.SetAttributes(
		attribute.String("scriptureforge.dependency", dependency),
		attribute.String("scriptureforge.dependency.operation", operation),
		attribute.String("scriptureforge.dependency.status", status),
		attribute.Float64("scriptureforge.dependency.duration_ms", float64(duration.Microseconds())/1000),
	)
	if dependencyStatusIsError(status) {
		span.SetStatus(codes.Error, status)
	}
}

func dependencyStatusIsError(status string) bool {
	switch status {
	case "", "success", "allowed":
		return false
	}
	if code, err := strconv.Atoi(status); err == nil {
		return code >= 400
	}
	return strings.Contains(status, "error") ||
		strings.Contains(status, "fail") ||
		strings.Contains(status, "fault") ||
		strings.Contains(status, "timeout") ||
		strings.Contains(status, "mock") ||
		strings.Contains(status, "denied") ||
		strings.Contains(status, "dropped") ||
		strings.Contains(status, "invalid") ||
		strings.Contains(status, "expired") ||
		strings.Contains(status, "limited") ||
		strings.Contains(status, "rejected") ||
		strings.Contains(status, "unavailable")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (o *Observer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMetricsScrape(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		start := o.now()
		traceID := ensureTraceID(traceIDFromHeaders(r.Header), o.generateID)

		spanCtx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		spanCtx = contextWithTraceID(spanCtx, traceID)
		spanCtx, span := otel.Tracer("scriptureforge-api").Start(spanCtx, r.Method+" "+routeLabel(r.URL.Path))
		defer span.End()
		logFields := &requestLogFields{}
		requestCtx := context.WithValue(spanCtx, contextKeyRequestLogFields, logFields)

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		recorder.Header().Set(HeaderTraceID, traceID)
		recorder.Header().Set(HeaderTraceparent, formatTraceparent(traceID))
		next.ServeHTTP(recorder, r.WithContext(WithTraceID(WithObserver(requestCtx, o), traceID)))

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
			Level:                 "info",
			Severity:              "info",
			Message:               "http_request",
			TraceID:               traceID,
			Component:             o.component,
			Service:               o.serviceName,
			ServiceVersion:        o.serviceVersion,
			DeploymentEnvironment: o.environment,
			TenantID:              logFields.TenantID,
			UserID:                logFields.UserID,
			Role:                  logFields.Role,
			Method:                r.Method,
			Path:                  route,
			Status:                recorder.status,
			DurationMS:            duration.Milliseconds(),
			RemoteAddr:            r.RemoteAddr,
			At:                    start.UTC().Format(time.RFC3339Nano),
			Timestamp:             start.UTC().Format(time.RFC3339Nano),
		})
	})
}

func isMetricsScrape(path string) bool {
	return path == "/metrics"
}

func traceIDFromHeaders(headers http.Header) string {
	if traceID := traceIDFromTraceparent(headers.Get(HeaderTraceparent)); traceID != "" {
		return traceID
	}
	return normalizeTraceID(headers.Get(HeaderTraceID))
}

func traceIDFromTraceparent(header string) string {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) != 4 {
		return ""
	}
	if parts[0] != "00" {
		return ""
	}
	if len(parts[2]) != 16 || parts[2] == "0000000000000000" {
		return ""
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return ""
	}
	if len(parts[3]) != 2 {
		return ""
	}
	if _, err := hex.DecodeString(parts[3]); err != nil {
		return ""
	}
	return normalizeTraceID(parts[1])
}

func normalizeTraceID(value string) string {
	traceID := strings.ToLower(strings.TrimSpace(value))
	if traceID == "00000000000000000000000000000000" {
		return ""
	}
	if len(traceID) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(traceID); err != nil {
		return ""
	}
	return traceID
}

func ensureTraceID(value string, generate func() string) string {
	if traceID := normalizeTraceID(value); traceID != "" {
		return traceID
	}
	for range 3 {
		if traceID := normalizeTraceID(generate()); traceID != "" {
			return traceID
		}
	}
	return fallbackTraceID()
}

func fallbackTraceID() string {
	sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	return hex.EncodeToString(sum[:16])
}

func formatTraceparent(traceID string) string {
	traceID = normalizeTraceID(traceID)
	if traceID == "" {
		return ""
	}
	return "00-" + traceID + "-0000000000000001-01"
}

func contextWithTraceID(ctx context.Context, traceID string) context.Context {
	traceID = normalizeTraceID(traceID)
	if traceID == "" {
		return ctx
	}
	current := trace.SpanContextFromContext(ctx)
	if current.IsValid() && current.TraceID().String() == traceID {
		return ctx
	}
	otelTraceID, err := trace.TraceIDFromHex(traceID)
	if err != nil || !otelTraceID.IsValid() {
		return ctx
	}
	spanID := parentSpanIDForTrace(traceID)
	return trace.ContextWithRemoteSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    otelTraceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	}))
}

func parentSpanIDForTrace(traceID string) trace.SpanID {
	sum := sha256.Sum256([]byte(traceID + ":scriptureforge-ingress"))
	var spanID trace.SpanID
	copy(spanID[:], sum[:8])
	if spanID.IsValid() {
		return spanID
	}
	spanID[7] = 1
	return spanID
}

func (o *Observer) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if r.Method == http.MethodHead {
			return
		}
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
	builder.WriteString("# HELP scriptureforge_http_request_duration_seconds HTTP request duration histogram by method, path, and status.\n")
	builder.WriteString("# TYPE scriptureforge_http_request_duration_seconds histogram\n")
	for key, count := range o.durationBuckets {
		builder.WriteString(fmt.Sprintf(
			"scriptureforge_http_request_duration_seconds_bucket{method=%q,path=%q,status=%q,le=%q} %d\n",
			key.Method,
			escapeLabel(key.Path),
			strconv.Itoa(key.Status),
			key.Le,
			count,
		))
	}
	for key, sum := range o.durationSum {
		builder.WriteString(fmt.Sprintf(
			"scriptureforge_http_request_duration_seconds_sum{method=%q,path=%q,status=%q} %.6f\n",
			key.Method,
			escapeLabel(key.Path),
			strconv.Itoa(key.Status),
			sum,
		))
	}
	for key, count := range o.requests {
		builder.WriteString(fmt.Sprintf(
			"scriptureforge_http_request_duration_seconds_count{method=%q,path=%q,status=%q} %d\n",
			key.Method,
			escapeLabel(key.Path),
			strconv.Itoa(key.Status),
			count,
		))
	}
	builder.WriteString("# HELP scriptureforge_dependency_operations_total Total dependency operations by dependency, operation, and status.\n")
	builder.WriteString("# TYPE scriptureforge_dependency_operations_total counter\n")
	for key, count := range o.dependencies {
		builder.WriteString(fmt.Sprintf(
			"scriptureforge_dependency_operations_total{dependency=%q,operation=%q,status=%q} %d\n",
			escapeLabel(key.Dependency),
			escapeLabel(key.Operation),
			escapeLabel(key.Status),
			count,
		))
	}
	builder.WriteString("# HELP scriptureforge_dependency_operation_duration_seconds_sum Total dependency operation duration seconds by dependency, operation, and status.\n")
	builder.WriteString("# TYPE scriptureforge_dependency_operation_duration_seconds_sum counter\n")
	for key, sum := range o.dependencyDuration {
		builder.WriteString(fmt.Sprintf(
			"scriptureforge_dependency_operation_duration_seconds_sum{dependency=%q,operation=%q,status=%q} %.6f\n",
			escapeLabel(key.Dependency),
			escapeLabel(key.Operation),
			escapeLabel(key.Status),
			sum,
		))
	}
	builder.WriteString("# HELP websocket_active_connections_count Active WebSocket connections across live room streams.\n")
	builder.WriteString("# TYPE websocket_active_connections_count gauge\n")
	builder.WriteString(fmt.Sprintf("websocket_active_connections_count %d\n", o.websocketActive))
	builder.WriteString("# HELP ai_inference_duration_seconds AI inference duration summary by profile and status.\n")
	builder.WriteString("# TYPE ai_inference_duration_seconds summary\n")
	for key, sum := range o.aiInferenceSum {
		builder.WriteString(fmt.Sprintf(
			"ai_inference_duration_seconds_sum{profile=%q,status=%q} %.6f\n",
			escapeLabel(key.Profile),
			escapeLabel(key.Status),
			sum,
		))
	}
	for key, count := range o.aiInferenceCount {
		builder.WriteString(fmt.Sprintf(
			"ai_inference_duration_seconds_count{profile=%q,status=%q} %d\n",
			escapeLabel(key.Profile),
			escapeLabel(key.Status),
			count,
		))
	}
	return builder.String()
}

func (o *Observer) ObserveDependency(dependency, operation, status string, duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	key := dependencyMetricKey{
		Dependency: lowCardinalityLabel(dependency),
		Operation:  lowCardinalityLabel(operation),
		Status:     lowCardinalityLabel(status),
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	o.dependencies[key]++
	o.dependencyDuration[key] += duration.Seconds()
}

func (o *Observer) AddWebSocketActiveConnection(delta int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.websocketActive += delta
	if o.websocketActive < 0 {
		o.websocketActive = 0
	}
}

func (o *Observer) ObserveAIInference(profile, status string, duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	key := aiInferenceMetricKey{
		Profile: lowCardinalityLabel(profile),
		Status:  lowCardinalityLabel(status),
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.aiInferenceCount[key]++
	o.aiInferenceSum[key] += duration.Seconds()
}

func (o *Observer) record(method, path string, status int, duration time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := metricKey{Method: method, Path: path, Status: status}
	if _, exists := o.requests[key]; !exists && len(o.requests) >= maxHTTPMetricSeries {
		key = metricKey{Method: "*", Path: "/:other", Status: 0}
	}
	durationSeconds := duration.Seconds()
	o.requests[key]++
	o.durationSum[key] += durationSeconds
	for _, bucket := range httpDurationBuckets {
		if durationSeconds <= bucket.upperBound {
			o.durationBuckets[metricBucketKey{metricKey: key, Le: bucket.label}]++
		}
	}
}

func (o *Observer) writeAccessLog(entry accessLog) {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = o.writer.Write(append(encoded, '\n'))
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(body)
}

func (r *statusRecorder) Flush() {
	flusher, ok := r.ResponseWriter.(http.Flusher)
	if !ok {
		return
	}
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	flusher.Flush()
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func newTraceID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fallbackTraceID()
	}
	return hex.EncodeToString(bytes)
}

var volatilePathSegment = regexp.MustCompile(`/[0-9a-fA-F-]{12,}`)

func routeLabel(path string) string {
	if path == "" {
		return "/"
	}
	label := volatilePathSegment.ReplaceAllString(path, "/:id")
	if len(label) > 256 {
		return "/:long_path"
	}
	return label
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func lowCardinalityLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}

	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			builder.WriteRune(r)
		default:
			builder.WriteRune('_')
		}
		if builder.Len() >= 64 {
			break
		}
	}
	result := strings.Trim(builder.String(), "_-.")
	if result == "" {
		return "unknown"
	}
	return result
}
