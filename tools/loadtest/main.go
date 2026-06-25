package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/ports"
)

type config struct {
	Target                    string
	Method                    string
	Duration                  time.Duration
	Concurrency               int
	Timeout                   time.Duration
	ExpectStatus              int
	MinRPS                    float64
	MaxP99                    time.Duration
	SelfTest                  bool
	WebSocket                 bool
	WebSocketSelfTest         bool
	WSEventsPerClient         int
	WSRoomID                  string
	WSToken                   string
	WSOrigin                  string
	WSReplicaArtifactURL      string
	RedisTelemetryArtifactURL string
}

type report struct {
	Target                    string   `json:"target"`
	Method                    string   `json:"method"`
	DurationMS                int64    `json:"duration_ms"`
	Concurrency               int      `json:"concurrency"`
	Requests                  int      `json:"requests"`
	Failures                  int      `json:"failures"`
	RPS                       float64  `json:"rps"`
	P50MS                     int64    `json:"p50_ms"`
	P95MS                     int64    `json:"p95_ms"`
	P99MS                     int64    `json:"p99_ms"`
	MinRPS                    float64  `json:"min_rps,omitempty"`
	MaxP99MS                  int64    `json:"max_p99_ms,omitempty"`
	WSReplicaArtifactURL      string   `json:"ws_replica_artifact_url,omitempty"`
	RedisTelemetryArtifactURL string   `json:"redis_telemetry_artifact_url,omitempty"`
	ThresholdPass             bool     `json:"threshold_pass"`
	EvidenceItems             []string `json:"evidence_items,omitempty"`
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
	flag.StringVar(&cfg.Target, "target", "", "HTTP URL to load test, for example http://127.0.0.1:8080/health")
	flag.StringVar(&cfg.Method, "method", http.MethodGet, "HTTP method")
	flag.DurationVar(&cfg.Duration, "duration", 10*time.Second, "test duration")
	flag.IntVar(&cfg.Concurrency, "concurrency", 16, "number of concurrent workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 2*time.Second, "per-request timeout")
	flag.IntVar(&cfg.ExpectStatus, "expect-status", http.StatusOK, "expected HTTP status code")
	flag.Float64Var(&cfg.MinRPS, "min-rps", 0, "optional minimum requests per second threshold")
	flag.DurationVar(&cfg.MaxP99, "max-p99", 0, "optional maximum P99 latency threshold")
	flag.BoolVar(&cfg.SelfTest, "self-test", false, "run against an in-process health endpoint")
	flag.BoolVar(&cfg.WebSocket, "websocket", false, "run a WebSocket room-stream load test against -target")
	flag.BoolVar(&cfg.WebSocketSelfTest, "websocket-self-test", false, "run against an in-process WebSocket room endpoint")
	flag.IntVar(&cfg.WSEventsPerClient, "ws-events-per-client", 5, "events each WebSocket client sends during -websocket or -websocket-self-test")
	flag.StringVar(&cfg.WSRoomID, "ws-room-id", "", "room id embedded in WebSocket room event envelopes; defaults to the final path segment of -target")
	flag.StringVar(&cfg.WSToken, "ws-token", "", "optional bearer token for WebSocket Authorization header")
	flag.StringVar(&cfg.WSOrigin, "ws-origin", "http://localhost", "Origin header for WebSocket upgrades")
	flag.StringVar(&cfg.WSReplicaArtifactURL, "ws-replica-artifact-url", os.Getenv("STAGING_WS_REPLICA_ARTIFACT_URL"), "HTTPS artifact proving WebSocket load reached multiple API replicas")
	flag.StringVar(&cfg.RedisTelemetryArtifactURL, "redis-telemetry-artifact-url", os.Getenv("STAGING_REDIS_TELEMETRY_ARTIFACT_URL"), "HTTPS artifact proving Redis telemetry during the WebSocket load run")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.Duration <= 0 {
		return errors.New("duration must be positive")
	}
	if cfg.Concurrency <= 0 {
		return errors.New("concurrency must be positive")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.WebSocketSelfTest {
		return runWebSocketSelfTest(cfg, output)
	}
	if cfg.WebSocket {
		return runWebSocketLoad(cfg, output)
	}

	var server *httptest.Server
	if cfg.SelfTest {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		defer server.Close()
		cfg.Target = server.URL + "/health"
	}
	if cfg.Target == "" {
		return errors.New("target is required unless -self-test is set")
	}

	start := time.Now()
	latencies, failures := execute(cfg)
	elapsed := time.Since(start)
	result := buildReport(cfg, elapsed, latencies, failures)

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	if !result.ThresholdPass {
		return errors.New("load thresholds failed")
	}
	return nil
}

func execute(cfg config) ([]time.Duration, int) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	client := &http.Client{Timeout: cfg.Timeout}
	var mu sync.Mutex
	latencies := make([]time.Duration, 0, cfg.Concurrency*1024)
	totalFailures := 0
	var wg sync.WaitGroup

	for worker := 0; worker < cfg.Concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localFailures := 0
			for ctx.Err() == nil {
				request, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.Target, nil)
				if err != nil {
					localFailures++
					continue
				}
				request.Header.Set("User-Agent", "scriptureforge-loadtest/1.0")
				before := time.Now()
				response, err := client.Do(request)
				latency := time.Since(before)
				if err != nil {
					if ctx.Err() == nil {
						localFailures++
					}
					continue
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != cfg.ExpectStatus {
					localFailures++
					continue
				}
				mu.Lock()
				latencies = append(latencies, latency)
				mu.Unlock()
			}
			if localFailures > 0 {
				mu.Lock()
				totalFailures += localFailures
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return latencies, totalFailures
}

type wsSelfTestStore struct {
	mu       sync.Mutex
	sequence int64
}

func (s *wsSelfTestStore) AppendRoomEvent(ctx context.Context, roomID, eventJSON string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	return s.sequence, nil
}

func runWebSocketSelfTest(cfg config, output io.Writer) error {
	if cfg.WSEventsPerClient <= 0 {
		return errors.New("ws-events-per-client must be positive")
	}
	originalLogOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(originalLogOutput)

	const roomID = "load-room"
	const orgID = "load-org"

	socket := &ports.SocketConnection{
		StateManager: &wsSelfTestStore{},
		Hub:          ports.NewRoomHub(),
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, requestedRoomID string) bool {
			return requestedRoomID == roomID && claims.OrganizationID == orgID && claims.UserID != ""
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("client")
		if clientID == "" {
			clientID = "anonymous"
		}
		claims := &auth.TokenClaims{
			UserID:         "load-client-" + clientID,
			OrganizationID: orgID,
			Role:           "member",
		}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	}))
	defer server.Close()

	cfg.Target = "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/" + roomID
	cfg.Method = "WEBSOCKET"
	cfg.WSRoomID = roomID
	cfg.WSOrigin = "http://localhost"

	start := time.Now()
	latencies, failures := executeWebSocketLoad(cfg)
	elapsed := time.Since(start)
	result := buildReport(cfg, elapsed, latencies, failures)

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	if !result.ThresholdPass {
		return errors.New("websocket load thresholds failed")
	}
	return nil
}

func runWebSocketLoad(cfg config, output io.Writer) error {
	if cfg.Target == "" {
		return errors.New("target is required for -websocket")
	}
	if cfg.WSEventsPerClient <= 0 {
		return errors.New("ws-events-per-client must be positive")
	}
	if !strings.HasPrefix(cfg.Target, "ws://") && !strings.HasPrefix(cfg.Target, "wss://") {
		return errors.New("websocket target must start with ws:// or wss://")
	}
	if cfg.WSRoomID == "" {
		cfg.WSRoomID = roomIDFromTarget(cfg.Target)
	}
	if cfg.WSRoomID == "" {
		return errors.New("ws-room-id is required when it cannot be inferred from target")
	}
	replicaArtifact, err := normalizeHTTPSArtifactURL(cfg.WSReplicaArtifactURL, "ws-replica-artifact-url")
	if err != nil {
		return err
	}
	redisArtifact, err := normalizeHTTPSArtifactURL(cfg.RedisTelemetryArtifactURL, "redis-telemetry-artifact-url")
	if err != nil {
		return err
	}
	cfg.WSReplicaArtifactURL = replicaArtifact
	cfg.RedisTelemetryArtifactURL = redisArtifact
	cfg.Method = "WEBSOCKET"

	start := time.Now()
	latencies, failures := executeWebSocketLoad(cfg)
	elapsed := time.Since(start)
	result := buildReport(cfg, elapsed, latencies, failures)

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	if !result.ThresholdPass {
		return errors.New("websocket load thresholds failed")
	}
	return nil
}

func executeWebSocketLoad(cfg config) ([]time.Duration, int) {
	var mu sync.Mutex
	latencies := make([]time.Duration, 0, cfg.Concurrency*cfg.WSEventsPerClient)
	totalFailures := 0
	var wg sync.WaitGroup
	dialer := websocket.Dialer{HandshakeTimeout: cfg.Timeout}

	for client := 0; client < cfg.Concurrency; client++ {
		wg.Add(1)
		go func(client int) {
			defer wg.Done()
			localFailures := 0
			target, err := addClientQuery(cfg.Target, client)
			if err != nil {
				mu.Lock()
				totalFailures++
				mu.Unlock()
				return
			}
			headers := http.Header{"Origin": []string{cfg.WSOrigin}}
			if cfg.WSToken != "" {
				headers.Set("Authorization", "Bearer "+cfg.WSToken)
			}
			conn, response, err := dialer.Dial(target, headers)
			if response != nil {
				_ = response.Body.Close()
			}
			if err != nil {
				mu.Lock()
				totalFailures++
				mu.Unlock()
				return
			}
			defer func() {
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "self-test complete"), time.Now().Add(cfg.Timeout))
				_ = conn.Close()
			}()

			for eventIndex := 0; eventIndex < cfg.WSEventsPerClient; eventIndex++ {
				marker := fmt.Sprintf("client:%d:event:%d", client, eventIndex)
				payload, _ := json.Marshal(map[string]string{"marker": marker})
				event := ports.RoomEvent{
					Type:    "load",
					RoomID:  cfg.WSRoomID,
					Payload: payload,
				}
				before := time.Now()
				if err := conn.WriteJSON(event); err != nil {
					localFailures++
					continue
				}
				if waitForOwnBroadcast(conn, cfg.Timeout, marker) {
					mu.Lock()
					latencies = append(latencies, time.Since(before))
					mu.Unlock()
				} else {
					localFailures++
				}
			}
			if localFailures > 0 {
				mu.Lock()
				totalFailures += localFailures
				mu.Unlock()
			}
		}(client)
	}

	wg.Wait()
	return latencies, totalFailures
}

func addClientQuery(target string, client int) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("client", fmt.Sprintf("%d", client))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func roomIDFromTarget(target string) string {
	beforeQuery, _, _ := strings.Cut(target, "?")
	index := strings.LastIndex(beforeQuery, "/")
	if index == -1 {
		return ""
	}
	return beforeQuery[index+1:]
}

func waitForOwnBroadcast(conn *websocket.Conn, timeout time.Duration, marker string) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		var event ports.RoomEvent
		if err := conn.ReadJSON(&event); err != nil {
			return false
		}
		if strings.Contains(string(event.Payload), marker) && event.Sequence > 0 {
			return true
		}
	}
	return false
}

func buildReport(cfg config, elapsed time.Duration, latencies []time.Duration, failures int) report {
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	requests := len(latencies)
	rps := 0.0
	if elapsed > 0 {
		rps = float64(requests) / elapsed.Seconds()
	}
	result := report{
		Target:                    cfg.Target,
		Method:                    cfg.Method,
		DurationMS:                elapsed.Milliseconds(),
		Concurrency:               cfg.Concurrency,
		Requests:                  requests,
		Failures:                  failures,
		RPS:                       rps,
		P50MS:                     percentile(latencies, 0.50).Milliseconds(),
		P95MS:                     percentile(latencies, 0.95).Milliseconds(),
		P99MS:                     percentile(latencies, 0.99).Milliseconds(),
		MinRPS:                    cfg.MinRPS,
		MaxP99MS:                  cfg.MaxP99.Milliseconds(),
		WSReplicaArtifactURL:      cfg.WSReplicaArtifactURL,
		RedisTelemetryArtifactURL: cfg.RedisTelemetryArtifactURL,
		ThresholdPass:             failures == 0 && requests > 0,
		EvidenceItems:             evidenceItemsFor(cfg),
	}
	if cfg.MinRPS > 0 && result.RPS < cfg.MinRPS {
		result.ThresholdPass = false
	}
	if cfg.MaxP99 > 0 && percentile(latencies, 0.99) > cfg.MaxP99 {
		result.ThresholdPass = false
	}
	return result
}

func evidenceItemsFor(cfg config) []string {
	if cfg.SelfTest || cfg.WebSocketSelfTest {
		return nil
	}
	if cfg.WebSocket {
		return []string{"PERF-WS-001", "DATA-REDIS-001"}
	}
	return []string{"PERF-HTTP-001"}
}

func percentile(sorted []time.Duration, ratio float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if ratio <= 0 {
		return sorted[0]
	}
	if ratio >= 1 {
		return sorted[len(sorted)-1]
	}
	index := int(float64(len(sorted)-1) * ratio)
	return sorted[index]
}

func normalizeHTTPSArtifactURL(raw, flagName string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("-%s or matching STAGING_* env var must use https", flagName)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("-%s or matching STAGING_* env var must include a host", flagName)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}
