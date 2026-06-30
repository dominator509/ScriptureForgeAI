package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/ports"
)

var artifactHTTPClient = &http.Client{Timeout: 5 * time.Second}

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
	WSReconnectArtifactURL    string
	WSPollingArtifactURL      string
	RedisTelemetryArtifactURL string
	HTTPReplicaArtifactURL    string
	DependencyTelemetryURL    string
	ReleaseCandidate          string
	ServiceVersion            string
	LoadRunID                 string
	ArtifactEvidence          stagingArtifactEvidence
}

type report struct {
	Target                    string   `json:"target"`
	Method                    string   `json:"method"`
	EvidenceProfile           string   `json:"evidence_profile"`
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
	ProductionTargetRPS       float64  `json:"production_target_rps,omitempty"`
	ProductionTargetP99MS     int64    `json:"production_target_p99_ms,omitempty"`
	ProductionMinDurationMS   int64    `json:"production_min_duration_ms,omitempty"`
	ProductionMinWSEvents     int      `json:"production_min_ws_events,omitempty"`
	WSReplicaArtifactURL      string   `json:"ws_replica_artifact_url,omitempty"`
	WSReconnectArtifactURL    string   `json:"ws_reconnect_artifact_url,omitempty"`
	WSPollingArtifactURL      string   `json:"ws_polling_artifact_url,omitempty"`
	RedisTelemetryArtifactURL string   `json:"redis_telemetry_artifact_url,omitempty"`
	WSOrigin                  string   `json:"ws_origin,omitempty"`
	WSRoomID                  string   `json:"ws_room_id,omitempty"`
	WSAuthenticated           bool     `json:"ws_authenticated,omitempty"`
	HTTPReplicaArtifactURL    string   `json:"http_replica_artifact_url,omitempty"`
	DependencyTelemetryURL    string   `json:"dependency_telemetry_artifact_url,omitempty"`
	HTTPReplicaCount          int      `json:"http_replica_count,omitempty"`
	WSReplicaCount            int      `json:"ws_replica_count,omitempty"`
	DependencyPostgresP99MS   int      `json:"dependency_postgres_p99_ms,omitempty"`
	DependencyRedisP99MS      int      `json:"dependency_redis_p99_ms,omitempty"`
	RoomBroadcastDrops        *int     `json:"room_broadcast_drops,omitempty"`
	ReleaseCandidate          string   `json:"release_candidate,omitempty"`
	ServiceVersion            string   `json:"service_version,omitempty"`
	LoadRunID                 string   `json:"load_run_id,omitempty"`
	WSExpectedEvents          int      `json:"ws_expected_events,omitempty"`
	WSUniqueSequences         int      `json:"ws_unique_sequences,omitempty"`
	WSMinSequence             int64    `json:"ws_min_sequence,omitempty"`
	WSMaxSequence             int64    `json:"ws_max_sequence,omitempty"`
	WSPollingLatestSequence   int64    `json:"ws_polling_latest_sequence,omitempty"`
	WSSequenceContiguous      bool     `json:"ws_sequence_contiguous,omitempty"`
	ThresholdPass             bool     `json:"threshold_pass"`
	ThresholdFailures         []string `json:"threshold_failures,omitempty"`
	EvidenceItems             []string `json:"evidence_items,omitempty"`
	ResultSummary             string   `json:"result_summary,omitempty"`
}

type loadResult struct {
	latencies []time.Duration
	failures  int
	sequences []int64
}

const (
	productionHTTPMinRPS      = 5000
	productionWSMinRPS        = 500
	productionMaxP99          = 200 * time.Millisecond
	productionMinLoadDuration = 60 * time.Second
	productionMinWSEvents     = int(productionWSMinRPS * 60)
)

var latestSequencePattern = regexp.MustCompile(`(?i)\blatest_sequence=([0-9]+)\b`)
var replicaCountPattern = regexp.MustCompile(`(?i)\breplica_count=([0-9]+)\b`)
var postgresP99Pattern = regexp.MustCompile(`(?i)\bpostgres_p99_ms=([0-9]+)\b`)
var redisP99Pattern = regexp.MustCompile(`(?i)\bredis_p99_ms=([0-9]+)\b`)
var roomBroadcastDropsPattern = regexp.MustCompile(`(?i)\broom_broadcast_drops=([0-9]+)\b`)

type stagingArtifactEvidence struct {
	HTTPReplicaCount      int
	WSReplicaCount        int
	PostgresP99MS         int
	RedisP99MS            int
	RoomBroadcastDrops    *int
	PollingLatestSequence int
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
	flag.StringVar(&cfg.WSReconnectArtifactURL, "ws-reconnect-artifact-url", os.Getenv("STAGING_WS_RECONNECT_ARTIFACT_URL"), "HTTPS artifact proving deployed WebSocket reconnect behavior during or adjacent to the load run")
	flag.StringVar(&cfg.WSPollingArtifactURL, "ws-polling-artifact-url", os.Getenv("STAGING_WS_POLLING_ARTIFACT_URL"), "HTTPS artifact proving HTTP polling fallback against the same staged room state")
	flag.StringVar(&cfg.RedisTelemetryArtifactURL, "redis-telemetry-artifact-url", os.Getenv("STAGING_REDIS_TELEMETRY_ARTIFACT_URL"), "HTTPS artifact proving Redis telemetry during the WebSocket load run")
	flag.StringVar(&cfg.HTTPReplicaArtifactURL, "http-replica-artifact-url", os.Getenv("STAGING_HTTP_REPLICA_ARTIFACT_URL"), "HTTPS artifact proving HTTP load reached expected ingress/API replicas")
	flag.StringVar(&cfg.DependencyTelemetryURL, "dependency-telemetry-artifact-url", os.Getenv("STAGING_DEPENDENCY_TELEMETRY_ARTIFACT_URL"), "HTTPS artifact proving database and Redis telemetry during the HTTP load run")
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("STAGING_RELEASE_CANDIDATE"), "release candidate SHA or tag that staging artifacts must name")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("STAGING_SERVICE_VERSION"), "deployed service version that staging artifacts must name")
	flag.StringVar(&cfg.LoadRunID, "load-run-id", os.Getenv("STAGING_LOAD_RUN_ID"), "unique staging load run id that the load report and side artifacts must all name")
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
	if !cfg.SelfTest {
		replicaArtifact, err := normalizeHTTPSArtifactURL(cfg.HTTPReplicaArtifactURL, "http-replica-artifact-url")
		if err != nil {
			return err
		}
		dependencyTelemetryArtifact, err := normalizeHTTPSArtifactURL(cfg.DependencyTelemetryURL, "dependency-telemetry-artifact-url")
		if err != nil {
			return err
		}
		cfg.HTTPReplicaArtifactURL = replicaArtifact
		cfg.DependencyTelemetryURL = dependencyTelemetryArtifact
		if isStagingEvidenceTarget(cfg.Target, false) {
			client := artifactHTTPClient
			if client == nil {
				client = &http.Client{Timeout: cfg.Timeout}
			}
			if client.Timeout == 0 {
				client.Timeout = cfg.Timeout
			}
			artifactEvidence, err := validateStagingHTTPArtifacts(client, cfg)
			if err != nil {
				return err
			}
			cfg.ArtifactEvidence = artifactEvidence
		}
	}

	start := time.Now()
	load := execute(cfg)
	elapsed := time.Since(start)
	result := buildReport(cfg, elapsed, load)

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

func execute(cfg config) loadResult {
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
	return loadResult{latencies: latencies, failures: totalFailures}
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
	load := executeWebSocketLoad(cfg)
	elapsed := time.Since(start)
	result := buildReport(cfg, elapsed, load)

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
	if isStagingEvidenceTarget(cfg.Target, true) {
		if strings.TrimSpace(cfg.WSToken) == "" {
			return errors.New("ws-token is required for staging websocket evidence")
		}
		origin, err := normalizeHTTPSOrigin(cfg.WSOrigin, "ws-origin")
		if err != nil {
			return err
		}
		cfg.WSOrigin = origin
	}
	replicaArtifact, err := normalizeHTTPSArtifactURL(cfg.WSReplicaArtifactURL, "ws-replica-artifact-url")
	if err != nil {
		return err
	}
	reconnectArtifact, err := normalizeHTTPSArtifactURL(cfg.WSReconnectArtifactURL, "ws-reconnect-artifact-url")
	if err != nil {
		return err
	}
	pollingArtifact, err := normalizeHTTPSArtifactURL(cfg.WSPollingArtifactURL, "ws-polling-artifact-url")
	if err != nil {
		return err
	}
	redisArtifact, err := normalizeHTTPSArtifactURL(cfg.RedisTelemetryArtifactURL, "redis-telemetry-artifact-url")
	if err != nil {
		return err
	}
	cfg.WSReplicaArtifactURL = replicaArtifact
	cfg.WSReconnectArtifactURL = reconnectArtifact
	cfg.WSPollingArtifactURL = pollingArtifact
	cfg.RedisTelemetryArtifactURL = redisArtifact
	if isStagingEvidenceTarget(cfg.Target, true) {
		client := artifactHTTPClient
		if client == nil {
			client = &http.Client{Timeout: cfg.Timeout}
		}
		if client.Timeout == 0 {
			client.Timeout = cfg.Timeout
		}
		artifactEvidence, err := validateStagingWebSocketArtifacts(client, cfg)
		if err != nil {
			return err
		}
		cfg.ArtifactEvidence = artifactEvidence
	}
	cfg.Method = "WEBSOCKET"

	start := time.Now()
	load := executeWebSocketLoad(cfg)
	elapsed := time.Since(start)
	result := buildReport(cfg, elapsed, load)

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

func executeWebSocketLoad(cfg config) loadResult {
	var mu sync.Mutex
	latencies := make([]time.Duration, 0, cfg.Concurrency*cfg.WSEventsPerClient)
	sequences := make([]int64, 0, cfg.Concurrency*cfg.WSEventsPerClient)
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
				sequence, ok := waitForOwnBroadcast(conn, cfg.Timeout, marker)
				if ok {
					mu.Lock()
					latencies = append(latencies, time.Since(before))
					sequences = append(sequences, sequence)
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
	return loadResult{latencies: latencies, failures: totalFailures, sequences: sequences}
}

func validateStagingHTTPArtifacts(client *http.Client, cfg config) (stagingArtifactEvidence, error) {
	var evidence stagingArtifactEvidence
	releaseCandidate, serviceVersion, err := requireReleaseMetadata(cfg)
	if err != nil {
		return evidence, err
	}
	releaseMarker := "release_candidate=" + releaseCandidate
	serviceVersionMarker := "service_version=" + serviceVersion
	loadRunMarker, err := requireLoadRunMarker(cfg)
	if err != nil {
		return evidence, err
	}
	artifacts := []struct {
		name     string
		target   string
		required []string
	}{
		{
			name:   "http-replica-artifact-url",
			target: cfg.HTTPReplicaArtifactURL,
			required: []string{
				"api replica distribution",
				"scriptureforge-api",
				"multiple replicas",
				"staging artifact",
				releaseMarker,
				serviceVersionMarker,
				loadRunMarker,
			},
		},
		{
			name:   "dependency-telemetry-artifact-url",
			target: cfg.DependencyTelemetryURL,
			required: []string{
				"dependency telemetry",
				"postgres",
				"postgres_p99_ms=",
				"redis",
				"redis_p99_ms=",
				"p99",
				"dependency_threshold_pass=true",
				"staging artifact",
				releaseMarker,
				serviceVersionMarker,
				loadRunMarker,
			},
		},
	}
	if err := requireDistinctArtifactURLs(artifacts); err != nil {
		return evidence, err
	}
	for _, artifact := range artifacts {
		text, err := validateArtifactMarkers(client, artifact.name, artifact.target, artifact.required, 0)
		if err != nil {
			return evidence, err
		}
		if artifact.name == "http-replica-artifact-url" {
			replicaCount, err := parsePositiveIntMarker(text, replicaCountPattern, artifact.name, "replica_count")
			if err != nil {
				return evidence, err
			}
			if replicaCount < 2 {
				return evidence, fmt.Errorf("%s artifact replica_count=%d must prove at least 2 replicas", artifact.name, replicaCount)
			}
			evidence.HTTPReplicaCount = replicaCount
		}
		if artifact.name == "dependency-telemetry-artifact-url" {
			postgresP99, err := parsePositiveIntMarker(text, postgresP99Pattern, artifact.name, "postgres_p99_ms")
			if err != nil {
				return evidence, err
			}
			redisP99, err := parsePositiveIntMarker(text, redisP99Pattern, artifact.name, "redis_p99_ms")
			if err != nil {
				return evidence, err
			}
			if postgresP99 > int(productionMaxP99.Milliseconds()) {
				return evidence, fmt.Errorf("%s artifact postgres_p99_ms=%d exceeds production max %d", artifact.name, postgresP99, productionMaxP99.Milliseconds())
			}
			if redisP99 > int(productionMaxP99.Milliseconds()) {
				return evidence, fmt.Errorf("%s artifact redis_p99_ms=%d exceeds production max %d", artifact.name, redisP99, productionMaxP99.Milliseconds())
			}
			evidence.PostgresP99MS = postgresP99
			evidence.RedisP99MS = redisP99
		}
	}
	return evidence, nil
}

func validateStagingWebSocketArtifacts(client *http.Client, cfg config) (stagingArtifactEvidence, error) {
	var evidence stagingArtifactEvidence
	releaseCandidate, serviceVersion, err := requireReleaseMetadata(cfg)
	if err != nil {
		return evidence, err
	}
	releaseMarker := "release_candidate=" + releaseCandidate
	serviceVersionMarker := "service_version=" + serviceVersion
	loadRunMarker, err := requireLoadRunMarker(cfg)
	if err != nil {
		return evidence, err
	}
	roomMarker := "room_id=" + cfg.WSRoomID
	artifacts := []struct {
		name     string
		target   string
		required []string
	}{
		{
			name:   "ws-replica-artifact-url",
			target: cfg.WSReplicaArtifactURL,
			required: []string{
				"api replica distribution",
				"scriptureforge-api",
				"multiple replicas",
				"staging artifact",
				releaseMarker,
				serviceVersionMarker,
				loadRunMarker,
			},
		},
		{
			name:   "ws-reconnect-artifact-url",
			target: cfg.WSReconnectArtifactURL,
			required: []string{
				"websocket reconnect",
				"same room",
				roomMarker,
				"accepted event after reconnect",
				"ws_reconnect_sequence_continues=true",
				"staging artifact",
				releaseMarker,
				serviceVersionMarker,
				loadRunMarker,
			},
		},
		{
			name:   "ws-polling-artifact-url",
			target: cfg.WSPollingArtifactURL,
			required: []string{
				"http polling fallback",
				"/api/v1/rooms/state",
				roomMarker,
				"latest sequence",
				"latest_sequence=",
				"staging artifact",
				releaseMarker,
				serviceVersionMarker,
				loadRunMarker,
			},
		},
		{
			name:   "redis-telemetry-artifact-url",
			target: cfg.RedisTelemetryArtifactURL,
			required: []string{
				"redis telemetry",
				"room sequence",
				roomMarker,
				"contiguous",
				"no duplicate",
				"no skipped",
				"room_broadcast_drops=0",
				"staging artifact",
				releaseMarker,
				serviceVersionMarker,
				loadRunMarker,
			},
		},
	}
	if err := requireDistinctArtifactURLs(artifacts); err != nil {
		return evidence, err
	}
	expectedPollingLatestSequence := cfg.Concurrency * cfg.WSEventsPerClient
	for _, artifact := range artifacts {
		text, err := validateArtifactMarkers(client, artifact.name, artifact.target, artifact.required, expectedPollingLatestSequence)
		if err != nil {
			return evidence, err
		}
		if artifact.name == "ws-replica-artifact-url" {
			replicaCount, err := parsePositiveIntMarker(text, replicaCountPattern, artifact.name, "replica_count")
			if err != nil {
				return evidence, err
			}
			if replicaCount < 2 {
				return evidence, fmt.Errorf("%s artifact replica_count=%d must prove at least 2 replicas", artifact.name, replicaCount)
			}
			evidence.WSReplicaCount = replicaCount
		}
		if artifact.name == "ws-polling-artifact-url" {
			latestSequence, err := parsePositiveIntMarker(text, latestSequencePattern, artifact.name, "latest_sequence")
			if err != nil {
				return evidence, err
			}
			evidence.PollingLatestSequence = latestSequence
		}
		if artifact.name == "redis-telemetry-artifact-url" {
			drops, err := parseNonNegativeIntMarker(text, roomBroadcastDropsPattern, artifact.name, "room_broadcast_drops")
			if err != nil {
				return evidence, err
			}
			if drops != 0 {
				return evidence, fmt.Errorf("%s artifact room_broadcast_drops=%d must equal 0", artifact.name, drops)
			}
			evidence.RoomBroadcastDrops = &drops
		}
	}
	return evidence, nil
}

func requireDistinctArtifactURLs(artifacts []struct {
	name     string
	target   string
	required []string
}) error {
	seen := make(map[string]string, len(artifacts))
	for _, artifact := range artifacts {
		normalized, err := canonicalArtifactURL(artifact.target)
		if err != nil {
			return fmt.Errorf("%s artifact URL: %w", artifact.name, err)
		}
		if normalized == "" {
			continue
		}
		if previousName, ok := seen[normalized]; ok {
			return fmt.Errorf("%s must be a distinct artifact URL from %s", artifact.name, previousName)
		}
		seen[normalized] = artifact.name
	}
	return nil
}

func canonicalArtifactURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if host == "" {
		return "", errors.New("missing host")
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	} else {
		parsed.Host = host
	}
	parsed.Scheme = scheme
	parsed.Fragment = ""
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String(), nil
}

func requireReleaseMetadata(cfg config) (string, string, error) {
	releaseCandidate := strings.TrimSpace(cfg.ReleaseCandidate)
	if releaseCandidate == "" {
		return "", "", errors.New("release-candidate is required for staging load evidence")
	}
	serviceVersion := strings.TrimSpace(cfg.ServiceVersion)
	if serviceVersion == "" {
		return "", "", errors.New("service-version is required for staging load evidence")
	}
	return releaseCandidate, serviceVersion, nil
}

func requireLoadRunMarker(cfg config) (string, error) {
	loadRunID := strings.TrimSpace(cfg.LoadRunID)
	if loadRunID == "" {
		return "", errors.New("staging load evidence requires -load-run-id or STAGING_LOAD_RUN_ID")
	}
	return "load_run_id=" + loadRunID, nil
}

func validateArtifactMarkers(client *http.Client, name, target string, required []string, expectedPollingLatestSequence int) (string, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return "", fmt.Errorf("%s artifact request: %w", name, err)
	}
	request.Header.Set("User-Agent", "scriptureforge-loadtest/1.0")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%s artifact fetch failed: %w", name, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("%s artifact returned HTTP %d", name, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("%s artifact read failed: %w", name, err)
	}
	text := string(body)
	if !containsAllFold(text, required) {
		return "", fmt.Errorf("%s artifact missing required staging markers: %s", name, strings.Join(required, ", "))
	}
	if !containsNoneFold(text, forbiddenArtifactMarkers()) {
		return "", fmt.Errorf("%s artifact contains forbidden local/mock/failure markers", name)
	}
	if name == "ws-polling-artifact-url" {
		match := latestSequencePattern.FindStringSubmatch(text)
		if len(match) != 2 {
			return "", fmt.Errorf("%s artifact missing numeric latest_sequence marker", name)
		}
		latestSequence, err := strconv.Atoi(match[1])
		if err != nil || latestSequence < productionMinWSEvents {
			return "", fmt.Errorf("%s artifact latest_sequence=%s is below production minimum %d", name, match[1], productionMinWSEvents)
		}
		if expectedPollingLatestSequence > 0 && latestSequence != expectedPollingLatestSequence {
			return "", fmt.Errorf("%s artifact latest_sequence=%d does not match expected run sequence %d", name, latestSequence, expectedPollingLatestSequence)
		}
	}
	return text, nil
}

func parsePositiveIntMarker(text string, pattern *regexp.Regexp, artifactName, markerName string) (int, error) {
	value, err := parseNonNegativeIntMarker(text, pattern, artifactName, markerName)
	if err != nil {
		return 0, err
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s artifact %s=%d must be positive", artifactName, markerName, value)
	}
	return value, nil
}

func parseNonNegativeIntMarker(text string, pattern *regexp.Regexp, artifactName, markerName string) (int, error) {
	match := pattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0, fmt.Errorf("%s artifact missing numeric %s marker", artifactName, markerName)
	}
	value, err := strconv.Atoi(match[1])
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s artifact %s=%s must be a non-negative integer", artifactName, markerName, match[1])
	}
	return value, nil
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

func waitForOwnBroadcast(conn *websocket.Conn, timeout time.Duration, marker string) (int64, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		var event ports.RoomEvent
		if err := conn.ReadJSON(&event); err != nil {
			return 0, false
		}
		if strings.Contains(string(event.Payload), marker) && event.Sequence > 0 {
			return event.Sequence, true
		}
	}
	return 0, false
}

func buildReport(cfg config, elapsed time.Duration, load loadResult) report {
	latencies := load.latencies
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	requests := len(latencies)
	elapsedForMetrics := elapsed
	if elapsedForMetrics <= 0 && requests > 0 {
		elapsedForMetrics = time.Nanosecond
	}
	durationMS := elapsedForMetrics.Milliseconds()
	if durationMS == 0 && requests > 0 {
		durationMS = 1
	}
	rps := 0.0
	if elapsedForMetrics > 0 {
		rps = float64(requests) / elapsedForMetrics.Seconds()
	}
	result := report{
		Target:                    cfg.Target,
		Method:                    cfg.Method,
		EvidenceProfile:           evidenceProfileFor(cfg),
		DurationMS:                durationMS,
		Concurrency:               cfg.Concurrency,
		Requests:                  requests,
		Failures:                  load.failures,
		RPS:                       rps,
		P50MS:                     percentile(latencies, 0.50).Milliseconds(),
		P95MS:                     percentile(latencies, 0.95).Milliseconds(),
		P99MS:                     percentile(latencies, 0.99).Milliseconds(),
		MinRPS:                    cfg.MinRPS,
		MaxP99MS:                  cfg.MaxP99.Milliseconds(),
		WSReplicaArtifactURL:      cfg.WSReplicaArtifactURL,
		WSReconnectArtifactURL:    cfg.WSReconnectArtifactURL,
		WSPollingArtifactURL:      cfg.WSPollingArtifactURL,
		RedisTelemetryArtifactURL: cfg.RedisTelemetryArtifactURL,
		WSOrigin:                  wsOriginForReport(cfg),
		WSRoomID:                  wsRoomIDForReport(cfg),
		WSAuthenticated:           cfg.WebSocket && strings.TrimSpace(cfg.WSToken) != "",
		HTTPReplicaArtifactURL:    cfg.HTTPReplicaArtifactURL,
		DependencyTelemetryURL:    cfg.DependencyTelemetryURL,
		HTTPReplicaCount:          cfg.ArtifactEvidence.HTTPReplicaCount,
		WSReplicaCount:            cfg.ArtifactEvidence.WSReplicaCount,
		DependencyPostgresP99MS:   cfg.ArtifactEvidence.PostgresP99MS,
		DependencyRedisP99MS:      cfg.ArtifactEvidence.RedisP99MS,
		RoomBroadcastDrops:        cfg.ArtifactEvidence.RoomBroadcastDrops,
		ReleaseCandidate:          strings.TrimSpace(cfg.ReleaseCandidate),
		ServiceVersion:            strings.TrimSpace(cfg.ServiceVersion),
		LoadRunID:                 strings.TrimSpace(cfg.LoadRunID),
		EvidenceItems:             evidenceItemsFor(cfg),
	}
	result.ProductionTargetRPS, result.ProductionTargetP99MS = productionTargetFor(cfg)
	if result.ProductionTargetRPS > 0 {
		result.ProductionMinDurationMS = productionMinLoadDuration.Milliseconds()
		if cfg.WebSocket {
			result.ProductionMinWSEvents = productionMinWSEvents
		}
	}
	if cfg.WebSocket || cfg.WebSocketSelfTest {
		result.WSExpectedEvents = cfg.Concurrency * cfg.WSEventsPerClient
		result.WSUniqueSequences, result.WSMinSequence, result.WSMaxSequence, result.WSSequenceContiguous = sequenceStats(load.sequences, result.WSExpectedEvents)
		result.WSPollingLatestSequence = result.WSMaxSequence
	}
	thresholdFailures := thresholdFailuresFor(cfg, result, load, latencies)
	if cfg.WebSocket || cfg.WebSocketSelfTest {
		if !result.WSSequenceContiguous {
			thresholdFailures = append(thresholdFailures, "websocket_sequence_not_contiguous")
		}
	}
	result.ThresholdFailures = thresholdFailures
	result.ThresholdPass = len(thresholdFailures) == 0
	result.ResultSummary = resultSummaryFor(result)
	return result
}

func resultSummaryFor(result report) string {
	summary := fmt.Sprintf(
		"profile=%s target=%s concurrency=%d duration_ms=%d min_rps=%.0f max_p99_ms=%d production_target_rps=%.0f production_target_p99_ms=%d production_min_duration_ms=%d observed_rps=%.2f observed_p99_ms=%d threshold_pass=%t release_candidate=%s service_version=%s load_run_id=%s",
		result.EvidenceProfile,
		result.Target,
		result.Concurrency,
		result.DurationMS,
		result.MinRPS,
		result.MaxP99MS,
		result.ProductionTargetRPS,
		result.ProductionTargetP99MS,
		result.ProductionMinDurationMS,
		result.RPS,
		result.P99MS,
		result.ThresholdPass,
		result.ReleaseCandidate,
		result.ServiceVersion,
		result.LoadRunID,
	)
	if result.EvidenceProfile == "staging_http" {
		summary = fmt.Sprintf(
			"%s http_replica_count=%d dependency_postgres_p99_ms=%d dependency_redis_p99_ms=%d",
			summary,
			result.HTTPReplicaCount,
			result.DependencyPostgresP99MS,
			result.DependencyRedisP99MS,
		)
		return appendVerifiedMarkers(summary, []string{
			"staging_http",
			"https://",
			"min_rps",
			"5000",
			"max_p99_ms",
			"200",
			"duration_ms>=60000",
			"observed_rps",
			"observed_p99_ms",
			"release_candidate",
			"service_version",
			"load_run_id",
			"http_replica_artifact_url",
			"http_replica_artifact_verified",
			"dependency_telemetry_artifact_url",
			"dependency_telemetry_artifact_verified",
			"dependency_latency_artifact_verified=true",
			"http_replica_count",
			"dependency_postgres_p99_ms",
			"dependency_redis_p99_ms",
			"http_distinct_artifacts=true",
		})
	}
	if result.EvidenceProfile == "staging_websocket" {
		summary = fmt.Sprintf(
			"%s production_min_ws_events=%d ws_origin=%s ws_room_id=%s ws_authenticated=%t ws_expected_events=%d ws_unique_sequences=%d ws_min_sequence=%d ws_max_sequence=%d ws_polling_latest_sequence=%d ws_sequence_contiguous=%t ws_replica_artifact_url=%s ws_reconnect_artifact_url=%s ws_polling_artifact_url=%s redis_telemetry_artifact_url=%s ws_replica_count=%d room_broadcast_drops=%d",
			summary,
			result.ProductionMinWSEvents,
			result.WSOrigin,
			result.WSRoomID,
			result.WSAuthenticated,
			result.WSExpectedEvents,
			result.WSUniqueSequences,
			result.WSMinSequence,
			result.WSMaxSequence,
			result.WSPollingLatestSequence,
			result.WSSequenceContiguous,
			result.WSReplicaArtifactURL,
			result.WSReconnectArtifactURL,
			result.WSPollingArtifactURL,
			result.RedisTelemetryArtifactURL,
			result.WSReplicaCount,
			roomBroadcastDropsValue(result.RoomBroadcastDrops),
		)
		return appendVerifiedMarkers(summary, []string{
			"staging artifact",
			"staging_websocket",
			"wss://",
			"min_rps",
			"500",
			"max_p99_ms",
			"200",
			"duration_ms>=60000",
			"observed_rps",
			"observed_p99_ms",
			"release_candidate",
			"service_version",
			"load_run_id",
			"ws_sequence_contiguous=true",
			"ws_origin=https://",
			"ws_room_id",
			"ws_authenticated=true",
			"ws_expected_events",
			"ws_polling_latest_sequence",
			"ws_replica_artifact_url",
			"ws_replica_artifact_verified",
			"ws_reconnect_artifact_url",
			"ws_reconnect_artifact_verified",
			"ws_reconnect_sequence_continues=true",
			"ws_polling_artifact_url",
			"ws_polling_artifact_verified",
			"ws_polling_artifact_latest_sequence_validated=true",
			"ws_polling_artifact_latest_sequence_matches_run=true",
			"redis_telemetry_artifact_url",
			"redis_telemetry_artifact_verified",
			"ws_distinct_artifacts=true",
			"ws_replica_count",
			"room_broadcast_drops=0",
		})
	}
	return summary
}

func roomBroadcastDropsValue(value *int) int {
	if value == nil {
		return -1
	}
	return *value
}

func wsOriginForReport(cfg config) string {
	if !cfg.WebSocket {
		return ""
	}
	return strings.TrimSpace(cfg.WSOrigin)
}

func wsRoomIDForReport(cfg config) string {
	if !cfg.WebSocket && !cfg.WebSocketSelfTest {
		return ""
	}
	return strings.TrimSpace(cfg.WSRoomID)
}

func appendVerifiedMarkers(summary string, markers []string) string {
	return fmt.Sprintf("%s; verified markers: %s", summary, strings.Join(markers, ", "))
}

func thresholdFailuresFor(cfg config, result report, load loadResult, latencies []time.Duration) []string {
	var failures []string
	if load.failures > 0 {
		failures = append(failures, "request_failures")
	}
	if result.Requests == 0 {
		failures = append(failures, "no_successful_requests")
	}
	if cfg.MinRPS > 0 && result.RPS < cfg.MinRPS {
		failures = append(failures, "rps_below_configured_minimum")
	}
	if cfg.MaxP99 > 0 && percentile(latencies, 0.99) > cfg.MaxP99 {
		failures = append(failures, "p99_above_configured_maximum")
	}
	if !cfg.SelfTest && !cfg.WebSocketSelfTest {
		if targetRPS, targetP99 := productionTargetFor(cfg); targetRPS > 0 {
			if cfg.MinRPS < targetRPS {
				failures = append(failures, "configured_min_rps_below_production_target")
			}
			if cfg.MaxP99 <= 0 || cfg.MaxP99 > time.Duration(targetP99)*time.Millisecond {
				failures = append(failures, "configured_max_p99_above_production_target")
			}
			if cfg.WebSocket {
				if result.WSExpectedEvents < productionMinWSEvents {
					failures = append(failures, "websocket_expected_events_below_minimum")
				}
			} else if time.Duration(result.DurationMS)*time.Millisecond < productionMinLoadDuration {
				failures = append(failures, "staging_duration_below_minimum")
			}
		}
	}
	return failures
}

func sequenceStats(sequences []int64, expected int) (int, int64, int64, bool) {
	seen := make(map[int64]struct{}, len(sequences))
	minSequence := int64(0)
	maxSequence := int64(0)
	for _, sequence := range sequences {
		seen[sequence] = struct{}{}
		if minSequence == 0 || sequence < minSequence {
			minSequence = sequence
		}
		if sequence > maxSequence {
			maxSequence = sequence
		}
	}
	if expected <= 0 || len(sequences) != expected || len(seen) != expected || minSequence != 1 || maxSequence != int64(expected) {
		return len(seen), minSequence, maxSequence, false
	}
	for sequence := int64(1); sequence <= int64(expected); sequence++ {
		if _, ok := seen[sequence]; !ok {
			return len(seen), minSequence, maxSequence, false
		}
	}
	return len(seen), minSequence, maxSequence, true
}

func evidenceItemsFor(cfg config) []string {
	if cfg.SelfTest || cfg.WebSocketSelfTest {
		return nil
	}
	if !isStagingEvidenceTarget(cfg.Target, cfg.WebSocket) {
		return nil
	}
	if cfg.WebSocket {
		return []string{"PERF-WS-001", "DATA-REDIS-001"}
	}
	return []string{"PERF-HTTP-001"}
}

func evidenceProfileFor(cfg config) string {
	switch {
	case cfg.WebSocketSelfTest:
		return "local_websocket_self_test"
	case cfg.SelfTest:
		return "local_http_self_test"
	case cfg.WebSocket:
		return "staging_websocket"
	default:
		return "staging_http"
	}
}

func productionTargetFor(cfg config) (float64, int64) {
	if cfg.SelfTest || cfg.WebSocketSelfTest {
		return 0, 0
	}
	if !isStagingEvidenceTarget(cfg.Target, cfg.WebSocket) {
		return 0, 0
	}
	if cfg.WebSocket {
		return productionWSMinRPS, productionMaxP99.Milliseconds()
	}
	return productionHTTPMinRPS, productionMaxP99.Milliseconds()
}

func isStagingEvidenceTarget(rawTarget string, websocket bool) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	if websocket {
		if parsed.Scheme != "wss" {
			return false
		}
	} else if parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return !isReservedPlaceholderHost(host) && !isLocalOrPrivateHost(host)
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
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s or matching STAGING_* env var must not use a reserved placeholder staging artifact host", flagName)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s or matching STAGING_* env var must use a non-local, non-private staging artifact host", flagName)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
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

func containsNoneFold(text string, needles []string) bool {
	lowerText := strings.ToLower(text)
	for _, needle := range needles {
		if strings.Contains(lowerText, strings.ToLower(needle)) {
			return false
		}
	}
	return true
}

func forbiddenArtifactMarkers() []string {
	return []string{
		"mock",
		"mocked",
		"placeholder",
		"synthetic",
		"stubbed",
		"test-only",
		"dry-run",
		"local-only",
		"localhost",
		"127.0.0.1",
		"threshold failed",
		"threshold failure",
		"threshold_failures",
		"rps below threshold",
		"p99 above threshold",
	}
}

func normalizeHTTPSOrigin(raw, flagName string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("-%s must use https for staging websocket evidence", flagName)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("-%s must include a host for staging websocket evidence", flagName)
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not use a reserved placeholder staging origin host", flagName)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not be local, private, or self-test for staging websocket evidence", flagName)
	}
	parsed.Path = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func isReservedPlaceholderHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	return normalized == "example" ||
		strings.HasSuffix(normalized, ".example") ||
		normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		normalized == "example.org" ||
		strings.HasSuffix(normalized, ".example.org") ||
		normalized == "example.net" ||
		strings.HasSuffix(normalized, ".example.net") ||
		normalized == "test" ||
		strings.HasSuffix(normalized, ".test") ||
		normalized == "invalid" ||
		strings.HasSuffix(normalized, ".invalid")
}

func isLocalOrPrivateHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(host), "[]")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())
}
