package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"scriptureforge/internal/ports"
)

func TestBuildReportAppliesThresholds(t *testing.T) {
	cfg := config{Target: "http://example.test/health", Method: "GET", Concurrency: 2, MinRPS: 100, MaxP99: 20 * time.Millisecond}
	result := buildReport(cfg, time.Second, loadResult{
		latencies: []time.Duration{
			5 * time.Millisecond,
			10 * time.Millisecond,
			15 * time.Millisecond,
		},
	})

	if result.ThresholdPass {
		t.Fatal("thresholds passed despite RPS below configured minimum")
	}

	cfg.MinRPS = 1
	result = buildReport(cfg, time.Second, loadResult{
		latencies: []time.Duration{
			5 * time.Millisecond,
			10 * time.Millisecond,
			15 * time.Millisecond,
		},
	})
	if !result.ThresholdPass {
		t.Fatalf("thresholds failed unexpectedly: %+v", result)
	}
}

func TestSelfTestRunProducesJSONReport(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		SelfTest:     true,
		Method:       "GET",
		Duration:     100 * time.Millisecond,
		Concurrency:  2,
		Timeout:      time.Second,
		ExpectStatus: 200,
		MinRPS:       1,
		MaxP99:       time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("self-test run failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": true`) {
		t.Fatalf("report did not include passing threshold:\n%s", output.String())
	}
	if strings.Contains(output.String(), `"evidence_items"`) {
		t.Fatalf("self-test report must not emit staging evidence items:\n%s", output.String())
	}
}

func TestWebSocketSelfTestRunProducesJSONReport(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		WebSocketSelfTest: true,
		Duration:          time.Second,
		Concurrency:       2,
		Timeout:           time.Second,
		WSEventsPerClient: 2,
		MinRPS:            1,
		MaxP99:            time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("websocket self-test run failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"method": "WEBSOCKET"`) {
		t.Fatalf("report did not identify websocket method:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": true`) {
		t.Fatalf("report did not include passing threshold:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"ws_sequence_contiguous": true`) || !strings.Contains(output.String(), `"ws_unique_sequences": 4`) {
		t.Fatalf("websocket report did not include contiguous sequence proof:\n%s", output.String())
	}
	if strings.Contains(output.String(), `"evidence_items"`) {
		t.Fatalf("websocket self-test report must not emit staging evidence items:\n%s", output.String())
	}
}

func TestWebSocketExternalRunUsesBearerAndOrigin(t *testing.T) {
	var sequence int64
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return r.Header.Get("Origin") == "https://app-load.staging.scriptureforge.ai"
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer staging-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			var event ports.RoomEvent
			if err := conn.ReadJSON(&event); err != nil {
				return
			}
			event.Sequence = atomic.AddInt64(&sequence, 1)
			encoded, _ := json.Marshal(event)
			if err := conn.WriteMessage(websocket.TextMessage, encoded); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		WebSocket:                 true,
		Target:                    "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/staging-room",
		Duration:                  time.Second,
		Concurrency:               2,
		Timeout:                   time.Second,
		WSEventsPerClient:         2,
		WSRoomID:                  "staging-room",
		WSToken:                   "staging-token",
		WSOrigin:                  "https://app-load.staging.scriptureforge.ai",
		WSReplicaArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-replicas.txt",
		WSReconnectArtifactURL:    "https://load-artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt",
		WSPollingArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-polling.txt",
		RedisTelemetryArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt",
		MinRPS:                    1,
		MaxP99:                    time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("external websocket run failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"method": "WEBSOCKET"`) {
		t.Fatalf("report did not identify websocket method:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": true`) {
		t.Fatalf("report did not include passing threshold:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"ws_sequence_contiguous": true`) || !strings.Contains(output.String(), `"ws_expected_events": 4`) {
		t.Fatalf("external websocket report did not include Redis sequence proof:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"ws_origin": "https://app-load.staging.scriptureforge.ai"`) || !strings.Contains(output.String(), `"ws_authenticated": true`) {
		t.Fatalf("external websocket report did not include origin/auth proof:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"ws_room_id": "staging-room"`) {
		t.Fatalf("external websocket report did not include room binding proof:\n%s", output.String())
	}
	if strings.Contains(output.String(), `"PERF-WS-001"`) || strings.Contains(output.String(), `"DATA-REDIS-001"`) {
		t.Fatalf("local websocket server report must not include staging evidence IDs:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"ws_replica_artifact_url"`) || !strings.Contains(output.String(), `"ws_reconnect_artifact_url"`) || !strings.Contains(output.String(), `"ws_polling_artifact_url"`) || !strings.Contains(output.String(), `"redis_telemetry_artifact_url"`) {
		t.Fatalf("external websocket report did not include staging artifact URLs:\n%s", output.String())
	}
}

func TestStagingWebSocketReportIncludesProductionTargetAndEvidenceIDs(t *testing.T) {
	cfg := config{
		WebSocket:                 true,
		Target:                    "wss://api-load.staging.scriptureforge.ai/api/v1/rooms/stream/staging-room",
		Method:                    "WEBSOCKET",
		Concurrency:               500,
		WSEventsPerClient:         60,
		WSRoomID:                  "staging-room",
		WSToken:                   "staging-token",
		WSOrigin:                  "https://app-load.staging.scriptureforge.ai",
		WSReplicaArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-replicas.txt",
		WSReconnectArtifactURL:    "https://load-artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt",
		WSPollingArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-polling.txt",
		RedisTelemetryArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt",
		ReleaseCandidate:          "abc123",
		ServiceVersion:            "scriptureforge-api:abc123",
		LoadRunID:                 "load-run-123",
		MinRPS:                    productionWSMinRPS,
		MaxP99:                    productionMaxP99,
		ArtifactEvidence: stagingArtifactEvidence{
			WSReplicaCount:               2,
			WSReconnectRoomID:            "staging-room",
			WSPollingRoomID:              "staging-room",
			RedisTelemetryRoomID:         "staging-room",
			WSReconnectSequenceContinues: true,
			RoomBroadcastDrops:           intPtr(0),
		},
	}
	result := buildReport(cfg, productionMinLoadDuration, loadResult{
		latencies: repeatedLatencies(productionMinWSEvents, 10*time.Millisecond),
		sequences: rangeSequences(productionMinWSEvents),
	})
	if !result.ThresholdPass {
		t.Fatalf("staging websocket report failed unexpectedly: %+v", result)
	}
	if result.EvidenceProfile != "staging_websocket" || result.ProductionTargetRPS != productionWSMinRPS || result.ProductionTargetP99MS != productionMaxP99.Milliseconds() {
		t.Fatalf("staging websocket target metadata = %+v", result)
	}
	if !containsAll(result.EvidenceItems, "PERF-WS-001", "DATA-REDIS-001") {
		t.Fatalf("staging websocket evidence items = %#v", result.EvidenceItems)
	}
	if result.WSOrigin != "https://app-load.staging.scriptureforge.ai" || !result.WSAuthenticated {
		t.Fatalf("staging websocket auth/origin metadata = %+v", result)
	}
	if result.WSExpectedEvents != productionMinWSEvents || result.WSPollingLatestSequence != result.WSMaxSequence {
		t.Fatalf("staging websocket polling latest sequence = %d, want max sequence %d", result.WSPollingLatestSequence, result.WSMaxSequence)
	}
	if !containsAllSummaryMarkers(result.ResultSummary, "staging artifact", "staging_websocket", "wss://", "min_rps", "500", "max_p99_ms", "200", "production_target_rps=500", "production_target_p99_ms=200", "production_min_duration_ms=60000", "duration_ms>=60000", "production_min_ws_events=30000", "observed_rps", "observed_p99_ms", "release_candidate", "service_version", "load_run_id=load-run-123", "ws_sequence_contiguous=true", "ws_origin=https://", "ws_room_id=staging-room", "ws_reconnect_room_id=staging-room", "ws_polling_room_id=staging-room", "redis_telemetry_room_id=staging-room", "ws_reconnect_sequence_continues=true", "ws_authenticated=true", "ws_expected_events=30000", "ws_polling_latest_sequence=30000", "ws_replica_artifact_url=https://load-artifacts.staging.scriptureforge.ai/load/ws-replicas.txt", "ws_replica_artifact_verified", "ws_reconnect_artifact_url=https://load-artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt", "ws_reconnect_artifact_verified", "ws_reconnect_sequence_continues=true", "ws_polling_artifact_url=https://load-artifacts.staging.scriptureforge.ai/load/ws-polling.txt", "ws_polling_artifact_verified", "ws_polling_artifact_latest_sequence_validated=true", "ws_polling_artifact_latest_sequence_matches_run=true", "redis_telemetry_artifact_url=https://load-artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt", "redis_telemetry_artifact_verified", "ws_distinct_artifacts=true", "room_broadcast_drops=0") {
		t.Fatalf("staging websocket summary omitted verified markers: %s", result.ResultSummary)
	}

	cfg.MinRPS = 1
	result = buildReport(cfg, productionMinLoadDuration, loadResult{
		latencies: repeatedLatencies(productionMinWSEvents, 10*time.Millisecond),
		sequences: rangeSequences(productionMinWSEvents),
	})
	if !containsAll(result.ThresholdFailures, "configured_min_rps_below_production_target") {
		t.Fatalf("staging websocket report did not reject weak configured threshold: %#v", result.ThresholdFailures)
	}

	cfg.MinRPS = productionWSMinRPS
	cfg.MaxP99 = time.Second
	result = buildReport(cfg, productionMinLoadDuration, loadResult{
		latencies: repeatedLatencies(productionMinWSEvents, 10*time.Millisecond),
		sequences: rangeSequences(productionMinWSEvents),
	})
	if !containsAll(result.ThresholdFailures, "configured_max_p99_above_production_target") {
		t.Fatalf("staging websocket report did not reject weak P99 threshold: %#v", result.ThresholdFailures)
	}

	cfg.MaxP99 = productionMaxP99
	cfg.WSEventsPerClient = 1
	result = buildReport(cfg, productionMinLoadDuration, loadResult{
		latencies: repeatedLatencies(400, 10*time.Millisecond),
		sequences: rangeSequences(400),
	})
	if !containsAll(result.ThresholdFailures, "websocket_expected_events_below_minimum") {
		t.Fatalf("staging websocket report did not reject short event run: %#v", result.ThresholdFailures)
	}
}

func TestWebSocketExternalRunRequiresStagingArtifacts(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		WebSocket:         true,
		Target:            "wss://api-load.staging.scriptureforge.ai/api/v1/rooms/stream/staging-room",
		Duration:          time.Second,
		Concurrency:       1,
		Timeout:           time.Second,
		WSEventsPerClient: 1,
		WSRoomID:          "staging-room",
		WSToken:           "staging-token",
		WSOrigin:          "https://app-load.staging.scriptureforge.ai",
		MinRPS:            1,
		MaxP99:            time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "ws-replica-artifact-url") {
		t.Fatalf("expected missing replica artifact URL error, got %v", err)
	}

	output.Reset()
	err = run(config{
		WebSocket:            true,
		Target:               "wss://api-load.staging.scriptureforge.ai/api/v1/rooms/stream/staging-room",
		Duration:             time.Second,
		Concurrency:          1,
		Timeout:              time.Second,
		WSEventsPerClient:    1,
		WSRoomID:             "staging-room",
		WSToken:              "staging-token",
		WSOrigin:             "https://app-load.staging.scriptureforge.ai",
		WSReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/ws-replicas.txt",
		MinRPS:               1,
		MaxP99:               time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "ws-reconnect-artifact-url") {
		t.Fatalf("expected missing reconnect artifact URL error, got %v", err)
	}

	output.Reset()
	err = run(config{
		WebSocket:              true,
		Target:                 "wss://api-load.staging.scriptureforge.ai/api/v1/rooms/stream/staging-room",
		Duration:               time.Second,
		Concurrency:            1,
		Timeout:                time.Second,
		WSEventsPerClient:      1,
		WSRoomID:               "staging-room",
		WSToken:                "staging-token",
		WSOrigin:               "https://app-load.staging.scriptureforge.ai",
		WSReplicaArtifactURL:   "https://load-artifacts.staging.scriptureforge.ai/load/ws-replicas.txt",
		WSReconnectArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt",
		MinRPS:                 1,
		MaxP99:                 time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "ws-polling-artifact-url") {
		t.Fatalf("expected missing polling artifact URL error, got %v", err)
	}
}

func TestWebSocketStagingEvidenceRequiresBearerAndHTTPSOrigin(t *testing.T) {
	base := config{
		WebSocket:                 true,
		Target:                    "wss://api-load.staging.scriptureforge.ai/api/v1/rooms/stream/staging-room",
		Duration:                  time.Second,
		Concurrency:               1,
		Timeout:                   time.Second,
		WSEventsPerClient:         1,
		WSRoomID:                  "staging-room",
		WSReplicaArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-replicas.txt",
		WSReconnectArtifactURL:    "https://load-artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt",
		WSPollingArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-polling.txt",
		RedisTelemetryArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt",
		MinRPS:                    1,
		MaxP99:                    time.Second,
	}

	var output bytes.Buffer
	err := run(base, &output)
	if err == nil || !strings.Contains(err.Error(), "ws-token") {
		t.Fatalf("expected missing ws-token error, got %v", err)
	}

	base.WSToken = "staging-token"
	base.WSOrigin = "http://localhost"
	output.Reset()
	err = run(base, &output)
	if err == nil || !strings.Contains(err.Error(), "ws-origin") {
		t.Fatalf("expected local/insecure ws-origin error, got %v", err)
	}

	for _, origin := range []string{
		"https://app.staging.example",
		"https://app.example.com",
		"https://app.staging.test",
		"https://app.invalid",
	} {
		base.WSOrigin = origin
		output.Reset()
		err = run(base, &output)
		if err == nil || !strings.Contains(err.Error(), "reserved placeholder staging origin host") {
			t.Fatalf("expected reserved ws-origin error for %s, got %v", origin, err)
		}
	}
}

func TestValidateStagingWebSocketArtifactsRequiresMarkerProofs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence latest_sequence=30000"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := stagingWebSocketArtifactConfig()
	evidence, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), cfg)
	if err != nil {
		t.Fatalf("valid artifacts rejected: %v", err)
	}
	if evidence.WSReplicaCount != 2 || evidence.PollingLatestSequence != 30000 || evidence.RoomBroadcastDrops == nil || *evidence.RoomBroadcastDrops != 0 {
		t.Fatalf("unexpected WebSocket artifact evidence: %+v", evidence)
	}
	if evidence.WSReconnectRoomID != "staging-room" || evidence.WSPollingRoomID != "staging-room" || evidence.RedisTelemetryRoomID != "staging-room" {
		t.Fatalf("unexpected WebSocket artifact room binding: %+v", evidence)
	}
	if !evidence.WSReconnectSequenceContinues {
		t.Fatalf("unexpected WebSocket reconnect continuity proof: %+v", evidence)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsDuplicateArtifactURLs(t *testing.T) {
	cfg := stagingWebSocketArtifactConfig()
	cfg.WSPollingArtifactURL = cfg.WSReconnectArtifactURL

	_, err := validateStagingWebSocketArtifacts(http.DefaultClient, cfg)
	if err == nil || !strings.Contains(err.Error(), "ws-polling-artifact-url must be a distinct artifact URL from ws-reconnect-artifact-url") {
		t.Fatalf("expected duplicate WebSocket artifact URL rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsWeakStructuredArtifactValues(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replicaBody string
		redisBody   string
		want        string
	}{
		{
			name:        "missing replica count",
			replicaBody: "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas",
			redisBody:   "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0",
			want:        "missing numeric replica_count marker",
		},
		{
			name:        "single replica",
			replicaBody: "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=1",
			redisBody:   "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0",
			want:        "replica_count=1 must prove at least 2 replicas",
		},
		{
			name:        "broadcast drops",
			replicaBody: "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2",
			redisBody:   "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=1",
			want:        "redis-telemetry-artifact-url artifact missing required staging markers",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/load/ws-replicas.txt":
					_, _ = w.Write([]byte(tc.replicaBody))
				case "/load/ws-reconnect.txt":
					_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
				case "/load/ws-polling.txt":
					_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence latest_sequence=30000"))
				case "/load/redis-telemetry.txt":
					_, _ = w.Write([]byte(tc.redisBody))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateStagingWebSocketArtifactsRejectsCanonicalDuplicateArtifactURLs(t *testing.T) {
	cfg := stagingWebSocketArtifactConfig()
	cfg.WSReconnectArtifactURL = "https://LOAD-ARTIFACTS.staging.scriptureforge.ai:443/load/ws-reconnect.txt?b=2&a=1"
	cfg.WSPollingArtifactURL = "https://load-artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt?a=1&b=2"

	_, err := validateStagingWebSocketArtifacts(http.DefaultClient, cfg)
	if err == nil || !strings.Contains(err.Error(), "ws-polling-artifact-url must be a distinct artifact URL from ws-reconnect-artifact-url") {
		t.Fatalf("expected canonical duplicate WebSocket artifact URL rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsWrongRoomBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=other-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=other-room latest sequence latest_sequence=30000"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=other-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "ws-reconnect-artifact-url artifact room_id=other-room does not match expected ws_room_id=staging-room") {
		t.Fatalf("expected wrong room binding rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsReconnectWithoutSequenceContinuity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence latest_sequence=30000"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "ws-reconnect-artifact-url artifact missing required staging markers") {
		t.Fatalf("expected reconnect sequence-continuity rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsStaleReleaseCandidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=def456 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=def456 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=def456 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence latest_sequence=30000"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=def456 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "ws-replica-artifact-url artifact missing required staging markers") {
		t.Fatalf("expected stale WebSocket release candidate rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsWeakPollingProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback room_id=staging-room latest sequence"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "ws-polling-artifact-url artifact missing required staging markers") {
		t.Fatalf("expected weak polling artifact rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsMissingBroadcastDropProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence latest_sequence=30000"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "redis-telemetry-artifact-url artifact missing required staging markers") {
		t.Fatalf("expected missing broadcast-drop proof rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsWeakLatestSequencePollingProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "ws-polling-artifact-url artifact missing required staging markers") {
		t.Fatalf("expected weak latest sequence polling proof rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsStalePollingLatestSequence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence latest_sequence=400"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "latest_sequence=400 is below production minimum 30000") {
		t.Fatalf("expected stale polling latest sequence rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsPollingLatestSequenceMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence latest_sequence=30001"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "latest_sequence=30001 does not match expected run sequence 30000") {
		t.Fatalf("expected polling latest sequence mismatch rejection, got %v", err)
	}
}

func TestValidateStagingWebSocketArtifactsRejectsMockRedisProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/ws-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/ws-reconnect.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 websocket reconnect same room room_id=staging-room accepted event after reconnect ws_reconnect_sequence_continues=true"))
		case "/load/ws-polling.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 http polling fallback /api/v1/rooms/state room_id=staging-room latest sequence latest_sequence=30000"))
		case "/load/redis-telemetry.txt":
			_, _ = w.Write([]byte("mock staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 redis telemetry room sequence room_id=staging-room contiguous no duplicate no skipped room_broadcast_drops=0"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := validateStagingWebSocketArtifacts(clientForArtifactServer(t, server), stagingWebSocketArtifactConfig())
	if err == nil || !strings.Contains(err.Error(), "redis-telemetry-artifact-url artifact contains forbidden") {
		t.Fatalf("expected mock redis artifact rejection, got %v", err)
	}
}

func TestBuildReportFailsWebSocketWhenSequencesAreDuplicatedOrSkipped(t *testing.T) {
	cfg := config{WebSocket: true, Method: "WEBSOCKET", Concurrency: 2, WSEventsPerClient: 2}
	result := buildReport(cfg, time.Second, loadResult{
		latencies: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond},
		sequences: []int64{1, 1, 3, 4},
	})
	if result.ThresholdPass || result.WSSequenceContiguous {
		t.Fatalf("duplicated sequence report passed unexpectedly: %+v", result)
	}

	result = buildReport(cfg, time.Second, loadResult{
		latencies: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond},
		sequences: []int64{1, 2, 4, 5},
	})
	if result.ThresholdPass || result.WSSequenceContiguous {
		t.Fatalf("skipped sequence report passed unexpectedly: %+v", result)
	}
}

func TestBuildReportHandlesFastWebSocketRunsWithoutZeroDurationThresholdFailure(t *testing.T) {
	cfg := config{WebSocket: true, Method: "WEBSOCKET", Concurrency: 2, WSEventsPerClient: 2, MinRPS: 1, MaxP99: time.Second}
	result := buildReport(cfg, 0, loadResult{
		latencies: []time.Duration{0, 0, 0, 0},
		sequences: []int64{1, 2, 3, 4},
	})
	if !result.ThresholdPass || result.DurationMS != 1 || result.RPS <= 0 {
		t.Fatalf("fast websocket report failed unexpectedly: %+v", result)
	}
}

func TestExternalHTTPLoadReportIncludesPerformanceEvidenceID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		Target:                 server.URL,
		Method:                 "GET",
		Duration:               100 * time.Millisecond,
		Concurrency:            2,
		Timeout:                time.Second,
		ExpectStatus:           200,
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
		MinRPS:                 1,
		MaxP99:                 time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("external HTTP run failed: %v\n%s", err, output.String())
	}
	if strings.Contains(output.String(), `"PERF-HTTP-001"`) {
		t.Fatalf("local HTTP server report must not include performance evidence ID:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"http_replica_artifact_url"`) || !strings.Contains(output.String(), `"dependency_telemetry_artifact_url"`) {
		t.Fatalf("external HTTP report did not include staging artifact URLs:\n%s", output.String())
	}
}

func TestStagingHTTPReportIncludesProductionTargetAndThresholdFailures(t *testing.T) {
	cfg := config{
		Target:                 "https://api-load.staging.scriptureforge.ai/ready",
		Method:                 "GET",
		Concurrency:            2,
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
		LoadRunID:              "load-run-123",
		MinRPS:                 productionHTTPMinRPS,
		MaxP99:                 productionMaxP99,
	}
	result := buildReport(cfg, time.Second, loadResult{
		latencies: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond},
	})
	if result.ThresholdPass {
		t.Fatalf("staging HTTP report passed despite RPS below production target: %+v", result)
	}
	if result.EvidenceProfile != "staging_http" || result.ProductionTargetRPS != productionHTTPMinRPS || result.ProductionTargetP99MS != productionMaxP99.Milliseconds() {
		t.Fatalf("staging HTTP target metadata = %+v", result)
	}
	if !containsAll(result.EvidenceItems, "PERF-HTTP-001") {
		t.Fatalf("staging HTTP evidence items = %#v", result.EvidenceItems)
	}
	if !containsAllSummaryMarkers(result.ResultSummary, "staging_http", "https://", "min_rps", "5000", "max_p99_ms", "200", "production_target_rps=5000", "production_target_p99_ms=200", "production_min_duration_ms=60000", "duration_ms>=60000", "observed_rps", "observed_p99_ms", "release_candidate", "service_version", "load_run_id=load-run-123", "http_replica_artifact_url", "http_replica_artifact_verified", "dependency_telemetry_artifact_url", "dependency_telemetry_artifact_verified", "http_distinct_artifacts=true") {
		t.Fatalf("staging HTTP summary omitted verified markers: %s", result.ResultSummary)
	}
	if !containsAll(result.ThresholdFailures, "rps_below_configured_minimum", "staging_duration_below_minimum") {
		t.Fatalf("staging HTTP threshold failures = %#v", result.ThresholdFailures)
	}

	cfg.MinRPS = 1
	result = buildReport(cfg, time.Second, loadResult{
		latencies: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond},
	})
	if !containsAll(result.ThresholdFailures, "configured_min_rps_below_production_target") {
		t.Fatalf("staging HTTP report did not reject weak configured threshold: %#v", result.ThresholdFailures)
	}
}

func TestStagingHTTPReportRejectsShortDurationEvenWithPassingRPS(t *testing.T) {
	cfg := config{
		Target:                 "https://api-load.staging.scriptureforge.ai/ready",
		Method:                 "GET",
		Concurrency:            500,
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
		LoadRunID:              "load-run-123",
		MinRPS:                 productionHTTPMinRPS,
		MaxP99:                 productionMaxP99,
	}
	result := buildReport(cfg, time.Second, loadResult{
		latencies: repeatedLatencies(productionHTTPMinRPS, 10*time.Millisecond),
	})
	if !containsAll(result.ThresholdFailures, "staging_duration_below_minimum") {
		t.Fatalf("staging HTTP report did not reject short load duration: %#v", result.ThresholdFailures)
	}
}

func TestExternalHTTPLoadReportRequiresStagingArtifacts(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		Target:       "https://api-load.staging.scriptureforge.ai/health",
		Method:       "GET",
		Duration:     100 * time.Millisecond,
		Concurrency:  2,
		Timeout:      time.Second,
		ExpectStatus: 200,
		MinRPS:       1,
		MaxP99:       time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "http-replica-artifact-url") {
		t.Fatalf("expected missing HTTP replica artifact URL error, got %v", err)
	}
}

func TestExternalHTTPLoadReportRejectsLocalArtifactURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{
			name: "localhost replica artifact",
			edit: func(cfg *config) {
				cfg.HTTPReplicaArtifactURL = "https://localhost/load/http-replicas.txt"
			},
			want: "http-replica-artifact-url",
		},
		{
			name: "loopback dependency telemetry",
			edit: func(cfg *config) {
				cfg.DependencyTelemetryURL = "https://127.0.0.1/load/dependency-telemetry.txt"
			},
			want: "dependency-telemetry-artifact-url",
		},
		{
			name: "private replica artifact",
			edit: func(cfg *config) {
				cfg.HTTPReplicaArtifactURL = "https://10.0.0.25/load/http-replicas.txt"
			},
			want: "non-private staging artifact host",
		},
		{
			name: "link-local dependency telemetry",
			edit: func(cfg *config) {
				cfg.DependencyTelemetryURL = "https://169.254.10.20/load/dependency-telemetry.txt"
			},
			want: "non-private staging artifact host",
		},
		{
			name: "reserved example replica artifact",
			edit: func(cfg *config) {
				cfg.HTTPReplicaArtifactURL = "https://artifacts.staging.example/load/http-replicas.txt"
			},
			want: "reserved placeholder staging artifact host",
		},
		{
			name: "reserved test dependency telemetry",
			edit: func(cfg *config) {
				cfg.DependencyTelemetryURL = "https://load-artifacts.staging.test/load/dependency-telemetry.txt"
			},
			want: "reserved placeholder staging artifact host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{
				Target:                 "https://api-load.staging.scriptureforge.ai/health",
				Method:                 "GET",
				Duration:               100 * time.Millisecond,
				Concurrency:            2,
				Timeout:                time.Second,
				ExpectStatus:           200,
				HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
				DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
				ReleaseCandidate:       "abc123",
				ServiceVersion:         "scriptureforge-api:abc123",
				MinRPS:                 1,
				MaxP99:                 time.Second,
			}
			tc.edit(&cfg)
			var output bytes.Buffer
			err := run(cfg, &output)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q artifact URL error, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateStagingHTTPArtifactsRequiresMarkerProofs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/http-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/dependency-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 dependency telemetry postgres postgres_p99_ms=32 redis redis_p99_ms=18 p99 below threshold dependency_threshold_pass=true"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config{
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
		LoadRunID:              "load-run-123",
	}
	evidence, err := validateStagingHTTPArtifacts(clientForArtifactServer(t, server), cfg)
	if err != nil {
		t.Fatalf("expected valid HTTP staging artifacts, got %v", err)
	}
	if evidence.HTTPReplicaCount != 2 || evidence.PostgresP99MS != 32 || evidence.RedisP99MS != 18 {
		t.Fatalf("unexpected HTTP artifact evidence: %+v", evidence)
	}
}

func TestValidateStagingHTTPArtifactsRejectsAdmittedThresholdFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/http-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/dependency-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 dependency telemetry postgres postgres_p99_ms=32 redis redis_p99_ms=18 p99 below threshold dependency_threshold_pass=true; threshold failed"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config{
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
		LoadRunID:              "load-run-123",
	}
	_, err := validateStagingHTTPArtifacts(clientForArtifactServer(t, server), cfg)
	if err == nil || !strings.Contains(err.Error(), "dependency-telemetry-artifact-url artifact contains forbidden local/mock/failure markers") {
		t.Fatalf("expected admitted threshold failure rejection, got %v", err)
	}
}

func TestValidateStagingHTTPArtifactsRequiresLoadRunID(t *testing.T) {
	cfg := config{
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
	}
	_, err := validateStagingHTTPArtifacts(http.DefaultClient, cfg)
	if err == nil || !strings.Contains(err.Error(), "load-run-id") {
		t.Fatalf("expected missing load-run-id rejection, got %v", err)
	}
}

func TestValidateStagingHTTPArtifactsRejectsDuplicateArtifactURLs(t *testing.T) {
	cfg := config{
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/shared-http-proof.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/shared-http-proof.txt",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
		LoadRunID:              "load-run-123",
	}
	_, err := validateStagingHTTPArtifacts(http.DefaultClient, cfg)
	if err == nil || !strings.Contains(err.Error(), "dependency-telemetry-artifact-url must be a distinct artifact URL from http-replica-artifact-url") {
		t.Fatalf("expected duplicate HTTP artifact URL rejection, got %v", err)
	}
}

func TestValidateStagingHTTPArtifactsRejectsCanonicalDuplicateArtifactURLs(t *testing.T) {
	cfg := config{
		HTTPReplicaArtifactURL: "https://LOAD-ARTIFACTS.staging.scriptureforge.ai:443/load/shared-http-proof.txt?b=2&a=1",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/shared-http-proof.txt?a=1&b=2",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
		LoadRunID:              "load-run-123",
	}
	_, err := validateStagingHTTPArtifacts(http.DefaultClient, cfg)
	if err == nil || !strings.Contains(err.Error(), "dependency-telemetry-artifact-url must be a distinct artifact URL from http-replica-artifact-url") {
		t.Fatalf("expected canonical duplicate HTTP artifact URL rejection, got %v", err)
	}
}

func TestValidateStagingHTTPArtifactsRequiresReleaseMetadata(t *testing.T) {
	cfg := config{
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
	}
	_, err := validateStagingHTTPArtifacts(http.DefaultClient, cfg)
	if err == nil || !strings.Contains(err.Error(), "release-candidate") {
		t.Fatalf("expected missing release-candidate error, got %v", err)
	}
}

func TestValidateStagingHTTPArtifactsRejectsStaleReleaseCandidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/http-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=def456 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/dependency-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=def456 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 dependency telemetry postgres postgres_p99_ms=32 redis redis_p99_ms=18 p99 below threshold dependency_threshold_pass=true"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config{
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
		LoadRunID:              "load-run-123",
	}
	_, err := validateStagingHTTPArtifacts(clientForArtifactServer(t, server), cfg)
	if err == nil || !strings.Contains(err.Error(), "http-replica-artifact-url artifact missing required staging markers") {
		t.Fatalf("expected stale HTTP release candidate rejection, got %v", err)
	}
}

func TestValidateStagingHTTPArtifactsRejectsWeakDependencyTelemetryProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load/http-replicas.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2"))
		case "/load/dependency-telemetry.txt":
			_, _ = w.Write([]byte("staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 dependency telemetry postgres redis p99 below threshold"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config{
		HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
		DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
		ReleaseCandidate:       "abc123",
		ServiceVersion:         "scriptureforge-api:abc123",
		LoadRunID:              "load-run-123",
	}
	_, err := validateStagingHTTPArtifacts(clientForArtifactServer(t, server), cfg)
	if err == nil || !strings.Contains(err.Error(), "dependency-telemetry-artifact-url artifact missing required staging markers") {
		t.Fatalf("expected dependency telemetry marker rejection, got %v", err)
	}
}

func TestValidateStagingHTTPArtifactsRejectsWeakStructuredArtifactValues(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replicaBody string
		telemetry   string
		want        string
	}{
		{
			name:        "missing replica count",
			replicaBody: "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas",
			telemetry:   "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 dependency telemetry postgres postgres_p99_ms=32 redis redis_p99_ms=18 p99 below threshold dependency_threshold_pass=true",
			want:        "missing numeric replica_count marker",
		},
		{
			name:        "single replica",
			replicaBody: "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=1",
			telemetry:   "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 dependency telemetry postgres postgres_p99_ms=32 redis redis_p99_ms=18 p99 below threshold dependency_threshold_pass=true",
			want:        "replica_count=1 must prove at least 2 replicas",
		},
		{
			name:        "postgres p99 above target",
			replicaBody: "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2",
			telemetry:   "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 dependency telemetry postgres postgres_p99_ms=250 redis redis_p99_ms=18 p99 below threshold dependency_threshold_pass=true",
			want:        "postgres_p99_ms=250 exceeds production max 200",
		},
		{
			name:        "redis p99 above target",
			replicaBody: "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 api replica distribution scriptureforge-api multiple replicas replica_count=2",
			telemetry:   "staging artifact release_candidate=abc123 service_version=scriptureforge-api:abc123 load_run_id=load-run-123 dependency telemetry postgres postgres_p99_ms=32 redis redis_p99_ms=250 p99 below threshold dependency_threshold_pass=true",
			want:        "redis_p99_ms=250 exceeds production max 200",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/load/http-replicas.txt":
					_, _ = w.Write([]byte(tc.replicaBody))
				case "/load/dependency-telemetry.txt":
					_, _ = w.Write([]byte(tc.telemetry))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			cfg := config{
				HTTPReplicaArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/http-replicas.txt",
				DependencyTelemetryURL: "https://load-artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt",
				ReleaseCandidate:       "abc123",
				ServiceVersion:         "scriptureforge-api:abc123",
				LoadRunID:              "load-run-123",
			}
			_, err := validateStagingHTTPArtifacts(clientForArtifactServer(t, server), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestWebSocketExternalRunRejectsLocalArtifactURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{
			name: "localhost websocket replica artifact",
			edit: func(cfg *config) {
				cfg.WSReplicaArtifactURL = "https://localhost/load/ws-replicas.txt"
			},
			want: "ws-replica-artifact-url",
		},
		{
			name: "loopback redis telemetry",
			edit: func(cfg *config) {
				cfg.RedisTelemetryArtifactURL = "https://[::1]/load/redis-telemetry.txt"
			},
			want: "redis-telemetry-artifact-url",
		},
		{
			name: "private websocket replica artifact",
			edit: func(cfg *config) {
				cfg.WSReplicaArtifactURL = "https://172.16.20.5/load/ws-replicas.txt"
			},
			want: "non-private staging artifact host",
		},
		{
			name: "private redis telemetry",
			edit: func(cfg *config) {
				cfg.RedisTelemetryArtifactURL = "https://192.168.100.30/load/redis-telemetry.txt"
			},
			want: "non-private staging artifact host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{
				WebSocket:                 true,
				Target:                    "wss://api-load.staging.scriptureforge.ai/api/v1/rooms/stream/staging-room",
				Duration:                  time.Second,
				Concurrency:               1,
				Timeout:                   time.Second,
				WSEventsPerClient:         1,
				WSRoomID:                  "staging-room",
				WSToken:                   "staging-token",
				WSOrigin:                  "https://app-load.staging.scriptureforge.ai",
				WSReplicaArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-replicas.txt",
				WSReconnectArtifactURL:    "https://load-artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt",
				WSPollingArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-polling.txt",
				RedisTelemetryArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt",
				ReleaseCandidate:          "abc123",
				ServiceVersion:            "scriptureforge-api:abc123",
				MinRPS:                    1,
				MaxP99:                    time.Second,
			}
			tc.edit(&cfg)
			var output bytes.Buffer
			err := run(cfg, &output)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q artifact URL error, got %v", tc.want, err)
			}
		})
	}
}

func TestAddClientQueryPreservesExistingTicket(t *testing.T) {
	got, err := addClientQuery("wss://api.example.test/api/v1/rooms/stream/room-1?ticket=abc", 7)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "ticket=abc") || !strings.Contains(got, "client=7") {
		t.Fatalf("query params not preserved/appended: %s", got)
	}
}

func TestIsStagingEvidenceTargetRejectsPrivateNetworkTargets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		target    string
		websocket bool
	}{
		{name: "private https", target: "https://10.0.0.25/health"},
		{name: "IPv4-mapped private https", target: "https://[::ffff:10.0.0.25]/health"},
		{name: "unspecified https", target: "https://0.0.0.0/health"},
		{name: "link local https", target: "https://169.254.10.20/health"},
		{name: "private wss", target: "wss://192.168.100.30/api/v1/rooms/stream/staging-room", websocket: true},
		{name: "IPv4-mapped private wss", target: "wss://[::ffff:192.168.100.30]/api/v1/rooms/stream/staging-room", websocket: true},
		{name: "reserved example https", target: "https://api.staging.example/health"},
		{name: "reserved example.com https", target: "https://api.example.com/health"},
		{name: "reserved test wss", target: "wss://api.staging.test/api/v1/rooms/stream/staging-room", websocket: true},
		{name: "reserved invalid wss", target: "wss://api.invalid/api/v1/rooms/stream/staging-room", websocket: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if isStagingEvidenceTarget(tc.target, tc.websocket) {
				t.Fatalf("%s was accepted as staging evidence target", tc.target)
			}
		})
	}
	if !isStagingEvidenceTarget("https://api-load.staging.scriptureforge.ai/health", false) {
		t.Fatal("public HTTPS API target should qualify as staging evidence")
	}
	if !isStagingEvidenceTarget("wss://api-load.staging.scriptureforge.ai/api/v1/rooms/stream/staging-room", true) {
		t.Fatal("public WSS API target should qualify as staging WebSocket evidence")
	}
}

func containsAll(values []string, expected ...string) bool {
	present := map[string]bool{}
	for _, value := range values {
		present[value] = true
	}
	for _, value := range expected {
		if !present[value] {
			return false
		}
	}
	return true
}

func containsAllSummaryMarkers(summary string, expected ...string) bool {
	for _, marker := range expected {
		if !strings.Contains(summary, marker) {
			return false
		}
	}
	return true
}

func stagingWebSocketArtifactConfig() config {
	return config{
		WSReplicaArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-replicas.txt",
		WSReconnectArtifactURL:    "https://load-artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt",
		WSPollingArtifactURL:      "https://load-artifacts.staging.scriptureforge.ai/load/ws-polling.txt",
		RedisTelemetryArtifactURL: "https://load-artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt",
		WSRoomID:                  "staging-room",
		Concurrency:               500,
		WSEventsPerClient:         60,
		ReleaseCandidate:          "abc123",
		ServiceVersion:            "scriptureforge-api:abc123",
		LoadRunID:                 "load-run-123",
	}
}

func repeatedLatencies(count int, latency time.Duration) []time.Duration {
	latencies := make([]time.Duration, count)
	for i := range latencies {
		latencies[i] = latency
	}
	return latencies
}

func rangeSequences(count int) []int64 {
	sequences := make([]int64, count)
	for i := range sequences {
		sequences[i] = int64(i + 1)
	}
	return sequences
}

func clientForArtifactServer(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("invalid test server URL: %v", err)
	}
	baseClient := server.Client()
	baseTransport := baseClient.Transport
	return &http.Client{
		Timeout: time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			cloned.URL.Scheme = serverURL.Scheme
			cloned.URL.Host = serverURL.Host
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func intPtr(value int) *int {
	return &value
}
