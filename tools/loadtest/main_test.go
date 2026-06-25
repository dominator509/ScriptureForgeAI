package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"scriptureforge/internal/ports"
)

func TestBuildReportAppliesThresholds(t *testing.T) {
	cfg := config{Target: "http://example.test/health", Method: "GET", Concurrency: 2, MinRPS: 100, MaxP99: 20 * time.Millisecond}
	result := buildReport(cfg, time.Second, []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		15 * time.Millisecond,
	}, 0)

	if result.ThresholdPass {
		t.Fatal("thresholds passed despite RPS below configured minimum")
	}

	cfg.MinRPS = 1
	result = buildReport(cfg, time.Second, []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		15 * time.Millisecond,
	}, 0)
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
	if strings.Contains(output.String(), `"evidence_items"`) {
		t.Fatalf("websocket self-test report must not emit staging evidence items:\n%s", output.String())
	}
}

func TestWebSocketExternalRunUsesBearerAndOrigin(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return r.Header.Get("Origin") == "https://app.staging.example"
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
			event.Sequence++
			encoded, _ := json.Marshal(event)
			if err := conn.WriteMessage(websocket.TextMessage, encoded); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		WebSocket:         true,
		Target:            "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/staging-room",
		Duration:          time.Second,
		Concurrency:       2,
		Timeout:           time.Second,
		WSEventsPerClient: 2,
		WSRoomID:          "staging-room",
		WSToken:           "staging-token",
		WSOrigin:          "https://app.staging.example",
		MinRPS:            1,
		MaxP99:            time.Second,
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
	if !strings.Contains(output.String(), `"PERF-WS-001"`) || !strings.Contains(output.String(), `"DATA-REDIS-001"`) {
		t.Fatalf("external websocket report did not include staging evidence IDs:\n%s", output.String())
	}
}

func TestExternalHTTPLoadReportIncludesPerformanceEvidenceID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		Target:       server.URL,
		Method:       "GET",
		Duration:     100 * time.Millisecond,
		Concurrency:  2,
		Timeout:      time.Second,
		ExpectStatus: 200,
		MinRPS:       1,
		MaxP99:       time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("external HTTP run failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"PERF-HTTP-001"`) {
		t.Fatalf("external HTTP report did not include performance evidence ID:\n%s", output.String())
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
