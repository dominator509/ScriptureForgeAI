package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresAllArtifacts(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "Zoom proof requires") {
		t.Fatalf("expected artifact requirement error, got %v", err)
	}
}

func TestRunEmitsZoomEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted"))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789"))
		case "/webhook":
			_, _ = w.Write([]byte("webhook signature invalid returned 401; signed webhook returned 200"))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook idempotent 200 no duplicate side effects"))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id zoom-123 mapped to live_rooms room room-abc"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		OAuthArtifactURL:       server.URL + "/oauth",
		MeetingArtifactURL:     server.URL + "/meeting",
		WebhookArtifactURL:     server.URL + "/webhook",
		DuplicateArtifactURL:   server.URL + "/duplicate",
		RoomMappingArtifactURL: server.URL + "/mapping",
		Timeout:                time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("zoom probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if len(result.EvidenceItems) != 1 || result.EvidenceItems[0] != "EXT-ZOOM-001" {
		t.Fatalf("unexpected evidence items: %+v", result.EvidenceItems)
	}
}

func TestRunAcceptsOfflineMeetingFallbackEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted"))
		case "/meeting":
			_, _ = w.Write([]byte("Zoom unavailable fallback offline://in-person"))
		case "/webhook":
			_, _ = w.Write([]byte("webhook signature invalid 401 signed 200"))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook idempotent 200 no duplicate side effects"))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id mapped live_rooms room"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		OAuthArtifactURL:       server.URL + "/oauth",
		MeetingArtifactURL:     server.URL + "/meeting",
		WebhookArtifactURL:     server.URL + "/webhook",
		DuplicateArtifactURL:   server.URL + "/duplicate",
		RoomMappingArtifactURL: server.URL + "/mapping",
		Timeout:                time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("offline fallback evidence should pass: %v\n%s", err, output.String())
	}
}

func TestRunFailsWhenOAuthArtifactLeaksSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok client_secret=leaked"))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789"))
		case "/webhook":
			_, _ = w.Write([]byte("webhook signature invalid 401 signed 200"))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook idempotent 200 no duplicate side effects"))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id mapped live_rooms room"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		OAuthArtifactURL:       server.URL + "/oauth",
		MeetingArtifactURL:     server.URL + "/meeting",
		WebhookArtifactURL:     server.URL + "/webhook",
		DuplicateArtifactURL:   server.URL + "/duplicate",
		RoomMappingArtifactURL: server.URL + "/mapping",
		Timeout:                time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected leaked OAuth secret to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}
