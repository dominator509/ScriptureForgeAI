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

func TestRunRequiresProbeMode(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "probe-rollback") {
		t.Fatalf("expected probe mode error, got %v", err)
	}
}

func TestRunEmitsRollbackAndBackupEvidenceWhenDrillsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready"}`))
		case "/rollout":
			_, _ = w.Write([]byte("kubectl rollout undo deployment/scriptureforge-api; deployment successfully rolled out"))
		case "/ready-after":
			_, _ = w.Write([]byte("ok ready"))
		case "/degradation":
			_, _ = w.Write([]byte("AI degradation fallback exercised; Zoom degradation fallback exercised"))
		case "/backup":
			_, _ = w.Write([]byte("snapshot scriptureforge-staging-backup available encrypted"))
		case "/restore":
			_, _ = w.Write([]byte("restore cluster scriptureforge-restore staging available"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("smoke passed against restored database"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeRollback:       true,
		ProbeBackup:         true,
		APIReadyBeforeURL:   server.URL + "/ready-before",
		APIReadyAfterURL:    server.URL + "/ready-after",
		RolloutArtifactURL:  server.URL + "/rollout",
		DegradationDrillURL: server.URL + "/degradation",
		BackupArtifactURL:   server.URL + "/backup",
		RestoreArtifactURL:  server.URL + "/restore",
		RestoredSmokeURL:    server.URL + "/restored-smoke",
		Timeout:             time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("resilience probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if !containsItem(result.EvidenceItems, "DR-ROLLBACK-001") || !containsItem(result.EvidenceItems, "DR-BACKUP-001") {
		t.Fatalf("report missing resilience evidence items: %+v", result.EvidenceItems)
	}
}

func TestRunFailsWhenRollbackReadinessDoesNotRecover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready"}`))
		case "/rollout":
			_, _ = w.Write([]byte("kubectl rollout undo deployment/scriptureforge-api; deployment successfully rolled out"))
		case "/ready-after":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
		case "/degradation":
			_, _ = w.Write([]byte("AI degradation fallback exercised; Zoom degradation fallback exercised"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeRollback:       true,
		APIReadyBeforeURL:   server.URL + "/ready-before",
		APIReadyAfterURL:    server.URL + "/ready-after",
		RolloutArtifactURL:  server.URL + "/rollout",
		DegradationDrillURL: server.URL + "/degradation",
		Timeout:             time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected failed readiness to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenRestoreArtifactIsIncomplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("snapshot scriptureforge-staging-backup available encrypted"))
		case "/restore":
			_, _ = w.Write([]byte("restore started but not complete"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("smoke passed against restored database"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeBackup:        true,
		BackupArtifactURL:  server.URL + "/backup",
		RestoreArtifactURL: server.URL + "/restore",
		RestoredSmokeURL:   server.URL + "/restored-smoke",
		Timeout:            time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected incomplete restore artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"restore-drill-artifact"`) {
		t.Fatalf("report missing restore probe:\n%s", output.String())
	}
}

func containsItem(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}
