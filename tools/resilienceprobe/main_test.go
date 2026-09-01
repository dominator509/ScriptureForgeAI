package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func stagingResilienceConfig(timeout time.Duration) config {
	return config{
		ProbeRollback:       true,
		ProbeBackup:         true,
		APIReadyBeforeURL:   "https://resilience-artifacts.staging.scriptureforge.ai/resilience/ready-before",
		APIReadyAfterURL:    "https://resilience-artifacts.staging.scriptureforge.ai/resilience/ready-after",
		RolloutArtifactURL:  "https://resilience-artifacts.staging.scriptureforge.ai/resilience/rollout",
		DegradationDrillURL: "https://resilience-artifacts.staging.scriptureforge.ai/resilience/degradation",
		BackupArtifactURL:   "https://resilience-artifacts.staging.scriptureforge.ai/resilience/backup",
		RestoreArtifactURL:  "https://resilience-artifacts.staging.scriptureforge.ai/resilience/restore",
		RestoredSmokeURL:    "https://resilience-artifacts.staging.scriptureforge.ai/resilience/restored-smoke",
		ReleaseCandidate:    "sha-new",
		ServiceVersion:      "release-1",
		LoadRunID:           "resilience-run-123",
		Timeout:             timeout,
	}
}

func TestRunRequiresProbeMode(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "probe-rollback") {
		t.Fatalf("expected probe mode error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ReleaseCandidate = ""
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "release-candidate") {
		t.Fatalf("expected release identity error, got %v", err)
	}
}

func TestRunRequiresLoadRunIdentity(t *testing.T) {
	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.LoadRunID = ""
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "load-run-id") {
		t.Fatalf("expected load run identity error, got %v", err)
	}
}

func TestRunEmitsRollbackAndBackupEvidenceWhenDrillsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-1","deployment_environment":"staging","pre_rollback_version":"release-1","release_candidate":"sha-new","markers":"staging artifact release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/rollout":
			_, _ = w.Write([]byte("staging artifact kubectl rollout undo deployment/scriptureforge-api previous_revision=42 target_revision=41; scriptureforge-api deployment successfully rolled out release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/ready-after":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-0","deployment_environment":"staging","post_rollback_version":"release-0","rolled_back_from":"release-1","rolled_back_to":"release-0","markers":"staging artifact release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/degradation":
			_, _ = w.Write([]byte("staging artifact AI degradation fallback exercised with AI_ORCHESTRATION_ENGINE_FAULT ai_fault=true; Zoom degradation fallback exercised with offline://in-person zoom_offline_fallback=true; non-AI routes healthy non_ai_routes_healthy=true; zoom circuit open zoom_circuit_open=true distinct_rollback_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/backup":
			_, _ = w.Write([]byte("staging artifact snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted kms_key_id=alias/scriptureforge-rds-backups retention 7 days automated backup source cluster scriptureforge-staging rpo_minutes=15 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restore":
			_, _ = w.Write([]byte("staging artifact restore restore_job_id=restore-456 cluster scriptureforge-restore staging available restored endpoint scriptureforge-restore.cluster source snapshot_id=snap-123 checksum verified isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("staging artifact smoke passed against restored database tenant auth RLS migration version journal read/write verified with no plaintext journal distinct_backup_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingResilienceConfig(time.Second), &output, clientForHTTPServer(t, server))
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
	if result.ReleaseCandidate != "sha-new" || result.ServiceVersion != "release-1" {
		t.Fatalf("report missing release identity: %+v", result)
	}
	if result.LoadRunID != "resilience-run-123" {
		t.Fatalf("report missing load run identity: %+v", result)
	}
	if !containsItem(result.EvidenceItems, "DR-ROLLBACK-001") || !containsItem(result.EvidenceItems, "DR-BACKUP-001") {
		t.Fatalf("report missing resilience evidence items: %+v", result.EvidenceItems)
	}
	expectedMarkers := map[string][]string{
		"api-ready-before-rollback":  {"staging artifact", "ready", "service_version", "deployment_environment", "pre_rollback_version", "pre_rollback_version=release-1", "release_candidate", "sha-new", "release-1", "load_run_id=resilience-run-123"},
		"rollback-rollout-artifact":  {"staging artifact", "rollout", "undo", "revision", "previous_revision", "target_revision", "scriptureforge-api", "successfully rolled out", "release_candidate", "sha-new", "release-1", "load_run_id=resilience-run-123"},
		"api-ready-after-rollback":   {"staging artifact", "ready", "service_version", "deployment_environment", "post_rollback_version", "post_rollback_version=release-0", "rolled_back_from", "rolled_back_from=release-1", "rolled_back_to", "rolled_back_to=release-0", "release_candidate", "sha-new", "release-1", "load_run_id=resilience-run-123"},
		"degradation-drill-artifact": {"staging artifact", "AI", "Zoom", "degradation", "fallback", "AI_ORCHESTRATION_ENGINE_FAULT", "offline://in-person", "non-AI routes healthy", "zoom circuit open", "ai_fault=true", "zoom_offline_fallback=true", "non_ai_routes_healthy=true", "zoom_circuit_open=true", "distinct_rollback_artifacts=true", "release_candidate", "sha-new", "release-1", "load_run_id=resilience-run-123"},
		"backup-snapshot-artifact":   {"staging artifact", "snapshot", "snapshot_id", "snapshot_id=snap-123", "available", "encrypted", "kms_key_id=alias/scriptureforge-rds-backups", "retention", "automated backup", "source cluster", "rpo_minutes", "rpo_minutes=15", "release_candidate", "sha-new", "release-1", "load_run_id=resilience-run-123"},
		"restore-drill-artifact":     {"staging artifact", "restore", "restore_job_id", "restore_job_id=restore-456", "available", "staging", "restored endpoint", "source snapshot_id", "source snapshot_id=snap-123", "checksum", "isolated restore", "rto_minutes", "rto_minutes=30", "restore_duration_minutes", "restore_duration_minutes=18", "release_candidate", "sha-new", "release-1", "load_run_id=resilience-run-123"},
		"restored-database-smoke":    {"staging artifact", "smoke passed", "restored database", "tenant", "journal", "auth", "RLS", "migration version", "no plaintext journal", "distinct_backup_artifacts=true", "release_candidate", "sha-new", "release-1", "load_run_id=resilience-run-123"},
	}
	for _, probe := range result.Probes {
		for _, marker := range expectedMarkers[probe.Name] {
			if !strings.Contains(probe.ResultSummary, marker) {
				t.Fatalf("probe %s summary missing marker %q: %s", probe.Name, marker, probe.ResultSummary)
			}
		}
	}
	assertBackupRestoreStructuredFields(t, result.Probes)
	assertRollbackStructuredFields(t, result.Probes)
}

func TestRunFailsWhenBackupArtifactOmitsStagingProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted kms_key_id=alias/scriptureforge-rds-backups retention 7 days automated backup source cluster scriptureforge-staging rpo_minutes=15 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restore":
			_, _ = w.Write([]byte("staging artifact restore restore_job_id=restore-456 cluster scriptureforge-restore staging available restored endpoint scriptureforge-restore.cluster source snapshot_id=snap-123 checksum verified isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("staging artifact smoke passed against restored database tenant auth RLS migration version journal read/write verified with no plaintext journal distinct_backup_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeRollback = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing staging provenance to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "backup-snapshot-artifact") {
		t.Fatalf("report missing backup probe:\n%s", output.String())
	}
}

func TestRunFailsWhenBackupArtifactOmitsKMSKeyID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("staging artifact snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted retention 7 days automated backup source cluster scriptureforge-staging rpo_minutes=15 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restore":
			_, _ = w.Write([]byte("staging artifact restore restore_job_id=restore-456 cluster scriptureforge-restore staging available restored endpoint scriptureforge-restore.cluster source snapshot_id=snap-123 checksum verified isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("staging artifact smoke passed against restored database tenant auth RLS migration version journal read/write verified with no plaintext journal distinct_backup_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeRollback = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing KMS key ID to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "kms_key_id") {
		t.Fatalf("report did not explain missing KMS key ID:\n%s", output.String())
	}
}

func TestRunFailsWhenRollbackArtifactUsesDifferentLoadRun(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-1","deployment_environment":"staging","pre_rollback_version":"release-1","release_candidate":"sha-new","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/rollout":
			_, _ = w.Write([]byte("kubectl rollout undo deployment/scriptureforge-api previous_revision=42 target_revision=41; scriptureforge-api deployment successfully rolled out release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-999"))
		case "/ready-after":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-0","deployment_environment":"staging","post_rollback_version":"release-0","rolled_back_from":"release-1","rolled_back_to":"release-0","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/degradation":
			_, _ = w.Write([]byte("AI degradation fallback exercised with AI_ORCHESTRATION_ENGINE_FAULT ai_fault=true; Zoom degradation fallback exercised with offline://in-person zoom_offline_fallback=true; non-AI routes healthy non_ai_routes_healthy=true; zoom circuit open zoom_circuit_open=true distinct_rollback_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeBackup = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched load run evidence to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "rollback-rollout-artifact") {
		t.Fatalf("report missing load-run-mismatched rollout probe:\n%s", output.String())
	}
}

func assertBackupRestoreStructuredFields(t *testing.T, probes []probeResult) {
	t.Helper()
	var sawBackup bool
	var sawRestore bool
	for _, probe := range probes {
		switch probe.Name {
		case "degradation-drill-artifact":
			if !probe.AIFault || !probe.ZoomOfflineFallback || !probe.NonAIRoutesHealthy || !probe.ZoomCircuitOpen {
				t.Fatalf("unexpected degradation structured fields: %+v", probe)
			}
		case "backup-snapshot-artifact":
			sawBackup = true
			if probe.SnapshotID != "snap-123" || probe.KMSKeyID != "alias/scriptureforge-rds-backups" || probe.RPOMinutes != 15 {
				t.Fatalf("unexpected backup structured fields: %+v", probe)
			}
		case "restore-drill-artifact":
			sawRestore = true
			if probe.RestoreJobID != "restore-456" || probe.SourceSnapshotID != "snap-123" || probe.RTOMinutes != 30 || probe.RestoreDurationMinutes != 18 {
				t.Fatalf("unexpected restore structured fields: %+v", probe)
			}
		}
	}
	if !sawBackup || !sawRestore {
		t.Fatalf("missing backup/restore structured probes: backup=%v restore=%v", sawBackup, sawRestore)
	}
}

func assertRollbackStructuredFields(t *testing.T, probes []probeResult) {
	t.Helper()
	var sawBefore bool
	var sawAfter bool
	for _, probe := range probes {
		switch probe.Name {
		case "api-ready-before-rollback":
			sawBefore = true
			if probe.PreRollbackVersion != "release-1" {
				t.Fatalf("unexpected rollback-before structured fields: %+v", probe)
			}
		case "api-ready-after-rollback":
			sawAfter = true
			if probe.PostRollbackVersion != "release-0" || probe.RolledBackFrom != "release-1" || probe.RolledBackTo != "release-0" {
				t.Fatalf("unexpected rollback-after structured fields: %+v", probe)
			}
		}
	}
	if !sawBefore || !sawAfter {
		t.Fatalf("missing rollback structured probes: before=%v after=%v", sawBefore, sawAfter)
	}
}

func TestRunFailsWhenArtifactsAreMarkedMockOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted kms_key_id=alias/scriptureforge-rds-backups retention 7 days automated backup source cluster scriptureforge-staging rpo_minutes=15 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restore":
			_, _ = w.Write([]byte("mock restore restore_job_id=restore-456 cluster scriptureforge-restore staging available restored endpoint scriptureforge-restore.cluster source snapshot_id=snap-123 checksum verified isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("smoke passed against restored database tenant auth RLS migration version journal read/write verified with no plaintext journal release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeRollback = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mock-only artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "marked mock/placeholder") {
		t.Fatalf("report did not explain weak artifact rejection:\n%s", output.String())
	}
}

func TestRunFailsWhenArtifactsAdmitFailedDrill(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-1","deployment_environment":"staging","pre_rollback_version":"release-1","release_candidate":"sha-new","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/rollout":
			_, _ = w.Write([]byte("kubectl rollout undo deployment/scriptureforge-api previous_revision=42 target_revision=41; scriptureforge-api deployment successfully rolled out release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123; rollback failed"))
		case "/ready-after":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-0","deployment_environment":"staging","post_rollback_version":"release-0","rolled_back_from":"release-1","rolled_back_to":"release-0","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/degradation":
			_, _ = w.Write([]byte("AI degradation fallback exercised with AI_ORCHESTRATION_ENGINE_FAULT ai_fault=true; Zoom degradation fallback exercised with offline://in-person zoom_offline_fallback=true; non-AI routes healthy non_ai_routes_healthy=true; zoom circuit open zoom_circuit_open=true distinct_rollback_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeBackup = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected failed-drill artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "rollback-rollout-artifact") || !strings.Contains(output.String(), "marked mock/placeholder") {
		t.Fatalf("report did not explain failed-drill artifact rejection:\n%s", output.String())
	}
}

func TestRunFailsWhenRollbackReadinessDoesNotRecover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-1","deployment_environment":"staging","pre_rollback_version":"release-1","release_candidate":"sha-new","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/rollout":
			_, _ = w.Write([]byte("kubectl rollout undo deployment/scriptureforge-api previous_revision=42 target_revision=41; scriptureforge-api deployment successfully rolled out release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/ready-after":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
		case "/degradation":
			_, _ = w.Write([]byte("AI degradation fallback exercised with AI_ORCHESTRATION_ENGINE_FAULT; Zoom degradation fallback exercised with offline://in-person; non-AI routes healthy; zoom circuit open release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeBackup = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected failed readiness to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenRollbackArtifactsOmitVersionLinkage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-1","deployment_environment":"staging"}`))
		case "/rollout":
			_, _ = w.Write([]byte("kubectl rollout undo deployment/scriptureforge-api previous_revision=42 target_revision=41; scriptureforge-api deployment successfully rolled out release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/ready-after":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-0","deployment_environment":"staging","post_rollback_version":"release-0","rolled_back_from":"release-1","rolled_back_to":"release-0","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/degradation":
			_, _ = w.Write([]byte("AI degradation fallback exercised with AI_ORCHESTRATION_ENGINE_FAULT; Zoom degradation fallback exercised with offline://in-person; non-AI routes healthy; zoom circuit open release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeBackup = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing rollback version linkage to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "api-ready-before-rollback") {
		t.Fatalf("report missing readiness-before probe:\n%s", output.String())
	}
}

func TestRunFailsWhenRollbackVersionLinkageIsInconsistent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-1","deployment_environment":"staging","pre_rollback_version":"release-1","release_candidate":"sha-new","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/rollout":
			_, _ = w.Write([]byte("kubectl rollout undo deployment/scriptureforge-api previous_revision=42 target_revision=41; scriptureforge-api deployment successfully rolled out release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/ready-after":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-0","deployment_environment":"staging","post_rollback_version":"release-0","rolled_back_from":"release-other","rolled_back_to":"release-0","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/degradation":
			_, _ = w.Write([]byte("AI degradation fallback exercised with AI_ORCHESTRATION_ENGINE_FAULT ai_fault=true; Zoom degradation fallback exercised with offline://in-person zoom_offline_fallback=true; non-AI routes healthy non_ai_routes_healthy=true; zoom circuit open zoom_circuit_open=true distinct_rollback_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeBackup = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected inconsistent rollback linkage to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "rolled_back_from") || !strings.Contains(output.String(), "pre_rollback_version") {
		t.Fatalf("report did not explain rollback version mismatch:\n%s", output.String())
	}
}

func TestRunFailsWhenRestoreArtifactIsIncomplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted kms_key_id=alias/scriptureforge-rds-backups retention 7 days automated backup source cluster scriptureforge-staging rpo_minutes=15 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restore":
			_, _ = w.Write([]byte("restore started but not complete"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("smoke passed against restored database tenant auth RLS migration version journal with no plaintext journal release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeRollback = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected incomplete restore artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"restore-drill-artifact"`) {
		t.Fatalf("report missing restore probe:\n%s", output.String())
	}
}

func TestRunFailsWhenRestoreSourceSnapshotDoesNotMatchBackupSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted kms_key_id=alias/scriptureforge-rds-backups retention 7 days automated backup source cluster scriptureforge-staging rpo_minutes=15 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restore":
			_, _ = w.Write([]byte("restore restore_job_id=restore-456 cluster scriptureforge-restore staging available restored endpoint scriptureforge-restore.cluster source snapshot_id=snap-other checksum verified isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("smoke passed against restored database tenant auth RLS migration version journal read/write verified with no plaintext journal distinct_backup_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeRollback = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched restore source snapshot to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "source_snapshot_id") || !strings.Contains(output.String(), "backup snapshot_id") {
		t.Fatalf("report did not explain source snapshot mismatch:\n%s", output.String())
	}
}

func TestRunFailsWhenBackupRestoreArtifactsOmitRecoveryObjectives(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted kms_key_id=alias/scriptureforge-rds-backups retention 7 days automated backup source cluster scriptureforge-staging"))
		case "/restore":
			_, _ = w.Write([]byte("restore restore_job_id=restore-456 cluster scriptureforge-restore staging available restored endpoint scriptureforge-restore.cluster source snapshot_id=snap-123 checksum verified isolated restore"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("smoke passed against restored database tenant auth RLS migration version journal read/write verified with no plaintext journal release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeRollback = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing recovery objective markers to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "backup-snapshot-artifact") || !strings.Contains(output.String(), "restore-drill-artifact") {
		t.Fatalf("report missing backup/restore probes:\n%s", output.String())
	}
}

func TestRunFailsWhenRestoreDurationExceedsRTO(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted kms_key_id=alias/scriptureforge-rds-backups retention 7 days automated backup source cluster scriptureforge-staging rpo_minutes=15 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restore":
			_, _ = w.Write([]byte("restore restore_job_id=restore-456 cluster scriptureforge-restore staging available restored endpoint scriptureforge-restore.cluster source snapshot_id=snap-123 checksum verified isolated restore rto_minutes=30 restore_duration_minutes=45 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("smoke passed against restored database tenant auth RLS migration version journal read/write verified with no plaintext journal distinct_backup_artifacts=true release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeRollback = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected restore duration above RTO to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "restore_duration_minutes 45 exceeds rto_minutes 30") {
		t.Fatalf("report did not explain RTO violation:\n%s", output.String())
	}
}

func TestRunFailsWhenDegradationDrillMissingTypedFallbacks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready-before":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-1","deployment_environment":"staging","pre_rollback_version":"release-1","release_candidate":"sha-new","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/rollout":
			_, _ = w.Write([]byte("kubectl rollout undo deployment/scriptureforge-api previous_revision=42 target_revision=41; scriptureforge-api deployment successfully rolled out release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/ready-after":
			_, _ = w.Write([]byte(`{"status":"ready","service_version":"release-0","deployment_environment":"staging","post_rollback_version":"release-0","rolled_back_from":"release-1","rolled_back_to":"release-0","markers":"release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"}`))
		case "/degradation":
			_, _ = w.Write([]byte("AI degradation fallback exercised; Zoom degradation fallback exercised"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeBackup = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected weak degradation proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "degradation-drill-artifact") {
		t.Fatalf("report missing degradation probe:\n%s", output.String())
	}
}

func TestRunFailsWhenRestoredSmokeOmitsTenantJournalChecks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup":
			_, _ = w.Write([]byte("snapshot snapshot_id=snap-123 scriptureforge-staging-backup available encrypted kms_key_id=alias/scriptureforge-rds-backups retention 7 days automated backup source cluster scriptureforge-staging rpo_minutes=15 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restore":
			_, _ = w.Write([]byte("restore restore_job_id=restore-456 cluster scriptureforge-restore staging available restored endpoint scriptureforge-restore.cluster source snapshot_id=snap-123 checksum verified isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		case "/restored-smoke":
			_, _ = w.Write([]byte("smoke passed against restored database release_candidate=sha-new service_version=release-1 load_run_id=resilience-run-123"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingResilienceConfig(time.Second)
	cfg.ProbeRollback = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected weak restored smoke proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "restored-database-smoke") {
		t.Fatalf("report missing restored smoke probe:\n%s", output.String())
	}
}

func TestRunRejectsDuplicateRollbackArtifactURLs(t *testing.T) {
	cfg := stagingResilienceConfig(time.Second)
	cfg.DegradationDrillURL = cfg.RolloutArtifactURL

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-degradation-drill-url must be a distinct artifact URL from -rollout-artifact-url") {
		t.Fatalf("expected duplicate rollback URL error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateRollbackArtifactURLs(t *testing.T) {
	cfg := stagingResilienceConfig(time.Second)
	cfg.RolloutArtifactURL = "https://RESILIENCE-ARTIFACTS.staging.scriptureforge.ai:443/resilience/shared-rollback?b=2&a=1"
	cfg.DegradationDrillURL = "https://resilience-artifacts.staging.scriptureforge.ai/resilience/shared-rollback?a=1&b=2"

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-degradation-drill-url must be a distinct artifact URL from -rollout-artifact-url") {
		t.Fatalf("expected canonical duplicate rollback URL error, got %v", err)
	}
}

func TestRunRejectsDuplicateBackupArtifactURLs(t *testing.T) {
	cfg := stagingResilienceConfig(time.Second)
	cfg.RestoredSmokeURL = cfg.RestoreArtifactURL

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-restored-smoke-url must be a distinct artifact URL from -restore-artifact-url") {
		t.Fatalf("expected duplicate backup URL error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateBackupArtifactURLs(t *testing.T) {
	cfg := stagingResilienceConfig(time.Second)
	cfg.RestoreArtifactURL = "https://RESILIENCE-ARTIFACTS.staging.scriptureforge.ai:443/resilience/shared-backup?b=2&a=1"
	cfg.RestoredSmokeURL = "https://resilience-artifacts.staging.scriptureforge.ai/resilience/shared-backup?a=1&b=2"

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-restored-smoke-url must be a distinct artifact URL from -restore-artifact-url") {
		t.Fatalf("expected canonical duplicate backup URL error, got %v", err)
	}
}

func TestRunRejectsLocalOrInsecureTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{
			name: "insecure readiness target",
			edit: func(cfg *config) {
				cfg.APIReadyBeforeURL = "http://resilience-artifacts.staging.scriptureforge.ai/ready"
			},
			want: "api-ready-before-url",
		},
		{
			name: "loopback rollout artifact",
			edit: func(cfg *config) {
				cfg.RolloutArtifactURL = "https://127.0.0.1/resilience/rollout"
			},
			want: "rollout-artifact-url",
		},
		{
			name: "private readiness artifact",
			edit: func(cfg *config) {
				cfg.APIReadyAfterURL = "https://10.0.0.25/resilience/ready-after"
			},
			want: "api-ready-after-url",
		},
		{
			name: "IPv4-mapped private readiness artifact",
			edit: func(cfg *config) {
				cfg.APIReadyAfterURL = "https://[::ffff:10.0.0.25]/resilience/ready-after"
			},
			want: "api-ready-after-url",
		},
		{
			name: "link-local degradation artifact",
			edit: func(cfg *config) {
				cfg.DegradationDrillURL = "https://169.254.10.20/resilience/degradation"
			},
			want: "degradation-drill-url",
		},
		{
			name: "private backup artifact",
			edit: func(cfg *config) {
				cfg.BackupArtifactURL = "https://172.16.20.5/resilience/backup"
			},
			want: "backup-artifact-url",
		},
		{
			name: "unspecified restore artifact",
			edit: func(cfg *config) {
				cfg.RestoreArtifactURL = "https://0.0.0.0/resilience/restore"
			},
			want: "restore-artifact-url",
		},
		{
			name: "localhost restored smoke",
			edit: func(cfg *config) {
				cfg.RestoredSmokeURL = "https://localhost/resilience/restored-smoke"
			},
			want: "restored-smoke-url",
		},
		{
			name: "reserved example readiness target",
			edit: func(cfg *config) {
				cfg.APIReadyBeforeURL = "https://artifacts.staging.example/resilience/ready-before"
			},
			want: "reserved placeholder staging host",
		},
		{
			name: "reserved example.com rollout artifact",
			edit: func(cfg *config) {
				cfg.RolloutArtifactURL = "https://resilience.example.com/resilience/rollout"
			},
			want: "reserved placeholder staging host",
		},
		{
			name: "reserved test backup artifact",
			edit: func(cfg *config) {
				cfg.BackupArtifactURL = "https://resilience-artifacts.staging.test/resilience/backup"
			},
			want: "reserved placeholder staging host",
		},
		{
			name: "reserved invalid restored smoke",
			edit: func(cfg *config) {
				cfg.RestoredSmokeURL = "https://resilience-artifacts.invalid/resilience/restored-smoke"
			},
			want: "reserved placeholder staging host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stagingResilienceConfig(time.Second)
			tc.edit(&cfg)
			var output bytes.Buffer
			err := runWithClient(cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q URL validation error, got %v", tc.want, err)
			}
		})
	}
}

func clientForHTTPServer(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("invalid test server URL: %v", err)
	}
	baseClient := server.Client()
	baseTransport := baseClient.Transport
	return &http.Client{
		Timeout: baseClient.Timeout,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			cloned.URL.Scheme = serverURL.Scheme
			cloned.URL.Host = serverURL.Host
			cloned.URL.Path = strings.TrimPrefix(cloned.URL.Path, "/resilience")
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func containsItem(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}
