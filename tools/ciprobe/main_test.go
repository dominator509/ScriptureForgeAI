package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testCommitSHA = "0123456789abcdef0123456789abcdef01234567"

func TestCIProbeEmitsSourceControlEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(successfulRunArtifact()))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		RunArtifactURL: server.URL,
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("expected CI probe to pass: %v\n%s", err, output.String())
	}

	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("threshold should pass: %+v", result)
	}
	if len(result.EvidenceItems) != 1 || result.EvidenceItems[0] != "SRC-CI-001" {
		t.Fatalf("unexpected evidence items: %+v", result.EvidenceItems)
	}
}

func TestCIProbeAcceptsLocalArtifactFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ci-release-evidence.txt")
	if err := os.WriteFile(path, []byte(successfulRunArtifact()), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	var output bytes.Buffer
	err := run(config{
		RunArtifactFile: path,
		CommitSHA:       testCommitSHA,
		WorkflowName:    "Security Pipeline Verification",
		Timeout:         time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("expected local artifact probe to pass: %v\n%s", err, output.String())
	}

	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("threshold should pass: %+v", result)
	}
}

func TestCIProbeRejectsBothArtifactSources(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		RunArtifactURL:  "https://example.invalid/run.txt",
		RunArtifactFile: "run.txt",
		CommitSHA:       testCommitSHA,
		WorkflowName:    "Security Pipeline Verification",
		Timeout:         time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("expected exclusive artifact source validation error, got %v", err)
	}
}

func TestCIProbeRejectsFailedRunArtifact(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(successfulRunArtifact() + "\nconclusion: failure\n"))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		RunArtifactURL: server.URL,
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected failed conclusion marker to fail probe:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failure report should be emitted:\n%s", output.String())
	}
}

func TestCIProbeRequiresFullCommitSHA(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		RunArtifactURL: "https://example.invalid/run.txt",
		CommitSHA:      "0123456",
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "40-character") {
		t.Fatalf("expected full SHA validation error, got %v", err)
	}
}

func TestCIProbeRejectsMissingGateMarker(t *testing.T) {
	artifact := strings.ReplaceAll(successfulRunArtifact(), "gate: terraform-validate", "gate: terraform-plan")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		RunArtifactURL: server.URL,
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected missing required gate marker to fail:\n%s", output.String())
	}
}

func successfulRunArtifact() string {
	return `
GitHub Actions run summary
workflow: Security Pipeline Verification
job: security-audit
commit: 0123456789abcdef0123456789abcdef01234567
status: completed
conclusion: success
required gates:
- gate: go-test
- gate: go-vet
- gate: evidence-probes
- gate: web-audit
- gate: web-smoke
- gate: web-typecheck
- gate: web-build
- gate: mobile-audit
- gate: mobile-smoke
- gate: mobile-build-check
- gate: rust-cargo-test
- gate: terraform-fmt
- gate: terraform-init-validate
- gate: terraform-validate
- gate: observability-validation
- gate: deployment-skeleton-validation
- gate: staging-evidence-validation
- gate: ci-workflow-validation
- gate: security-artifacts-validation
- gate: dependency-risk-validation
- gate: secret-hygiene-validation
- gate: journal-crypto-validation
- gate: tooling-tests
- TruffleHog Secret Scanning
`
}
