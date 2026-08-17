package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
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
	if result.CommitSHA != testCommitSHA || result.WorkflowName != "Security Pipeline Verification" {
		t.Fatalf("release identity was not propagated: %+v", result)
	}
	if result.ArtifactCommitSHA != testCommitSHA || result.RunID != "1234567890" || result.RunAttempt != "1" || result.RunNumber != "42" {
		t.Fatalf("structured CI run identity was not propagated: %+v", result)
	}
	if result.CIRunURL != "https://github.com/example/scriptureforgeai/actions/runs/1234567890" {
		t.Fatalf("CI run URL was not propagated: %+v", result)
	}
	if result.Repository != "example/scriptureforgeai" || result.Ref != "refs/heads/main" || result.RefName != "main" || result.EventName != "push" {
		t.Fatalf("source-control provenance was not propagated: %+v", result)
	}
	if result.SourceControlStatus != "clean" || result.ReleaseEvidenceScope != "exact-github-sha-required-gates" {
		t.Fatalf("source-control cleanliness was not propagated: %+v", result)
	}
	assertProbeSummaryProofMarkers(t, result)
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
	if result.CIRunURL == "" || result.Probes[0].RunURL == "" {
		t.Fatalf("local artifact probe should propagate run URL: %+v", result)
	}
	if result.ArtifactCommitSHA != testCommitSHA || result.RunID != "1234567890" || result.RunAttempt != "1" || result.RunNumber != "42" {
		t.Fatalf("local artifact probe should propagate structured run identity: %+v", result)
	}
	assertProbeSummaryProofMarkers(t, result)
}

func assertProbeSummaryProofMarkers(t *testing.T, result report) {
	t.Helper()
	if len(result.Probes) != 1 {
		t.Fatalf("expected one probe result: %+v", result.Probes)
	}
	for _, marker := range requiredProofMarkers() {
		if !strings.Contains(result.Probes[0].ResultSummary, marker) {
			t.Fatalf("probe summary missing proof marker %q: %s", marker, result.Probes[0].ResultSummary)
		}
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
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
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
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing required gate marker to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsMissingRLSSchemaGateMarker(t *testing.T) {
	artifact := strings.ReplaceAll(successfulRunArtifact(), "- gate: rls-schema-validation\n", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing RLS schema gate marker to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsMissingRunURL(t *testing.T) {
	artifact := strings.ReplaceAll(successfulRunArtifact(), "run_url: https://github.com/example/scriptureforgeai/actions/runs/1234567890\n", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing run URL to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsStaleCommitLineEvenWhenTargetSHAIsMentioned(t *testing.T) {
	artifact := strings.ReplaceAll(
		successfulRunArtifact(),
		"commit: 0123456789abcdef0123456789abcdef01234567\n",
		"commit: fedcba9876543210fedcba9876543210fedcba98\nrelease_candidate: 0123456789abcdef0123456789abcdef01234567\n",
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched commit line to fail even though target SHA is mentioned:\n%s", output.String())
	}
}

func TestCIProbeRejectsRunURLNotBoundToRunID(t *testing.T) {
	artifact := strings.ReplaceAll(
		successfulRunArtifact(),
		"run_url: https://github.com/example/scriptureforgeai/actions/runs/1234567890\n",
		"run_url: https://github.com/example/scriptureforgeai/actions/runs/9999999999\n",
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected run_url/run_id mismatch to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsRunURLRunIDPrefixMatch(t *testing.T) {
	artifact := strings.ReplaceAll(
		successfulRunArtifact(),
		"run_id: 1234567890\n",
		"run_id: 123\n",
	)
	artifact = strings.ReplaceAll(
		artifact,
		"run_url: https://github.com/example/scriptureforgeai/actions/runs/1234567890\n",
		"run_url: https://github.com/example/scriptureforgeai/actions/runs/1234\n",
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected prefix-only run_url/run_id match to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsMissingRunAttemptProvenance(t *testing.T) {
	artifact := strings.ReplaceAll(successfulRunArtifact(), "run_attempt: 1\n", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing run attempt provenance to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsMissingSourceControlProvenance(t *testing.T) {
	artifact := strings.ReplaceAll(successfulRunArtifact(), "source_control_status: clean\n", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing source-control provenance to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsMissingUntrackedSourceCleanProof(t *testing.T) {
	artifact := strings.ReplaceAll(successfulRunArtifact(), "source_control_untracked_status: clean\n", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing untracked source clean proof to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsMissingReleaseEvidenceProofMarker(t *testing.T) {
	artifact := strings.ReplaceAll(successfulRunArtifact(), "local_gate_markers_included=true, ", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing release evidence proof marker to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsMissingRunAttemptProofMarker(t *testing.T) {
	artifact := strings.ReplaceAll(successfulRunArtifact(), "github_run_attempt_provenance_required=true, ", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(artifact))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		RunArtifactURL: "https://ci-artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt",
		CommitSHA:      testCommitSHA,
		WorkflowName:   "Security Pipeline Verification",
		Timeout:        time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing run attempt proof marker to fail:\n%s", output.String())
	}
}

func TestCIProbeRejectsLocalOrInsecureArtifactURL(t *testing.T) {
	for _, raw := range []string{
		"http://artifacts.example.test/ci.txt",
		"https://artifacts.staging.example/ci.txt",
		"https://ci.example.com/run.txt",
		"https://ci-artifacts.staging.test/run.txt",
		"https://ci-artifacts.invalid/run.txt",
		"https://127.0.0.1/ci.txt",
		"https://localhost/ci.txt",
		"https://10.0.0.15/ci.txt",
		"https://[::ffff:10.0.0.15]/ci.txt",
		"https://169.254.10.20/ci.txt",
		"https://0.0.0.0/ci.txt",
	} {
		t.Run(raw, func(t *testing.T) {
			var output bytes.Buffer
			err := run(config{
				RunArtifactURL: raw,
				CommitSHA:      testCommitSHA,
				WorkflowName:   "Security Pipeline Verification",
				Timeout:        time.Second,
			}, &output)
			if err == nil || !strings.Contains(err.Error(), "run-artifact-url") {
				t.Fatalf("expected artifact URL validation error, got %v", err)
			}
		})
	}
}

func successfulRunArtifact() string {
	return `
GitHub Actions run summary
workflow: Security Pipeline Verification
job: security-audit
repository: example/scriptureforgeai
ref: refs/heads/main
ref_name: main
ref_type: branch
event_name: push
commit: 0123456789abcdef0123456789abcdef01234567
run_id: 1234567890
run_attempt: 1
run_number: 42
actor: codex
run_url: https://github.com/example/scriptureforgeai/actions/runs/1234567890
source_control_status: clean
source_control_clean: verified-before-evidence-write
source_control_untracked_status: clean
source_control_clean_command: git diff --quiet
source_control_cached_clean_command: git diff --cached --quiet
source_control_untracked_clean_command: git status --short
release_evidence_scope: exact-github-sha-required-gates
proof markers: full_commit_sha_required=true, artifact_commit_sha_structural_binding_required=true, github_run_provenance_required=true, github_run_id_url_binding_required=true, source_control_clean_verified=true, source_control_untracked_clean_verified=true, github_run_attempt_provenance_required=true, exact_sha_required_gates_scope=true, local_gate_markers_included=true, staging_gap_report_footer_contract_required=true, staging_gap_report_required_evidence_contract_required=true, trufflehog_marker_included=true, success_conclusion_required=true
status: completed
conclusion: success
required gates:
- gate: project-path-readiness
- gate: strict-staging-path-readiness
- gate: go-test
- gate: go-vet
- gate: rls-db-integration
- gate: evidence-probes
- gate: web-audit
- gate: web-smoke
- gate: web-typecheck
- gate: web-build
- gate: mobile-audit
- gate: mobile-smoke
- gate: mobile-build-check
- gate: rust-protobuf-validation
- gate: rust-cargo-test
- gate: terraform-fmt
- gate: terraform-init-validate
- gate: terraform-validate
- gate: observability-validation
- gate: rls-schema-validation
- gate: deployment-skeleton-validation
- gate: staging-evidence-validation
- gate: staging-evidence-gap-report
- gate: ci-workflow-validation
- gate: ci-evidence-gate-validation
- gate: security-artifacts-validation
- gate: dependency-risk-validation
- gate: secret-hygiene-validation
- gate: journal-crypto-validation
- gate: roadmap-artifact-validation
- gate: serena-obsidian-validation
- gate: staging-evidence-contract-check
- gate: obsidian-readiness-snapshot-check
- gate: tooling-tests
- TruffleHog Secret Scanning
`
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
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
