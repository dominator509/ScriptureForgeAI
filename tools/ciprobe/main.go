package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type config struct {
	RunArtifactURL  string
	RunArtifactFile string
	CommitSHA       string
	WorkflowName    string
	Timeout         time.Duration
}

type report struct {
	ObservedAt           string        `json:"observed_at"`
	ThresholdPass        bool          `json:"threshold_pass"`
	CommitSHA            string        `json:"commit_sha"`
	WorkflowName         string        `json:"workflow_name"`
	Repository           string        `json:"repository,omitempty"`
	Ref                  string        `json:"ref,omitempty"`
	RefName              string        `json:"ref_name,omitempty"`
	EventName            string        `json:"event_name,omitempty"`
	SourceControlStatus  string        `json:"source_control_status,omitempty"`
	ReleaseEvidenceScope string        `json:"release_evidence_scope,omitempty"`
	CIRunURL             string        `json:"ci_run_url,omitempty"`
	Probes               []probeResult `json:"probes"`
	EvidenceItems        []string      `json:"evidence_items"`
}

type probeResult struct {
	Name                 string `json:"name"`
	Target               string `json:"target"`
	Passed               bool   `json:"passed"`
	StatusCode           int    `json:"status_code,omitempty"`
	LatencyMS            int64  `json:"latency_ms,omitempty"`
	RunURL               string `json:"run_url,omitempty"`
	Repository           string `json:"repository,omitempty"`
	Ref                  string `json:"ref,omitempty"`
	RefName              string `json:"ref_name,omitempty"`
	EventName            string `json:"event_name,omitempty"`
	SourceControlStatus  string `json:"source_control_status,omitempty"`
	ReleaseEvidenceScope string `json:"release_evidence_scope,omitempty"`
	ResultSummary        string `json:"result_summary"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseFlags() config {
	cfg := config{WorkflowName: "Security Pipeline Verification"}
	flag.StringVar(&cfg.RunArtifactURL, "run-artifact-url", os.Getenv("STAGING_CI_RUN_ARTIFACT_URL"), "GitHub Actions run summary or artifact URL for the release candidate SHA")
	flag.StringVar(&cfg.RunArtifactFile, "run-artifact-file", os.Getenv("STAGING_CI_RUN_ARTIFACT_FILE"), "local GitHub Actions run summary or artifact file for the release candidate SHA")
	flag.StringVar(&cfg.CommitSHA, "commit-sha", os.Getenv("STAGING_RELEASE_COMMIT"), "full 40-character release candidate commit SHA")
	flag.StringVar(&cfg.WorkflowName, "workflow-name", envOrDefault("STAGING_CI_WORKFLOW_NAME", cfg.WorkflowName), "expected GitHub Actions workflow name")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	return runWithClient(cfg, output, &http.Client{Timeout: cfg.Timeout})
}

func runWithClient(cfg config, output io.Writer, client *http.Client) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.RunArtifactURL == "" && cfg.RunArtifactFile == "" {
		return errors.New("-run-artifact-url/STAGING_CI_RUN_ARTIFACT_URL or -run-artifact-file/STAGING_CI_RUN_ARTIFACT_FILE is required")
	}
	if cfg.RunArtifactURL != "" && cfg.RunArtifactFile != "" {
		return errors.New("provide only one of -run-artifact-url or -run-artifact-file")
	}
	if !isFullCommitSHA(cfg.CommitSHA) {
		return errors.New("-commit-sha or STAGING_RELEASE_COMMIT must be a full 40-character hex SHA")
	}
	if strings.TrimSpace(cfg.WorkflowName) == "" {
		return errors.New("-workflow-name must not be empty")
	}
	var err error
	if cfg.RunArtifactURL != "" {
		cfg.RunArtifactURL, err = normalizeArtifactURL(cfg.RunArtifactURL)
		if err != nil {
			return err
		}
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	probes := []probeResult{
		probeCIArtifact(client, cfg),
	}

	result := report{
		ObservedAt:           time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass:        true,
		CommitSHA:            cfg.CommitSHA,
		WorkflowName:         cfg.WorkflowName,
		Repository:           probes[0].Repository,
		Ref:                  probes[0].Ref,
		RefName:              probes[0].RefName,
		EventName:            probes[0].EventName,
		SourceControlStatus:  probes[0].SourceControlStatus,
		ReleaseEvidenceScope: probes[0].ReleaseEvidenceScope,
		CIRunURL:             probes[0].RunURL,
		Probes:               probes,
		EvidenceItems:        []string{"SRC-CI-001"},
	}
	for _, probe := range probes {
		if !probe.Passed {
			result.ThresholdPass = false
			break
		}
	}

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	if !result.ThresholdPass {
		return errors.New("CI artifact probe failed")
	}
	return nil
}

func probeCIArtifact(client *http.Client, cfg config) probeResult {
	if cfg.RunArtifactFile != "" {
		return probeCIArtifactFile(cfg)
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, cfg.RunArtifactURL, nil)
	if err != nil {
		return failedProbe("github-actions-release-run", cfg.RunArtifactURL, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-ciprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("github-actions-release-run", cfg.RunArtifactURL, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyText := string(body)
	metadata := extractCIArtifactMetadata(bodyText)
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && ciArtifactTextPasses(bodyText, cfg)
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if passed {
		summary += "; " + strings.Join(requiredProofMarkers(), " ")
	} else {
		summary += "; artifact must prove the exact release SHA completed all required CI gates successfully"
	}
	metadata.Name = "github-actions-release-run"
	metadata.Target = cfg.RunArtifactURL
	metadata.Passed = passed
	metadata.StatusCode = resp.StatusCode
	metadata.LatencyMS = latency
	metadata.ResultSummary = summary
	return metadata
}

func probeCIArtifactFile(cfg config) probeResult {
	start := time.Now()
	body, err := os.ReadFile(cfg.RunArtifactFile)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("github-actions-release-run", cfg.RunArtifactFile, err.Error())
	}
	bodyText := string(body)
	metadata := extractCIArtifactMetadata(bodyText)
	passed := ciArtifactTextPasses(bodyText, cfg)
	summary := fmt.Sprintf("read local artifact in %dms", latency)
	if passed {
		summary += "; " + strings.Join(requiredProofMarkers(), " ")
	} else {
		summary += "; artifact must prove the exact release SHA completed all required CI gates successfully"
	}
	metadata.Name = "github-actions-release-run"
	metadata.Target = cfg.RunArtifactFile
	metadata.Passed = passed
	metadata.LatencyMS = latency
	metadata.ResultSummary = summary
	return metadata
}

func extractCIArtifactMetadata(text string) probeResult {
	return probeResult{
		RunURL:               extractLineValue(text, "run_url:"),
		Repository:           extractLineValue(text, "repository:"),
		Ref:                  extractLineValue(text, "ref:"),
		RefName:              extractLineValue(text, "ref_name:"),
		EventName:            extractLineValue(text, "event_name:"),
		SourceControlStatus:  extractLineValue(text, "source_control_status:"),
		ReleaseEvidenceScope: extractLineValue(text, "release_evidence_scope:"),
	}
}

func ciArtifactTextPasses(text string, cfg config) bool {
	required := append([]string{
		cfg.CommitSHA,
		cfg.WorkflowName,
		"github actions",
		"security-audit",
		"repository:",
		"ref:",
		"ref_name:",
		"event_name:",
		"run_id:",
		"run_attempt:",
		"run_number:",
		"run_url: https://github.com/",
		"source_control_status: clean",
		"source_control_clean: verified-before-evidence-write",
		"source_control_untracked_status: clean",
		"source_control_clean_command: git diff --quiet",
		"source_control_cached_clean_command: git diff --cached --quiet",
		"source_control_untracked_clean_command: git status --short",
		"release_evidence_scope: exact-github-sha-required-gates",
		"conclusion: success",
		"status: completed",
	}, requiredGateMarkers()...)
	required = append(required, requiredProofMarkers()...)
	return containsAllFold(text, required) && containsNoneFold(text, failingRunMarkers())
}

func requiredGateMarkers() []string {
	return []string{
		"gate: project-path-readiness",
		"gate: strict-staging-path-readiness",
		"gate: go-test",
		"gate: go-vet",
		"gate: rls-db-integration",
		"gate: evidence-probes",
		"gate: web-audit",
		"gate: web-smoke",
		"gate: web-typecheck",
		"gate: web-build",
		"gate: mobile-audit",
		"gate: mobile-smoke",
		"gate: mobile-build-check",
		"gate: rust-cargo-test",
		"gate: rust-protobuf-validation",
		"gate: terraform-fmt",
		"gate: terraform-init-validate",
		"gate: terraform-validate",
		"gate: observability-validation",
		"gate: rls-schema-validation",
		"gate: deployment-skeleton-validation",
		"gate: staging-evidence-validation",
		"gate: staging-evidence-gap-report",
		"gate: ci-workflow-validation",
		"gate: ci-evidence-gate-validation",
		"gate: security-artifacts-validation",
		"gate: dependency-risk-validation",
		"gate: secret-hygiene-validation",
		"gate: journal-crypto-validation",
		"gate: serena-obsidian-validation",
		"gate: staging-evidence-contract-check",
		"gate: obsidian-readiness-snapshot-check",
		"gate: tooling-tests",
		"trufflehog",
	}
}

func requiredProofMarkers() []string {
	return []string{
		"proof markers:",
		"full_commit_sha_required=true",
		"github_run_provenance_required=true",
		"source_control_clean_verified=true",
		"source_control_untracked_clean_verified=true",
		"github_run_attempt_provenance_required=true",
		"exact_sha_required_gates_scope=true",
		"local_gate_markers_included=true",
		"staging_gap_report_footer_contract_required=true",
		"staging_gap_report_required_evidence_contract_required=true",
		"trufflehog_marker_included=true",
		"success_conclusion_required=true",
	}
}

func failingRunMarkers() []string {
	return []string{
		"conclusion: failure",
		"conclusion: cancelled",
		"conclusion: timed_out",
		"conclusion: startup_failure",
		"required gate skipped",
		"dirty worktree",
		"stale commit sha",
	}
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

func extractLineValue(text, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(prefix)) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return ""
}

func isFullCommitSHA(value string) bool {
	return regexp.MustCompile(`^[a-fA-F0-9]{40}$`).MatchString(value)
}

func normalizeArtifactURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", errors.New("-run-artifact-url/STAGING_CI_RUN_ARTIFACT_URL must use https")
	}
	if parsed.Host == "" {
		return "", errors.New("-run-artifact-url/STAGING_CI_RUN_ARTIFACT_URL must include a host")
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", errors.New("-run-artifact-url/STAGING_CI_RUN_ARTIFACT_URL must not use a reserved placeholder artifact host")
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", errors.New("-run-artifact-url/STAGING_CI_RUN_ARTIFACT_URL must use a public GitHub artifact host")
	}
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

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
