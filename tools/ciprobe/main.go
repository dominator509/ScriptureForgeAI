package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
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
	ObservedAt    string        `json:"observed_at"`
	ThresholdPass bool          `json:"threshold_pass"`
	Probes        []probeResult `json:"probes"`
	EvidenceItems []string      `json:"evidence_items"`
}

type probeResult struct {
	Name          string `json:"name"`
	Target        string `json:"target"`
	Passed        bool   `json:"passed"`
	StatusCode    int    `json:"status_code,omitempty"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	ResultSummary string `json:"result_summary"`
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

	client := &http.Client{Timeout: cfg.Timeout}
	probes := []probeResult{
		probeCIArtifact(client, cfg),
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: []string{"SRC-CI-001"},
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
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && ciArtifactTextPasses(string(body), cfg)
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary += "; artifact must prove the exact release SHA completed all required CI gates successfully"
	}
	return probeResult{Name: "github-actions-release-run", Target: cfg.RunArtifactURL, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
}

func probeCIArtifactFile(cfg config) probeResult {
	start := time.Now()
	body, err := os.ReadFile(cfg.RunArtifactFile)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("github-actions-release-run", cfg.RunArtifactFile, err.Error())
	}
	passed := ciArtifactTextPasses(string(body), cfg)
	summary := fmt.Sprintf("read local artifact in %dms", latency)
	if !passed {
		summary += "; artifact must prove the exact release SHA completed all required CI gates successfully"
	}
	return probeResult{Name: "github-actions-release-run", Target: cfg.RunArtifactFile, Passed: passed, LatencyMS: latency, ResultSummary: summary}
}

func ciArtifactTextPasses(text string, cfg config) bool {
	required := append([]string{
		cfg.CommitSHA,
		cfg.WorkflowName,
		"github actions",
		"security-audit",
		"conclusion: success",
		"status: completed",
	}, requiredGateMarkers()...)
	return containsAllFold(text, required) && containsNoneFold(text, failingRunMarkers())
}

func requiredGateMarkers() []string {
	return []string{
		"go test",
		"go vet",
		"npm audit",
		"npm run smoke",
		"npm run typecheck",
		"npm run build",
		"cargo test",
		"terraform fmt",
		"terraform validate",
		"trufflehog",
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

func isFullCommitSHA(value string) bool {
	return regexp.MustCompile(`^[a-fA-F0-9]{40}$`).MatchString(value)
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
