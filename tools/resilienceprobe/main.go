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
	"strings"
	"time"
)

type config struct {
	ProbeRollback       bool
	ProbeBackup         bool
	APIReadyBeforeURL   string
	APIReadyAfterURL    string
	RolloutArtifactURL  string
	DegradationDrillURL string
	BackupArtifactURL   string
	RestoreArtifactURL  string
	RestoredSmokeURL    string
	Timeout             time.Duration
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
	cfg := config{}
	flag.BoolVar(&cfg.ProbeRollback, "probe-rollback", false, "probe staging rollback and degradation drill evidence")
	flag.BoolVar(&cfg.ProbeBackup, "probe-backup", false, "probe staging backup and restore drill evidence")
	flag.StringVar(&cfg.APIReadyBeforeURL, "api-ready-before-url", os.Getenv("STAGING_API_READY_BEFORE_URL"), "API /ready URL or captured readiness artifact before rollback")
	flag.StringVar(&cfg.APIReadyAfterURL, "api-ready-after-url", os.Getenv("STAGING_API_READY_AFTER_URL"), "API /ready URL or captured readiness artifact after rollback")
	flag.StringVar(&cfg.RolloutArtifactURL, "rollout-artifact-url", os.Getenv("STAGING_ROLLOUT_ARTIFACT_URL"), "kubectl rollout undo/status artifact URL")
	flag.StringVar(&cfg.DegradationDrillURL, "degradation-drill-url", os.Getenv("STAGING_DEGRADATION_DRILL_URL"), "AI/Zoom degradation drill artifact URL")
	flag.StringVar(&cfg.BackupArtifactURL, "backup-artifact-url", os.Getenv("STAGING_BACKUP_ARTIFACT_URL"), "RDS backup/snapshot creation artifact URL")
	flag.StringVar(&cfg.RestoreArtifactURL, "restore-artifact-url", os.Getenv("STAGING_RESTORE_ARTIFACT_URL"), "RDS restore drill artifact URL")
	flag.StringVar(&cfg.RestoredSmokeURL, "restored-smoke-url", os.Getenv("STAGING_RESTORED_SMOKE_URL"), "application smoke artifact or /ready URL against restored database")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if !cfg.ProbeRollback && !cfg.ProbeBackup {
		return errors.New("at least one of -probe-rollback or -probe-backup is required")
	}
	if cfg.ProbeRollback {
		if cfg.APIReadyBeforeURL == "" || cfg.APIReadyAfterURL == "" || cfg.RolloutArtifactURL == "" || cfg.DegradationDrillURL == "" {
			return errors.New("-probe-rollback requires before/after readiness, rollout, and degradation drill URLs")
		}
	}
	if cfg.ProbeBackup {
		if cfg.BackupArtifactURL == "" || cfg.RestoreArtifactURL == "" || cfg.RestoredSmokeURL == "" {
			return errors.New("-probe-backup requires backup, restore, and restored smoke URLs")
		}
	}

	client := &http.Client{Timeout: cfg.Timeout}
	probes := []probeResult{}
	evidenceItems := []string{}
	if cfg.ProbeRollback {
		probes = append(probes,
			probeReadyOrArtifact(client, "api-ready-before-rollback", cfg.APIReadyBeforeURL),
			probeArtifact(client, "rollback-rollout-artifact", cfg.RolloutArtifactURL, []string{"rollout", "undo", "successfully rolled out"}),
			probeReadyOrArtifact(client, "api-ready-after-rollback", cfg.APIReadyAfterURL),
			probeArtifact(client, "degradation-drill-artifact", cfg.DegradationDrillURL, []string{"AI", "Zoom", "degradation", "fallback"}),
		)
		evidenceItems = append(evidenceItems, "DR-ROLLBACK-001")
	}
	if cfg.ProbeBackup {
		probes = append(probes,
			probeArtifact(client, "backup-snapshot-artifact", cfg.BackupArtifactURL, []string{"snapshot", "available", "encrypted"}),
			probeArtifact(client, "restore-drill-artifact", cfg.RestoreArtifactURL, []string{"restore", "available", "staging"}),
			probeReadyOrArtifact(client, "restored-database-smoke", cfg.RestoredSmokeURL),
		)
		evidenceItems = append(evidenceItems, "DR-BACKUP-001")
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: evidenceItems,
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
		return errors.New("one or more resilience probes failed")
	}
	return nil
}

func probeReadyOrArtifact(client *http.Client, name, target string) probeResult {
	return probeHTTPBody(client, name, target)
}

func probeArtifact(client *http.Client, name, target string, required []string) probeResult {
	result, body := fetch(client, name, target)
	if !result.Passed {
		return result
	}
	if !containsAllFold(body, required) {
		result.Passed = false
		result.ResultSummary += "; artifact missing required markers"
	}
	return result
}

func probeHTTPBody(client *http.Client, name, target string) probeResult {
	result, body := fetch(client, name, target)
	if !result.Passed {
		return result
	}
	if !isReadyBody(body) {
		result.Passed = false
		result.ResultSummary += "; readiness/smoke marker missing"
	}
	return result
}

func fetch(client *http.Client, name, target string) (probeResult, string) {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error()), ""
	}
	req.Header.Set("User-Agent", "scriptureforge-resilienceprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error()), ""
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}, string(bodyBytes)
}

func isReadyBody(body string) bool {
	return containsAnyFold(body, []string{"ready", "ok", "healthy", "smoke passed", "status\":\"ok", "status\":\"ready"})
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

func containsAnyFold(text string, needles []string) bool {
	lowerText := strings.ToLower(text)
	for _, needle := range needles {
		if strings.Contains(lowerText, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
