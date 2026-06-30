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
	"strconv"
	"strings"
	"time"
)

var (
	snapshotIDPattern             = regexp.MustCompile(`(?i)\bsnapshot_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	restoreJobIDPattern           = regexp.MustCompile(`(?i)\brestore_job_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	sourceSnapshotIDPattern       = regexp.MustCompile(`(?i)\bsource snapshot_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	rpoMinutesPattern             = regexp.MustCompile(`(?i)\brpo_minutes=([0-9]+)\b`)
	rtoMinutesPattern             = regexp.MustCompile(`(?i)\brto_minutes=([0-9]+)\b`)
	restoreDurationMinutesPattern = regexp.MustCompile(`(?i)\brestore_duration_minutes=([0-9]+)\b`)
	aiFaultPattern                = regexp.MustCompile(`(?i)\bai_fault=true\b`)
	zoomOfflineFallbackPattern    = regexp.MustCompile(`(?i)\bzoom_offline_fallback=true\b`)
	nonAIRoutesHealthyPattern     = regexp.MustCompile(`(?i)\bnon_ai_routes_healthy=true\b`)
	zoomCircuitOpenPattern        = regexp.MustCompile(`(?i)\bzoom_circuit_open=true\b`)
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
	ReleaseCandidate    string
	ServiceVersion      string
	LoadRunID           string
	Timeout             time.Duration
}

type report struct {
	ObservedAt       string        `json:"observed_at"`
	ThresholdPass    bool          `json:"threshold_pass"`
	ReleaseCandidate string        `json:"release_candidate"`
	ServiceVersion   string        `json:"service_version"`
	LoadRunID        string        `json:"load_run_id"`
	Probes           []probeResult `json:"probes"`
	EvidenceItems    []string      `json:"evidence_items"`
}

type probeResult struct {
	Name                   string `json:"name"`
	Target                 string `json:"target"`
	Passed                 bool   `json:"passed"`
	StatusCode             int    `json:"status_code,omitempty"`
	LatencyMS              int64  `json:"latency_ms,omitempty"`
	SnapshotID             string `json:"snapshot_id,omitempty"`
	RestoreJobID           string `json:"restore_job_id,omitempty"`
	SourceSnapshotID       string `json:"source_snapshot_id,omitempty"`
	RPOMinutes             int    `json:"rpo_minutes,omitempty"`
	RTOMinutes             int    `json:"rto_minutes,omitempty"`
	RestoreDurationMinutes int    `json:"restore_duration_minutes,omitempty"`
	AIFault                bool   `json:"ai_fault,omitempty"`
	ZoomOfflineFallback    bool   `json:"zoom_offline_fallback,omitempty"`
	NonAIRoutesHealthy     bool   `json:"non_ai_routes_healthy,omitempty"`
	ZoomCircuitOpen        bool   `json:"zoom_circuit_open,omitempty"`
	ResultSummary          string `json:"result_summary"`
}

type artifactTarget struct {
	Label string
	URL   string
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
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("RELEASE_CANDIDATE"), "exact release candidate SHA being proven")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("SERVICE_VERSION"), "deployed service version being proven")
	flag.StringVar(&cfg.LoadRunID, "load-run-id", os.Getenv("STAGING_LOAD_RUN_ID"), "exact staging resilience run identifier that every rollback, degradation, backup, and restore artifact must name")
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
	if !cfg.ProbeRollback && !cfg.ProbeBackup {
		return errors.New("at least one of -probe-rollback or -probe-backup is required")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	cfg.LoadRunID = strings.TrimSpace(cfg.LoadRunID)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" || cfg.LoadRunID == "" {
		return errors.New("resilience probes require -release-candidate, -service-version, and -load-run-id")
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
	var err error
	if cfg.ProbeRollback {
		cfg.APIReadyBeforeURL, err = normalizeStagingURL(cfg.APIReadyBeforeURL, "api-ready-before-url")
		if err != nil {
			return err
		}
		cfg.APIReadyAfterURL, err = normalizeStagingURL(cfg.APIReadyAfterURL, "api-ready-after-url")
		if err != nil {
			return err
		}
		cfg.RolloutArtifactURL, err = normalizeStagingURL(cfg.RolloutArtifactURL, "rollout-artifact-url")
		if err != nil {
			return err
		}
		cfg.DegradationDrillURL, err = normalizeStagingURL(cfg.DegradationDrillURL, "degradation-drill-url")
		if err != nil {
			return err
		}
		if err := requireDistinctURLs([]artifactTarget{
			{Label: "api-ready-before-url", URL: cfg.APIReadyBeforeURL},
			{Label: "rollout-artifact-url", URL: cfg.RolloutArtifactURL},
			{Label: "api-ready-after-url", URL: cfg.APIReadyAfterURL},
			{Label: "degradation-drill-url", URL: cfg.DegradationDrillURL},
		}); err != nil {
			return err
		}
	}
	if cfg.ProbeBackup {
		cfg.BackupArtifactURL, err = normalizeStagingURL(cfg.BackupArtifactURL, "backup-artifact-url")
		if err != nil {
			return err
		}
		cfg.RestoreArtifactURL, err = normalizeStagingURL(cfg.RestoreArtifactURL, "restore-artifact-url")
		if err != nil {
			return err
		}
		cfg.RestoredSmokeURL, err = normalizeStagingURL(cfg.RestoredSmokeURL, "restored-smoke-url")
		if err != nil {
			return err
		}
		if err := requireDistinctURLs([]artifactTarget{
			{Label: "backup-artifact-url", URL: cfg.BackupArtifactURL},
			{Label: "restore-artifact-url", URL: cfg.RestoreArtifactURL},
			{Label: "restored-smoke-url", URL: cfg.RestoredSmokeURL},
		}); err != nil {
			return err
		}
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	probes := []probeResult{}
	evidenceItems := []string{}
	releaseMarkers := []string{
		fmt.Sprintf("release_candidate=%s", cfg.ReleaseCandidate),
		fmt.Sprintf("service_version=%s", cfg.ServiceVersion),
		fmt.Sprintf("load_run_id=%s", cfg.LoadRunID),
	}
	if cfg.ProbeRollback {
		probes = append(probes,
			probeReadyOrArtifact(client, "api-ready-before-rollback", cfg.APIReadyBeforeURL, append([]string{"ready", "deployment_environment", "pre_rollback_version"}, releaseMarkers...)),
			probeArtifact(client, "rollback-rollout-artifact", cfg.RolloutArtifactURL, append([]string{"rollout", "undo", "revision", "previous_revision", "target_revision", "scriptureforge-api", "successfully rolled out"}, releaseMarkers...)),
			probeReadyOrArtifact(client, "api-ready-after-rollback", cfg.APIReadyAfterURL, append([]string{"ready", "deployment_environment", "post_rollback_version", "rolled_back_from", "rolled_back_to"}, releaseMarkers...)),
			probeArtifact(client, "degradation-drill-artifact", cfg.DegradationDrillURL, append([]string{"AI", "Zoom", "degradation", "fallback", "AI_ORCHESTRATION_ENGINE_FAULT", "offline://in-person", "non-AI routes healthy", "zoom circuit open", "ai_fault=true", "zoom_offline_fallback=true", "non_ai_routes_healthy=true", "zoom_circuit_open=true", "distinct_rollback_artifacts=true"}, releaseMarkers...)),
		)
		evidenceItems = append(evidenceItems, "DR-ROLLBACK-001")
	}
	if cfg.ProbeBackup {
		probes = append(probes,
			probeArtifact(client, "backup-snapshot-artifact", cfg.BackupArtifactURL, append([]string{"snapshot", "snapshot_id", "available", "encrypted", "kms", "retention", "automated backup", "source cluster", "rpo_minutes"}, releaseMarkers...)),
			probeArtifact(client, "restore-drill-artifact", cfg.RestoreArtifactURL, append([]string{"restore", "restore_job_id", "available", "staging", "restored endpoint", "source snapshot_id", "checksum", "isolated restore", "rto_minutes", "restore_duration_minutes"}, releaseMarkers...)),
			probeReadyOrArtifact(client, "restored-database-smoke", cfg.RestoredSmokeURL, append([]string{"smoke passed", "restored database", "tenant", "journal", "auth", "RLS", "migration version", "no plaintext journal", "distinct_backup_artifacts=true"}, releaseMarkers...)),
		)
		enforceBackupRestoreLinkage(probes)
		evidenceItems = append(evidenceItems, "DR-BACKUP-001")
	}

	result := report{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass:    true,
		ReleaseCandidate: cfg.ReleaseCandidate,
		ServiceVersion:   cfg.ServiceVersion,
		LoadRunID:        cfg.LoadRunID,
		Probes:           probes,
		EvidenceItems:    evidenceItems,
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

func probeReadyOrArtifact(client *http.Client, name, target string, required []string) probeResult {
	return probeHTTPBody(client, name, target, required)
}

func probeArtifact(client *http.Client, name, target string, required []string) probeResult {
	result, body := fetch(client, name, target)
	if !result.Passed {
		return result
	}
	applyStructuredProbeFields(&result, body)
	if !containsAllFold(body, required) || containsAnyFold(body, forbiddenArtifactMarkers()) {
		result.Passed = false
		result.ResultSummary += "; artifact missing required markers or marked mock/placeholder"
	} else {
		result.ResultSummary += fmt.Sprintf("; staging artifact; verified markers: %s", strings.Join(required, ", "))
	}
	if name == "backup-snapshot-artifact" && (result.SnapshotID == "" || result.RPOMinutes <= 0) {
		result.Passed = false
		result.ResultSummary += "; structured snapshot_id or rpo_minutes missing"
	}
	if name == "restore-drill-artifact" && (result.RestoreJobID == "" || result.SourceSnapshotID == "" || result.RTOMinutes <= 0 || result.RestoreDurationMinutes <= 0) {
		result.Passed = false
		result.ResultSummary += "; structured restore_job_id, source_snapshot_id, rto_minutes, or restore_duration_minutes missing"
	}
	if name == "restore-drill-artifact" && result.RTOMinutes > 0 && result.RestoreDurationMinutes > result.RTOMinutes {
		result.Passed = false
		result.ResultSummary += fmt.Sprintf("; restore_duration_minutes %d exceeds rto_minutes %d", result.RestoreDurationMinutes, result.RTOMinutes)
	}
	if name == "degradation-drill-artifact" && (!result.AIFault || !result.ZoomOfflineFallback || !result.NonAIRoutesHealthy || !result.ZoomCircuitOpen) {
		result.Passed = false
		result.ResultSummary += "; structured ai_fault, zoom_offline_fallback, non_ai_routes_healthy, or zoom_circuit_open missing"
	}
	result.ResultSummary += resilienceStructuredSummaryMarkers(result)
	return result
}

func resilienceStructuredSummaryMarkers(result probeResult) string {
	switch result.Name {
	case "backup-snapshot-artifact":
		if result.SnapshotID == "" || result.RPOMinutes <= 0 {
			return ""
		}
		return fmt.Sprintf("; snapshot_id=%s rpo_minutes=%d", result.SnapshotID, result.RPOMinutes)
	case "restore-drill-artifact":
		if result.RestoreJobID == "" || result.SourceSnapshotID == "" || result.RTOMinutes <= 0 || result.RestoreDurationMinutes <= 0 {
			return ""
		}
		return fmt.Sprintf("; restore_job_id=%s source snapshot_id=%s rto_minutes=%d restore_duration_minutes=%d", result.RestoreJobID, result.SourceSnapshotID, result.RTOMinutes, result.RestoreDurationMinutes)
	case "degradation-drill-artifact":
		if !result.AIFault || !result.ZoomOfflineFallback || !result.NonAIRoutesHealthy || !result.ZoomCircuitOpen {
			return ""
		}
		return "; ai_fault=true zoom_offline_fallback=true non_ai_routes_healthy=true zoom_circuit_open=true"
	default:
		return ""
	}
}

func enforceBackupRestoreLinkage(probes []probeResult) {
	var snapshotID string
	var restoreIndex = -1
	for i := range probes {
		switch probes[i].Name {
		case "backup-snapshot-artifact":
			snapshotID = probes[i].SnapshotID
		case "restore-drill-artifact":
			restoreIndex = i
		}
	}
	if snapshotID == "" || restoreIndex < 0 {
		return
	}
	if probes[restoreIndex].SourceSnapshotID != snapshotID {
		probes[restoreIndex].Passed = false
		probes[restoreIndex].ResultSummary += fmt.Sprintf("; source_snapshot_id %q does not match backup snapshot_id %q", probes[restoreIndex].SourceSnapshotID, snapshotID)
	}
}

func applyStructuredProbeFields(result *probeResult, text string) {
	switch result.Name {
	case "backup-snapshot-artifact":
		result.SnapshotID = extractStringField(snapshotIDPattern, text)
		result.RPOMinutes = extractPositiveIntField(rpoMinutesPattern, text)
	case "restore-drill-artifact":
		result.RestoreJobID = extractStringField(restoreJobIDPattern, text)
		result.SourceSnapshotID = extractStringField(sourceSnapshotIDPattern, text)
		result.RTOMinutes = extractPositiveIntField(rtoMinutesPattern, text)
		result.RestoreDurationMinutes = extractPositiveIntField(restoreDurationMinutesPattern, text)
	case "degradation-drill-artifact":
		result.AIFault = aiFaultPattern.MatchString(text)
		result.ZoomOfflineFallback = zoomOfflineFallbackPattern.MatchString(text)
		result.NonAIRoutesHealthy = nonAIRoutesHealthyPattern.MatchString(text)
		result.ZoomCircuitOpen = zoomCircuitOpenPattern.MatchString(text)
	}
}

func extractStringField(pattern *regexp.Regexp, text string) string {
	match := pattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractPositiveIntField(pattern *regexp.Regexp, text string) int {
	value := extractStringField(pattern, text)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func probeHTTPBody(client *http.Client, name, target string, required []string) probeResult {
	result, body := fetch(client, name, target)
	if !result.Passed {
		return result
	}
	if !containsAllFold(body, required) || containsAnyFold(body, forbiddenArtifactMarkers()) {
		result.Passed = false
		result.ResultSummary += "; readiness/smoke markers missing or marked mock/placeholder"
	} else {
		result.ResultSummary += fmt.Sprintf("; staging artifact; verified markers: %s", strings.Join(required, ", "))
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

func normalizeStagingURL(raw, field string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("-%s must use https", field)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("-%s must include a host", field)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must use a non-local, non-private staging host", field)
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not use a reserved placeholder staging host", field)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func requireDistinctURLs(targets []artifactTarget) error {
	seen := map[string]string{}
	for _, target := range targets {
		normalized, err := canonicalArtifactURL(target.URL)
		if err != nil {
			return fmt.Errorf("-%s artifact URL: %w", target.Label, err)
		}
		if normalized == "" {
			continue
		}
		if previous, ok := seen[normalized]; ok {
			return fmt.Errorf("-%s must be a distinct artifact URL from -%s", target.Label, previous)
		}
		seen[normalized] = target.Label
	}
	return nil
}

func canonicalArtifactURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if host == "" {
		return "", errors.New("missing host")
	}
	if scheme == "https" && port == "443" {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	} else {
		parsed.Host = host
	}
	parsed.Scheme = scheme
	parsed.Fragment = ""
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String(), nil
}

func isLocalOrPrivateHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(host), "[]")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())
}

func isReservedPlaceholderHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if normalized == "" {
		return false
	}
	return strings.HasSuffix(normalized, ".example") ||
		normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		normalized == "example.org" ||
		strings.HasSuffix(normalized, ".example.org") ||
		normalized == "example.net" ||
		strings.HasSuffix(normalized, ".example.net") ||
		strings.HasSuffix(normalized, ".test") ||
		strings.HasSuffix(normalized, ".invalid")
}

func forbiddenArtifactMarkers() []string {
	return []string{
		"rollback failed",
		"rollback failure",
		"rollout undo failed",
		"undo failed",
		"degradation drill failed",
		"degradation failed",
		"backup failed",
		"backup failure",
		"snapshot failed",
		"snapshot unavailable",
		"restore failed",
		"restore failure",
		"restore unavailable",
		"smoke failed",
		"rpo exceeded",
		"rto exceeded",
		"mock",
		"mocked",
		"placeholder",
		"sample artifact",
		"synthetic",
		"stubbed",
		"test-only",
		"dry-run",
		"local-only",
		"localhost",
		"127.0.0.1",
	}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
