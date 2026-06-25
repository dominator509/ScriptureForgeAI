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
	ProviderArtifactURL    string
	GenerationArtifactURL  string
	DegradationArtifactURL string
	CitationArtifactURL    string
	AuditArtifactURL       string
	Timeout                time.Duration
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
	flag.StringVar(&cfg.ProviderArtifactURL, "provider-artifact-url", os.Getenv("STAGING_AI_PROVIDER_ARTIFACT_URL"), "AI provider/model/config readiness artifact URL")
	flag.StringVar(&cfg.GenerationArtifactURL, "generation-artifact-url", os.Getenv("STAGING_AI_GENERATION_ARTIFACT_URL"), "authenticated AI generation artifact URL")
	flag.StringVar(&cfg.DegradationArtifactURL, "degradation-artifact-url", os.Getenv("STAGING_AI_DEGRADATION_ARTIFACT_URL"), "AI timeout/degradation artifact URL")
	flag.StringVar(&cfg.CitationArtifactURL, "citation-artifact-url", os.Getenv("STAGING_AI_CITATION_ARTIFACT_URL"), "citation verification artifact URL")
	flag.StringVar(&cfg.AuditArtifactURL, "audit-artifact-url", os.Getenv("STAGING_AI_AUDIT_ARTIFACT_URL"), "ai_request_logs/citation_trails query artifact URL")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.ProviderArtifactURL == "" || cfg.GenerationArtifactURL == "" || cfg.DegradationArtifactURL == "" || cfg.CitationArtifactURL == "" || cfg.AuditArtifactURL == "" {
		return errors.New("AI proof requires provider, generation, degradation, citation, and audit artifact URLs")
	}

	client := &http.Client{Timeout: cfg.Timeout}
	probes := []probeResult{
		probeArtifact(client, "ai-provider-config", cfg.ProviderArtifactURL, []string{"AI_CHAT_MODEL", "AI_CHAT_ENDPOINT", "AI_HTTP_TIMEOUT_MS", "AI_MAX_RETRIES", "configured"}, forbiddenSecretMarkers()),
		probeArtifact(client, "ai-generation-route", cfg.GenerationArtifactURL, []string{"/api/v1/ai/generate/study", "authenticated", "tenant", "200", "generated_curriculum", "[Genesis 1:1]"}, forbiddenSecretMarkers()),
		probeArtifact(client, "ai-timeout-degradation", cfg.DegradationArtifactURL, []string{"timeout", "degradation", "retry", "503", "AI_ORCHESTRATION_ENGINE_FAULT"}, forbiddenSecretMarkers()),
		probeArtifact(client, "ai-citation-verification", cfg.CitationArtifactURL, []string{"no-citation", "rejected", "hallucinated citation", "verified citation"}, nil),
		probeArtifact(client, "ai-audit-persistence", cfg.AuditArtifactURL, []string{"ai_request_logs", "citation_trails", "organization_id", "user_id", "request_id", "succeeded", "failed", "verified"}, nil),
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: []string{"EXT-AI-001"},
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
		return errors.New("one or more AI probes failed")
	}
	return nil
}

func probeArtifact(client *http.Client, name, target string, required []string, forbidden []string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-aiprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	text := string(body)
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && containsAllFold(text, required) && containsNoneFold(text, forbidden)
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary += "; artifact missing required AI markers or leaks forbidden provider secret material"
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
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

func forbiddenSecretMarkers() []string {
	return []string{
		"OPENAI_API_KEY=",
		"Authorization: Bearer",
		"sk-",
		"api_key",
	}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
