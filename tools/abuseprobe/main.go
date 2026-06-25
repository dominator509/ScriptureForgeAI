package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	APIBase           string
	BearerToken       string
	Origin            string
	ConfigArtifactURL string
	Attempts          int
	Timeout           time.Duration
}

type report struct {
	ObservedAt     string        `json:"observed_at"`
	APITarget      string        `json:"api_target"`
	ConfigArtifact string        `json:"config_artifact_url"`
	ThresholdPass  bool          `json:"threshold_pass"`
	Probes         []probeResult `json:"probes"`
	EvidenceItems  []string      `json:"evidence_items"`
}

type probeResult struct {
	Name          string `json:"name"`
	Target        string `json:"target"`
	Passed        bool   `json:"passed"`
	Attempts      int    `json:"attempts"`
	StatusCode    int    `json:"status_code,omitempty"`
	RetryAfter    string `json:"retry_after,omitempty"`
	RateLimit     string `json:"rate_limit,omitempty"`
	RateRemaining string `json:"rate_limit_remaining,omitempty"`
	RateReset     string `json:"rate_limit_reset,omitempty"`
	ResultSummary string `json:"result_summary"`
}

type endpointProbe struct {
	Name   string
	Method string
	Path   string
	Body   []byte
	Auth   bool
	Origin bool
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
	flag.StringVar(&cfg.APIBase, "api-base", "", "deployed API base URL, for example https://api.staging.example")
	flag.StringVar(&cfg.BearerToken, "bearer-token", os.Getenv("STAGING_ABUSE_BEARER_TOKEN"), "staging bearer token for protected abuse probes")
	flag.StringVar(&cfg.Origin, "origin", os.Getenv("STAGING_ABUSE_ORIGIN"), "allowed staging web origin for room stream probe")
	flag.StringVar(&cfg.ConfigArtifactURL, "config-artifact-url", os.Getenv("STAGING_ABUSE_CONFIG_ARTIFACT_URL"), "redacted staging ABUSE_LIMIT_* configuration artifact URL")
	flag.IntVar(&cfg.Attempts, "attempts", 35, "maximum attempts per profile; set above deployed ABUSE_LIMIT_* values")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-request timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	return runWithClient(cfg, output, &http.Client{Timeout: cfg.Timeout})
}

func runWithClient(cfg config, output io.Writer, client *http.Client) error {
	if cfg.APIBase == "" {
		return errors.New("-api-base is required")
	}
	if cfg.BearerToken == "" {
		return errors.New("-bearer-token or STAGING_ABUSE_BEARER_TOKEN is required")
	}
	configArtifact, err := normalizeArtifactURL(cfg.ConfigArtifactURL)
	if err != nil {
		return err
	}
	if cfg.Attempts < 2 {
		return errors.New("-attempts must be at least 2")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	apiBase, err := normalizeBaseURL(cfg.APIBase)
	if err != nil {
		return err
	}

	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	probes := []endpointProbe{
		{Name: "auth-rate-limit", Method: http.MethodPost, Path: "/api/v1/auth/login", Body: []byte(`{"email":"abuse-probe@example.invalid","password":"invalid"}`)},
		{Name: "ai-rate-limit", Method: http.MethodPost, Path: "/api/v1/ai/generate/study", Body: []byte(`{"topic":"abuse readiness probe"}`), Auth: true},
		{Name: "journal-rate-limit", Method: http.MethodPost, Path: "/api/v1/journal_entries", Body: []byte(`{"ciphertext":"probe","iv":"probe","salt_id":"probe","salt_version":1}`), Auth: true},
		{Name: "rooms-rate-limit", Method: http.MethodGet, Path: "/api/v1/rooms/active", Auth: true},
		{Name: "websocket-rate-limit", Method: http.MethodGet, Path: "/api/v1/rooms/stream/abuse-probe-room", Auth: true, Origin: true},
	}

	results := make([]probeResult, 0, len(probes))
	for _, probe := range probes {
		results = append(results, runEndpointProbe(client, apiBase, cfg, probe))
	}

	result := report{
		ObservedAt:     time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		APITarget:      apiBase,
		ConfigArtifact: configArtifact,
		ThresholdPass:  true,
		Probes:         results,
		EvidenceItems:  []string{"ABUSE-LIMIT-001"},
	}
	for _, probe := range results {
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
		return errors.New("one or more abuse probes failed")
	}
	return nil
}

func runEndpointProbe(client *http.Client, apiBase string, cfg config, probe endpointProbe) probeResult {
	target := strings.TrimRight(apiBase, "/") + probe.Path
	result := probeResult{Name: probe.Name, Target: target, Attempts: cfg.Attempts}
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		status, retryAfter, rateLimit, rateRemaining, rateReset, err := sendProbeRequest(client, target, cfg, probe)
		if err != nil {
			result.StatusCode = 0
			result.ResultSummary = err.Error()
			return result
		}
		result.StatusCode = status
		result.RetryAfter = retryAfter
		result.RateLimit = rateLimit
		result.RateRemaining = rateRemaining
		result.RateReset = rateReset
		if status == http.StatusTooManyRequests {
			result.Attempts = attempt
			result.Passed = retryAfter != "" && rateLimit != "" && rateRemaining != "" && rateReset != ""
			result.ResultSummary = fmt.Sprintf("got 429 with Retry-After=%q X-RateLimit-Limit=%q X-RateLimit-Remaining=%q X-RateLimit-Reset=%q after %d attempts", retryAfter, rateLimit, rateRemaining, rateReset, attempt)
			if !result.Passed {
				result.ResultSummary = "got 429 without required rate-limit headers"
			}
			return result
		}
	}
	result.ResultSummary = fmt.Sprintf("no 429 observed after %d attempts; lower staging ABUSE_LIMIT_* values or raise -attempts", cfg.Attempts)
	return result
}

func sendProbeRequest(client *http.Client, target string, cfg config, probe endpointProbe) (int, string, string, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, probe.Method, target, bytes.NewReader(probe.Body))
	if err != nil {
		return 0, "", "", "", "", err
	}
	req.Header.Set("User-Agent", "scriptureforge-abuseprobe/1.0")
	if len(probe.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if probe.Auth {
		req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	}
	if probe.Origin && cfg.Origin != "" {
		req.Header.Set("Origin", cfg.Origin)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", "", "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode,
		resp.Header.Get("Retry-After"),
		resp.Header.Get("X-RateLimit-Limit"),
		resp.Header.Get("X-RateLimit-Remaining"),
		resp.Header.Get("X-RateLimit-Reset"),
		nil
}

func normalizeBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", errors.New("api-base must use https")
	}
	if parsed.Host == "" {
		return "", errors.New("api-base must include a host")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeArtifactURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", errors.New("-config-artifact-url or STAGING_ABUSE_CONFIG_ARTIFACT_URL must use https")
	}
	if parsed.Host == "" {
		return "", errors.New("-config-artifact-url or STAGING_ABUSE_CONFIG_ARTIFACT_URL must include a host")
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}
