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
	EASArtifactURL        string
	NativeCryptoSmokeURL  string
	StagingConfigProofURL string
	Timeout               time.Duration
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
	flag.StringVar(&cfg.EASArtifactURL, "eas-artifact-url", os.Getenv("STAGING_MOBILE_EAS_ARTIFACT_URL"), "EAS or native-device run artifact URL")
	flag.StringVar(&cfg.NativeCryptoSmokeURL, "native-crypto-smoke-url", os.Getenv("STAGING_MOBILE_NATIVE_CRYPTO_SMOKE_URL"), "native AES-GCM smoke output artifact URL")
	flag.StringVar(&cfg.StagingConfigProofURL, "staging-config-proof-url", os.Getenv("STAGING_MOBILE_CONFIG_PROOF_URL"), "mobile staging API/WS config proof artifact URL")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.EASArtifactURL == "" || cfg.NativeCryptoSmokeURL == "" || cfg.StagingConfigProofURL == "" {
		return errors.New("mobile proof requires EAS/native run, native crypto smoke, and staging config artifact URLs")
	}

	client := &http.Client{Timeout: cfg.Timeout}
	probes := []probeResult{
		probeArtifact(client, "mobile-eas-or-device-run", cfg.EASArtifactURL, []string{"eas", "build", "finished", "android", "ios"}, nil),
		probeArtifact(client, "mobile-native-crypto-smoke", cfg.NativeCryptoSmokeURL, []string{"react-native-quick-crypto", "AES-GCM", "round-trip", "tamper rejected", "non-extractable", "key disposed", "disposed handle rejected"}, []string{"node:webcrypto", "node crypto shim", "expo-crypto", "placeholder", "mock"}),
		probeArtifact(client, "mobile-staging-config", cfg.StagingConfigProofURL, []string{"EXPO_PUBLIC_API_BASE_URL", "EXPO_PUBLIC_WS_BASE_URL", "https://", "wss://", "staging"}, []string{"localhost", "127.0.0.1", "wss://api.scriptureforge.com"}),
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: []string{"CLIENT-MOBILE-001"},
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
		return errors.New("one or more mobile probes failed")
	}
	return nil
}

func probeArtifact(client *http.Client, name, target string, required []string, forbidden []string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-mobileprobe/1.0")
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
		summary += "; artifact missing required markers or contains forbidden local/shim markers"
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

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
