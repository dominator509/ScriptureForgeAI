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
	OAuthArtifactURL       string
	MeetingArtifactURL     string
	WebhookArtifactURL     string
	DuplicateArtifactURL   string
	RoomMappingArtifactURL string
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
	flag.StringVar(&cfg.OAuthArtifactURL, "oauth-artifact-url", os.Getenv("STAGING_ZOOM_OAUTH_ARTIFACT_URL"), "Zoom OAuth readiness artifact URL")
	flag.StringVar(&cfg.MeetingArtifactURL, "meeting-artifact-url", os.Getenv("STAGING_ZOOM_MEETING_ARTIFACT_URL"), "Zoom meeting create or offline fallback artifact URL")
	flag.StringVar(&cfg.WebhookArtifactURL, "webhook-artifact-url", os.Getenv("STAGING_ZOOM_WEBHOOK_ARTIFACT_URL"), "Zoom webhook signature validation/delivery artifact URL")
	flag.StringVar(&cfg.DuplicateArtifactURL, "duplicate-artifact-url", os.Getenv("STAGING_ZOOM_DUPLICATE_ARTIFACT_URL"), "duplicate webhook idempotency artifact URL")
	flag.StringVar(&cfg.RoomMappingArtifactURL, "room-mapping-artifact-url", os.Getenv("STAGING_ZOOM_ROOM_MAPPING_ARTIFACT_URL"), "meeting-to-room mapping artifact URL")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.OAuthArtifactURL == "" || cfg.MeetingArtifactURL == "" || cfg.WebhookArtifactURL == "" || cfg.DuplicateArtifactURL == "" || cfg.RoomMappingArtifactURL == "" {
		return errors.New("Zoom proof requires OAuth, meeting, webhook, duplicate idempotency, and room mapping artifact URLs")
	}

	client := &http.Client{Timeout: cfg.Timeout}
	probes := []probeResult{
		probeArtifact(client, "zoom-oauth-readiness", cfg.OAuthArtifactURL, []string{"oauth", "account_credentials", "status", "ok"}, forbiddenSecretMarkers()),
		probeArtifactAny(client, "zoom-meeting-create-or-fallback", cfg.MeetingArtifactURL, [][]string{
			{"meeting", "join_url", "zoom.us"},
			{"offline://in-person", "fallback", "Zoom"},
		}, forbiddenSecretMarkers()),
		probeArtifact(client, "zoom-webhook-signature-delivery", cfg.WebhookArtifactURL, []string{"webhook", "signature", "invalid", "401", "signed", "200"}, forbiddenSecretMarkers()),
		probeArtifact(client, "zoom-duplicate-webhook-idempotency", cfg.DuplicateArtifactURL, []string{"duplicate", "idempotent", "200", "no duplicate side effects"}, nil),
		probeArtifact(client, "zoom-meeting-room-mapping", cfg.RoomMappingArtifactURL, []string{"meeting_external_id", "live_rooms", "room", "mapped"}, nil),
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: []string{"EXT-ZOOM-001"},
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
		return errors.New("one or more Zoom probes failed")
	}
	return nil
}

func probeArtifact(client *http.Client, name, target string, required []string, forbidden []string) probeResult {
	return probeArtifactAny(client, name, target, [][]string{required}, forbidden)
}

func probeArtifactAny(client *http.Client, name, target string, acceptableRequiredSets [][]string, forbidden []string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-zoomprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	text := string(body)
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && containsAnyRequiredSet(text, acceptableRequiredSets) && containsNoneFold(text, forbidden)
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary += "; artifact missing required Zoom markers or leaks forbidden secret material"
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
}

func containsAnyRequiredSet(text string, sets [][]string) bool {
	for _, set := range sets {
		if containsAllFold(text, set) {
			return true
		}
	}
	return false
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
		"client_secret",
		"webhook_secret",
		"ZOOM_CLIENT_SECRET=",
		"ZOOM_WEBHOOK_SECRET_TOKEN=",
		"Basic ",
	}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
