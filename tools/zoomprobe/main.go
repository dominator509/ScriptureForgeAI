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

var (
	deliveryIDPattern         = regexp.MustCompile(`(?i)\bdelivery_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	meetingExternalIDPattern  = regexp.MustCompile(`(?i)\bmeeting_external_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	internalRoomIDPattern     = regexp.MustCompile(`(?i)\binternal_room_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	webhookSignaturePattern   = regexp.MustCompile(`(?i)\bx-zm-signature=(v0[:=][0-9a-f]{64})\b`)
	webhookTimestampPattern   = regexp.MustCompile(`(?i)\bx-zm-request-timestamp=([0-9]{10,})\b`)
	plainTokenPattern         = regexp.MustCompile(`(?i)\bplain_token=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	encryptedTokenPattern     = regexp.MustCompile(`(?i)\bencrypted_token=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`)
	validationResponsePattern = regexp.MustCompile(`(?i)\bvalidation_response=(200)\b`)
)

type config struct {
	OAuthArtifactURL       string
	MeetingArtifactURL     string
	ResilienceArtifactURL  string
	WebhookArtifactURL     string
	WebhookValidationURL   string
	DuplicateArtifactURL   string
	RoomMappingArtifactURL string
	ReleaseCandidate       string
	ServiceVersion         string
	Timeout                time.Duration
}

type artifactTarget struct {
	Label string
	URL   string
}

type report struct {
	ObservedAt       string        `json:"observed_at"`
	ThresholdPass    bool          `json:"threshold_pass"`
	ReleaseCandidate string        `json:"release_candidate"`
	ServiceVersion   string        `json:"service_version"`
	Probes           []probeResult `json:"probes"`
	EvidenceItems    []string      `json:"evidence_items"`
}

type probeResult struct {
	Name               string `json:"name"`
	Target             string `json:"target"`
	Passed             bool   `json:"passed"`
	StatusCode         int    `json:"status_code,omitempty"`
	LatencyMS          int64  `json:"latency_ms,omitempty"`
	DeliveryID         string `json:"delivery_id,omitempty"`
	MeetingID          string `json:"meeting_external_id,omitempty"`
	RoomID             string `json:"internal_room_id,omitempty"`
	WebhookSig         string `json:"webhook_signature,omitempty"`
	WebhookTS          string `json:"webhook_timestamp,omitempty"`
	PlainToken         string `json:"plain_token,omitempty"`
	EncryptedToken     string `json:"encrypted_token,omitempty"`
	ValidationResponse string `json:"validation_response,omitempty"`
	ResultSummary      string `json:"result_summary"`
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
	flag.StringVar(&cfg.ResilienceArtifactURL, "resilience-artifact-url", os.Getenv("STAGING_ZOOM_RESILIENCE_ARTIFACT_URL"), "Zoom timeout/circuit-open fallback artifact URL")
	flag.StringVar(&cfg.WebhookArtifactURL, "webhook-artifact-url", os.Getenv("STAGING_ZOOM_WEBHOOK_ARTIFACT_URL"), "Zoom webhook signature validation/delivery artifact URL")
	flag.StringVar(&cfg.WebhookValidationURL, "webhook-validation-artifact-url", os.Getenv("STAGING_ZOOM_WEBHOOK_VALIDATION_ARTIFACT_URL"), "Zoom endpoint.url_validation challenge response artifact URL")
	flag.StringVar(&cfg.DuplicateArtifactURL, "duplicate-artifact-url", os.Getenv("STAGING_ZOOM_DUPLICATE_ARTIFACT_URL"), "duplicate webhook idempotency artifact URL")
	flag.StringVar(&cfg.RoomMappingArtifactURL, "room-mapping-artifact-url", os.Getenv("STAGING_ZOOM_ROOM_MAPPING_ARTIFACT_URL"), "meeting-to-room mapping artifact URL")
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("RELEASE_CANDIDATE"), "release candidate Git SHA or tag expected in Zoom evidence artifacts")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("SERVICE_VERSION"), "service version expected in Zoom evidence artifacts")
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
	if cfg.OAuthArtifactURL == "" || cfg.MeetingArtifactURL == "" || cfg.ResilienceArtifactURL == "" || cfg.WebhookArtifactURL == "" || cfg.WebhookValidationURL == "" || cfg.DuplicateArtifactURL == "" || cfg.RoomMappingArtifactURL == "" {
		return errors.New("Zoom proof requires OAuth, meeting, timeout/circuit fallback, webhook, url validation, duplicate idempotency, and room mapping artifact URLs")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" {
		return errors.New("Zoom proof requires -release-candidate and -service-version")
	}
	var err error
	cfg.OAuthArtifactURL, err = normalizeArtifactURL(cfg.OAuthArtifactURL, "oauth-artifact-url")
	if err != nil {
		return err
	}
	cfg.MeetingArtifactURL, err = normalizeArtifactURL(cfg.MeetingArtifactURL, "meeting-artifact-url")
	if err != nil {
		return err
	}
	cfg.ResilienceArtifactURL, err = normalizeArtifactURL(cfg.ResilienceArtifactURL, "resilience-artifact-url")
	if err != nil {
		return err
	}
	cfg.WebhookArtifactURL, err = normalizeArtifactURL(cfg.WebhookArtifactURL, "webhook-artifact-url")
	if err != nil {
		return err
	}
	cfg.WebhookValidationURL, err = normalizeArtifactURL(cfg.WebhookValidationURL, "webhook-validation-artifact-url")
	if err != nil {
		return err
	}
	cfg.DuplicateArtifactURL, err = normalizeArtifactURL(cfg.DuplicateArtifactURL, "duplicate-artifact-url")
	if err != nil {
		return err
	}
	cfg.RoomMappingArtifactURL, err = normalizeArtifactURL(cfg.RoomMappingArtifactURL, "room-mapping-artifact-url")
	if err != nil {
		return err
	}
	if err := requireDistinctArtifactURLs([]artifactTarget{
		{Label: "oauth-artifact-url", URL: cfg.OAuthArtifactURL},
		{Label: "meeting-artifact-url", URL: cfg.MeetingArtifactURL},
		{Label: "resilience-artifact-url", URL: cfg.ResilienceArtifactURL},
		{Label: "webhook-artifact-url", URL: cfg.WebhookArtifactURL},
		{Label: "webhook-validation-artifact-url", URL: cfg.WebhookValidationURL},
		{Label: "duplicate-artifact-url", URL: cfg.DuplicateArtifactURL},
		{Label: "room-mapping-artifact-url", URL: cfg.RoomMappingArtifactURL},
	}); err != nil {
		return err
	}

	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	forbiddenWithSecrets := forbiddenArtifactMarkers(true)
	forbiddenEvidenceOnly := forbiddenArtifactMarkers(false)
	releaseMarkers := []string{
		fmt.Sprintf("release_candidate=%s", cfg.ReleaseCandidate),
		fmt.Sprintf("service_version=%s", cfg.ServiceVersion),
	}
	probes := []probeResult{
		probeArtifact(client, "zoom-oauth-readiness", cfg.OAuthArtifactURL, append([]string{"oauth", "account_credentials", "status", "ok"}, releaseMarkers...), forbiddenWithSecrets),
		probeArtifactAny(client, "zoom-meeting-create-or-fallback", cfg.MeetingArtifactURL, [][]string{
			append([]string{"meeting", "join_url", "zoom.us"}, releaseMarkers...),
			append([]string{"offline://in-person", "fallback", "Zoom"}, releaseMarkers...),
		}, forbiddenWithSecrets),
		probeArtifact(client, "zoom-timeout-circuit-fallback", cfg.ResilienceArtifactURL, append([]string{"timeout", "provider timeout", "circuit", "open", "circuit_open_fallback", "fallback", "offline://in-person"}, releaseMarkers...), forbiddenWithSecrets),
		probeArtifact(client, "zoom-webhook-signature-delivery", cfg.WebhookArtifactURL, append([]string{"webhook", "signature", "x-zm-signature=", "x-zm-request-timestamp=", "stale", "replay", "401", "invalid", "signed", "200"}, releaseMarkers...), forbiddenWithSecrets),
		probeArtifact(client, "zoom-webhook-url-validation", cfg.WebhookValidationURL, append([]string{"endpoint.url_validation", "plain_token=", "encrypted_token=", "validation_response=200"}, releaseMarkers...), forbiddenWithSecrets),
		probeArtifact(client, "zoom-duplicate-webhook-idempotency", cfg.DuplicateArtifactURL, append([]string{"duplicate", "x-zm-trackingid", "delivery_id=", "delivery id", "same Zoom event", "idempotent", "200", "single state mutation", "no duplicate side effects"}, releaseMarkers...), forbiddenEvidenceOnly),
		probeArtifact(client, "zoom-meeting-room-mapping", cfg.RoomMappingArtifactURL, append([]string{"meeting_external_id=", "live_rooms", "internal_room_id=", "redis room state", "mapped", "unknown meeting ignored", "no external meeting id fallback", "distinct_zoom_artifacts=true"}, releaseMarkers...), forbiddenEvidenceOnly),
	}

	result := report{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass:    true,
		ReleaseCandidate: cfg.ReleaseCandidate,
		ServiceVersion:   cfg.ServiceVersion,
		Probes:           probes,
		EvidenceItems:    []string{"EXT-ZOOM-001"},
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

func requireDistinctArtifactURLs(targets []artifactTarget) error {
	seen := map[string]string{}
	for _, target := range targets {
		normalized, err := canonicalArtifactURL(target.URL)
		if err != nil {
			return fmt.Errorf("%s artifact URL: %w", target.Label, err)
		}
		if normalized == "" {
			continue
		}
		if previous, ok := seen[normalized]; ok {
			return fmt.Errorf("%s must be a distinct artifact URL; duplicates %s", target.Label, previous)
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
	matchedRequiredSet := matchingRequiredSet(text, acceptableRequiredSets)
	deliveryID := ""
	if name == "zoom-duplicate-webhook-idempotency" {
		deliveryID = extractDeliveryID(text)
	}
	webhookSignature := ""
	webhookTimestamp := ""
	if name == "zoom-webhook-signature-delivery" {
		webhookSignature = extractWebhookSignature(text)
		webhookTimestamp = extractWebhookTimestamp(text)
	}
	plainToken := ""
	encryptedToken := ""
	validationResponse := ""
	if name == "zoom-webhook-url-validation" {
		plainToken = extractPlainToken(text)
		encryptedToken = extractEncryptedToken(text)
		validationResponse = extractValidationResponse(text)
	}
	meetingID := ""
	roomID := ""
	if name == "zoom-meeting-room-mapping" {
		meetingID = extractMeetingExternalID(text)
		roomID = extractInternalRoomID(text)
	}
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && matchedRequiredSet != nil && containsNoneFold(text, forbidden)
	if name == "zoom-duplicate-webhook-idempotency" && deliveryID == "" {
		passed = false
	}
	if name == "zoom-webhook-signature-delivery" && (webhookSignature == "" || webhookTimestamp == "") {
		passed = false
	}
	if name == "zoom-webhook-url-validation" && (plainToken == "" || encryptedToken == "" || validationResponse != "200") {
		passed = false
	}
	if name == "zoom-meeting-room-mapping" && (meetingID == "" || roomID == "") {
		passed = false
	}
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary += "; artifact missing required Zoom markers, leaks forbidden secret material, or is marked mock/placeholder"
	} else {
		summary += "; staging artifact; verified markers: " + strings.Join(matchedRequiredSet, ", ")
		if deliveryID != "" {
			summary += fmt.Sprintf("; delivery_id=%s", deliveryID)
		}
		if webhookSignature != "" || webhookTimestamp != "" {
			summary += fmt.Sprintf("; x-zm-signature=%s; x-zm-request-timestamp=%s", webhookSignature, webhookTimestamp)
		}
		if plainToken != "" || encryptedToken != "" || validationResponse != "" {
			summary += fmt.Sprintf("; plain_token=%s; encrypted_token=%s; validation_response=%s", plainToken, encryptedToken, validationResponse)
		}
		if meetingID != "" || roomID != "" {
			summary += fmt.Sprintf("; meeting_external_id=%s; internal_room_id=%s", meetingID, roomID)
		}
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, DeliveryID: deliveryID, MeetingID: meetingID, RoomID: roomID, WebhookSig: webhookSignature, WebhookTS: webhookTimestamp, PlainToken: plainToken, EncryptedToken: encryptedToken, ValidationResponse: validationResponse, ResultSummary: summary}
}

func extractDeliveryID(text string) string {
	match := deliveryIDPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractMeetingExternalID(text string) string {
	match := meetingExternalIDPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractInternalRoomID(text string) string {
	match := internalRoomIDPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractWebhookSignature(text string) string {
	match := webhookSignaturePattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractWebhookTimestamp(text string) string {
	match := webhookTimestampPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractPlainToken(text string) string {
	match := plainTokenPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractEncryptedToken(text string) string {
	match := encryptedTokenPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractValidationResponse(text string) string {
	match := validationResponsePattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func containsAnyRequiredSet(text string, sets [][]string) bool {
	return matchingRequiredSet(text, sets) != nil
}

func matchingRequiredSet(text string, sets [][]string) []string {
	for _, set := range sets {
		if containsAllFold(text, set) {
			return set
		}
	}
	return nil
}

func normalizeArtifactURL(raw, field string) (string, error) {
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
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not use a reserved placeholder artifact host", field)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must use a non-local, non-private staging artifact host", field)
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

func forbiddenArtifactMarkers(includeSecrets bool) []string {
	markers := []string{
		"mock",
		"mocked",
		"placeholder",
		"sample artifact",
		"synthetic",
		"fake provider",
		"stubbed",
		"test-only",
		"dry-run",
		"local-only",
		"localhost",
		"127.0.0.1",
		"private-network",
		"private network",
		"private ipv6",
		"ipv4-mapped",
		"link-local",
		"link local",
		"unspecified",
		"signature verification disabled",
		"webhook signature disabled",
		"signature verification bypassed",
		"skip signature verification",
	}
	if includeSecrets {
		markers = append(markers,
			"client_secret",
			"webhook_secret",
			"ZOOM_CLIENT_SECRET=",
			"ZOOM_WEBHOOK_SECRET_TOKEN=",
			"Basic ",
		)
	}
	return markers
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
