package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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

	"scriptureforge/tools/probehttp"
)

type config struct {
	APIBase            string
	WebBase            string
	DNSArtifactURL     string
	ACMArtifactURL     string
	SSLLabsArtifactURL string
	WebAuthSmokeURL    string
	WebJournalSmokeURL string
	WebRoomSmokeURL    string
	ReleaseCandidate   string
	ServiceVersion     string
	LoadRunID          string
	Timeout            time.Duration
	ProbeZoom          bool
	ZoomWebhookSecret  string
	ProbeAI            bool
	AIBearerToken      string
	AITopic            string
}

type report struct {
	ObservedAt        string        `json:"observed_at"`
	APITarget         string        `json:"api_target,omitempty"`
	WebTarget         string        `json:"web_target,omitempty"`
	DNSArtifact       string        `json:"dns_artifact_url"`
	ACMArtifact       string        `json:"acm_artifact_url"`
	SSLLabsArtifact   string        `json:"ssl_labs_artifact_url"`
	WebAuthSmoke      string        `json:"web_auth_smoke_url,omitempty"`
	WebJournalSmoke   string        `json:"web_journal_smoke_url,omitempty"`
	WebRoomSmoke      string        `json:"web_room_smoke_url,omitempty"`
	WebUserID         string        `json:"web_user_id,omitempty"`
	WebOrganizationID string        `json:"web_organization_id,omitempty"`
	WebJournalID      string        `json:"web_journal_id,omitempty"`
	WebRoomID         string        `json:"web_room_id,omitempty"`
	ReleaseCandidate  string        `json:"release_candidate,omitempty"`
	ServiceVersion    string        `json:"service_version,omitempty"`
	LoadRunID         string        `json:"load_run_id,omitempty"`
	ThresholdPass     bool          `json:"threshold_pass"`
	Probes            []probeResult `json:"probes"`
	EvidenceItems     []string      `json:"evidence_items"`
}

type probeResult struct {
	Name           string `json:"name"`
	Target         string `json:"target"`
	Passed         bool   `json:"passed"`
	StatusCode     int    `json:"status_code,omitempty"`
	LatencyMS      int64  `json:"latency_ms,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
	CertNotAfter   string `json:"cert_not_after,omitempty"`
	CertHostname   string `json:"cert_hostname,omitempty"`
	CertIssuer     string `json:"cert_issuer,omitempty"`
	RedirectTo     string `json:"redirect_to,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	JournalID      string `json:"journal_id,omitempty"`
	RoomID         string `json:"room_id,omitempty"`
	ResultSummary  string `json:"result_summary"`
}

var webSmokeIDPatterns = map[string]*regexp.Regexp{
	"user_id":         regexp.MustCompile(`(?i)\buser_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`),
	"organization_id": regexp.MustCompile(`(?i)\borganization_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`),
	"journal_id":      regexp.MustCompile(`(?i)\bjournal_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`),
	"room_id":         regexp.MustCompile(`(?i)\broom_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b`),
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
	flag.StringVar(&cfg.WebBase, "web-base", "", "deployed web base URL, for example https://app.staging.example")
	flag.StringVar(&cfg.DNSArtifactURL, "dns-artifact-url", os.Getenv("STAGING_DNS_ARTIFACT_URL"), "HTTPS artifact proving deployed DNS records for API/web hostnames")
	flag.StringVar(&cfg.ACMArtifactURL, "acm-artifact-url", os.Getenv("STAGING_ACM_ARTIFACT_URL"), "HTTPS artifact proving ACM certificate status and TLS policy")
	flag.StringVar(&cfg.SSLLabsArtifactURL, "ssl-labs-artifact-url", os.Getenv("STAGING_SSL_LABS_ARTIFACT_URL"), "HTTPS artifact proving SSL Labs A+ grade for deployed API/web hostnames")
	flag.StringVar(&cfg.WebAuthSmokeURL, "web-auth-smoke-url", os.Getenv("STAGING_WEB_AUTH_SMOKE_URL"), "HTTPS browser smoke artifact proving web login/register against staging")
	flag.StringVar(&cfg.WebJournalSmokeURL, "web-journal-smoke-url", os.Getenv("STAGING_WEB_JOURNAL_SMOKE_URL"), "HTTPS browser smoke artifact proving web journal save/load against staging")
	flag.StringVar(&cfg.WebRoomSmokeURL, "web-room-smoke-url", os.Getenv("STAGING_WEB_ROOM_SMOKE_URL"), "HTTPS browser smoke artifact proving web room create/select/WebSocket against staging")
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("RELEASE_CANDIDATE"), "exact release candidate Git SHA expected in deployed web smoke artifacts")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("SERVICE_VERSION"), "deployed service version marker expected in deployed web smoke artifacts")
	flag.StringVar(&cfg.LoadRunID, "load-run-id", os.Getenv("STAGING_LOAD_RUN_ID"), "exact staging load run ID this TLS/web evidence is bound to")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.BoolVar(&cfg.ProbeZoom, "probe-zoom", false, "probe Zoom webhook invalid-signature denial; add -zoom-webhook-secret to also send signed no-op and endpoint.url_validation webhook probes")
	flag.StringVar(&cfg.ZoomWebhookSecret, "zoom-webhook-secret", os.Getenv("ZOOM_WEBHOOK_SECRET_TOKEN"), "Zoom webhook secret token for optional signed no-op webhook probe")
	flag.BoolVar(&cfg.ProbeAI, "probe-ai", false, "probe authenticated AI study generation against staging; may call the configured provider")
	flag.StringVar(&cfg.AIBearerToken, "ai-bearer-token", os.Getenv("STAGING_AI_BEARER_TOKEN"), "bearer token for -probe-ai")
	flag.StringVar(&cfg.AITopic, "ai-topic", "Genesis 1:1 staging readiness probe", "topic for -probe-ai")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.APIBase == "" && cfg.WebBase == "" {
		return errors.New("at least one of -api-base or -web-base is required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	dnsArtifact, err := normalizeArtifactURL(cfg.DNSArtifactURL, "dns-artifact-url")
	if err != nil {
		return err
	}
	acmArtifact, err := normalizeArtifactURL(cfg.ACMArtifactURL, "acm-artifact-url")
	if err != nil {
		return err
	}
	sslLabsArtifact, err := normalizeArtifactURL(cfg.SSLLabsArtifactURL, "ssl-labs-artifact-url")
	if err != nil {
		return err
	}
	if err := validateDistinctArtifactURLs("TLS artifacts", map[string]string{
		"dns-artifact-url":      dnsArtifact,
		"acm-artifact-url":      acmArtifact,
		"ssl-labs-artifact-url": sslLabsArtifact,
	}); err != nil {
		return err
	}
	webAuthSmoke := ""
	webJournalSmoke := ""
	webRoomSmoke := ""
	if cfg.WebBase != "" {
		webAuthSmoke, err = normalizeArtifactURL(cfg.WebAuthSmokeURL, "web-auth-smoke-url")
		if err != nil {
			return err
		}
		webJournalSmoke, err = normalizeArtifactURL(cfg.WebJournalSmokeURL, "web-journal-smoke-url")
		if err != nil {
			return err
		}
		webRoomSmoke, err = normalizeArtifactURL(cfg.WebRoomSmokeURL, "web-room-smoke-url")
		if err != nil {
			return err
		}
		if err := validateDistinctArtifactURLs("web browser smoke artifacts", map[string]string{
			"web-auth-smoke-url":    webAuthSmoke,
			"web-journal-smoke-url": webJournalSmoke,
			"web-room-smoke-url":    webRoomSmoke,
		}); err != nil {
			return err
		}
	}
	if (cfg.ProbeZoom || cfg.ProbeAI) && cfg.APIBase == "" {
		return errors.New("-api-base is required for -probe-zoom or -probe-ai")
	}
	if cfg.ProbeAI && cfg.AIBearerToken == "" {
		return errors.New("-ai-bearer-token or STAGING_AI_BEARER_TOKEN is required for -probe-ai")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	cfg.LoadRunID = strings.TrimSpace(cfg.LoadRunID)
	if cfg.ReleaseCandidate == "" {
		return errors.New("-release-candidate or RELEASE_CANDIDATE is required for TLS/web evidence")
	}
	if cfg.ServiceVersion == "" {
		return errors.New("-service-version or SERVICE_VERSION is required for TLS/web evidence")
	}
	if cfg.LoadRunID == "" {
		return errors.New("-load-run-id or STAGING_LOAD_RUN_ID is required for TLS/web evidence")
	}
	releaseMarkers := releaseMarkers(cfg.ReleaseCandidate, cfg.ServiceVersion, cfg.LoadRunID)

	client := probehttp.NewClient(cfg.Timeout)
	results := make([]probeResult, 0, 6)
	evidenceItems := []string{"DEPLOY-TLS-001"}
	sslLabsMarkers := append([]string{"staging artifact", "SSL Labs", "grade=A+", "ssl_labs_grade=A+"}, releaseMarkers...)
	if cfg.APIBase != "" {
		apiBase, err := normalizeBaseURL(cfg.APIBase)
		if err != nil {
			return fmt.Errorf("api-base: %w", err)
		}
		sslLabsMarkers = append(sslLabsMarkers, "api_hostname="+mustHostname(apiBase))
		results = append(results, probeHTTP(client, "api-live", joinURL(apiBase, "/live"), http.StatusOK, releaseMarkers))
		results = append(results, probeHTTP(client, "api-ready", joinURL(apiBase, "/ready"), http.StatusOK, releaseMarkers))
		results = append(results, probeTLS("api-tls", apiBase, cfg.Timeout, releaseMarkers))
		results = append(results, probeHTTPSRedirect(client, "api-http-redirect", apiBase, releaseMarkers))
		if cfg.ProbeZoom {
			results = append(results, probeZoomInvalidSignature(client, joinURL(apiBase, "/api/webhooks/zoom")))
			if cfg.ZoomWebhookSecret != "" {
				results = append(results, probeZoomSignedNoop(client, joinURL(apiBase, "/api/webhooks/zoom"), cfg.ZoomWebhookSecret))
				results = append(results, probeZoomURLValidation(client, joinURL(apiBase, "/api/webhooks/zoom"), cfg.ZoomWebhookSecret))
			}
		}
		if cfg.ProbeAI {
			results = append(results, probeAIStudyGeneration(client, joinURL(apiBase, "/api/v1/ai/generate/study"), cfg.AIBearerToken, cfg.AITopic))
		}
		cfg.APIBase = apiBase
	}
	if cfg.WebBase != "" {
		webBase, err := normalizeBaseURL(cfg.WebBase)
		if err != nil {
			return fmt.Errorf("web-base: %w", err)
		}
		sslLabsMarkers = append(sslLabsMarkers, "web_hostname="+mustHostname(webBase))
		results = append(results, probeHTTP(client, "web-root", webBase, http.StatusOK, releaseMarkers))
		results = append(results, probeTLS("web-tls", webBase, cfg.Timeout, releaseMarkers))
		results = append(results, probeHTTPSRedirect(client, "web-http-redirect", webBase, releaseMarkers))
		results = append(results, probeArtifactContains(client, "web-auth-browser-smoke", webAuthSmoke, append([]string{"staging artifact", "login", "register", "authenticated", "https://", "user_id=", "organization_id=", "distinct_web_artifacts=true"}, releaseMarkers...)))
		results = append(results, probeArtifactContains(client, "web-journal-browser-smoke", webJournalSmoke, append([]string{"staging artifact", "journal", "encrypted", "save", "load", "plaintext absent", "associated data", "wrong associated data rejected", "user_id=", "organization_id=", "journal_id=", "distinct_web_artifacts=true"}, releaseMarkers...)))
		results = append(results, probeArtifactContains(client, "web-room-browser-smoke", webRoomSmoke, append([]string{"staging artifact", "room", "create", "select", "WebSocket", "connected", "user_id=", "organization_id=", "room_id=", "distinct_web_artifacts=true"}, releaseMarkers...)))
		enforceWebSmokeIdentityLinkage(results)
		evidenceItems = appendEvidenceItem(evidenceItems, "CLIENT-WEB-001")
		cfg.WebBase = webBase
	}
	results = append(results, probeArtifactContains(client, "ssl-labs-a-plus", sslLabsArtifact, sslLabsMarkers))
	webUserID, webOrganizationID, webJournalID, webRoomID := linkedWebSmokeIDs(results)

	result := report{
		ObservedAt:        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		APITarget:         cfg.APIBase,
		WebTarget:         cfg.WebBase,
		DNSArtifact:       dnsArtifact,
		ACMArtifact:       acmArtifact,
		SSLLabsArtifact:   sslLabsArtifact,
		WebAuthSmoke:      webAuthSmoke,
		WebJournalSmoke:   webJournalSmoke,
		WebRoomSmoke:      webRoomSmoke,
		WebUserID:         webUserID,
		WebOrganizationID: webOrganizationID,
		WebJournalID:      webJournalID,
		WebRoomID:         webRoomID,
		ReleaseCandidate:  cfg.ReleaseCandidate,
		ServiceVersion:    cfg.ServiceVersion,
		LoadRunID:         cfg.LoadRunID,
		ThresholdPass:     true,
		Probes:            results,
		EvidenceItems:     evidenceItems,
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
		return errors.New("one or more staging probes failed")
	}
	return nil
}

func releaseMarkers(releaseCandidate, serviceVersion, loadRunID string) []string {
	return []string{"release_candidate=" + releaseCandidate, "service_version=" + serviceVersion, "load_run_id=" + loadRunID}
}

func normalizeBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", errors.New("base URL must use https")
	}
	if parsed.Host == "" {
		return "", errors.New("base URL must include a host")
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", errors.New("base URL must use a non-local, non-private staging host")
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", errors.New("base URL must not use a reserved placeholder staging host")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeArtifactURL(raw, flagName string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("-%s or matching STAGING_* env var must use https", flagName)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("-%s or matching STAGING_* env var must include a host", flagName)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s or matching STAGING_* env var must use a non-local, non-private staging artifact host", flagName)
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s or matching STAGING_* env var must not use a reserved placeholder staging artifact host", flagName)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func validateDistinctArtifactURLs(scope string, urls map[string]string) error {
	seen := make(map[string]string, len(urls))
	for field, artifactURL := range urls {
		normalized, err := canonicalArtifactURL(artifactURL)
		if err != nil {
			return fmt.Errorf("-%s artifact URL: %w", field, err)
		}
		if previous, ok := seen[normalized]; ok {
			return fmt.Errorf("%s must be distinct: -%s duplicates -%s", scope, field, previous)
		}
		seen[normalized] = field
	}
	return nil
}

func canonicalArtifactURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("artifact URL is empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	if scheme == "" || host == "" {
		return "", errors.New("artifact URL must include scheme and host")
	}
	parsed.Scheme = scheme
	port := parsed.Port()
	switch {
	case port == "443" && scheme == "https":
		parsed.Host = host
	case port != "":
		parsed.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		parsed.Host = "[" + host + "]"
	default:
		parsed.Host = host
	}
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

func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + path
}

func mustHostname(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func appendEvidenceItem(items []string, item string) []string {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func probeHTTP(client *http.Client, name, target string, expectedStatus int, releaseMarkers []string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-stagingprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	passed := resp.StatusCode == expectedStatus
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if markers := verifiedHTTPMarkers(name); passed && len(markers) > 0 {
		summary = appendVerifiedMarkers(summary, append(markers, releaseMarkers...))
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
}

func probeArtifactContains(client *http.Client, name, target string, requiredAll []string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-stagingprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	text := string(body)
	passed := resp.StatusCode == http.StatusOK && containsAllFold(text, requiredAll) && containsNoneFold(text, forbiddenArtifactMarkers())
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	result := probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency}
	if isWebSmokeProbe(name) {
		applyWebSmokeStructuredFields(&result, text)
		if result.Passed && !webSmokeHasRequiredIDs(result) {
			result.Passed = false
			summary += "; web smoke artifact omitted required concrete resource IDs"
		}
	}
	if passed {
		summary = appendVerifiedMarkers(summary, append(requiredAll, webSmokeConcreteMarkers(result)...))
	}
	result.ResultSummary = summary
	return result
}

func isWebSmokeProbe(name string) bool {
	return name == "web-auth-browser-smoke" || name == "web-journal-browser-smoke" || name == "web-room-browser-smoke"
}

func applyWebSmokeStructuredFields(result *probeResult, text string) {
	result.UserID = extractWebSmokeID(text, "user_id")
	result.OrganizationID = extractWebSmokeID(text, "organization_id")
	result.JournalID = extractWebSmokeID(text, "journal_id")
	result.RoomID = extractWebSmokeID(text, "room_id")
}

func extractWebSmokeID(text, key string) string {
	match := webSmokeIDPatterns[key].FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func webSmokeHasRequiredIDs(result probeResult) bool {
	if result.UserID == "" || result.OrganizationID == "" {
		return false
	}
	switch result.Name {
	case "web-auth-browser-smoke":
		return true
	case "web-journal-browser-smoke":
		return result.JournalID != ""
	case "web-room-browser-smoke":
		return result.RoomID != ""
	default:
		return true
	}
}

func webSmokeConcreteMarkers(result probeResult) []string {
	markers := []string{}
	if result.UserID != "" {
		markers = append(markers, "user_id="+result.UserID)
	}
	if result.OrganizationID != "" {
		markers = append(markers, "organization_id="+result.OrganizationID)
	}
	if result.JournalID != "" {
		markers = append(markers, "journal_id="+result.JournalID)
	}
	if result.RoomID != "" {
		markers = append(markers, "room_id="+result.RoomID)
	}
	return markers
}

func enforceWebSmokeIdentityLinkage(results []probeResult) {
	var auth *probeResult
	for i := range results {
		if results[i].Name == "web-auth-browser-smoke" {
			auth = &results[i]
			break
		}
	}
	if auth == nil || auth.UserID == "" || auth.OrganizationID == "" {
		return
	}
	for i := range results {
		if results[i].Name != "web-journal-browser-smoke" && results[i].Name != "web-room-browser-smoke" {
			continue
		}
		if results[i].UserID == auth.UserID && results[i].OrganizationID == auth.OrganizationID {
			continue
		}
		results[i].Passed = false
		results[i].ResultSummary += "; web smoke user_id/organization_id did not match auth browser smoke"
	}
}

func linkedWebSmokeIDs(results []probeResult) (string, string, string, string) {
	userID := ""
	organizationID := ""
	journalID := ""
	roomID := ""
	for i := range results {
		if !results[i].Passed {
			continue
		}
		switch results[i].Name {
		case "web-auth-browser-smoke":
			userID = results[i].UserID
			organizationID = results[i].OrganizationID
		case "web-journal-browser-smoke":
			if userID != "" && (results[i].UserID != userID || results[i].OrganizationID != organizationID) {
				return "", "", "", ""
			}
			if userID == "" {
				userID = results[i].UserID
				organizationID = results[i].OrganizationID
			}
			journalID = results[i].JournalID
		case "web-room-browser-smoke":
			if userID != "" && (results[i].UserID != userID || results[i].OrganizationID != organizationID) {
				return "", "", "", ""
			}
			if userID == "" {
				userID = results[i].UserID
				organizationID = results[i].OrganizationID
			}
			roomID = results[i].RoomID
		}
	}
	if userID == "" || organizationID == "" || journalID == "" || roomID == "" {
		return "", "", "", ""
	}
	return userID, organizationID, journalID, roomID
}

func probePostJSON(client *http.Client, name, target string, body []byte, headers map[string]string, expectedStatus int) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-stagingprobe/1.0")
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	passed := resp.StatusCode == expectedStatus
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
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

func forbiddenArtifactMarkers() []string {
	return []string{
		"mock",
		"placeholder",
		"synthetic",
		"stubbed",
		"test-only",
		"dry run",
		"dry-run",
		"local-only",
		"localhost",
		"127.0.0.1",
		"https://api.scriptureforge.com",
		"wss://api.scriptureforge.com",
	}
}

func probeZoomInvalidSignature(client *http.Client, target string) probeResult {
	body := zoomProbePayload("meeting.started")
	return probePostJSON(client, "zoom-webhook-invalid-signature-denied", target, body, map[string]string{
		"x-zm-request-timestamp": fmt.Sprintf("%d", time.Now().Unix()),
		"x-zm-signature":         "v0=invalid",
	}, http.StatusUnauthorized)
}

func probeZoomSignedNoop(client *http.Client, target, secret string) probeResult {
	body := zoomProbePayload("staging.probe")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := zoomSignature(secret, timestamp, body)
	return probePostJSON(client, "zoom-webhook-signed-noop-accepted", target, body, map[string]string{
		"x-zm-request-timestamp": timestamp,
		"x-zm-signature":         signature,
	}, http.StatusOK)
}

func probeZoomURLValidation(client *http.Client, target, secret string) probeResult {
	body, _ := json.Marshal(map[string]any{
		"event": "endpoint.url_validation",
		"payload": map[string]string{
			"plainToken": "staging-url-validation-token",
		},
	})
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := zoomSignature(secret, timestamp, body)
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return failedProbe("zoom-webhook-url-validation", target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-stagingprobe/1.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-zm-request-timestamp", timestamp)
	req.Header.Set("x-zm-signature", signature)
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("zoom-webhook-url-validation", target, err.Error())
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	responseText := string(responseBody)
	passed := resp.StatusCode == http.StatusOK &&
		strings.Contains(responseText, `"plainToken"`) &&
		strings.Contains(responseText, "staging-url-validation-token") &&
		strings.Contains(responseText, `"encryptedToken"`)
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary += "; response did not include Zoom URL validation tokens"
	}
	return probeResult{Name: "zoom-webhook-url-validation", Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
}

func zoomProbePayload(event string) []byte {
	body, _ := json.Marshal(map[string]any{
		"event": event,
		"payload": map[string]any{
			"object": map[string]string{
				"id":         "staging-probe-meeting",
				"topic":      "staging readiness probe",
				"start_time": time.Now().UTC().Format(time.RFC3339),
			},
		},
	})
	return body
}

func zoomSignature(secret, timestamp string, body []byte) string {
	message := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func probeAIStudyGeneration(client *http.Client, target, bearerToken, topic string) probeResult {
	body, _ := json.Marshal(map[string]string{"topic": topic})
	return probePostJSON(client, "ai-study-generation", target, body, map[string]string{
		"Authorization": "Bearer " + bearerToken,
	}, http.StatusOK)
}

func probeTLS(name, target string, timeout time.Duration, releaseMarkers []string) probeResult {
	parsed, err := url.Parse(target)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	host := parsed.Host
	serverName := parsed.Hostname()
	if serverName == "" {
		return failedProbe(name, target, "target did not include a hostname")
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	dialer := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", host)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return failedProbe(name, target, "connection did not expose TLS state")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return failedProbe(name, target, "no peer certificates returned")
	}
	cert := state.PeerCertificates[0]
	if time.Until(cert.NotAfter) < 14*24*time.Hour {
		return failedProbe(name, target, "certificate expires in less than 14 days")
	}
	certIssuer := certificateNameToken(cert.Issuer.String())
	if certIssuer == "" {
		return failedProbe(name, target, "certificate issuer was empty")
	}
	summary := appendVerifiedMarkers(
		fmt.Sprintf("%s certificate valid until %s", tlsVersionName(state.Version), cert.NotAfter.UTC().Format("2006-01-02")),
		append([]string{name, "TLS", "certificate", "cert_not_after", "cert_hostname=" + serverName, "cert_issuer=" + certIssuer}, releaseMarkers...),
	)
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        true,
		LatencyMS:     latency,
		TLSVersion:    tlsVersionName(state.Version),
		CertNotAfter:  cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		CertHostname:  serverName,
		CertIssuer:    certIssuer,
		ResultSummary: summary,
	}
}

func certificateNameToken(name string) string {
	cleaned := strings.TrimSpace(name)
	cleaned = strings.ReplaceAll(cleaned, " ", "_")
	cleaned = strings.ReplaceAll(cleaned, ",", "_")
	cleaned = strings.ReplaceAll(cleaned, "=", "-")
	cleaned = strings.ReplaceAll(cleaned, "/", "_")
	cleaned = strings.ReplaceAll(cleaned, ":", "-")
	return strings.Trim(cleaned, "_")
}

func probeHTTPSRedirect(client *http.Client, name, httpsBase string, releaseMarkers []string) probeResult {
	parsed, err := url.Parse(httpsBase)
	if err != nil {
		return failedProbe(name, httpsBase, err.Error())
	}
	parsed.Scheme = "http"
	target := parsed.String()
	redirectClient := *client
	redirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	start := time.Now()
	resp, err := redirectClient.Get(target)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	location := resp.Header.Get("Location")
	passed := resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(location, "https://")
	summary := fmt.Sprintf("got HTTP %d redirect to %q in %dms", resp.StatusCode, location, latency)
	if passed {
		summary = appendVerifiedMarkers(summary, append([]string{name, "HTTP", "HTTPS", "redirect"}, releaseMarkers...))
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, RedirectTo: location, ResultSummary: summary}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}

func verifiedHTTPMarkers(name string) []string {
	switch name {
	case "api-live":
		return []string{"api-live", "/live", "HTTP 200"}
	case "api-ready":
		return []string{"api-ready", "/ready", "HTTP 200"}
	case "web-root":
		return []string{"web-root", "web root", "HTTP 200"}
	default:
		return nil
	}
}

func appendVerifiedMarkers(summary string, markers []string) string {
	return fmt.Sprintf("%s; verified markers: %s", summary, strings.Join(markers, ", "))
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}
