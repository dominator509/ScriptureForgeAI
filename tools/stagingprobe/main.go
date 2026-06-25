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
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	APIBase           string
	WebBase           string
	Timeout           time.Duration
	ProbeZoom         bool
	ZoomWebhookSecret string
	ProbeAI           bool
	AIBearerToken     string
	AITopic           string
}

type report struct {
	ObservedAt    string        `json:"observed_at"`
	APITarget     string        `json:"api_target,omitempty"`
	WebTarget     string        `json:"web_target,omitempty"`
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
	TLSVersion    string `json:"tls_version,omitempty"`
	CertNotAfter  string `json:"cert_not_after,omitempty"`
	RedirectTo    string `json:"redirect_to,omitempty"`
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
	flag.StringVar(&cfg.APIBase, "api-base", "", "deployed API base URL, for example https://api.staging.example")
	flag.StringVar(&cfg.WebBase, "web-base", "", "deployed web base URL, for example https://app.staging.example")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.BoolVar(&cfg.ProbeZoom, "probe-zoom", false, "probe Zoom webhook invalid-signature denial; add -zoom-webhook-secret to also send a signed no-op webhook")
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
	if (cfg.ProbeZoom || cfg.ProbeAI) && cfg.APIBase == "" {
		return errors.New("-api-base is required for -probe-zoom or -probe-ai")
	}
	if cfg.ProbeAI && cfg.AIBearerToken == "" {
		return errors.New("-ai-bearer-token or STAGING_AI_BEARER_TOKEN is required for -probe-ai")
	}

	client := &http.Client{Timeout: cfg.Timeout}
	results := make([]probeResult, 0, 6)
	evidenceItems := []string{"DEPLOY-TLS-001", "DEPLOY-K8S-001", "CLIENT-WEB-001"}
	if cfg.APIBase != "" {
		apiBase, err := normalizeBaseURL(cfg.APIBase)
		if err != nil {
			return fmt.Errorf("api-base: %w", err)
		}
		results = append(results, probeHTTP(client, "api-live", joinURL(apiBase, "/live"), http.StatusOK))
		results = append(results, probeHTTP(client, "api-ready", joinURL(apiBase, "/ready"), http.StatusOK))
		results = append(results, probeTLS("api-tls", apiBase, cfg.Timeout))
		results = append(results, probeHTTPSRedirect(client, "api-http-redirect", apiBase))
		if cfg.ProbeZoom {
			results = append(results, probeZoomInvalidSignature(client, joinURL(apiBase, "/api/webhooks/zoom")))
			evidenceItems = appendEvidenceItem(evidenceItems, "EXT-ZOOM-001")
			if cfg.ZoomWebhookSecret != "" {
				results = append(results, probeZoomSignedNoop(client, joinURL(apiBase, "/api/webhooks/zoom"), cfg.ZoomWebhookSecret))
			}
		}
		if cfg.ProbeAI {
			results = append(results, probeAIStudyGeneration(client, joinURL(apiBase, "/api/v1/ai/generate/study"), cfg.AIBearerToken, cfg.AITopic))
			evidenceItems = appendEvidenceItem(evidenceItems, "EXT-AI-001")
		}
		cfg.APIBase = apiBase
	}
	if cfg.WebBase != "" {
		webBase, err := normalizeBaseURL(cfg.WebBase)
		if err != nil {
			return fmt.Errorf("web-base: %w", err)
		}
		results = append(results, probeHTTP(client, "web-root", webBase, http.StatusOK))
		results = append(results, probeTLS("web-tls", webBase, cfg.Timeout))
		results = append(results, probeHTTPSRedirect(client, "web-http-redirect", webBase))
		cfg.WebBase = webBase
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		APITarget:     cfg.APIBase,
		WebTarget:     cfg.WebBase,
		ThresholdPass: true,
		Probes:        results,
		EvidenceItems: evidenceItems,
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
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + path
}

func appendEvidenceItem(items []string, item string) []string {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func probeHTTP(client *http.Client, name, target string, expectedStatus int) probeResult {
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
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
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

func probeTLS(name, target string, timeout time.Duration) probeResult {
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
	summary := fmt.Sprintf("%s certificate valid until %s", tlsVersionName(state.Version), cert.NotAfter.UTC().Format("2006-01-02"))
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        true,
		LatencyMS:     latency,
		TLSVersion:    tlsVersionName(state.Version),
		CertNotAfter:  cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		ResultSummary: summary,
	}
}

func probeHTTPSRedirect(client *http.Client, name, httpsBase string) probeResult {
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
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, RedirectTo: location, ResultSummary: summary}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
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
