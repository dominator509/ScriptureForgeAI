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
	mobilePlatformsPattern             = regexp.MustCompile(`(?i)\bplatforms=([A-Za-z0-9_,.-]+)\b`)
	mobileReleaseChannelPattern        = regexp.MustCompile(`(?i)\brelease_channel=([A-Za-z0-9_.:-]+)\b`)
	mobileExpoProfilePattern           = regexp.MustCompile(`(?i)\bexpo_profile=([A-Za-z0-9_.:-]+)\b`)
	mobileAPIBaseURLPattern            = regexp.MustCompile(`(?i)\bEXPO_PUBLIC_API_BASE_URL=(https://[^\s;,]+)\b`)
	mobileWSBaseURLPattern             = regexp.MustCompile(`(?i)\bEXPO_PUBLIC_WS_BASE_URL=(wss://[^\s;,]+)\b`)
	mobileRequireNativeCryptoPattern   = regexp.MustCompile(`(?i)\bEXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=(true|false)\b`)
	mobileDeploymentEnvironmentPattern = regexp.MustCompile(`(?i)\bEXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=([A-Za-z0-9_.:-]+)\b`)
)

type config struct {
	EASArtifactURL        string
	NativeCryptoSmokeURL  string
	StagingConfigProofURL string
	ReleaseCandidate      string
	ServiceVersion        string
	Timeout               time.Duration
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
	Name                  string `json:"name"`
	Target                string `json:"target"`
	Passed                bool   `json:"passed"`
	StatusCode            int    `json:"status_code,omitempty"`
	LatencyMS             int64  `json:"latency_ms,omitempty"`
	Provider              string `json:"provider,omitempty"`
	NativeRequired        *bool  `json:"native_required,omitempty"`
	Platforms             string `json:"platforms,omitempty"`
	ReleaseChannel        string `json:"release_channel,omitempty"`
	ExpoProfile           string `json:"expo_profile,omitempty"`
	APIBaseURL            string `json:"api_base_url,omitempty"`
	WSBaseURL             string `json:"ws_base_url,omitempty"`
	RequireNativeCrypto   string `json:"require_native_crypto,omitempty"`
	DeploymentEnvironment string `json:"deployment_environment,omitempty"`
	ResultSummary         string `json:"result_summary"`
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
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("STAGING_RELEASE_CANDIDATE"), "exact git SHA or release candidate represented by this mobile evidence")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("STAGING_MOBILE_SERVICE_VERSION"), "exact mobile app/service version represented by this evidence")
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
	if cfg.EASArtifactURL == "" || cfg.NativeCryptoSmokeURL == "" || cfg.StagingConfigProofURL == "" {
		return errors.New("mobile proof requires EAS/native run, native crypto smoke, and staging config artifact URLs")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" {
		return errors.New("mobile proof requires release-candidate and service-version")
	}
	var err error
	cfg.EASArtifactURL, err = normalizeArtifactURL(cfg.EASArtifactURL, "eas-artifact-url")
	if err != nil {
		return err
	}
	cfg.NativeCryptoSmokeURL, err = normalizeArtifactURL(cfg.NativeCryptoSmokeURL, "native-crypto-smoke-url")
	if err != nil {
		return err
	}
	cfg.StagingConfigProofURL, err = normalizeArtifactURL(cfg.StagingConfigProofURL, "staging-config-proof-url")
	if err != nil {
		return err
	}
	if err := validateDistinctArtifactURLs(map[string]string{
		"eas-artifact-url":         cfg.EASArtifactURL,
		"native-crypto-smoke-url":  cfg.NativeCryptoSmokeURL,
		"staging-config-proof-url": cfg.StagingConfigProofURL,
	}); err != nil {
		return err
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	releaseMarkers := []string{
		"release_candidate=" + cfg.ReleaseCandidate,
		"service_version=" + cfg.ServiceVersion,
	}
	probes := []probeResult{
		probeArtifact(client, "mobile-eas-or-device-run", cfg.EASArtifactURL, append([]string{"staging artifact", "eas", "build", "finished", "android", "ios", "native device", "installed app", "release channel staging", "expo profile staging"}, releaseMarkers...), []string{"development client only", "development client", "development build", "dev client", "debug client", "expo go", "simulator", "simulator only", "simulator run", "simulator validation", "emulator", "android emulator", "ios simulator", "remote debug", "mock", "placeholder", "dry-run", "local-only"}),
		enrichNativeCryptoProbe(probeArtifact(client, "mobile-native-crypto-smoke", cfg.NativeCryptoSmokeURL, append([]string{"staging artifact", "runJournalCryptoSelfTest", "react-native-quick-crypto", "native provider", "native module loaded", "provider status react-native-quick-crypto", "provider=react-native-quick-crypto", "native-required true", "native_required=true", "AES-GCM", "round-trip", "unique_iv=true", "unique IV", "tamper rejected", "associated data", "wrong associated data rejected", "associated_data_salt_id=", "associated_data_salt_version=", "non-extractable", "provider-bound key", "fallback-derived key rejected", "key disposed", "disposed handle rejected", "passphrase wiped", "passphrase buffer zeroized", "salt wiped", "salt buffer zeroized", "plaintext cleared", "plaintext buffer zeroized"}, releaseMarkers...), []string{"node:webcrypto", "node webcrypto", "node crypto", "node.js crypto", "node crypto shim", "browser webcrypto", "global webcrypto", "globalthis.crypto", "crypto.subtle", "javascript fallback", "js fallback", "fallback webcrypto", "webcrypto fallback", "expo-crypto", "expo crypto", "placeholder", "mock", "local-only"})),
		probeArtifact(client, "mobile-staging-config", cfg.StagingConfigProofURL, append([]string{"staging artifact", "EXPO_PUBLIC_API_BASE_URL", "EXPO_PUBLIC_WS_BASE_URL", "EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true", "EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging", "https://", "wss://", "staging"}, releaseMarkers...), []string{"localhost", "127.0.0.1", "10.", "172.16.", "192.168.", "169.254.", "0.0.0.0", "[::1]", "local-only", "https://api.scriptureforge.com", "wss://api.scriptureforge.com", "EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=false", "EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = false", "EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=development", "EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=local"}),
	}

	result := report{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass:    true,
		ReleaseCandidate: cfg.ReleaseCandidate,
		ServiceVersion:   cfg.ServiceVersion,
		Probes:           probes,
		EvidenceItems:    []string{"CLIENT-MOBILE-001"},
	}
	for _, probe := range probes {
		if !probe.Passed {
			result.ThresholdPass = false
			break
		}
	}
	if result.ThresholdPass {
		for index := range result.Probes {
			result.Probes[index].ResultSummary += ", distinct_mobile_artifacts=true"
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
	platforms := ""
	releaseChannel := ""
	expoProfile := ""
	apiBaseURL := ""
	wsBaseURL := ""
	requireNativeCrypto := ""
	deploymentEnvironment := ""
	if name == "mobile-eas-or-device-run" {
		platforms = extractMatch(text, mobilePlatformsPattern)
		releaseChannel = extractMatch(text, mobileReleaseChannelPattern)
		expoProfile = extractMatch(text, mobileExpoProfilePattern)
		if platforms == "" || !containsAllFold(platforms, []string{"android", "ios"}) || releaseChannel != "staging" || expoProfile != "staging" {
			passed = false
		}
	}
	if name == "mobile-staging-config" {
		apiBaseURL = extractMatch(text, mobileAPIBaseURLPattern)
		wsBaseURL = extractMatch(text, mobileWSBaseURLPattern)
		requireNativeCrypto = extractMatch(text, mobileRequireNativeCryptoPattern)
		deploymentEnvironment = extractMatch(text, mobileDeploymentEnvironmentPattern)
		if apiBaseURL == "" || wsBaseURL == "" || requireNativeCrypto != "true" || deploymentEnvironment != "staging" {
			passed = false
		}
	}
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary += "; artifact missing required markers or contains forbidden local/shim markers"
	} else {
		summary += "; verified markers: " + strings.Join(required, ", ")
		if name == "mobile-eas-or-device-run" {
			summary += fmt.Sprintf(", platforms=%s, release_channel=%s, expo_profile=%s", platforms, releaseChannel, expoProfile)
		}
		if name == "mobile-staging-config" {
			summary += fmt.Sprintf(", EXPO_PUBLIC_API_BASE_URL=%s, EXPO_PUBLIC_WS_BASE_URL=%s, EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=%s, EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=%s", apiBaseURL, wsBaseURL, requireNativeCrypto, deploymentEnvironment)
		}
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, Platforms: platforms, ReleaseChannel: releaseChannel, ExpoProfile: expoProfile, APIBaseURL: apiBaseURL, WSBaseURL: wsBaseURL, RequireNativeCrypto: requireNativeCrypto, DeploymentEnvironment: deploymentEnvironment, ResultSummary: summary}
}

func enrichNativeCryptoProbe(probe probeResult) probeResult {
	nativeRequired := probe.Passed
	if probe.Passed {
		probe.Provider = "react-native-quick-crypto"
		probe.NativeRequired = &nativeRequired
	}
	return probe
}

func validateDistinctArtifactURLs(urls map[string]string) error {
	seen := make(map[string]string, len(urls))
	for field, artifactURL := range urls {
		normalized, err := canonicalArtifactURL(artifactURL)
		if err != nil {
			return fmt.Errorf("-%s artifact URL: %w", field, err)
		}
		if previous, ok := seen[normalized]; ok {
			return fmt.Errorf("mobile proof artifacts must be distinct: -%s duplicates -%s", field, previous)
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

func extractMatch(text string, pattern *regexp.Regexp) string {
	match := pattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
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
		return "", fmt.Errorf("-%s must use a public staging artifact host", field)
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

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
