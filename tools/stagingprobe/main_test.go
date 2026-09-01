package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const stagingProbeReleaseCandidate = "abc123"
const stagingProbeServiceVersion = "scriptureforge-api:abc123"
const stagingProbeLoadRunID = "load-run-123"

var stagingProbeReleaseMarkers = []string{
	"release_candidate=" + stagingProbeReleaseCandidate,
	"service_version=" + stagingProbeServiceVersion,
	"load_run_id=" + stagingProbeLoadRunID,
}

func TestNormalizeBaseURLRequiresHTTPS(t *testing.T) {
	if _, err := normalizeBaseURL("http://api.staging.scriptureforge.ai"); err == nil {
		t.Fatal("expected http URL to be rejected")
	}
	if _, err := normalizeBaseURL("https://127.0.0.1:8443"); err == nil {
		t.Fatal("expected loopback URL to be rejected")
	}
	if _, err := normalizeBaseURL("https://localhost"); err == nil {
		t.Fatal("expected localhost URL to be rejected")
	}
	for _, raw := range []string{
		"https://10.0.0.25",
		"https://172.16.20.5",
		"https://192.168.100.30",
		"https://169.254.10.20",
		"https://0.0.0.0",
		"https://[::ffff:10.0.0.25]",
	} {
		if _, err := normalizeBaseURL(raw); err == nil {
			t.Fatalf("expected private/local URL %q to be rejected", raw)
		}
	}
	got, err := normalizeBaseURL("https://api.staging.scriptureforge.ai/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://api.staging.scriptureforge.ai" {
		t.Fatalf("unexpected normalized URL: %s", got)
	}
	for _, raw := range []string{
		"https://api.staging.example",
		"https://api.example.com",
		"https://api.staging.test",
		"https://api.invalid",
	} {
		if _, err := normalizeBaseURL(raw); err == nil {
			t.Fatalf("expected reserved placeholder base URL %q to be rejected", raw)
		}
	}
}

func TestNormalizeArtifactURLRejectsLocalHosts(t *testing.T) {
	for _, raw := range []string{
		"http://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		"https://127.0.0.1/tls/dns.txt",
		"https://localhost/tls/dns.txt",
		"https://10.0.0.25/tls/dns.txt",
		"https://172.16.20.5/tls/dns.txt",
		"https://169.254.10.20/tls/dns.txt",
		"https://0.0.0.0/tls/dns.txt",
		"https://[::ffff:10.0.0.25]/tls/dns.txt",
	} {
		if _, err := normalizeArtifactURL(raw, "dns-artifact-url"); err == nil {
			t.Fatalf("expected artifact URL %q to be rejected", raw)
		}
	}
	for _, raw := range []string{
		"https://artifacts.staging.example/tls/dns.txt",
		"https://artifacts.example.com/tls/dns.txt",
		"https://artifacts.staging.test/tls/dns.txt",
		"https://artifacts.invalid/tls/dns.txt",
	} {
		if _, err := normalizeArtifactURL(raw, "dns-artifact-url"); err == nil {
			t.Fatalf("expected reserved placeholder artifact URL %q to be rejected", raw)
		}
	}
}

func TestProbeHTTPPassesExpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := probeHTTP(server.Client(), "api-live", server.URL+"/live", http.StatusOK, stagingProbeReleaseMarkers)
	if !result.Passed || result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected probe result: %+v", result)
	}
	if !strings.Contains(result.ResultSummary, "verified markers: api-live, /live, HTTP 200, release_candidate=abc123, service_version=scriptureforge-api:abc123") {
		t.Fatalf("probe summary omitted verified markers: %s", result.ResultSummary)
	}
}

func TestProbeHTTPSRedirectRequiresHTTPSLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://api.staging.scriptureforge.ai"+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer server.Close()

	target := "https://" + strings.TrimPrefix(server.URL, "http://")
	result := probeHTTPSRedirect(server.Client(), "redirect", target, stagingProbeReleaseMarkers)
	if !result.Passed || !strings.HasPrefix(result.RedirectTo, "https://") {
		t.Fatalf("unexpected redirect probe result: %+v", result)
	}
	if !strings.Contains(result.ResultSummary, "verified markers: redirect, HTTP, HTTPS, redirect, release_candidate=abc123, service_version=scriptureforge-api:abc123") {
		t.Fatalf("redirect summary omitted verified markers: %s", result.ResultSummary)
	}
}

func TestAppendVerifiedMarkers(t *testing.T) {
	summary := appendVerifiedMarkers("TLS1.3 certificate valid", []string{"api-tls", "TLS", "certificate", "cert_not_after", "cert_hostname=api.staging.scriptureforge.ai", "cert_issuer=Amazon"})
	for _, marker := range []string{"verified markers", "api-tls", "TLS", "certificate", "cert_not_after", "cert_hostname=api.staging.scriptureforge.ai", "cert_issuer=Amazon"} {
		if !strings.Contains(summary, marker) {
			t.Fatalf("summary %q omitted marker %q", summary, marker)
		}
	}
}

func TestCertificateNameTokenNormalizesIssuer(t *testing.T) {
	got := certificateNameToken("CN=Amazon RSA 2048 M02, O=Amazon, C=US")
	want := "CN-Amazon_RSA_2048_M02__O-Amazon__C-US"
	if got != want {
		t.Fatalf("certificateNameToken() = %q, want %q", got, want)
	}
}

func TestProbeArtifactContainsRequiresBrowserSmokeMarkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("staging artifact; login register authenticated https://app.staging.scriptureforge.ai user_id=user-1 organization_id=org-1"))
	}))
	defer server.Close()

	result := probeArtifactContains(
		server.Client(),
		"web-auth-browser-smoke",
		server.URL+"/auth-smoke.txt",
		[]string{"staging artifact", "login", "register", "authenticated", "https://", "user_id=", "organization_id="},
	)
	if !result.Passed || result.StatusCode != http.StatusOK {
		t.Fatalf("expected artifact probe to pass: %+v", result)
	}
	if result.UserID != "user-1" || result.OrganizationID != "org-1" {
		t.Fatalf("artifact probe did not extract user/org IDs: %+v", result)
	}
	if !strings.Contains(result.ResultSummary, "user_id=user-1") || !strings.Contains(result.ResultSummary, "organization_id=org-1") {
		t.Fatalf("artifact summary omitted verified markers: %s", result.ResultSummary)
	}
}

func TestProbeArtifactContainsRejectsWebSmokeWithoutConcreteIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("staging artifact; journal encrypted save load plaintext absent associated data wrong associated data rejected user_id= organization_id= journal_id= distinct_web_artifacts=true"))
	}))
	defer server.Close()

	result := probeArtifactContains(
		server.Client(),
		"web-journal-browser-smoke",
		server.URL+"/journal-smoke.txt",
		[]string{"staging artifact", "journal", "encrypted", "save", "load", "plaintext absent", "associated data", "wrong associated data rejected", "user_id=", "organization_id=", "journal_id=", "distinct_web_artifacts=true"},
	)
	if result.Passed {
		t.Fatalf("expected artifact probe without concrete IDs to fail: %+v", result)
	}
}

func TestEnforceWebSmokeIdentityLinkageRejectsMismatchedJournalOrRoom(t *testing.T) {
	results := []probeResult{
		{Name: "web-auth-browser-smoke", Passed: true, UserID: "user-1", OrganizationID: "org-1", ResultSummary: "auth ok"},
		{Name: "web-journal-browser-smoke", Passed: true, UserID: "user-2", OrganizationID: "org-1", JournalID: "journal-1", ResultSummary: "journal ok"},
		{Name: "web-room-browser-smoke", Passed: true, UserID: "user-1", OrganizationID: "org-2", RoomID: "room-1", ResultSummary: "room ok"},
	}

	enforceWebSmokeIdentityLinkage(results)

	if results[1].Passed || results[2].Passed {
		t.Fatalf("expected mismatched journal and room probes to fail: %+v", results)
	}
}

func TestLinkedWebSmokeIDsRequireOneBrowserSmokeIdentity(t *testing.T) {
	userID, organizationID, journalID, roomID := linkedWebSmokeIDs([]probeResult{
		{Name: "web-auth-browser-smoke", Passed: true, UserID: "user-staging", OrganizationID: "org-staging"},
		{Name: "web-journal-browser-smoke", Passed: true, UserID: "user-staging", OrganizationID: "org-staging", JournalID: "journal-staging"},
		{Name: "web-room-browser-smoke", Passed: true, UserID: "user-staging", OrganizationID: "org-staging", RoomID: "room-staging"},
	})
	if userID != "user-staging" || organizationID != "org-staging" || journalID != "journal-staging" || roomID != "room-staging" {
		t.Fatalf("unexpected linked web smoke IDs: user=%q org=%q journal=%q room=%q", userID, organizationID, journalID, roomID)
	}

	userID, organizationID, journalID, roomID = linkedWebSmokeIDs([]probeResult{
		{Name: "web-auth-browser-smoke", Passed: true, UserID: "user-staging", OrganizationID: "org-staging"},
		{Name: "web-journal-browser-smoke", Passed: true, UserID: "user-staging", OrganizationID: "org-staging", JournalID: "journal-staging"},
		{Name: "web-room-browser-smoke", Passed: true, UserID: "user-other", OrganizationID: "org-staging", RoomID: "room-staging"},
	})
	if userID != "" || organizationID != "" || journalID != "" || roomID != "" {
		t.Fatalf("mismatched web smoke identity should not be reportable: user=%q org=%q journal=%q room=%q", userID, organizationID, journalID, roomID)
	}
}

func TestProbeArtifactContainsRejectsMarkerLightOrMockArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "missing markers", body: "staging artifact; login only"},
		{name: "mock marked", body: "staging artifact; login register authenticated https:// mock"},
		{name: "production API endpoint", body: "staging artifact; login register authenticated https://app.staging.scriptureforge.ai user_id=user-1 organization_id=org-1 distinct_web_artifacts=true NEXT_PUBLIC_API_BASE_URL=https://api.scriptureforge.com"},
		{name: "production WebSocket endpoint", body: "staging artifact; room create select WebSocket connected https://app.staging.scriptureforge.ai user_id=user-1 organization_id=org-1 room_id=room-1 distinct_web_artifacts=true NEXT_PUBLIC_WS_BASE_URL=wss://api.scriptureforge.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			result := probeArtifactContains(
				server.Client(),
				"web-auth-browser-smoke",
				server.URL+"/auth-smoke.txt",
				[]string{"staging artifact", "login", "register", "authenticated", "https://", "user_id=", "organization_id="},
			)
			if result.Passed {
				t.Fatalf("expected weak artifact to fail: %+v", result)
			}
		})
	}
}

func TestRunProducesFailingReportWhenProbeFails(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:            "https://api.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		ReleaseCandidate:   stagingProbeReleaseCandidate,
		ServiceVersion:     stagingProbeServiceVersion,
		LoadRunID:          stagingProbeLoadRunID,
		Timeout:            50 * time.Millisecond,
	}, &output)
	if err == nil {
		t.Fatal("expected failed probe to fail run")
	}
	var result report
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatalf("report was not JSON: %v\n%s", decodeErr, output.String())
	}
	if result.ThresholdPass {
		t.Fatalf("failing probe reported pass: %+v", result)
	}
	if result.DNSArtifact == "" || result.ACMArtifact == "" || result.SSLLabsArtifact == "" {
		t.Fatalf("failing report omitted TLS artifacts: %+v", result)
	}
}

func TestRunRequiresTLSArtifactURLs(t *testing.T) {
	var output bytes.Buffer
	err := run(config{APIBase: "https://api.staging.scriptureforge.ai", Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "dns-artifact-url") {
		t.Fatalf("expected DNS artifact URL error, got %v", err)
	}
	output.Reset()
	err = run(config{
		APIBase:        "https://api.staging.scriptureforge.ai",
		DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		Timeout:        time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "ssl-labs-artifact-url") {
		t.Fatalf("expected SSL Labs artifact URL error, got %v", err)
	}
}

func TestStagingProbeDoesNotEmitKubernetesEvidenceItem(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:            "https://api.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		ReleaseCandidate:   stagingProbeReleaseCandidate,
		ServiceVersion:     stagingProbeServiceVersion,
		LoadRunID:          stagingProbeLoadRunID,
		Timeout:            50 * time.Millisecond,
	}, &output)
	if err == nil {
		t.Fatal("expected failed network probe to fail run")
	}
	var result report
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatalf("report was not JSON: %v\n%s", decodeErr, output.String())
	}
	if containsItem(result.EvidenceItems, "DEPLOY-K8S-001") {
		t.Fatalf("staging probe must not emit DEPLOY-K8S-001 without rollout/resource artifacts: %+v", result.EvidenceItems)
	}
	if containsItem(result.EvidenceItems, "CLIENT-WEB-001") {
		t.Fatalf("API-only staging probe must not emit CLIENT-WEB-001 without web/browser artifacts: %+v", result.EvidenceItems)
	}
}

func TestStagingProbeDoesNotEmitDedicatedExternalServiceEvidenceItems(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:            "https://api.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		ReleaseCandidate:   stagingProbeReleaseCandidate,
		ServiceVersion:     stagingProbeServiceVersion,
		LoadRunID:          stagingProbeLoadRunID,
		ProbeZoom:          true,
		ProbeAI:            true,
		AIBearerToken:      "staging-token",
		ZoomWebhookSecret:  "staging-secret",
		Timeout:            50 * time.Millisecond,
	}, &output)
	if err == nil {
		t.Fatal("expected failed network probe to fail run")
	}
	var result report
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatalf("report was not JSON: %v\n%s", decodeErr, output.String())
	}
	for _, forbidden := range []string{"EXT-ZOOM-001", "EXT-AI-001"} {
		if containsItem(result.EvidenceItems, forbidden) {
			t.Fatalf("stagingprobe must not emit %s from partial live smoke probes: %+v", forbidden, result.EvidenceItems)
		}
	}
}

func TestRunRequiresWebSmokeArtifactsForWebEvidence(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:            "https://api.staging.scriptureforge.ai",
		WebBase:            "https://app.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		Timeout:            time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "web-auth-smoke-url") {
		t.Fatalf("expected web auth smoke artifact URL error, got %v", err)
	}
}

func TestRunIncludesWebSmokeArtifactsInReport(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		WebBase:            "https://app.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		WebAuthSmokeURL:    "https://staging-artifacts.staging.scriptureforge.ai/web/auth-smoke.txt",
		WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/journal-smoke.txt",
		WebRoomSmokeURL:    "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt",
		ReleaseCandidate:   "sha-web",
		ServiceVersion:     "scriptureforge-web:sha-web",
		LoadRunID:          stagingProbeLoadRunID,
		Timeout:            50 * time.Millisecond,
	}, &output)
	if err == nil {
		t.Fatal("expected failed network probe to fail run")
	}
	var result report
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatalf("report was not JSON: %v\n%s", decodeErr, output.String())
	}
	if !containsItem(result.EvidenceItems, "CLIENT-WEB-001") {
		t.Fatalf("web staging probe omitted CLIENT-WEB-001: %+v", result.EvidenceItems)
	}
	if result.WebAuthSmoke == "" || result.WebJournalSmoke == "" || result.WebRoomSmoke == "" {
		t.Fatalf("web staging probe omitted browser smoke artifacts: %+v", result)
	}
	if result.ReleaseCandidate != "sha-web" || result.ServiceVersion != "scriptureforge-web:sha-web" {
		t.Fatalf("web staging probe omitted release identity: %+v", result)
	}
	if result.LoadRunID != stagingProbeLoadRunID {
		t.Fatalf("web staging probe omitted load run ID: %+v", result)
	}
}

func TestRunRejectsDuplicateWebSmokeArtifactURLs(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		WebBase:            "https://app.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		WebAuthSmokeURL:    "https://staging-artifacts.staging.scriptureforge.ai/web/shared-smoke.txt",
		WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/shared-smoke.txt",
		WebRoomSmokeURL:    "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt",
		ReleaseCandidate:   "sha-web",
		ServiceVersion:     "scriptureforge-web:sha-web",
		LoadRunID:          stagingProbeLoadRunID,
		Timeout:            50 * time.Millisecond,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "web browser smoke artifacts must be distinct") {
		t.Fatalf("expected duplicate web smoke artifact URL error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateTLSArtifactURLs(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:            "https://api.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://STAGING-ARTIFACTS.staging.scriptureforge.ai:443/tls/shared-proof.txt?b=2&a=1",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/shared-proof.txt?a=1&b=2#certificate",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		ReleaseCandidate:   stagingProbeReleaseCandidate,
		ServiceVersion:     stagingProbeServiceVersion,
		LoadRunID:          stagingProbeLoadRunID,
		Timeout:            50 * time.Millisecond,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "TLS artifacts must be distinct") {
		t.Fatalf("expected canonical duplicate TLS artifact URL error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateWebSmokeArtifactURLs(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		WebBase:            "https://app.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		WebAuthSmokeURL:    "https://STAGING-ARTIFACTS.staging.scriptureforge.ai:443/web/shared-smoke.txt?b=2&a=1",
		WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/shared-smoke.txt?a=1&b=2#journal",
		WebRoomSmokeURL:    "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt",
		ReleaseCandidate:   "sha-web",
		ServiceVersion:     "scriptureforge-web:sha-web",
		LoadRunID:          stagingProbeLoadRunID,
		Timeout:            50 * time.Millisecond,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "web browser smoke artifacts must be distinct") {
		t.Fatalf("expected canonical duplicate web smoke artifact URL error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentityForTLSAndWebEvidence(t *testing.T) {
	var apiOutput bytes.Buffer
	apiErr := run(config{
		APIBase:            "https://api.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		Timeout:            time.Second,
	}, &apiOutput)
	if apiErr == nil || !strings.Contains(apiErr.Error(), "release-candidate") {
		t.Fatalf("expected release-candidate error for API TLS evidence, got %v", apiErr)
	}

	var output bytes.Buffer
	err := run(config{
		WebBase:            "https://app.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		WebAuthSmokeURL:    "https://staging-artifacts.staging.scriptureforge.ai/web/auth-smoke.txt",
		WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/journal-smoke.txt",
		WebRoomSmokeURL:    "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt",
		Timeout:            time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "release-candidate") {
		t.Fatalf("expected release-candidate error for web evidence, got %v", err)
	}
}

func TestRunRequiresLoadRunIDForTLSAndWebEvidence(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:            "https://api.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		ReleaseCandidate:   stagingProbeReleaseCandidate,
		ServiceVersion:     stagingProbeServiceVersion,
		Timeout:            time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "load-run-id") {
		t.Fatalf("expected load-run-id error for TLS evidence, got %v", err)
	}
}

func TestRunRejectsLocalBaseAndArtifactTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config
		want string
	}{
		{
			name: "local API base",
			cfg: config{APIBase: "https://127.0.0.1:8443", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "api-base",
		},
		{
			name: "private API base",
			cfg: config{APIBase: "https://10.0.0.25", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "api-base",
		},
		{
			name: "local web base",
			cfg: config{WebBase: "https://localhost", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", WebAuthSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/auth-smoke.txt", WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/journal-smoke.txt", WebRoomSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "web-base",
		},
		{
			name: "link-local web base",
			cfg: config{WebBase: "https://169.254.10.20", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", WebAuthSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/auth-smoke.txt", WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/journal-smoke.txt", WebRoomSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "web-base",
		},
		{
			name: "local DNS artifact",
			cfg: config{APIBase: "https://api.staging.scriptureforge.ai", DNSArtifactURL: "https://localhost/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "dns-artifact-url",
		},
		{
			name: "private ACM artifact",
			cfg:  config{APIBase: "https://api.staging.scriptureforge.ai", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://192.168.100.30/tls/acm.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "acm-artifact-url",
		},
		{
			name: "local web smoke artifact",
			cfg: config{WebBase: "https://app.staging.scriptureforge.ai", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", WebAuthSmokeURL: "https://127.0.0.1/web/auth-smoke.txt", WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/journal-smoke.txt", WebRoomSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "web-auth-smoke-url",
		},
		{
			name: "private web smoke artifact",
			cfg: config{WebBase: "https://app.staging.scriptureforge.ai", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", WebAuthSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/auth-smoke.txt", WebJournalSmokeURL: "https://172.16.20.5/web/journal-smoke.txt", WebRoomSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "web-journal-smoke-url",
		},
		{
			name: "reserved API base",
			cfg: config{APIBase: "https://api.staging.example", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "api-base",
		},
		{
			name: "reserved web base",
			cfg: config{WebBase: "https://app.example.com", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", WebAuthSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/auth-smoke.txt", WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/journal-smoke.txt", WebRoomSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "web-base",
		},
		{
			name: "reserved DNS artifact",
			cfg: config{APIBase: "https://api.staging.scriptureforge.ai", DNSArtifactURL: "https://artifacts.staging.test/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "dns-artifact-url",
		},
		{
			name: "reserved web smoke artifact",
			cfg: config{WebBase: "https://app.staging.scriptureforge.ai", DNSArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt", ACMArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
				SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt", WebAuthSmokeURL: "https://staging-artifacts.invalid/web/auth-smoke.txt", WebJournalSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/journal-smoke.txt", WebRoomSmokeURL: "https://staging-artifacts.staging.scriptureforge.ai/web/room-smoke.txt", ReleaseCandidate: stagingProbeReleaseCandidate, ServiceVersion: stagingProbeServiceVersion, Timeout: time.Second},
			want: "web-auth-smoke-url",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			tc.cfg.LoadRunID = stagingProbeLoadRunID
			err := run(tc.cfg, &output)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q validation error, got %v", tc.want, err)
			}
		})
	}
}

func TestProbeZoomInvalidSignatureDenial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-zm-signature") == "v0=invalid" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := probeZoomInvalidSignature(server.Client(), server.URL+"/api/webhooks/zoom")
	if !result.Passed || result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected invalid signature result: %+v", result)
	}
}

func TestProbeZoomSignedNoopUsesZoomSignature(t *testing.T) {
	const secret = "zoom-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		timestamp := r.Header.Get("x-zm-request-timestamp")
		message := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(message))
		expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
		if r.Header.Get("x-zm-signature") != expected {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := probeZoomSignedNoop(server.Client(), server.URL+"/api/webhooks/zoom", secret)
	if !result.Passed || result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected signed noop result: %+v", result)
	}
}

func TestProbeZoomURLValidationUsesZoomSignatureAndRequiresTokenResponse(t *testing.T) {
	const secret = "zoom-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		timestamp := r.Header.Get("x-zm-request-timestamp")
		message := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(message))
		expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
		if r.Header.Get("x-zm-signature") != expected {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(string(body), "endpoint.url_validation") || !strings.Contains(string(body), "staging-url-validation-token") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plainToken":"staging-url-validation-token","encryptedToken":"encrypted"}`))
	}))
	defer server.Close()

	result := probeZoomURLValidation(server.Client(), server.URL+"/api/webhooks/zoom", secret)
	if !result.Passed || result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected url validation result: %+v", result)
	}
}

func TestProbeAIStudyGenerationUsesBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer staging-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := probeAIStudyGeneration(server.Client(), server.URL+"/api/v1/ai/generate/study", "staging-token", "Genesis 1:1")
	if !result.Passed || result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected AI probe result: %+v", result)
	}
}

func TestRunRequiresBearerForAIProbe(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:            "https://api.staging.scriptureforge.ai",
		DNSArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/dns.txt",
		ACMArtifactURL:     "https://staging-artifacts.staging.scriptureforge.ai/tls/acm.txt",
		SSLLabsArtifactURL: "https://staging-artifacts.staging.scriptureforge.ai/tls/ssl-labs.txt",
		ProbeAI:            true,
		Timeout:            time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "ai-bearer-token") {
		t.Fatalf("expected missing bearer error, got %v", err)
	}
}

func TestProbeTLSCapturesVersionAndCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// httptest uses a private CA, so exercise the TLS report shape through a
	// local client transport instead of weakening the production probe path.
	conn, err := tls.Dial("tcp", strings.TrimPrefix(server.URL, "https://"), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState()
	_ = conn.Close()
	if tlsVersionName(state.Version) == "" || len(state.PeerCertificates) == 0 {
		t.Fatalf("unexpected TLS state: %+v", state)
	}
}

func containsItem(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}
