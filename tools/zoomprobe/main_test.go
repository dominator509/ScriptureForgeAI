package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var requiredZoomProbeSummaryMarkers = map[string][]string{
	"zoom-oauth-readiness":               {"staging artifact", "oauth", "account_credentials", "status", "ok", "release_candidate=sha-zoom", "service_version=scriptureforge-api:sha-zoom"},
	"zoom-meeting-create-or-fallback":    {"staging artifact", "meeting", "join_url", "zoom.us", "release_candidate=sha-zoom", "service_version=scriptureforge-api:sha-zoom"},
	"zoom-timeout-circuit-fallback":      {"staging artifact", "timeout", "provider timeout", "circuit", "open", "circuit_open_fallback", "fallback", "offline://in-person", "provider_timeout=true", "circuit_open=true", "offline_fallback=true", "release_candidate=sha-zoom", "service_version=scriptureforge-api:sha-zoom"},
	"zoom-webhook-signature-delivery":    {"staging artifact", "webhook", "signature", "x-zm-signature=v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "x-zm-request-timestamp=1710000000", "stale", "replay", "401", "invalid", "signed", "200", "release_candidate=sha-zoom", "service_version=scriptureforge-api:sha-zoom"},
	"zoom-webhook-url-validation":        {"staging artifact", "endpoint.url_validation", "plain_token=zoom-plain-123", "encrypted_token=zoom-encrypted-456", "validation_response=200", "release_candidate=sha-zoom", "service_version=scriptureforge-api:sha-zoom"},
	"zoom-duplicate-webhook-idempotency": {"staging artifact", "duplicate", "x-zm-trackingid", "delivery_id=", "delivery id", "same Zoom event", "idempotent", "200", "single state mutation", "no duplicate side effects", "release_candidate=sha-zoom", "service_version=scriptureforge-api:sha-zoom"},
	"zoom-meeting-room-mapping":          {"staging artifact", "meeting_external_id=", "live_rooms", "internal_room_id=", "redis room state", "mapped", "unknown meeting ignored", "no external meeting id fallback", "distinct_zoom_artifacts=true", "release_candidate=sha-zoom", "service_version=scriptureforge-api:sha-zoom"},
}

const zoomReleaseEvidence = " release_candidate=sha-zoom service_version=scriptureforge-api:sha-zoom"
const zoomWebhookEvidence = "webhook signature x-zm-signature=v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa x-zm-request-timestamp=1710000000 stale replay 401 invalid 401 signed 200"
const zoomURLValidationEvidence = "endpoint.url_validation plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200"

func stagingZoomConfig(timeout time.Duration) config {
	return config{
		OAuthArtifactURL:       "https://zoom-artifacts.staging.scriptureforge.ai/zoom/oauth",
		MeetingArtifactURL:     "https://zoom-artifacts.staging.scriptureforge.ai/zoom/meeting",
		ResilienceArtifactURL:  "https://zoom-artifacts.staging.scriptureforge.ai/zoom/resilience",
		WebhookArtifactURL:     "https://zoom-artifacts.staging.scriptureforge.ai/zoom/webhook",
		WebhookValidationURL:   "https://zoom-artifacts.staging.scriptureforge.ai/zoom/validation",
		DuplicateArtifactURL:   "https://zoom-artifacts.staging.scriptureforge.ai/zoom/duplicate",
		RoomMappingArtifactURL: "https://zoom-artifacts.staging.scriptureforge.ai/zoom/mapping",
		ReleaseCandidate:       "sha-zoom",
		ServiceVersion:         "scriptureforge-api:sha-zoom",
		Timeout:                timeout,
	}
}

func TestRunRequiresAllArtifacts(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "Zoom proof requires") {
		t.Fatalf("expected artifact requirement error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	cfg := stagingZoomConfig(time.Second)
	cfg.ReleaseCandidate = ""
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "release-candidate") {
		t.Fatalf("expected release identity requirement error, got %v", err)
	}
}

func TestRunRejectsDuplicateZoomArtifactURLs(t *testing.T) {
	cfg := stagingZoomConfig(time.Second)
	cfg.RoomMappingArtifactURL = cfg.WebhookArtifactURL
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "room-mapping-artifact-url must be a distinct artifact URL") {
		t.Fatalf("expected duplicate artifact URL error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateZoomArtifactURLs(t *testing.T) {
	cfg := stagingZoomConfig(time.Second)
	cfg.WebhookArtifactURL = "https://ZOOM-ARTIFACTS.staging.scriptureforge.ai:443/zoom/shared-proof?b=2&a=1"
	cfg.RoomMappingArtifactURL = "https://zoom-artifacts.staging.scriptureforge.ai/zoom/shared-proof?a=1&b=2"
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "room-mapping-artifact-url must be a distinct artifact URL") {
		t.Fatalf("expected canonical duplicate artifact URL error, got %v", err)
	}
}

func TestRunEmitsZoomEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte(zoomURLValidationEvidence + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped to live_rooms internal_room_id=room-abc redis room state updated; unknown meeting ignored; no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("zoom probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if len(result.EvidenceItems) != 1 || result.EvidenceItems[0] != "EXT-ZOOM-001" {
		t.Fatalf("unexpected evidence items: %+v", result.EvidenceItems)
	}
	if result.ReleaseCandidate != "sha-zoom" || result.ServiceVersion != "scriptureforge-api:sha-zoom" {
		t.Fatalf("unexpected release identity: %+v", result)
	}
	assertProbeSummariesIncludeMarkers(t, result.Probes, requiredZoomProbeSummaryMarkers)
	assertTimeoutCircuitFallbackProof(t, result.Probes)
	assertWebhookSignatureProof(t, result.Probes, "v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1710000000")
	assertURLValidationProof(t, result.Probes, "zoom-plain-123", "zoom-encrypted-456", "200")
	assertDuplicateWebhookDeliveryID(t, result.Probes, "zm-delivery-123")
	assertRoomMappingIDs(t, result.Probes, "zoom-123", "room-abc")
}

func TestRunAcceptsOfflineMeetingFallbackEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("Zoom unavailable fallback offline://in-person" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("offline fallback evidence should pass: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	for _, probe := range result.Probes {
		if probe.Name == "zoom-meeting-create-or-fallback" {
			assertSummaryIncludesMarkers(t, probe, []string{"staging artifact", "offline://in-person", "fallback", "Zoom", "release_candidate=sha-zoom", "service_version=scriptureforge-api:sha-zoom"})
			return
		}
	}
	t.Fatal("offline fallback report missing zoom-meeting-create-or-fallback probe")
}

func assertProbeSummariesIncludeMarkers(t *testing.T, probes []probeResult, required map[string][]string) {
	t.Helper()
	seen := make(map[string]bool, len(probes))
	for _, probe := range probes {
		markers, ok := required[probe.Name]
		if !ok {
			t.Fatalf("unexpected probe %s", probe.Name)
		}
		seen[probe.Name] = true
		assertSummaryIncludesMarkers(t, probe, markers)
	}
	for name := range required {
		if !seen[name] {
			t.Fatalf("missing probe summary for %s", name)
		}
	}
}

func assertSummaryIncludesMarkers(t *testing.T, probe probeResult, markers []string) {
	t.Helper()
	summary := strings.ToLower(probe.ResultSummary)
	for _, marker := range markers {
		if !strings.Contains(summary, strings.ToLower(marker)) {
			t.Fatalf("%s summary missing marker %q: %s", probe.Name, marker, probe.ResultSummary)
		}
	}
}

func assertDuplicateWebhookDeliveryID(t *testing.T, probes []probeResult, want string) {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == "zoom-duplicate-webhook-idempotency" {
			if probe.DeliveryID != want {
				t.Fatalf("duplicate webhook delivery_id = %q, want %q", probe.DeliveryID, want)
			}
			return
		}
	}
	t.Fatal("missing zoom-duplicate-webhook-idempotency probe")
}

func assertTimeoutCircuitFallbackProof(t *testing.T, probes []probeResult) {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == "zoom-timeout-circuit-fallback" {
			if !probe.ProviderTimeout {
				t.Fatal("zoom-timeout-circuit-fallback missing provider_timeout=true")
			}
			if !probe.CircuitOpen {
				t.Fatal("zoom-timeout-circuit-fallback missing circuit_open=true")
			}
			if !probe.OfflineFallback {
				t.Fatal("zoom-timeout-circuit-fallback missing offline_fallback=true")
			}
			return
		}
	}
	t.Fatal("missing zoom-timeout-circuit-fallback probe")
}

func assertWebhookSignatureProof(t *testing.T, probes []probeResult, wantSignature, wantTimestamp string) {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == "zoom-webhook-signature-delivery" {
			if probe.WebhookSig != wantSignature {
				t.Fatalf("webhook signature = %q, want %q", probe.WebhookSig, wantSignature)
			}
			if probe.WebhookTS != wantTimestamp {
				t.Fatalf("webhook timestamp = %q, want %q", probe.WebhookTS, wantTimestamp)
			}
			return
		}
	}
	t.Fatal("missing zoom-webhook-signature-delivery probe")
}

func assertURLValidationProof(t *testing.T, probes []probeResult, wantPlainToken, wantEncryptedToken, wantResponse string) {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == "zoom-webhook-url-validation" {
			if probe.PlainToken != wantPlainToken {
				t.Fatalf("url validation plain_token = %q, want %q", probe.PlainToken, wantPlainToken)
			}
			if probe.EncryptedToken != wantEncryptedToken {
				t.Fatalf("url validation encrypted_token = %q, want %q", probe.EncryptedToken, wantEncryptedToken)
			}
			if probe.ValidationResponse != wantResponse {
				t.Fatalf("url validation response = %q, want %q", probe.ValidationResponse, wantResponse)
			}
			return
		}
	}
	t.Fatal("missing zoom-webhook-url-validation probe")
}

func assertRoomMappingIDs(t *testing.T, probes []probeResult, wantMeetingID, wantRoomID string) {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == "zoom-meeting-room-mapping" {
			if probe.MeetingID != wantMeetingID {
				t.Fatalf("room mapping meeting_external_id = %q, want %q", probe.MeetingID, wantMeetingID)
			}
			if probe.RoomID != wantRoomID {
				t.Fatalf("room mapping internal_room_id = %q, want %q", probe.RoomID, wantRoomID)
			}
			return
		}
	}
	t.Fatal("missing zoom-meeting-room-mapping probe")
}

func TestRunFailsWhenOAuthArtifactLeaksSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok client_secret=leaked" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected leaked OAuth secret to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenResilienceArtifactMissingCircuitFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("timeout drill observed slow response but no fallback proof" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing circuit fallback proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-timeout-circuit-fallback") {
		t.Fatalf("report missing resilience probe:\n%s", output.String())
	}
}

func TestRunFailsWhenArtifactsAreMarkedMockOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("mock artifact: meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mock-only room mapping artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-meeting-room-mapping") {
		t.Fatalf("report missing room mapping probe:\n%s", output.String())
	}
}

func TestRunFailsWhenArtifactsAdmitPrivateNetworkEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback private-network link-local unspecified ipv4-mapped" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected private-network room mapping artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-meeting-room-mapping") {
		t.Fatalf("report missing room mapping probe:\n%s", output.String())
	}
}

func TestRunFailsWhenWebhookArtifactLacksZoomSignatureHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte("webhook signature invalid returned 401; signed webhook returned 200" + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing Zoom signature header proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-webhook-signature-delivery") {
		t.Fatalf("report missing webhook signature probe:\n%s", output.String())
	}
}

func TestRunFailsWhenURLValidationArtifactLacksStructuredTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation plainToken encryptedToken 200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing URL validation token proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-webhook-url-validation") {
		t.Fatalf("report missing URL validation probe:\n%s", output.String())
	}
}

func TestRunFailsWhenWebhookArtifactOmitsStaleReplayDenial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte("webhook signature x-zm-signature=v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa x-zm-request-timestamp=1710000000 invalid 401 signed 200" + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing stale replay proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-webhook-signature-delivery") {
		t.Fatalf("report missing webhook signature probe:\n%s", output.String())
	}
}

func TestRunFailsWhenWebhookArtifactDisablesSignatureVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + "; signature verification disabled" + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected disabled signature verification proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-webhook-signature-delivery") {
		t.Fatalf("report missing webhook signature probe:\n%s", output.String())
	}
}

func TestRunFailsWhenDuplicateWebhookLacksStructuredDeliveryID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing structured delivery_id proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-duplicate-webhook-idempotency") {
		t.Fatalf("report missing duplicate webhook probe:\n%s", output.String())
	}
}

func TestRunFailsWhenDuplicateWebhookLacksTrackingHeaderProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id=zoom-123 mapped live_rooms internal_room_id=room-abc redis room state unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing x-zm-trackingid proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-duplicate-webhook-idempotency") {
		t.Fatalf("report missing duplicate webhook probe:\n%s", output.String())
	}
}

func TestRunFailsWhenRoomMappingLacksInternalRoomProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth":
			_, _ = w.Write([]byte("Zoom oauth account_credentials status ok token redacted" + zoomReleaseEvidence))
		case "/meeting":
			_, _ = w.Write([]byte("meeting created join_url=https://zoom.us/j/123456789" + zoomReleaseEvidence))
		case "/resilience":
			_, _ = w.Write([]byte("provider timeout drill opened circuit; circuit open circuit_open_fallback returned offline://in-person fallback" + zoomReleaseEvidence))
		case "/webhook":
			_, _ = w.Write([]byte(zoomWebhookEvidence + zoomReleaseEvidence))
		case "/validation":
			_, _ = w.Write([]byte("endpoint.url_validation 200 plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200" + zoomReleaseEvidence))
		case "/duplicate":
			_, _ = w.Write([]byte("duplicate webhook x-zm-trackingid delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects" + zoomReleaseEvidence))
		case "/mapping":
			_, _ = w.Write([]byte("meeting_external_id mapped live_rooms room" + zoomReleaseEvidence))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingZoomConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing internal room mapping proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "zoom-meeting-room-mapping") {
		t.Fatalf("report missing room mapping probe:\n%s", output.String())
	}
}

func TestRunRejectsLocalOrInsecureArtifactURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{
			name: "insecure oauth artifact",
			edit: func(cfg *config) {
				cfg.OAuthArtifactURL = "http://zoom-artifacts.staging.scriptureforge.ai/zoom/oauth"
			},
			want: "oauth-artifact-url",
		},
		{
			name: "reserved example oauth artifact",
			edit: func(cfg *config) {
				cfg.OAuthArtifactURL = "https://artifacts.staging.example/zoom/oauth"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved example.com meeting artifact",
			edit: func(cfg *config) {
				cfg.MeetingArtifactURL = "https://zoom.example.com/zoom/meeting"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved test validation artifact",
			edit: func(cfg *config) {
				cfg.WebhookValidationURL = "https://zoom-artifacts.staging.test/zoom/validation"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved invalid room mapping artifact",
			edit: func(cfg *config) {
				cfg.RoomMappingArtifactURL = "https://zoom-artifacts.invalid/zoom/mapping"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "loopback resilience artifact",
			edit: func(cfg *config) {
				cfg.ResilienceArtifactURL = "https://127.0.0.1/zoom/resilience"
			},
			want: "resilience-artifact-url",
		},
		{
			name: "localhost mapping artifact",
			edit: func(cfg *config) {
				cfg.RoomMappingArtifactURL = "https://localhost/zoom/mapping"
			},
			want: "room-mapping-artifact-url",
		},
		{
			name: "private network duplicate artifact",
			edit: func(cfg *config) {
				cfg.DuplicateArtifactURL = "https://10.0.0.5/zoom/duplicate"
			},
			want: "duplicate-artifact-url",
		},
		{
			name: "IPv4-mapped private duplicate artifact",
			edit: func(cfg *config) {
				cfg.DuplicateArtifactURL = "https://[::ffff:10.0.0.5]/zoom/duplicate"
			},
			want: "duplicate-artifact-url",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stagingZoomConfig(time.Second)
			tc.edit(&cfg)
			var output bytes.Buffer
			err := runWithClient(cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q URL validation error, got %v", tc.want, err)
			}
		})
	}
}

func clientForHTTPServer(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("invalid test server URL: %v", err)
	}
	baseClient := server.Client()
	baseTransport := baseClient.Transport
	return &http.Client{
		Timeout: baseClient.Timeout,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			cloned.URL.Scheme = serverURL.Scheme
			cloned.URL.Host = serverURL.Host
			cloned.URL.Path = strings.TrimPrefix(cloned.URL.Path, "/zoom")
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
