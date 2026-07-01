package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const mobileReleaseCandidate = "abc123"
const mobileServiceVersion = "scriptureforge-mobile:abc123"
const mobileLoadRunID = "load-run-123"
const mobileReleaseMarkersText = " release_candidate=" + mobileReleaseCandidate + " service_version=" + mobileServiceVersion + " load_run_id=" + mobileLoadRunID

var requiredMobileProbeSummaryMarkers = map[string][]string{
	"mobile-eas-or-device-run":   {"staging artifact", "eas", "build", "finished", "android", "ios", "native device", "installed app", "release channel staging", "expo profile staging", "mobile_build_id=mobile-build-123", "platforms=android,ios", "release_channel=staging", "expo_profile=staging", "release_candidate=" + mobileReleaseCandidate, "service_version=" + mobileServiceVersion, "load_run_id=" + mobileLoadRunID, "distinct_mobile_artifacts=true"},
	"mobile-native-crypto-smoke": {"staging artifact", "react-native-quick-crypto", "native provider", "native module loaded", "provider status react-native-quick-crypto", "native-required true", "mobile_build_id=mobile-build-123", "AES-GCM", "round-trip", "unique_iv=true", "unique IV", "tamper rejected", "associated data", "wrong associated data rejected", "associated_data_salt_id=", "associated_data_salt_version=", "non-extractable", "provider-bound key", "fallback-derived key rejected", "key disposed", "disposed handle rejected", "revoked_key_rejected=true", "stale raw key rejected", "passphrase wiped", "passphrase buffer zeroized", "salt wiped", "salt buffer zeroized", "plaintext cleared", "plaintext buffer zeroized", "release_candidate=" + mobileReleaseCandidate, "service_version=" + mobileServiceVersion, "load_run_id=" + mobileLoadRunID, "distinct_mobile_artifacts=true"},
	"mobile-staging-config":      {"staging artifact", "EXPO_PUBLIC_API_BASE_URL", "EXPO_PUBLIC_WS_BASE_URL", "EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true", "EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging", "mobile_build_id=mobile-build-123", "https://", "wss://", "staging", "EXPO_PUBLIC_API_BASE_URL=https://api.staging.example", "EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example", "release_candidate=" + mobileReleaseCandidate, "service_version=" + mobileServiceVersion, "load_run_id=" + mobileLoadRunID, "distinct_mobile_artifacts=true"},
}

func stagingMobileConfig(timeout time.Duration) config {
	return config{
		EASArtifactURL:        "https://mobile-artifacts.staging.scriptureforge.ai/mobile/eas",
		NativeCryptoSmokeURL:  "https://mobile-artifacts.staging.scriptureforge.ai/mobile/crypto",
		StagingConfigProofURL: "https://mobile-artifacts.staging.scriptureforge.ai/mobile/config",
		ReleaseCandidate:      mobileReleaseCandidate,
		ServiceVersion:        mobileServiceVersion,
		LoadRunID:             mobileLoadRunID,
		Timeout:               timeout,
	}
}

func TestRunRequiresAllArtifacts(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "mobile proof requires") {
		t.Fatalf("expected artifact requirement error, got %v", err)
	}
}

func TestRunRequiresLoadRunID(t *testing.T) {
	cfg := stagingMobileConfig(time.Second)
	cfg.LoadRunID = ""
	var output bytes.Buffer
	err := run(cfg, &output)
	if err == nil || !strings.Contains(err.Error(), "load-run-id") {
		t.Fatalf("expected load-run-id requirement error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	cfg := stagingMobileConfig(time.Second)
	cfg.ReleaseCandidate = ""
	var output bytes.Buffer
	err := run(cfg, &output)
	if err == nil || !strings.Contains(err.Error(), "release-candidate and service-version") {
		t.Fatalf("expected release identity requirement error, got %v", err)
	}
}

func TestRunRejectsDuplicateArtifactURLs(t *testing.T) {
	cfg := stagingMobileConfig(time.Second)
	cfg.NativeCryptoSmokeURL = cfg.EASArtifactURL
	var output bytes.Buffer
	err := run(cfg, &output)
	if err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("expected duplicate artifact URL validation error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateArtifactURLs(t *testing.T) {
	cfg := stagingMobileConfig(time.Second)
	cfg.EASArtifactURL = "https://MOBILE-ARTIFACTS.staging.scriptureforge.ai:443/mobile/shared-proof?b=2&a=1"
	cfg.NativeCryptoSmokeURL = "https://mobile-artifacts.staging.scriptureforge.ai/mobile/shared-proof?a=1&b=2#crypto"
	var output bytes.Buffer
	err := run(cfg, &output)
	if err == nil || !strings.Contains(err.Error(), "mobile proof artifacts must be distinct") {
		t.Fatalf("expected canonical duplicate artifact URL validation error, got %v", err)
	}
}

func TestRunEmitsMobileEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("staging artifact EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, mobile_build_id=mobile-build-123 platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true mobile_build_id=mobile-build-123 AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging artifact mobile_build_id=mobile-build-123 EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("mobile probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if len(result.EvidenceItems) != 1 || result.EvidenceItems[0] != "CLIENT-MOBILE-001" {
		t.Fatalf("unexpected evidence items: %+v", result.EvidenceItems)
	}
	if result.ReleaseCandidate != mobileReleaseCandidate || result.ServiceVersion != mobileServiceVersion {
		t.Fatalf("unexpected release identity: %+v", result)
	}
	if result.LoadRunID != mobileLoadRunID {
		t.Fatalf("unexpected load run ID: %+v", result)
	}
	assertProbeSummariesIncludeMarkers(t, result.Probes, requiredMobileProbeSummaryMarkers)
	for _, probe := range result.Probes {
		if probe.MobileBuildID != "mobile-build-123" {
			t.Fatalf("probe %s did not expose shared mobile build ID: %+v", probe.Name, probe)
		}
	}
	cryptoProbe := findProbe(t, result.Probes, "mobile-native-crypto-smoke")
	if cryptoProbe.Provider != "react-native-quick-crypto" {
		t.Fatalf("native crypto probe did not expose structured provider: %+v", cryptoProbe)
	}
	if cryptoProbe.NativeRequired == nil || *cryptoProbe.NativeRequired != true {
		t.Fatalf("native crypto probe did not expose structured native_required=true: %+v", cryptoProbe)
	}
	if cryptoProbe.AssociatedDataSaltID != "journal:self-test:server-derived-salt" || cryptoProbe.AssociatedDataVersion != "1" {
		t.Fatalf("native crypto probe did not expose structured associated-data salt binding: %+v", cryptoProbe)
	}
}

func TestRunFailsWhenMobileBuildIDsDoNotMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("staging artifact EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, mobile_build_id=mobile-build-123 platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true mobile_build_id=mobile-build-other AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging artifact mobile_build_id=mobile-build-123 EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched mobile build ID evidence to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile_build_id values do not match") {
		t.Fatalf("report did not explain mobile build ID mismatch:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoOmitsExactProviderMarkers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cryptoText string
	}{
		{
			name:       "missing exact provider",
			cryptoText: "staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto native-required true native_required=true AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized" + mobileReleaseMarkersText,
		},
		{
			name:       "missing exact native required",
			cryptoText: "staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized" + mobileReleaseMarkersText,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/eas":
					_, _ = w.Write([]byte("staging artifact EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging" + mobileReleaseMarkersText))
				case "/crypto":
					_, _ = w.Write([]byte(tc.cryptoText))
				case "/config":
					_, _ = w.Write([]byte("staging artifact EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging" + mobileReleaseMarkersText))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			var output bytes.Buffer
			err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
			if err == nil {
				t.Fatalf("expected native crypto artifact without exact provider markers to fail:\n%s", output.String())
			}
			if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
				t.Fatalf("report missing crypto probe:\n%s", output.String())
			}
		})
	}
}

func TestRunFailsWhenNativeCryptoBindsWrongProviderFirst(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("staging artifact EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging" + mobileReleaseMarkersText))
		case "/crypto":
			_, _ = w.Write([]byte("staging artifact runJournalCryptoSelfTest provider=expo-secure-store native_required=false react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized" + mobileReleaseMarkersText))
		case "/config":
			_, _ = w.Write([]byte("staging artifact EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging" + mobileReleaseMarkersText))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected native crypto artifact with wrong first provider binding to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoOmitsConcreteAssociatedDataSaltValues(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cryptoText string
	}{
		{
			name:       "empty salt id",
			cryptoText: "staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized" + mobileReleaseMarkersText,
		},
		{
			name:       "empty salt version",
			cryptoText: "staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized" + mobileReleaseMarkersText,
		},
		{
			name:       "zero salt version",
			cryptoText: "staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=0; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized" + mobileReleaseMarkersText,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/eas":
					_, _ = w.Write([]byte("staging artifact EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging" + mobileReleaseMarkersText))
				case "/crypto":
					_, _ = w.Write([]byte(tc.cryptoText))
				case "/config":
					_, _ = w.Write([]byte("staging artifact EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging" + mobileReleaseMarkersText))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			var output bytes.Buffer
			err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
			if err == nil {
				t.Fatalf("expected native crypto artifact without concrete associated-data salt values to fail:\n%s", output.String())
			}
			if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
				t.Fatalf("report missing crypto probe:\n%s", output.String())
			}
		})
	}
}

func TestRunFailsWhenMobileArtifactsOmitStagingProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM native smoke round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing staging provenance marker to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-eas-or-device-run") ||
		!strings.Contains(output.String(), "mobile-native-crypto-smoke") ||
		!strings.Contains(output.String(), "mobile-staging-config") {
		t.Fatalf("report missing mobile probe names:\n%s", output.String())
	}
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
		summary := strings.ToLower(probe.ResultSummary)
		for _, marker := range markers {
			if !strings.Contains(summary, strings.ToLower(marker)) {
				t.Fatalf("%s summary missing marker %q: %s", probe.Name, marker, probe.ResultSummary)
			}
		}
	}
	for name := range required {
		if !seen[name] {
			t.Fatalf("missing probe summary for %s", name)
		}
	}
}

func findProbe(t *testing.T, probes []probeResult, name string) probeResult {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == name {
			return probe
		}
	}
	t.Fatalf("missing probe %s: %+v", name, probes)
	return probeResult{}
}

func TestRunFailsWhenNativeCryptoUsesNodeShim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized using node:webcrypto"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected node shim crypto artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoUsesGenericNodeCrypto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized via Node crypto"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected generic Node crypto artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenConfigUsesHardcodedProductionSocket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.scriptureforge.com EXPO_PUBLIC_WS_BASE_URL=wss://api.scriptureforge.com EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected hardcoded production socket artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-staging-config") {
		t.Fatalf("report missing config probe:\n%s", output.String())
	}
}

func TestRunFailsWhenConfigUsesHardcodedProductionAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.scriptureforge.com EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.scriptureforge.ai EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected hardcoded production API artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-staging-config") {
		t.Fatalf("report missing config probe:\n%s", output.String())
	}
}

func TestRunFailsWhenArtifactLacksReleaseMarkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServerWithoutReleaseMarkers(t, server))
	if err == nil {
		t.Fatalf("expected missing release markers to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoLacksKeyLifecycleProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing key lifecycle proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoLacksAssociatedDataProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing associated-data proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoLacksAssociatedDataSaltProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing associated-data salt proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoLacksZeroizedBufferProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; salt wiped; plaintext cleared"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing zeroized-buffer proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoLacksProviderBindingProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded native-required true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing provider-binding proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoUsesFallbackWebCrypto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized via fallback WebCrypto"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected fallback WebCrypto artifact to fail:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoUsesJavaScriptFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized through JavaScript fallback"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected JavaScript fallback artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenNativeCryptoUsesBrowserWebCryptoFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized through browser WebCrypto globalThis.crypto crypto.subtle shim"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected browser WebCrypto fallback artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-native-crypto-smoke") {
		t.Fatalf("report missing crypto probe:\n%s", output.String())
	}
}

func TestRunFailsWhenEASArtifactLacksNativeDeviceProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing native-device proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-eas-or-device-run") {
		t.Fatalf("report missing EAS/device probe:\n%s", output.String())
	}
}

func TestRunFailsWhenEASArtifactLacksInstalledStagingAppProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing installed staging app proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-eas-or-device-run") {
		t.Fatalf("report missing EAS/device probe:\n%s", output.String())
	}
}

func TestRunFailsWhenEASArtifactIsDryRun(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, dry-run"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected dry-run EAS artifact to fail:\n%s", output.String())
	}
}

func TestRunFailsWhenEASArtifactUsesDevClientOrSimulator(t *testing.T) {
	for _, tc := range []struct {
		name    string
		easText string
	}{
		{
			name:    "dev client",
			easText: "EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, dev client",
		},
		{
			name:    "simulator validation",
			easText: "EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, simulator validation",
		},
		{
			name:    "Expo Go",
			easText: "EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, Expo Go",
		},
		{
			name:    "Android emulator",
			easText: "EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, Android emulator",
		},
		{
			name:    "remote debug",
			easText: "EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, remote debug",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/eas":
					_, _ = w.Write([]byte(tc.easText))
				case "/crypto":
					_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
				case "/config":
					_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
				}
			}))
			defer server.Close()

			var output bytes.Buffer
			err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
			if err == nil {
				t.Fatalf("expected dev-client/simulator EAS artifact to fail:\n%s", output.String())
			}
			if !strings.Contains(output.String(), "mobile-eas-or-device-run") {
				t.Fatalf("report missing EAS/device probe:\n%s", output.String())
			}
		})
	}
}

func TestRunFailsWhenConfigDoesNotRequireNativeCrypto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=false EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing native-required config to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-staging-config") {
		t.Fatalf("report missing config probe:\n%s", output.String())
	}
}

func TestRunFailsWhenConfigContainsContradictoryStagingCryptoMarkers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configText string
	}{
		{
			name:       "spaced disabled native crypto",
			configText: "staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = false",
		},
		{
			name:       "development deployment environment",
			configText: "staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=development",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/eas":
					_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
				case "/crypto":
					_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
				case "/config":
					_, _ = w.Write([]byte(tc.configText))
				}
			}))
			defer server.Close()

			var output bytes.Buffer
			err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
			if err == nil {
				t.Fatalf("expected contradictory staging config proof to fail:\n%s", output.String())
			}
			if !strings.Contains(output.String(), "mobile-staging-config") {
				t.Fatalf("report missing config probe:\n%s", output.String())
			}
		})
	}
}

func TestRunFailsWhenConfigLacksStagingDeploymentEnvironment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing staging deployment environment proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-staging-config") {
		t.Fatalf("report missing config probe:\n%s", output.String())
	}
}

func TestRunFailsWhenConfigUsesPrivateStagingEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation with installed app, release channel staging, expo profile staging, platforms=android,ios release_channel=staging expo_profile=staging, platforms=android,ios release_channel=staging expo_profile=staging"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true AES-GCM round-trip passed; unique_iv=true; unique IV; tamper rejected; associated data; wrong associated data rejected; associated_data_salt_id=journal:self-test:server-derived-salt; associated_data_salt_version=1; non-extractable key verified; provider-bound key; fallback-derived key rejected; key disposed; disposed handle rejected; revoked_key_rejected=true; stale raw key rejected; passphrase wiped; passphrase buffer zeroized; salt wiped; salt buffer zeroized; plaintext cleared; plaintext buffer zeroized"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://10.0.0.12 EXPO_PUBLIC_WS_BASE_URL=wss://192.168.1.20 EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingMobileConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected private staging endpoints to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-staging-config") {
		t.Fatalf("report missing config probe:\n%s", output.String())
	}
}

func TestRunRejectsLocalOrInsecureArtifactURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{
			name: "insecure eas artifact",
			edit: func(cfg *config) {
				cfg.EASArtifactURL = "http://mobile-artifacts.staging.scriptureforge.ai/mobile/eas"
			},
			want: "eas-artifact-url",
		},
		{
			name: "reserved example eas artifact",
			edit: func(cfg *config) {
				cfg.EASArtifactURL = "https://artifacts.staging.example/mobile/eas"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved example.com native crypto artifact",
			edit: func(cfg *config) {
				cfg.NativeCryptoSmokeURL = "https://artifacts.example.com/mobile/crypto"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved test config artifact",
			edit: func(cfg *config) {
				cfg.StagingConfigProofURL = "https://artifacts.staging.test/mobile/config"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "loopback native crypto artifact",
			edit: func(cfg *config) {
				cfg.NativeCryptoSmokeURL = "https://127.0.0.1/mobile/crypto"
			},
			want: "native-crypto-smoke-url",
		},
		{
			name: "private eas artifact",
			edit: func(cfg *config) {
				cfg.EASArtifactURL = "https://10.0.0.15/mobile/eas"
			},
			want: "eas-artifact-url",
		},
		{
			name: "IPv4-mapped private eas artifact",
			edit: func(cfg *config) {
				cfg.EASArtifactURL = "https://[::ffff:10.0.0.15]/mobile/eas"
			},
			want: "eas-artifact-url",
		},
		{
			name: "link-local native crypto artifact",
			edit: func(cfg *config) {
				cfg.NativeCryptoSmokeURL = "https://169.254.10.20/mobile/crypto"
			},
			want: "native-crypto-smoke-url",
		},
		{
			name: "unspecified staging config artifact",
			edit: func(cfg *config) {
				cfg.StagingConfigProofURL = "https://0.0.0.0/mobile/config"
			},
			want: "staging-config-proof-url",
		},
		{
			name: "localhost staging config artifact",
			edit: func(cfg *config) {
				cfg.StagingConfigProofURL = "https://localhost/mobile/config"
			},
			want: "staging-config-proof-url",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stagingMobileConfig(time.Second)
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
	return clientForHTTPServerWithReleaseMarkers(t, server, true)
}

func clientForHTTPServerWithoutReleaseMarkers(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	return clientForHTTPServerWithReleaseMarkers(t, server, false)
}

func clientForHTTPServerWithReleaseMarkers(t *testing.T, server *httptest.Server, appendReleaseMarkers bool) *http.Client {
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
			cloned.URL.Path = strings.TrimPrefix(cloned.URL.Path, "/mobile")
			resp, err := baseTransport.RoundTrip(cloned)
			if err != nil || resp == nil || !appendReleaseMarkers {
				return resp, err
			}
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return resp, nil
			}
			_ = resp.Body.Close()
			resp.Body = io.NopCloser(strings.NewReader(string(body) + mobileReleaseMarkersText))
			resp.ContentLength = -1
			resp.Header.Del("Content-Length")
			return resp, nil
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
