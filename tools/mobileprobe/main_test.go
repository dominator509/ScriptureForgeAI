package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresAllArtifacts(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "mobile proof requires") {
		t.Fatalf("expected artifact requirement error, got %v", err)
	}
}

func TestRunEmitsMobileEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios native device validation"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto AES-GCM native smoke round-trip passed; tamper rejected"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		EASArtifactURL:        server.URL + "/eas",
		NativeCryptoSmokeURL:  server.URL + "/crypto",
		StagingConfigProofURL: server.URL + "/config",
		Timeout:               time.Second,
	}, &output)
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
}

func TestRunFailsWhenNativeCryptoUsesNodeShim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto AES-GCM round-trip passed; tamper rejected using node:webcrypto"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.example"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		EASArtifactURL:        server.URL + "/eas",
		NativeCryptoSmokeURL:  server.URL + "/crypto",
		StagingConfigProofURL: server.URL + "/config",
		Timeout:               time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected node shim crypto artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenConfigUsesHardcodedProductionSocket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eas":
			_, _ = w.Write([]byte("EAS build finished successfully for android and ios"))
		case "/crypto":
			_, _ = w.Write([]byte("react-native-quick-crypto AES-GCM round-trip passed; tamper rejected"))
		case "/config":
			_, _ = w.Write([]byte("staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.example EXPO_PUBLIC_WS_BASE_URL=wss://api.scriptureforge.com"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		EASArtifactURL:        server.URL + "/eas",
		NativeCryptoSmokeURL:  server.URL + "/crypto",
		StagingConfigProofURL: server.URL + "/config",
		Timeout:               time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected hardcoded production socket artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "mobile-staging-config") {
		t.Fatalf("report missing config probe:\n%s", output.String())
	}
}
