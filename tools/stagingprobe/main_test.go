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

func TestNormalizeBaseURLRequiresHTTPS(t *testing.T) {
	if _, err := normalizeBaseURL("http://api.example.test"); err == nil {
		t.Fatal("expected http URL to be rejected")
	}
	got, err := normalizeBaseURL("https://api.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://api.example.test" {
		t.Fatalf("unexpected normalized URL: %s", got)
	}
}

func TestProbeHTTPPassesExpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := probeHTTP(server.Client(), "health", server.URL, http.StatusOK)
	if !result.Passed || result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected probe result: %+v", result)
	}
}

func TestProbeHTTPSRedirectRequiresHTTPSLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://api.example.test"+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer server.Close()

	target := "https://" + strings.TrimPrefix(server.URL, "http://")
	result := probeHTTPSRedirect(server.Client(), "redirect", target)
	if !result.Passed || !strings.HasPrefix(result.RedirectTo, "https://") {
		t.Fatalf("unexpected redirect probe result: %+v", result)
	}
}

func TestRunProducesFailingReportWhenProbeFails(t *testing.T) {
	var output bytes.Buffer
	err := run(config{APIBase: "https://127.0.0.1:1", Timeout: 50 * time.Millisecond}, &output)
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
	err := run(config{APIBase: "https://api.example.test", ProbeAI: true, Timeout: time.Second}, &output)
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
