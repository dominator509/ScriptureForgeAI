package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunRequiresAPIBaseAndToken(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Attempts: 2, Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "api-base") {
		t.Fatalf("expected api-base error, got %v", err)
	}
}

func TestRunEmitsAbuseEvidenceWhenAllProfilesRateLimit(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/login" && r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		counts[r.URL.Path]++
		count := counts[r.URL.Path]
		mu.Unlock()
		if count >= 2 {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("X-RateLimit-Limit", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:     server.URL,
		BearerToken: "token",
		Origin:      "https://app.staging.example",
		Attempts:    3,
		Timeout:     time.Second,
	}, &output, server.Client())
	if err != nil {
		t.Fatalf("abuse probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if len(result.EvidenceItems) != 1 || result.EvidenceItems[0] != "ABUSE-LIMIT-001" {
		t.Fatalf("unexpected evidence items: %+v", result.EvidenceItems)
	}
	for _, probe := range result.Probes {
		if probe.StatusCode != http.StatusTooManyRequests || probe.RetryAfter == "" || probe.RateLimit == "" {
			t.Fatalf("probe did not capture rate-limit headers: %+v", probe)
		}
	}
}

func TestRunFailsWhenRateLimitHeadersAreMissing(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:     server.URL,
		BearerToken: "token",
		Attempts:    2,
		Timeout:     time.Second,
	}, &output, server.Client())
	if err == nil {
		t.Fatalf("expected missing headers to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenNoRateLimitObserved(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strconv.Itoa(len(r.URL.Path))))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:     server.URL,
		BearerToken: "token",
		Attempts:    2,
		Timeout:     time.Second,
	}, &output, server.Client())
	if err == nil {
		t.Fatalf("expected no-rate-limit run to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "no 429 observed") {
		t.Fatalf("report missing no-429 summary:\n%s", output.String())
	}
}
