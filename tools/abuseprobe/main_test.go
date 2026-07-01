package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const abuseReleaseCandidate = "abc123"
const abuseServiceVersion = "scriptureforge-api:abc123"
const abuseLoadRunID = "abuse-load-run-123"

func TestRunRequiresAPIBaseAndToken(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Attempts: 2, Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "api-base") {
		t.Fatalf("expected api-base error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:           "https://api-abuse.staging.scriptureforge.ai",
		BearerToken:       "token",
		Origin:            "https://app-abuse.staging.scriptureforge.ai",
		ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
		Attempts:          2,
		Timeout:           time.Second,
	}, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "release-candidate and service-version") {
		t.Fatalf("expected release identity error, got %v", err)
	}
}

func TestRunEmitsAbuseEvidenceWhenAllProfilesRateLimit(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	accountForwardedFor := map[string]bool{}
	webSocketUpgradeSeen := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/abuse/config.txt" {
			_, _ = w.Write([]byte(validAbuseConfigArtifact()))
			return
		}
		if r.URL.Path != "/api/v1/auth/login" && r.URL.Path != "/api/v1/auth/refresh" && r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		probeName := r.Header.Get("X-ScriptureForge-Probe")
		if probeName == "" {
			probeName = r.URL.Path
		}
		if r.URL.Path == "/api/v1/rooms/stream/abuse-probe-room" {
			if r.Header.Get("Origin") != "https://app-abuse.staging.scriptureforge.ai" ||
				!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
				!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") ||
				r.Header.Get("Sec-WebSocket-Version") != "13" ||
				r.Header.Get("Sec-WebSocket-Key") == "" {
				w.WriteHeader(http.StatusUpgradeRequired)
				return
			}
			mu.Lock()
			webSocketUpgradeSeen = true
			mu.Unlock()
		}
		mu.Lock()
		counts[probeName]++
		count := counts[probeName]
		if probeName == "auth-account-rate-limit" {
			accountForwardedFor[r.Header.Get("X-Forwarded-For")] = true
		}
		mu.Unlock()
		if count >= 2 {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("X-RateLimit-Limit", "1")
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1782403200")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:           "https://api-abuse.staging.scriptureforge.ai",
		BearerToken:       "token",
		Origin:            "https://app-abuse.staging.scriptureforge.ai",
		ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
		ReleaseCandidate:  abuseReleaseCandidate,
		ServiceVersion:    abuseServiceVersion,
		LoadRunID:         abuseLoadRunID,
		Attempts:          3,
		Timeout:           time.Second,
	}, &output, clientForTLSServer(t, server))
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
	if result.ConfigArtifact != "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt" {
		t.Fatalf("unexpected config artifact: %q", result.ConfigArtifact)
	}
	if result.WebOrigin != "https://app-abuse.staging.scriptureforge.ai" {
		t.Fatalf("unexpected web origin: %q", result.WebOrigin)
	}
	if !result.ConfigArtifactVerified || !strings.Contains(result.ConfigArtifactSummary, "ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS") || !strings.Contains(result.ConfigArtifactSummary, "distinct_abuse_artifacts=true") {
		t.Fatalf("config artifact verification missing: %+v", result)
	}
	if result.ReleaseCandidate != abuseReleaseCandidate || result.ServiceVersion != abuseServiceVersion {
		t.Fatalf("unexpected release identity: %+v", result)
	}
	if result.LoadRunID != abuseLoadRunID {
		t.Fatalf("unexpected load run identity: %+v", result)
	}
	mu.Lock()
	upgradeSeen := webSocketUpgradeSeen
	rotatedAccountForwardedFor := len(accountForwardedFor)
	mu.Unlock()
	if !upgradeSeen {
		t.Fatal("websocket probe did not send a WebSocket upgrade request")
	}
	if rotatedAccountForwardedFor < 2 {
		t.Fatalf("auth account probe did not rotate forwarded client IP headers, saw %d unique values", rotatedAccountForwardedFor)
	}
	for _, probe := range result.Probes {
		if probe.StatusCode != http.StatusTooManyRequests || probe.RetryAfter == "" || probe.RateLimit == "" || probe.RateRemaining == "" || probe.RateReset == "" {
			t.Fatalf("probe did not capture rate-limit headers: %+v", probe)
		}
		if probe.Name == "auth-account-rate-limit" {
			if !probe.AccountScoped || !probe.ForwardedClientIPRotated {
				t.Fatalf("auth account probe did not capture structured account/forwarded-IP proof: %+v", probe)
			}
		}
		if probe.Name == "auth-refresh-rate-limit" && !probe.RefreshTokenScoped {
			t.Fatalf("auth refresh probe did not capture structured refresh-token proof: %+v", probe)
		}
		if probe.Name == "websocket-rate-limit" && !probe.WebSocketUpgrade {
			t.Fatalf("websocket probe did not capture structured upgrade proof: %+v", probe)
		}
		for _, marker := range abuseSummaryMarkers(endpointProbe{Name: probe.Name, WebSocketUpgrade: probe.Name == "websocket-rate-limit"}) {
			if !strings.Contains(strings.ToLower(probe.ResultSummary), strings.ToLower(marker)) {
				t.Fatalf("probe %s result summary missing marker %q: %s", probe.Name, marker, probe.ResultSummary)
			}
		}
		for _, marker := range []string{"release_candidate=" + abuseReleaseCandidate, "service_version=" + abuseServiceVersion, "load_run_id=" + abuseLoadRunID} {
			if !strings.Contains(probe.ResultSummary, marker) {
				t.Fatalf("probe %s result summary missing release marker %q: %s", probe.Name, marker, probe.ResultSummary)
			}
		}
		if _, err := strconv.Atoi(probe.RetryAfter); err != nil {
			t.Fatalf("probe %s Retry-After is not an integer: %q", probe.Name, probe.RetryAfter)
		}
		if _, err := strconv.Atoi(probe.RateLimit); err != nil {
			t.Fatalf("probe %s X-RateLimit-Limit is not an integer: %q", probe.Name, probe.RateLimit)
		}
		if _, err := strconv.Atoi(probe.RateRemaining); err != nil {
			t.Fatalf("probe %s X-RateLimit-Remaining is not an integer: %q", probe.Name, probe.RateRemaining)
		}
		if _, err := strconv.Atoi(probe.RateReset); err != nil {
			t.Fatalf("probe %s X-RateLimit-Reset is not an integer: %q", probe.Name, probe.RateReset)
		}
	}
}

func TestRunFailsWhenRateLimitHeadersAreMissing(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/abuse/config.txt" {
			_, _ = w.Write([]byte(validAbuseConfigArtifact()))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:           "https://api-abuse.staging.scriptureforge.ai",
		BearerToken:       "token",
		Origin:            "https://app-abuse.staging.scriptureforge.ai",
		ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
		ReleaseCandidate:  abuseReleaseCandidate,
		ServiceVersion:    abuseServiceVersion,
		LoadRunID:         abuseLoadRunID,
		Attempts:          2,
		Timeout:           time.Second,
	}, &output, clientForTLSServer(t, server))
	if err == nil {
		t.Fatalf("expected missing headers to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunRequiresLoadRunID(t *testing.T) {
	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:           "https://api-abuse.staging.scriptureforge.ai",
		BearerToken:       "token",
		Origin:            "https://app-abuse.staging.scriptureforge.ai",
		ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
		ReleaseCandidate:  abuseReleaseCandidate,
		ServiceVersion:    abuseServiceVersion,
		Attempts:          2,
		Timeout:           time.Second,
	}, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "load-run-id") {
		t.Fatalf("expected load-run-id error, got %v", err)
	}
}

func TestRunFailsWhenRateLimitAppearsBeforeRepeatedAttempts(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/abuse/config.txt" {
			_, _ = w.Write([]byte(validAbuseConfigArtifact()))
			return
		}
		w.Header().Set("Retry-After", "60")
		w.Header().Set("X-RateLimit-Limit", "1")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1782403200")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:           "https://api-abuse.staging.scriptureforge.ai",
		BearerToken:       "token",
		Origin:            "https://app-abuse.staging.scriptureforge.ai",
		ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
		ReleaseCandidate:  abuseReleaseCandidate,
		ServiceVersion:    abuseServiceVersion,
		LoadRunID:         abuseLoadRunID,
		Attempts:          2,
		Timeout:           time.Second,
	}, &output, clientForTLSServer(t, server))
	if err == nil {
		t.Fatalf("expected first-attempt 429 to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "before repeated attempts") {
		t.Fatalf("report missing repeated-attempt failure summary:\n%s", output.String())
	}
}

func TestRunFailsWhenRateLimitHeadersHaveWeakValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		header    string
		value     string
		wantProbe string
	}{
		{name: "zero retry after", header: "Retry-After", value: "0", wantProbe: "auth-rate-limit"},
		{name: "zero limit", header: "X-RateLimit-Limit", value: "0", wantProbe: "auth-rate-limit"},
		{name: "remaining not exhausted", header: "X-RateLimit-Remaining", value: "1", wantProbe: "auth-rate-limit"},
		{name: "zero reset", header: "X-RateLimit-Reset", value: "0", wantProbe: "auth-rate-limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			seen := map[string]int{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/abuse/config.txt" {
					_, _ = w.Write([]byte(validAbuseConfigArtifact()))
					return
				}
				mu.Lock()
				seen[r.URL.Path]++
				attempt := seen[r.URL.Path]
				mu.Unlock()
				if attempt == 1 {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Retry-After", "60")
				w.Header().Set("X-RateLimit-Limit", "1")
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", "1782403200")
				w.Header().Set(tc.header, tc.value)
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer server.Close()

			var output bytes.Buffer
			err := runWithClient(config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			}, &output, clientForTLSServer(t, server))
			if err == nil {
				t.Fatalf("expected weak rate-limit header values to fail:\n%s", output.String())
			}
			if !strings.Contains(output.String(), tc.wantProbe) || !strings.Contains(output.String(), "got 429 without required rate-limit headers") {
				t.Fatalf("report missing weak-header failure summary:\n%s", output.String())
			}
		})
	}
}

func TestRunFailsWhenNoRateLimitObserved(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/abuse/config.txt" {
			_, _ = w.Write([]byte(validAbuseConfigArtifact()))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strconv.Itoa(len(r.URL.Path))))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:           "https://api-abuse.staging.scriptureforge.ai",
		BearerToken:       "token",
		Origin:            "https://app-abuse.staging.scriptureforge.ai",
		ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
		ReleaseCandidate:  abuseReleaseCandidate,
		ServiceVersion:    abuseServiceVersion,
		LoadRunID:         abuseLoadRunID,
		Attempts:          2,
		Timeout:           time.Second,
	}, &output, clientForTLSServer(t, server))
	if err == nil {
		t.Fatalf("expected no-rate-limit run to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "no 429 observed") {
		t.Fatalf("report missing no-429 summary:\n%s", output.String())
	}
}

func TestRunRequiresConfigArtifactURL(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:          "https://api-abuse.staging.scriptureforge.ai",
		BearerToken:      "token",
		Origin:           "https://app-abuse.staging.scriptureforge.ai",
		ReleaseCandidate: abuseReleaseCandidate,
		ServiceVersion:   abuseServiceVersion,
		LoadRunID:        abuseLoadRunID,
		Attempts:         2,
		Timeout:          time.Second,
	}, &output, clientForTLSServer(t, server))
	if err == nil || !strings.Contains(err.Error(), "config-artifact-url") {
		t.Fatalf("expected config artifact URL error, got %v", err)
	}
}

func TestRunRequiresOriginForWebSocketProbe(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/abuse/config.txt" {
			_, _ = w.Write([]byte(validAbuseConfigArtifact()))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:           "https://api-abuse.staging.scriptureforge.ai",
		BearerToken:       "token",
		ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
		ReleaseCandidate:  abuseReleaseCandidate,
		ServiceVersion:    abuseServiceVersion,
		LoadRunID:         abuseLoadRunID,
		Attempts:          2,
		Timeout:           time.Second,
	}, &output, clientForTLSServer(t, server))
	if err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("expected origin error, got %v", err)
	}
}

func TestRunRejectsLocalEvidenceTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config
		want string
	}{
		{
			name: "api base",
			cfg: config{
				APIBase:           "https://localhost:8443",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "api-base must use a non-local, non-private staging host",
		},
		{
			name: "private api base",
			cfg: config{
				APIBase:           "https://10.0.0.25",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "api-base must use a non-local, non-private staging host",
		},
		{
			name: "IPv4-mapped private api base",
			cfg: config{
				APIBase:           "https://[::ffff:10.0.0.25]",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "api-base must use a non-local, non-private staging host",
		},
		{
			name: "origin",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://127.0.0.1:3000",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "origin must use a non-local, non-private staging host",
		},
		{
			name: "private origin",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://172.16.20.5",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "origin must use a non-local, non-private staging host",
		},
		{
			name: "config artifact",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://[::1]/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "config-artifact-url",
		},
		{
			name: "config artifact hosted on api base",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://api-abuse.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "distinct evidence host from api-base",
		},
		{
			name: "config artifact hosted on api base alias",
			cfg: config{
				APIBase:           "https://API-Abuse.Staging.ScriptureForge.AI.",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://api-abuse.staging.scriptureforge.ai./abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "distinct evidence host from api-base",
		},
		{
			name: "config artifact hosted on origin",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://app-abuse.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "distinct evidence host from origin",
		},
		{
			name: "config artifact hosted on origin alias",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://APP-Abuse.Staging.ScriptureForge.AI.",
				ConfigArtifactURL: "https://app-abuse.staging.scriptureforge.ai./abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "distinct evidence host from origin",
		},
		{
			name: "private config artifact",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://192.168.100.30/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "non-private staging host",
		},
		{
			name: "IPv4-mapped private config artifact",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://[::ffff:192.168.100.30]/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "non-private staging host",
		},
		{
			name: "reserved example api base",
			cfg: config{
				APIBase:           "https://api.staging.example",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "api-base must not use a reserved placeholder staging host",
		},
		{
			name: "reserved example.com origin",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app.example.com",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "origin must not use a reserved placeholder staging host",
		},
		{
			name: "reserved test config artifact",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://abuse-artifacts.staging.test/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "reserved placeholder staging host",
		},
		{
			name: "reserved invalid config artifact",
			cfg: config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://abuse-artifacts.invalid/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			},
			want: "reserved placeholder staging host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := runWithClient(tc.cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestRunRejectsWeakConfigArtifact(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing profile marker",
			body: strings.ReplaceAll(validAbuseConfigArtifact(), "ABUSE_LIMIT_WEBSOCKET_REQUESTS", ""),
			want: "config artifact missing required staging markers",
		},
		{
			name: "missing concrete assignment marker",
			body: strings.ReplaceAll(validAbuseConfigArtifact(), "ABUSE_LIMIT_AI_REQUESTS=2", "ABUSE_LIMIT_AI_REQUESTS"),
			want: "config artifact missing required staging markers",
		},
		{
			name: "trust proxy headers not enabled",
			body: strings.ReplaceAll(validAbuseConfigArtifact(), "TRUST_PROXY_HEADERS=true", "TRUST_PROXY_HEADERS=false"),
			want: "config artifact missing required staging markers",
		},
		{
			name: "zero limiter assignment",
			body: strings.ReplaceAll(validAbuseConfigArtifact(), "ABUSE_LIMIT_AI_REQUESTS=2", "ABUSE_LIMIT_AI_REQUESTS=0"),
			want: "config artifact assignment ABUSE_LIMIT_AI_REQUESTS must be a positive integer",
		},
		{
			name: "mock artifact",
			body: validAbuseConfigArtifact() + "\nmock dry-run",
			want: "config artifact contains forbidden",
		},
		{
			name: "secret leak",
			body: validAbuseConfigArtifact() + "\nOPENAI_API_KEY=sk-test",
			want: "config artifact contains forbidden",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/abuse/config.txt" {
					_, _ = w.Write([]byte(tc.body))
					return
				}
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer server.Close()

			var output bytes.Buffer
			err := runWithClient(config{
				APIBase:           "https://api-abuse.staging.scriptureforge.ai",
				BearerToken:       "token",
				Origin:            "https://app-abuse.staging.scriptureforge.ai",
				ConfigArtifactURL: "https://abuse-artifacts.staging.scriptureforge.ai/abuse/config.txt",
				ReleaseCandidate:  abuseReleaseCandidate,
				ServiceVersion:    abuseServiceVersion,
				LoadRunID:         abuseLoadRunID,
				Attempts:          2,
				Timeout:           time.Second,
			}, &output, clientForTLSServer(t, server))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func clientForTLSServer(t *testing.T, server *httptest.Server) *http.Client {
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
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

func validAbuseConfigArtifact() string {
	return strings.Join([]string{
		"staging artifact",
		"redacted",
		"ABUSE_LIMIT_AUTH_REQUESTS=2",
		"ABUSE_LIMIT_AUTH_WINDOW_SECONDS=60",
		"ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=2",
		"ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=60",
		"ABUSE_LIMIT_AI_REQUESTS=2",
		"ABUSE_LIMIT_JOURNAL_REQUESTS=2",
		"ABUSE_LIMIT_ROOMS_REQUESTS=2",
		"ABUSE_LIMIT_WEBSOCKET_REQUESTS=2",
		"ABUSE_LIMIT_MAX_BUCKETS=1000",
		"TRUST_PROXY_HEADERS=true",
		"trusted headers: X-Forwarded-For X-Real-IP",
		"release_candidate=" + abuseReleaseCandidate,
		"service_version=" + abuseServiceVersion,
		"load_run_id=" + abuseLoadRunID,
	}, "\n")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
