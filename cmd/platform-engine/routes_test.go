package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scriptureforge/internal/domain/auth"
)

func exerciseRoute(t *testing.T, handler http.Handler, path string, body string) (int, auth.PlatformException) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.RemoteAddr = "203.0.113.25:49152"
	handler.ServeHTTP(recorder, request)

	var response auth.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode %s response %d %q: %v", path, recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, response
}

func exerciseRouteRaw(t *testing.T, handler http.Handler, path string, body string, remoteAddr string) (int, http.Header, auth.PlatformException) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	handler.ServeHTTP(recorder, request)

	var response auth.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode %s response %d %q: %v", path, recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, recorder.Header(), response
}

func TestLegacyAuthRoutesUseCanonicalValidation(t *testing.T) {
	router := setupRoutes(nil, nil, nil)

	tests := []struct {
		name          string
		canonicalPath string
		legacyPath    string
		body          string
	}{
		{
			name:          "register",
			canonicalPath: "/api/v1/auth/register",
			legacyPath:    "/api/auth/register",
			body:          `{"email":"not-an-email","password":"short","organization_id":""}`,
		},
		{
			name:          "login",
			canonicalPath: "/api/v1/auth/login",
			legacyPath:    "/api/auth/login",
			body:          `{"email":"member@example.test","password":"password-without-org"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonicalStatus, canonicalError := exerciseRoute(t, router, tt.canonicalPath, tt.body)
			legacyStatus, legacyError := exerciseRoute(t, router, tt.legacyPath, tt.body)

			if legacyStatus != canonicalStatus {
				t.Fatalf("legacy status = %d, canonical status = %d", legacyStatus, canonicalStatus)
			}
			if legacyError.Category != canonicalError.Category || legacyError.Message != canonicalError.Message || legacyError.Code != canonicalError.Code {
				t.Fatalf("legacy error = %#v, canonical error = %#v", legacyError, canonicalError)
			}
		})
	}
}

func TestHealthRoutesExposeLivenessAndDependencyReadiness(t *testing.T) {
	router := setupRoutes(nil, nil, nil)

	liveRecorder := httptest.NewRecorder()
	router.ServeHTTP(liveRecorder, httptest.NewRequest(http.MethodGet, "/live", nil))
	if liveRecorder.Code != http.StatusOK {
		t.Fatalf("/live status = %d body = %q", liveRecorder.Code, liveRecorder.Body.String())
	}
	if !strings.Contains(liveRecorder.Body.String(), `"status":"ok"`) {
		t.Fatalf("/live body = %q", liveRecorder.Body.String())
	}

	readyRecorder := httptest.NewRecorder()
	router.ServeHTTP(readyRecorder, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if readyRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ready status = %d body = %q, want 503 without dependencies", readyRecorder.Code, readyRecorder.Body.String())
	}
	if !strings.Contains(readyRecorder.Body.String(), "dependencies_not_configured") {
		t.Fatalf("/ready body = %q", readyRecorder.Body.String())
	}
}

func TestMountedAuthRoutesEnforceAbuseRateLimit(t *testing.T) {
	t.Setenv("ABUSE_LIMIT_AUTH_REQUESTS", "1")
	t.Setenv("ABUSE_LIMIT_AUTH_WINDOW_SECONDS", "60")
	router := setupRoutes(nil, nil, nil)
	body := `{"email":"member@example.test","password":"password-without-org"}`
	remoteAddr := "198.51.100.10:49152"

	firstStatus, _, firstError := exerciseRouteRaw(t, router, "/api/v1/auth/login", body, remoteAddr)
	if firstStatus != http.StatusBadRequest {
		t.Fatalf("first auth request status = %d error = %#v, want validation 400", firstStatus, firstError)
	}

	secondStatus, headers, secondError := exerciseRouteRaw(t, router, "/api/v1/auth/login", body, remoteAddr)
	if secondStatus != http.StatusTooManyRequests {
		t.Fatalf("second auth request status = %d error = %#v, want 429", secondStatus, secondError)
	}
	if secondError.Category != "ABUSE_RATE_LIMIT_FAULT" || secondError.Code != http.StatusTooManyRequests {
		t.Fatalf("second auth error = %#v, want abuse rate-limit fault", secondError)
	}
	if headers.Get("Retry-After") == "" || headers.Get("X-RateLimit-Limit") != "1" {
		t.Fatalf("rate-limit headers Retry-After=%q X-RateLimit-Limit=%q", headers.Get("Retry-After"), headers.Get("X-RateLimit-Limit"))
	}

	otherClientStatus, _, otherClientError := exerciseRouteRaw(t, router, "/api/v1/auth/login", body, "198.51.100.11:49152")
	if otherClientStatus != http.StatusBadRequest {
		t.Fatalf("other client status = %d error = %#v, want independent validation 400", otherClientStatus, otherClientError)
	}
}

func TestLegacyAuthAliasSharesCanonicalAbuseBucket(t *testing.T) {
	t.Setenv("ABUSE_LIMIT_AUTH_REQUESTS", "1")
	t.Setenv("ABUSE_LIMIT_AUTH_WINDOW_SECONDS", "60")
	router := setupRoutes(nil, nil, nil)
	body := `{"email":"member@example.test","password":"password-without-org"}`
	remoteAddr := "198.51.100.12:49152"

	canonicalStatus, _, canonicalError := exerciseRouteRaw(t, router, "/api/v1/auth/login", body, remoteAddr)
	if canonicalStatus != http.StatusBadRequest {
		t.Fatalf("canonical auth status = %d error = %#v, want validation 400", canonicalStatus, canonicalError)
	}

	legacyStatus, _, legacyError := exerciseRouteRaw(t, router, "/api/auth/login", body, remoteAddr)
	if legacyStatus != http.StatusTooManyRequests {
		t.Fatalf("legacy auth alias status = %d error = %#v, want shared bucket 429", legacyStatus, legacyError)
	}
	if legacyError.Category != "ABUSE_RATE_LIMIT_FAULT" {
		t.Fatalf("legacy auth alias error = %#v, want abuse rate-limit fault", legacyError)
	}
}
