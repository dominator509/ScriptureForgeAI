package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"scriptureforge/internal/domain/abuse"
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

func TestRouteProfilesEnforceRateLimitsForAIJournalRoomsAndWebSocket(t *testing.T) {
	tests := []struct {
		name           string
		profileEnvName string
		profileEnvKey  string
		path           string
		method         string
		requiresDB     bool
	}{
		{
			name:           "ai",
			profileEnvName: abuse.ProfileAI,
			profileEnvKey:  "ABUSE_LIMIT_AI_REQUESTS",
			path:           "/api/v1/ai/generate/study",
			method:         http.MethodPost,
			requiresDB:     false,
		},
		{
			name:           "journal",
			profileEnvName: abuse.ProfileJournal,
			profileEnvKey:  "ABUSE_LIMIT_JOURNAL_REQUESTS",
			path:           "/api/v1/journal_entries",
			method:         http.MethodGet,
			requiresDB:     true,
		},
		{
			name:           "rooms",
			profileEnvName: abuse.ProfileRooms,
			profileEnvKey:  "ABUSE_LIMIT_ROOMS_REQUESTS",
			path:           "/api/v1/rooms/active",
			method:         http.MethodGet,
			requiresDB:     true,
		},
		{
			name:           "websocket",
			profileEnvName: abuse.ProfileWebSocket,
			profileEnvKey:  "ABUSE_LIMIT_WEBSOCKET_REQUESTS",
			path:           "/api/v1/rooms/stream/room-1",
			method:         http.MethodGet,
			requiresDB:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.requiresDB && os.Getenv("DATABASE_URL") == "" {
				t.Skip("DATABASE_URL required for DB-backed route profile assertion")
			}
			t.Setenv(test.profileEnvKey, "1")
			t.Setenv(test.profileEnvName+"_WINDOW_SECONDS", "60")
			t.Setenv("JWT_SECRET_KEY", "route-profile-test-secret")
			router := setupRoutes(nil, nil, nil)
			token, err := auth.GenerateToken("test-user-id", "test-org-id", "admin", time.Minute)
			if err != nil {
				t.Fatalf("generate token: %v", err)
			}
			remoteAddr := "192.0.2.10:49152"

			firstStatus, _, firstError := exerciseRouteRawWithMethodAndAuth(t, router, test.path, "", remoteAddr, test.method, token)
			if firstStatus == http.StatusTooManyRequests {
				t.Fatalf("%s first status = %d error = %#v, should be below limit", test.name, firstStatus, firstError)
			}

			secondStatus, secondHeaders, secondError := exerciseRouteRawWithMethodAndAuth(t, router, test.path, "", remoteAddr, test.method, token)
			if secondStatus != http.StatusTooManyRequests {
				t.Fatalf("%s second status = %d error = %#v, want 429", test.name, secondStatus, secondError)
			}
			if secondError.Category != "ABUSE_RATE_LIMIT_FAULT" || secondError.Code != http.StatusTooManyRequests {
				t.Fatalf("%s second error = %#v, want abuse rate-limit fault", test.name, secondError)
			}
			if got := secondHeaders.Get("Retry-After"); got == "" {
				t.Fatalf("%s missing Retry-After header", test.name)
			}
			if limit := secondHeaders.Get("X-RateLimit-Limit"); limit != "1" {
				t.Fatalf("%s X-RateLimit-Limit=%q, want 1", test.name, limit)
			}
			if remaining := secondHeaders.Get("X-RateLimit-Remaining"); remaining != "0" {
				t.Fatalf("%s X-RateLimit-Remaining=%q, want 0", test.name, remaining)
			}
			if reset := secondHeaders.Get("X-RateLimit-Reset"); reset == "" {
				t.Fatalf("%s missing X-RateLimit-Reset header", test.name)
			}
		})
	}
}

func TestWorkspaceSwitchRouteEnforcesOrgMatch(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "route-workspace-switch-secret")
	orgID := "55555555-5555-4555-8555-555555555555"
	router := setupRoutes(nil, nil, nil)
	token, err := auth.GenerateToken("member-user-id", orgID, "member", time.Minute)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/switch", strings.NewReader(`{"organization_id":"`+orgID+`"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	allowed := httptest.NewRecorder()
	router.ServeHTTP(allowed, request)
	if allowed.Code != http.StatusOK {
		t.Fatalf("/api/v1/workspaces/switch status = %d body = %q", allowed.Code, allowed.Body.String())
	}

	requestMismatch := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/switch", strings.NewReader(`{"organization_id":"55555555-0000-4555-8555-555555555555"}`))
	requestMismatch.Header.Set("Authorization", "Bearer "+token)
	forbidden := httptest.NewRecorder()
	router.ServeHTTP(forbidden, requestMismatch)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("workspace switch mismatch status = %d body = %q", forbidden.Code, forbidden.Body.String())
	}
}

func exerciseRouteRawWithMethodAndAuth(t *testing.T, handler http.Handler, path string, body string, remoteAddr string, method string, token string) (int, http.Header, auth.PlatformException) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	handler.ServeHTTP(recorder, request)

	var response auth.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode %s response %d %q: %v", path, recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, recorder.Header(), response
}

func exerciseRouteRawWithMethod(t *testing.T, handler http.Handler, path string, body string, remoteAddr string, method string) (int, http.Header, auth.PlatformException) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	handler.ServeHTTP(recorder, request)

	var response auth.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode %s response %d %q: %v", path, recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, recorder.Header(), response
}
