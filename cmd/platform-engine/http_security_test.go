package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadAllowedBrowserOriginsFailsClosedInStrictEnvironments(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
	t.Setenv("ALLOWED_WS_ORIGINS", "")
	if _, errConfig := loadAllowedBrowserOrigins(); errConfig == nil || !strings.Contains(errConfig.Message, "ALLOWED_WS_ORIGINS") {
		t.Fatalf("loadAllowedBrowserOrigins error = %#v, want missing strict origin configuration", errConfig)
	}

	t.Setenv("ALLOWED_WS_ORIGINS", "http://app.production.scriptureforge.ai")
	if _, errConfig := loadAllowedBrowserOrigins(); errConfig == nil {
		t.Fatal("loadAllowedBrowserOrigins accepted a non-HTTPS strict origin")
	}

	t.Setenv("ALLOWED_WS_ORIGINS", "https://app.production.scriptureforge.ai")
	origins, errConfig := loadAllowedBrowserOrigins()
	if errConfig != nil {
		t.Fatalf("loadAllowedBrowserOrigins rejected valid strict origin: %v", errConfig)
	}
	if _, ok := origins["https://app.production.scriptureforge.ai"]; !ok {
		t.Fatalf("origins = %#v, want normalized production origin", origins)
	}
}

func TestAPISecurityMiddlewareSetsHeadersAndHandlesCredentialedPreflight(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "development")
	t.Setenv("ALLOWED_WS_ORIGINS", "http://localhost:3000")
	called := false
	handler := apiSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	request.Header.Set("Origin", "http://localhost:3000")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !called {
		t.Fatalf("allowed browser request status=%d called=%t", recorder.Code, called)
	}
	for name, want := range map[string]string{
		"Access-Control-Allow-Origin":      "http://localhost:3000",
		"Access-Control-Allow-Credentials": "true",
		"X-Content-Type-Options":           "nosniff",
		"X-Frame-Options":                  "DENY",
		"Referrer-Policy":                  "no-referrer",
		"Cache-Control":                    "no-store",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("header %s=%q, want %q", name, got, want)
		}
	}

	called = false
	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	preflight.Header.Set("Origin", "http://localhost:3000")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
	preflight.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type, X-ScriptureForge-Client")
	preflightRecorder := httptest.NewRecorder()
	handler.ServeHTTP(preflightRecorder, preflight)
	if preflightRecorder.Code != http.StatusNoContent || called {
		t.Fatalf("preflight status=%d called=%t, want 204 without route execution", preflightRecorder.Code, called)
	}
	if preflightRecorder.Header().Get("Access-Control-Allow-Methods") != allowedCORSMethods {
		t.Fatalf("preflight methods=%q, want %q", preflightRecorder.Header().Get("Access-Control-Allow-Methods"), allowedCORSMethods)
	}
}

func TestAPISecurityMiddlewareRejectsForeignOriginsAndUnknownPreflightHeaders(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "development")
	t.Setenv("ALLOWED_WS_ORIGINS", "http://localhost:3000")
	handler := apiSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	foreign := httptest.NewRequest(http.MethodPost, "/api/v1/journal_entries", nil)
	foreign.Header.Set("Origin", "https://foreign.example.net")
	foreignRecorder := httptest.NewRecorder()
	handler.ServeHTTP(foreignRecorder, foreign)
	if foreignRecorder.Code != http.StatusForbidden || !strings.Contains(foreignRecorder.Body.String(), "origin_not_allowed") {
		t.Fatalf("foreign origin status=%d body=%q, want 403 origin_not_allowed", foreignRecorder.Code, foreignRecorder.Body.String())
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	preflight.Header.Set("Origin", "http://localhost:3000")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
	preflight.Header.Set("Access-Control-Request-Headers", "X-Unexpected-Header")
	preflightRecorder := httptest.NewRecorder()
	handler.ServeHTTP(preflightRecorder, preflight)
	if preflightRecorder.Code != http.StatusForbidden {
		t.Fatalf("unknown preflight header status=%d, want 403", preflightRecorder.Code)
	}
}

func TestAPISecurityMiddlewareAllowsNativeRequestsWithoutOrigin(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "development")
	t.Setenv("ALLOWED_WS_ORIGINS", "http://localhost:3000")
	handler := apiSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "/api/v1/journal_entries", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("native request status=%d, want 204", recorder.Code)
	}
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("native request unexpectedly received a CORS allow-origin header")
	}
}
