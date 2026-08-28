package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtectedMetricsHandlerAllowsExplicitLocalModesWithoutToken(t *testing.T) {
	for _, environment := range []string{"", "development", "dev", "test", "local"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_ENVIRONMENT", environment)
			t.Setenv("METRICS_AUTH_TOKEN", "")
			handler := protectedMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if recorder.Code != http.StatusNoContent {
				t.Fatalf("local metrics status = %d, want 204", recorder.Code)
			}
		})
	}
}

func TestProtectedMetricsHandlerFailsClosedWhenStrictTokenIsMissing(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
	t.Setenv("METRICS_AUTH_TOKEN", "")
	called := false
	handler := protectedMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("missing strict metrics token status = %d called=%t, want 503 without handler execution", recorder.Code, called)
	}
	if strings.Contains(recorder.Body.String(), "METRICS_AUTH_TOKEN") {
		t.Fatalf("missing-token response exposed configuration details: %q", recorder.Body.String())
	}
}

func TestProtectedMetricsHandlerRejectsInvalidStrictToken(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "staging")
	t.Setenv("METRICS_AUTH_TOKEN", "metrics-secret-0123456789")
	handler := protectedMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, authorization := range []string{"", "Basic metrics-secret-0123456789", "Bearer wrong-token", "Bearer metrics-secret-0123456789 extra"} {
		t.Run(authorization, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			request.Header.Set("Authorization", authorization)
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("authorization %q status = %d, want 401", authorization, recorder.Code)
			}
			if recorder.Header().Get("WWW-Authenticate") != `Bearer realm="metrics"` {
				t.Fatalf("authorization %q missing bearer challenge", authorization)
			}
		})
	}
}

func TestProtectedMetricsHandlerAcceptsStrictBearerToken(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
	t.Setenv("METRICS_AUTH_TOKEN", "metrics-secret-0123456789")
	called := false
	handler := protectedMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer metrics-secret-0123456789")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("valid bearer status = %d called=%t, want 204 and handler execution", recorder.Code, called)
	}
}

func TestProtectedMetricsHandlerTreatsUnknownEnvironmentAsStrict(t *testing.T) {
	if !requiresConfiguredMetricsAuthForEnvironment("production-blue") {
		t.Fatal("unknown non-local environment must require metrics authentication")
	}
	if requiresConfiguredMetricsAuthForEnvironment("development") {
		t.Fatal("development must retain explicit local metrics behavior")
	}
}
