package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFHandlerIssuesReadableStrictCookie(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "development")

	first := httptest.NewRecorder()
	csrfHandler(first, httptest.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("csrf GET status=%d, want 200", first.Code)
	}
	var body struct {
		Token string `json:"csrf_token"`
	}
	if err := json.NewDecoder(first.Body).Decode(&body); err != nil {
		t.Fatalf("decode csrf response: %v", err)
	}
	if !validCSRFToken(body.Token) {
		t.Fatalf("csrf token %q is invalid", body.Token)
	}
	cookies := first.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("csrf cookies=%d, want one", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != csrfCookieName || cookie.Value != body.Token || cookie.Path != "/" || cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("csrf cookie=%#v, want readable strict root cookie", cookie)
	}

	reuse := httptest.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	reuse.AddCookie(cookie)
	reuseRecorder := httptest.NewRecorder()
	csrfHandler(reuseRecorder, reuse)
	var reusedBody struct {
		Token string `json:"csrf_token"`
	}
	if err := json.NewDecoder(reuseRecorder.Body).Decode(&reusedBody); err != nil {
		t.Fatalf("decode reused csrf response: %v", err)
	}
	if reusedBody.Token != body.Token {
		t.Fatalf("reused csrf token=%q, want original token", reusedBody.Token)
	}

	methodRecorder := httptest.NewRecorder()
	csrfHandler(methodRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/csrf", nil))
	if methodRecorder.Code != http.StatusMethodNotAllowed || methodRecorder.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("csrf POST status=%d allow=%q, want 405/GET", methodRecorder.Code, methodRecorder.Header().Get("Allow"))
	}
}

func TestAPISecurityMiddlewareEnforcesBrowserCSRF(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "development")
	t.Setenv("ALLOWED_WS_ORIGINS", "http://localhost:3000")
	token, err := generateCSRFToken()
	if err != nil {
		t.Fatalf("generate csrf token: %v", err)
	}
	otherToken, err := generateCSRFToken()
	if err != nil {
		t.Fatalf("generate second csrf token: %v", err)
	}

	tests := []struct {
		name       string
		method     string
		cookie     string
		header     string
		wantStatus int
		wantCalled bool
	}{
		{name: "matching token", method: http.MethodPost, cookie: token, header: token, wantStatus: http.StatusNoContent, wantCalled: true},
		{name: "missing header", method: http.MethodPost, cookie: token, wantStatus: http.StatusForbidden},
		{name: "mismatched token", method: http.MethodPost, cookie: token, header: otherToken, wantStatus: http.StatusForbidden},
		{name: "web read request", method: http.MethodGet, wantStatus: http.StatusNoContent, wantCalled: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			called := false
			handler := apiSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(testCase.method, "/api/v1/journal_entries", nil)
			request.Header.Set("Origin", "http://localhost:3000")
			request.Header.Set("X-ScriptureForge-Client", "web")
			if testCase.cookie != "" {
				request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: testCase.cookie})
			}
			if testCase.header != "" {
				request.Header.Set(csrfHeaderName, testCase.header)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != testCase.wantStatus || called != testCase.wantCalled {
				t.Fatalf("status=%d called=%t body=%q, want status=%d called=%t", recorder.Code, called, recorder.Body.String(), testCase.wantStatus, testCase.wantCalled)
			}
			if testCase.wantStatus == http.StatusForbidden && !strings.Contains(recorder.Body.String(), "csrf_token_invalid") {
				t.Fatalf("body=%q, want csrf_token_invalid", recorder.Body.String())
			}
		})
	}
}
