package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"scriptureforge/internal/domain/observability"
)

func TestRBACMiddlewareEnrichesAccessLogWithVerifiedClaims(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "auth-observability-test-secret-0123456789")
	token, err := GenerateToken("user-log-123", "org-log-456", "admin", time.Minute)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	var logs bytes.Buffer
	observer := observability.NewObserver(observability.Options{
		Writer:                &logs,
		GenerateID:            func() string { return "3333444455556666777788889999aaaa" },
		ServiceVersion:        "auth-log-test",
		DeploymentEnvironment: "test",
	})
	handler := observer.Middleware(RBACMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "admin"))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/mfa/enroll", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	var entry struct {
		TraceID               string `json:"trace_id"`
		Component             string `json:"component"`
		Service               string `json:"service"`
		ServiceVersion        string `json:"service_version"`
		DeploymentEnvironment string `json:"deployment_environment"`
		TenantID              string `json:"tenant_id"`
		UserID                string `json:"user_id"`
		Role                  string `json:"role"`
		Path                  string `json:"path"`
		Status                int    `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("decode access log: %v\n%s", err, logs.String())
	}
	if entry.TraceID != "3333444455556666777788889999aaaa" || entry.Component != "scriptureforge-api" || entry.Service != "scriptureforge-api" {
		t.Fatalf("access log missing trace/service fields: %#v", entry)
	}
	if entry.ServiceVersion != "auth-log-test" || entry.DeploymentEnvironment != "test" {
		t.Fatalf("access log missing deployment fields: %#v", entry)
	}
	if entry.TenantID != "org-log-456" || entry.UserID != "user-log-123" || entry.Role != "admin" {
		t.Fatalf("access log did not use verified JWT claims: %#v", entry)
	}
	if entry.Path != "/api/v1/auth/mfa/enroll" || entry.Status != http.StatusNoContent {
		t.Fatalf("access log route/status mismatch: %#v", entry)
	}
}

func TestRBACMiddlewareOnlyAcceptsWebSocketSubprotocolOnRoomStreams(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "auth-ticket-scope-test-secret-0123456789")
	token, err := GenerateToken("user-ticket-123", "org-ticket-456", "member", time.Minute)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	handler := RBACMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "")

	for _, tc := range []struct {
		name      string
		path      string
		protocols string
		want      int
	}{
		{name: "ordinary API route", path: "/api/v1/rooms/active?ticket=" + token, want: http.StatusUnauthorized},
		{name: "room stream query token", path: "/api/v1/rooms/stream/room-1?ticket=" + token, want: http.StatusUnauthorized},
		{name: "room stream subprotocol", path: "/api/v1/rooms/stream/room-1", protocols: RoomWebSocketSubprotocol + ", " + token, want: http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.protocols != "" {
				request.Header.Set("Sec-WebSocket-Protocol", tc.protocols)
			}
			handler.ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("websocket auth status = %d, want %d", recorder.Code, tc.want)
			}
		})
	}
}

func TestRBACMiddlewareAnyRoleAllowsDocumentedAIRolesOnly(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "auth-role-test-secret-0123456789")
	handler := RBACMiddlewareAnyRole(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "moderator", "author")

	for _, test := range []struct {
		name string
		role string
		want int
	}{
		{name: "member denied", role: "member", want: http.StatusForbidden},
		{name: "moderator accepted", role: "Moderator", want: http.StatusNoContent},
		{name: "author accepted", role: "author", want: http.StatusNoContent},
		{name: "admin compatibility override", role: "admin", want: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, err := GenerateToken("user-role", "org-role", test.role, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/ai/generate/study", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("role %s status = %d, want %d", test.role, recorder.Code, test.want)
			}
		})
	}
}
