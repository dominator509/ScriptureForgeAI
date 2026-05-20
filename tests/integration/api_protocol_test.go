package integration_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/ports"
	"scriptureforge/internal/adapters/integration_zoom"
)

// Tests REST-specific constraints, HTTP parameter pollution, and protocol boundaries

func TestREST_ImproperMethodHandling(t *testing.T) {
	authHandler := &ports.AuthHandler{DB: nil}
	aiHandler := &ports.AIHandler{}

	// Zoom webhook handler relies on StateManager, but for method testing it might fail on signature check first.
	// But it handles IO first, so we'll test auth and AI

	tests := []struct {
		name     string
		handler  http.HandlerFunc
		endpoint string
		methods  []string // Methods that should be REJECTED
	}{
		{
			name:     "Auth Register Reject GET/PUT/DELETE",
			handler:  authHandler.RegisterHandler,
			endpoint: "/api/auth/register",
			methods:  []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch},
		},
		{
			name:     "Auth Login Reject GET/PUT/DELETE",
			handler:  authHandler.LoginHandler,
			endpoint: "/api/auth/login",
			methods:  []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch},
		},
		{
			name:     "AI Curriculum Reject GET/PUT/DELETE",
			handler:  aiHandler.GenerateCurriculumHandler,
			endpoint: "/api/ai/curriculum",
			methods:  []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch},
		},
	}

	for _, tc := range tests {
		for _, method := range tc.methods {
			t.Run(tc.name+"_"+method, func(t *testing.T) {
				req, _ := http.NewRequest(method, tc.endpoint, nil)
				rr := httptest.NewRecorder()
				tc.handler(rr, req)

				if rr.Code != http.StatusMethodNotAllowed {
					t.Errorf("expected StatusMethodNotAllowed (405) for %s on %s, got %v", method, tc.endpoint, rr.Code)
				}
			})
		}
	}
}

func TestZoomWebhook_SignatureValidation(t *testing.T) {
	// Must fail without valid signature headers
	webhookHandler := integration_zoom.NewWebhookHandler(nil)

	req, _ := http.NewRequest(http.MethodPost, "/api/webhooks/zoom", bytes.NewBufferString(`{"event":"test"}`))
	rr := httptest.NewRecorder()

	webhookHandler.HandleZoomWebhook(rr, req)

	// In zoom_webhook.go, failing signature check returns 401 Unauthorized
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for missing Zoom signature, got %v", rr.Code)
	}
}

func TestWebSocket_UpgradeBoundary(t *testing.T) {
	// A direct HTTP GET without WebSocket Upgrade headers should fail gracefully
	// (usually Bad Request from the Gorilla Upgrader)
	socketConn := &ports.SocketConnection{}

	req, _ := http.NewRequest(http.MethodGet, "/ws/room", nil)

	// Generate valid token to pass middleware so we hit the upgrader
	token, _ := auth.GenerateToken("user1", "org1", "member", time.Hour)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()

	handler := auth.RBACMiddleware(http.HandlerFunc(socketConn.HandleLiveRoom), "")
	handler.ServeHTTP(rr, req)

	// Gorilla upgrader returns 400 Bad Request if the Upgrade header is not present
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for non-websocket upgrade request, got %v", rr.Code)
	}
}
