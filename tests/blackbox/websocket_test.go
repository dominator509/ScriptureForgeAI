package blackbox

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketInterface(t *testing.T) {
	wsURL := "ws://localhost:8080/ws/room"

	t.Run("Unauthorized WebSocket Upgrade", func(t *testing.T) {
		// Attempt upgrade without JWT
		dialer := websocket.Dialer{
			HandshakeTimeout: 5 * time.Second,
		}

		_, resp, err := dialer.Dial(wsURL, nil)
		if err == nil {
			t.Fatalf("Expected WebSocket dial to fail without authorization")
		}

		if resp != nil && resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for missing token on WebSocket upgrade, got %d", resp.StatusCode)
		}
	})

	t.Run("WebSocket Origin Hijacking Denial", func(t *testing.T) {
		// Even with auth (which we would test if the DB was live),
		// if the origin is explicitly evil, it should be rejected.
		dialer := websocket.Dialer{
			HandshakeTimeout: 5 * time.Second,
		}

		headers := http.Header{}
		headers.Add("Origin", "http://malicious-hijacker-domain.com")
		// We simulate a fake token just to see if it bypasses or gets caught by auth middleware first.
		// It should get caught by auth middleware first (401), but if auth is mocked/bypassed, it would hit 403.
		headers.Add("Authorization", fmt.Sprintf("Bearer %s", "fake-token"))

		_, resp, err := dialer.Dial(wsURL, headers)
		if err == nil {
			t.Fatalf("Expected WebSocket dial to fail for invalid origin or auth")
		}

		if resp != nil && resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("System leaked connection state. Expected 401 or 403, got %d", resp.StatusCode)
		}
	})
}
