package unit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"fmt"

	"scriptureforge/internal/adapters/integration_zoom"
	"scriptureforge/internal/domain/room"
	"github.com/redis/go-redis/v9"
)

// setupMockZoomWebhook returns a mocked WebhookHandler
func setupMockZoomWebhook() *integration_zoom.WebhookHandler {
	// Instead of a full mock, we can pass a nil client if the underlying state manager can gracefully handle it,
	// or provide a simple mock structure if needed. For now, since RoomStateManager just holds the redis client,
	// we will leave it as nil since it'll fail at runtime if it executes. We just want to test the signature mapping first.
	// Actually, a safer way is to provide a local Redis instance or a mocked interface if the project allows interfaces.
	// Let's create a dummy payload and verify signature logic.

	// Create dummy state manager
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"}) // Doesn't matter if it fails unless we test the redis state explicitly
	sm := room.NewRoomStateManager(rdb)
	return integration_zoom.NewWebhookHandler(sm)
}

func generateValidZoomSignature(timestamp, payload, secret string) string {
	message := fmt.Sprintf("v0:%s:%s", timestamp, payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestZoomWebhookSignatureValidation(t *testing.T) {
	os.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "test-secret")
	defer os.Unsetenv("ZOOM_WEBHOOK_SECRET_TOKEN")

	handler := setupMockZoomWebhook()

	payloadStr := `{"event": "meeting.started", "payload": {"object": {"id": "12345"}}}`
	timestamp := "123456789"
	validSignature := generateValidZoomSignature(timestamp, payloadStr, "test-secret")

	t.Run("ValidSignature", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/webhooks/zoom", bytes.NewBufferString(payloadStr))
		req.Header.Set("x-zm-signature", validSignature)
		req.Header.Set("x-zm-request-timestamp", timestamp)

		rr := httptest.NewRecorder()

		// Note: since this attempts to connect to Redis inside HandleZoomWebhook,
		// we should expect it to potentially panic or fail redis if redis isn't running.
		// Actually, let's verify if HandleZoomWebhook returns 200.

		handler.HandleZoomWebhook(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for valid signature, got %v", rr.Code)
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/webhooks/zoom", bytes.NewBufferString(payloadStr))
		req.Header.Set("x-zm-signature", "v0=invalidhash")
		req.Header.Set("x-zm-request-timestamp", timestamp)

		rr := httptest.NewRecorder()
		handler.HandleZoomWebhook(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for invalid signature, got %v", rr.Code)
		}
	})

	t.Run("MissingHeaders", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/webhooks/zoom", bytes.NewBufferString(payloadStr))

		rr := httptest.NewRecorder()
		handler.HandleZoomWebhook(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for missing headers, got %v", rr.Code)
		}
	})
}
