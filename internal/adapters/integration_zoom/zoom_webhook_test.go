package integration_zoom

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type stateChange struct {
	roomID string
	active bool
}

type fakeRoomStateManager struct {
	mu      sync.Mutex
	changes []stateChange
}

func (f *fakeRoomStateManager) SetRoomActiveState(ctx context.Context, roomID string, active bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, stateChange{roomID: roomID, active: active})
	return nil
}

func (f *fakeRoomStateManager) snapshot() []stateChange {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]stateChange, len(f.changes))
	copy(copied, f.changes)
	return copied
}

func TestZoomWebhookRejectsInvalidSignature(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)

	request := httptest.NewRequest(http.MethodPost, "/api/webhooks/zoom", bytes.NewBufferString(`{"event":"meeting.started"}`))
	request.Header.Set("x-zm-request-timestamp", "1710000000")
	request.Header.Set("x-zm-signature", "v0=invalid")
	recorder := httptest.NewRecorder()

	handler.HandleZoomWebhook(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid signature status = %d, want 401", recorder.Code)
	}
	if changes := stateManager.snapshot(); len(changes) != 0 {
		t.Fatalf("state changed after invalid signature: %#v", changes)
	}
}

func TestZoomWebhookMapsMeetingToRoomAndIsDuplicateSafe(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)
	handler.ResolveRoomID = func(ctx context.Context, meetingID string) (string, error) {
		if meetingID != "zoom-meeting-123" {
			t.Fatalf("meeting id = %q, want zoom-meeting-123", meetingID)
		}
		return "room-abc", nil
	}

	body := `{"event":"meeting.started","payload":{"object":{"id":"zoom-meeting-123","topic":"Study"}}}`
	for i := 0; i < 2; i++ {
		request := signedZoomRequest(t, body, "secret")
		recorder := httptest.NewRecorder()
		handler.HandleZoomWebhook(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("duplicate %d status = %d, want 200", i+1, recorder.Code)
		}
	}

	changes := stateManager.snapshot()
	if len(changes) != 2 {
		t.Fatalf("state changes = %#v, want two idempotent updates", changes)
	}
	for _, change := range changes {
		if change.roomID != "room-abc" || !change.active {
			t.Fatalf("unexpected mapped state change: %#v", change)
		}
	}
}

func TestZoomWebhookEndedEventUpdatesMappedRoomInactive(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)
	handler.ResolveRoomID = func(ctx context.Context, meetingID string) (string, error) {
		return "room-ended", nil
	}

	body := `{"event":"meeting.ended","payload":{"object":{"id":"zoom-ended-123"}}}`
	recorder := httptest.NewRecorder()
	handler.HandleZoomWebhook(recorder, signedZoomRequest(t, body, "secret"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("ended webhook status = %d, want 200", recorder.Code)
	}
	changes := stateManager.snapshot()
	if len(changes) != 1 || changes[0].roomID != "room-ended" || changes[0].active {
		t.Fatalf("ended state changes = %#v, want one inactive mapped room update", changes)
	}
}

func signedZoomRequest(t *testing.T, body string, secret string) *http.Request {
	t.Helper()
	timestamp := "1710000000"
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(fmt.Sprintf("v0:%s:%s", timestamp, body)))
	request := httptest.NewRequest(http.MethodPost, "/api/webhooks/zoom", bytes.NewBufferString(body))
	request.Header.Set("x-zm-request-timestamp", timestamp)
	request.Header.Set("x-zm-signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	return request
}
