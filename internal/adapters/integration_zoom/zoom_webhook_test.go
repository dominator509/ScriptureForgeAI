package integration_zoom

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type stateChange struct {
	roomID string
	active bool
}

type fakeRoomStateManager struct {
	mu      sync.Mutex
	changes []stateChange
	err     error
}

func (f *fakeRoomStateManager) SetRoomActiveState(ctx context.Context, roomID string, active bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		err := f.err
		f.err = nil
		return err
	}
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

func TestZoomWebhookRejectsStaleSignedDelivery(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)

	body := `{"event":"meeting.started","payload":{"object":{"id":"zoom-meeting-123","topic":"Study"}}}`
	recorder := httptest.NewRecorder()
	request := signedZoomRequestAt(t, body, "secret", time.Now().Add(-maxZoomWebhookClockSkew-time.Minute))

	handler.HandleZoomWebhook(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("stale signed delivery status = %d, want 401", recorder.Code)
	}
	if changes := stateManager.snapshot(); len(changes) != 0 {
		t.Fatalf("state changed after stale signed delivery: %#v", changes)
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
	if len(changes) != 1 {
		t.Fatalf("state changes = %#v, want one idempotent update", changes)
	}
	for _, change := range changes {
		if change.roomID != "room-abc" || !change.active {
			t.Fatalf("unexpected mapped state change: %#v", change)
		}
	}
}

func TestZoomWebhookDoesNotMutateStateWhenMeetingMappingIsMissing(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)
	handler.ResolveRoomID = func(ctx context.Context, meetingID string) (string, error) {
		return "", nil
	}

	body := `{"event":"meeting.started","payload":{"object":{"id":"unknown-zoom-meeting","topic":"Study"}}}`
	recorder := httptest.NewRecorder()
	handler.HandleZoomWebhook(recorder, signedZoomRequest(t, body, "secret"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("unmapped webhook status = %d, want 200", recorder.Code)
	}
	if changes := stateManager.snapshot(); len(changes) != 0 {
		t.Fatalf("unmapped webhook changed state: %#v", changes)
	}
}

func TestZoomWebhookDoesNotFallbackToMeetingIDWhenMappingFails(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)
	handler.ResolveRoomID = func(ctx context.Context, meetingID string) (string, error) {
		return "", errors.New("database unavailable")
	}

	body := `{"event":"meeting.ended","payload":{"object":{"id":"zoom-meeting-123","topic":"Study"}}}`
	recorder := httptest.NewRecorder()
	handler.HandleZoomWebhook(recorder, signedZoomRequest(t, body, "secret"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("mapping-error webhook status = %d, want 200", recorder.Code)
	}
	if changes := stateManager.snapshot(); len(changes) != 0 {
		t.Fatalf("mapping-error webhook changed state using meeting id fallback: %#v", changes)
	}
}

func TestZoomWebhookDoesNotConsumeDeliveryIDWhenMappingFails(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)
	var lookups int
	handler.ResolveRoomID = func(ctx context.Context, meetingID string) (string, error) {
		lookups++
		if lookups == 1 {
			return "", errors.New("database temporarily unavailable")
		}
		return "room-after-retry", nil
	}

	body := `{"event":"meeting.started","payload":{"object":{"id":"zoom-meeting-123","topic":"Study"}}}`
	first := signedZoomRequest(t, body, "secret")
	first.Header.Set("x-zm-trackingid", "retryable-delivery")
	firstRecorder := httptest.NewRecorder()
	handler.HandleZoomWebhook(firstRecorder, first)
	if firstRecorder.Code != http.StatusOK {
		t.Fatalf("mapping-error webhook status = %d, want 200", firstRecorder.Code)
	}
	if changes := stateManager.snapshot(); len(changes) != 0 {
		t.Fatalf("mapping-error webhook changed state before retry: %#v", changes)
	}

	retry := signedZoomRequest(t, body, "secret")
	retry.Header.Set("x-zm-trackingid", "retryable-delivery")
	retryRecorder := httptest.NewRecorder()
	handler.HandleZoomWebhook(retryRecorder, retry)
	if retryRecorder.Code != http.StatusOK {
		t.Fatalf("retry webhook status = %d, want 200", retryRecorder.Code)
	}
	changes := stateManager.snapshot()
	if len(changes) != 1 || changes[0].roomID != "room-after-retry" || !changes[0].active {
		t.Fatalf("retry state changes = %#v, want one active update after mapping recovers", changes)
	}
}

func TestZoomWebhookDoesNotConsumeDeliveryIDWhenStateMutationFails(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{err: errors.New("redis temporarily unavailable")}
	handler := NewWebhookHandler(stateManager)
	handler.ResolveRoomID = func(ctx context.Context, meetingID string) (string, error) {
		return "room-after-state-retry", nil
	}

	body := `{"event":"meeting.started","payload":{"object":{"id":"zoom-meeting-123","topic":"Study"}}}`
	first := signedZoomRequest(t, body, "secret")
	first.Header.Set("x-zm-trackingid", "retryable-state-delivery")
	firstRecorder := httptest.NewRecorder()
	handler.HandleZoomWebhook(firstRecorder, first)
	if firstRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("state-error webhook status = %d, want 503", firstRecorder.Code)
	}
	if changes := stateManager.snapshot(); len(changes) != 0 {
		t.Fatalf("state-error webhook changed state before retry: %#v", changes)
	}

	retry := signedZoomRequest(t, body, "secret")
	retry.Header.Set("x-zm-trackingid", "retryable-state-delivery")
	retryRecorder := httptest.NewRecorder()
	handler.HandleZoomWebhook(retryRecorder, retry)
	if retryRecorder.Code != http.StatusOK {
		t.Fatalf("retry webhook status = %d, want 200", retryRecorder.Code)
	}
	changes := stateManager.snapshot()
	if len(changes) != 1 || changes[0].roomID != "room-after-state-retry" || !changes[0].active {
		t.Fatalf("retry state changes = %#v, want one active update after state mutation recovers", changes)
	}
}

func TestZoomWebhookProcessesDistinctTrackedDeliveries(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)
	handler.ResolveRoomID = func(ctx context.Context, meetingID string) (string, error) {
		return "room-abc", nil
	}

	body := `{"event":"meeting.started","payload":{"object":{"id":"zoom-meeting-123","topic":"Study"}}}`
	for _, trackingID := range []string{"delivery-1", "delivery-2"} {
		request := signedZoomRequest(t, body, "secret")
		request.Header.Set("x-zm-trackingid", trackingID)
		recorder := httptest.NewRecorder()
		handler.HandleZoomWebhook(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("tracked delivery %s status = %d, want 200", trackingID, recorder.Code)
		}
	}

	if changes := stateManager.snapshot(); len(changes) != 2 {
		t.Fatalf("state changes = %#v, want distinct tracked deliveries processed", changes)
	}
}

func TestZoomWebhookURLValidationReturnsEncryptedTokenWithoutStateMutation(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	stateManager := &fakeRoomStateManager{}
	handler := NewWebhookHandler(stateManager)
	body := `{"event":"endpoint.url_validation","payload":{"plainToken":"zoom-plain-token"}}`
	recorder := httptest.NewRecorder()

	handler.HandleZoomWebhook(recorder, signedZoomRequest(t, body, "secret"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("url validation status = %d, want 200", recorder.Code)
	}
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode url validation response: %v", err)
	}
	if response["plainToken"] != "zoom-plain-token" {
		t.Fatalf("plainToken = %q, want original token", response["plainToken"])
	}
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte("zoom-plain-token"))
	expected := hex.EncodeToString(mac.Sum(nil))
	if response["encryptedToken"] != expected {
		t.Fatalf("encryptedToken = %q, want %q", response["encryptedToken"], expected)
	}
	if changes := stateManager.snapshot(); len(changes) != 0 {
		t.Fatalf("url validation changed room state: %#v", changes)
	}
}

func TestZoomWebhookURLValidationRejectsMissingPlainToken(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	handler := NewWebhookHandler(&fakeRoomStateManager{})
	body := `{"event":"endpoint.url_validation","payload":{}}`
	recorder := httptest.NewRecorder()

	handler.HandleZoomWebhook(recorder, signedZoomRequest(t, body, "secret"))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing plainToken status = %d, want 400", recorder.Code)
	}
}

func TestZoomWebhookDeliveryCacheIsBounded(t *testing.T) {
	t.Setenv("ZOOM_WEBHOOK_SECRET_TOKEN", "secret")
	handler := NewWebhookHandler(&fakeRoomStateManager{})
	body := []byte(`{"event":"staging.probe","payload":{"object":{"id":"zoom-meeting-123"}}}`)
	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < maxProcessedZoomDeliveries+10; i++ {
		request := signedZoomRequest(t, string(body), "secret")
		request.Header.Set("x-zm-trackingid", fmt.Sprintf("delivery-%d", i))
		if !handler.markDeliveryProcessed(request, payload, body) {
			t.Fatalf("delivery %d unexpectedly treated as duplicate", i)
		}
	}

	if len(handler.processed) != maxProcessedZoomDeliveries || len(handler.processedFIFO) != maxProcessedZoomDeliveries {
		t.Fatalf("processed cache sizes map=%d fifo=%d, want %d", len(handler.processed), len(handler.processedFIFO), maxProcessedZoomDeliveries)
	}
	if _, exists := handler.processed["x-zm-trackingid:delivery-0"]; exists {
		t.Fatal("oldest processed delivery was not evicted")
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
	return signedZoomRequestAt(t, body, secret, time.Now())
}

func signedZoomRequestAt(t *testing.T, body string, secret string, at time.Time) *http.Request {
	t.Helper()
	timestamp := fmt.Sprintf("%d", at.Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(fmt.Sprintf("v0:%s:%s", timestamp, body)))
	request := httptest.NewRequest(http.MethodPost, "/api/webhooks/zoom", bytes.NewBufferString(body))
	request.Header.Set("x-zm-request-timestamp", timestamp)
	request.Header.Set("x-zm-signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	return request
}
