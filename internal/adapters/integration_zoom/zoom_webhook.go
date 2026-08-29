package integration_zoom

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type WebhookPayload struct {
	Event   string `json:"event"`
	Payload struct {
		PlainToken string `json:"plainToken"`
		Object     struct {
			Id        string `json:"id"`
			Topic     string `json:"topic"`
			StartTime string `json:"start_time"`
		} `json:"object"`
	} `json:"payload"`
}

type WebhookHandler struct {
	StateManager  roomStateWriter
	DB            *pgxpool.Pool
	ResolveRoomID func(ctx context.Context, meetingID string) (string, error)
	mu            sync.Mutex
	processed     map[string]struct{}
	inFlight      map[string]struct{}
	processedFIFO []string
}

const maxProcessedZoomDeliveries = 4096
const maxZoomWebhookClockSkew = 5 * time.Minute
const maxZoomWebhookBodyBytes = 1 << 20
const zoomWebhookNoTenantOrgID = "00000000-0000-4000-8000-000000000000"

var errZoomRoomMappingUnavailable = errors.New("zoom room mapping unavailable")

type roomStateWriter interface {
	SetRoomActiveState(ctx context.Context, roomID string, active bool) error
}

type webhookDeliveryStore interface {
	ClaimWebhookDelivery(ctx context.Context, deliveryID string, ttl time.Duration) (bool, error)
	ReleaseWebhookDelivery(ctx context.Context, deliveryID string) error
}

func NewWebhookHandler(sm roomStateWriter, db ...*pgxpool.Pool) *WebhookHandler {
	handler := &WebhookHandler{
		StateManager: sm,
		processed:    map[string]struct{}{},
		inFlight:     map[string]struct{}{},
	}
	if len(db) > 0 {
		handler.DB = db[0]
	}
	return handler
}

func (h *WebhookHandler) beginDelivery(r *http.Request, payload WebhookPayload, body []byte) (string, bool) {
	deliveryID := zoomDeliveryID(r, payload, body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.processed == nil {
		h.processed = map[string]struct{}{}
	}
	if h.inFlight == nil {
		h.inFlight = map[string]struct{}{}
	}
	if _, exists := h.processed[deliveryID]; exists {
		return deliveryID, false
	}
	if _, exists := h.inFlight[deliveryID]; exists {
		return deliveryID, false
	}
	h.inFlight[deliveryID] = struct{}{}
	return deliveryID, true
}

func (h *WebhookHandler) finishDelivery(deliveryID string, processed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.processed == nil {
		h.processed = map[string]struct{}{}
	}
	if h.inFlight == nil {
		h.inFlight = map[string]struct{}{}
	}
	delete(h.inFlight, deliveryID)
	if !processed {
		return
	}
	h.addProcessedLocked(deliveryID)
}

func (h *WebhookHandler) markDeliveryProcessed(r *http.Request, payload WebhookPayload, body []byte) bool {
	deliveryID := zoomDeliveryID(r, payload, body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.processed == nil {
		h.processed = map[string]struct{}{}
	}
	if _, exists := h.processed[deliveryID]; exists {
		return false
	}
	h.addProcessedLocked(deliveryID)
	return true
}

func (h *WebhookHandler) addProcessedLocked(deliveryID string) {
	h.processed[deliveryID] = struct{}{}
	h.processedFIFO = append(h.processedFIFO, deliveryID)
	if len(h.processedFIFO) > maxProcessedZoomDeliveries {
		oldest := h.processedFIFO[0]
		h.processedFIFO = h.processedFIFO[1:]
		delete(h.processed, oldest)
	}
}

func zoomDeliveryID(r *http.Request, payload WebhookPayload, body []byte) string {
	// Only use values covered by Zoom's HMAC. Tracking/request-id headers are
	// not part of the signed message and therefore cannot be replay keys.
	sum := sha256.Sum256([]byte(r.Header.Get("x-zm-request-timestamp") + "\x00" + string(body)))
	return "body:" + hex.EncodeToString(sum[:])
}

func (h *WebhookHandler) releaseDelivery(ctx context.Context, deliveryID string) {
	if store, ok := h.StateManager.(webhookDeliveryStore); ok {
		if err := store.ReleaseWebhookDelivery(ctx, deliveryID); err != nil {
			log.Printf("Zoom webhook delivery release failed: %v", err)
		}
	}
	h.finishDelivery(deliveryID, false)
}

func (h *WebhookHandler) resolveRoomID(ctx context.Context, meetingID string) (string, error) {
	if h.ResolveRoomID != nil {
		return h.ResolveRoomID(ctx, meetingID)
	}
	if h.DB == nil {
		return "", errZoomRoomMappingUnavailable
	}
	tx, err := h.DB.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: begin transaction", errZoomRoomMappingUnavailable)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		SELECT
			set_config('app.current_org_id', $1, true),
			set_config('app.webhook_lookup_verified', 'true', true),
			set_config('app.webhook_lookup_meeting_id', $2, true)
	`, zoomWebhookNoTenantOrgID, meetingID); err != nil {
		return "", fmt.Errorf("%w: configure lookup context", errZoomRoomMappingUnavailable)
	}
	var roomID string
	err = tx.QueryRow(ctx, `SELECT id FROM live_rooms WHERE meeting_external_id = $1 LIMIT 1`, meetingID).Scan(&roomID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		log.Printf("Zoom webhook room lookup failed for meeting %s: %v", meetingID, err)
		return "", fmt.Errorf("%w: query mapping", errZoomRoomMappingUnavailable)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("%w: commit mapping lookup", errZoomRoomMappingUnavailable)
	}
	return roomID, nil
}

func (h *WebhookHandler) setDurableRoomActive(ctx context.Context, roomID, meetingID string, active bool) error {
	if h.DB == nil {
		return nil
	}
	tx, err := h.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin durable Zoom room state update: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		SELECT
			set_config('app.current_org_id', $1, true),
			set_config('app.webhook_lookup_verified', 'true', true),
			set_config('app.webhook_lookup_meeting_id', $2, true)
	`, zoomWebhookNoTenantOrgID, meetingID); err != nil {
		return fmt.Errorf("configure durable Zoom room state context: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE live_rooms
		SET is_active = $1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2 AND meeting_external_id = $3
	`, active, roomID, meetingID)
	if err != nil {
		return fmt.Errorf("update durable Zoom room state: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("durable Zoom room state update affected %d rows", tag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit durable Zoom room state update: %w", err)
	}
	return nil
}

// verifyZoomSignature validates the Zoom webhook signature to ensure authenticity
func verifyZoomSignature(r *http.Request, body []byte) bool {
	zoomSignature := r.Header.Get("x-zm-signature")
	zoomTimestamp := r.Header.Get("x-zm-request-timestamp")
	zoomSecretToken := os.Getenv("ZOOM_WEBHOOK_SECRET_TOKEN")

	if zoomSignature == "" || zoomTimestamp == "" || zoomSecretToken == "" {
		return false
	}

	timestampUnix, err := strconv.ParseInt(zoomTimestamp, 10, 64)
	if err != nil {
		return false
	}
	requestTime := time.Unix(timestampUnix, 0)
	now := time.Now()
	if requestTime.Before(now.Add(-maxZoomWebhookClockSkew)) || requestTime.After(now.Add(maxZoomWebhookClockSkew)) {
		return false
	}

	message := fmt.Sprintf("v0:%s:%s", zoomTimestamp, string(body))

	mac := hmac.New(sha256.New, []byte(zoomSecretToken))
	mac.Write([]byte(message))
	expectedSignature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSignature), []byte(zoomSignature))
}

func zoomURLValidationResponse(plainToken string) (map[string]string, bool) {
	secret := os.Getenv("ZOOM_WEBHOOK_SECRET_TOKEN")
	if plainToken == "" || secret == "" {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(plainToken))
	return map[string]string{
		"plainToken":     plainToken,
		"encryptedToken": hex.EncodeToString(mac.Sum(nil)),
	}, true
}

func (h *WebhookHandler) HandleZoomWebhook(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxZoomWebhookBodyBytes)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if !verifyZoomSignature(r, bodyBytes) {
		log.Println("Unauthorized Zoom webhook signature")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if payload.Event == "endpoint.url_validation" {
		response, ok := zoomURLValidationResponse(payload.Payload.PlainToken)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	deliveryID, ok := h.beginDelivery(r, payload, bodyBytes)
	if !ok {
		w.WriteHeader(http.StatusOK)
		return
	}
	if store, durable := h.StateManager.(webhookDeliveryStore); durable {
		claimed, claimErr := store.ClaimWebhookDelivery(r.Context(), deliveryID, maxZoomWebhookClockSkew)
		if claimErr != nil {
			h.releaseDelivery(r.Context(), deliveryID)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !claimed {
			h.finishDelivery(deliveryID, true)
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	meetingID := payload.Payload.Object.Id
	roomID, mappingErr := h.resolveRoomID(r.Context(), meetingID)
	if mappingErr != nil {
		log.Printf("Webhook: room mapping unavailable for Zoom meeting %s: %v", meetingID, mappingErr)
		h.releaseDelivery(r.Context(), deliveryID)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if roomID == "" {
		log.Printf("Webhook: No live room mapping for Zoom meeting %s", meetingID)
		h.releaseDelivery(r.Context(), deliveryID)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Persist the authoritative room state before publishing the Redis state.
	// A failed Redis update is still retryable, while the durable update is idempotent.
	var mutationErr error
	switch payload.Event {
	case "meeting.started":
		log.Printf("Webhook: Meeting %s started", meetingID)
		mutationErr = h.setDurableRoomActive(r.Context(), roomID, meetingID, true)
		if mutationErr == nil && h.StateManager != nil {
			mutationErr = h.StateManager.SetRoomActiveState(r.Context(), roomID, true)
		}
	case "meeting.ended":
		log.Printf("Webhook: Meeting %s ended", meetingID)
		mutationErr = h.setDurableRoomActive(r.Context(), roomID, meetingID, false)
		if mutationErr == nil && h.StateManager != nil {
			mutationErr = h.StateManager.SetRoomActiveState(r.Context(), roomID, false)
		}
	default:
		log.Printf("Webhook: Unhandled event %s for meeting %s", payload.Event, meetingID)
	}
	if mutationErr != nil {
		log.Printf("Webhook: room state update failed for Zoom meeting %s mapped to room %s: %v", meetingID, roomID, mutationErr)
		h.releaseDelivery(r.Context(), deliveryID)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	h.finishDelivery(deliveryID, true)

	w.WriteHeader(http.StatusOK)
}
