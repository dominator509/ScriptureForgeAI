package integration_zoom

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

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

type roomStateWriter interface {
	SetRoomActiveState(ctx context.Context, roomID string, active bool) error
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
	for _, header := range []string{"x-zm-trackingid", "x-zm-request-id"} {
		if value := r.Header.Get(header); value != "" {
			return header + ":" + value
		}
	}
	sum := sha256.Sum256([]byte(payload.Event + "\x00" + r.Header.Get("x-zm-request-timestamp") + "\x00" + string(body)))
	return "body:" + hex.EncodeToString(sum[:])
}

func (h *WebhookHandler) resolveRoomID(ctx context.Context, meetingID string) (string, bool) {
	if h.ResolveRoomID != nil {
		mappedRoomID, err := h.ResolveRoomID(ctx, meetingID)
		return mappedRoomID, err == nil && mappedRoomID != ""
	}
	if h.DB == nil {
		return "", false
	}
	var roomID string
	err := h.DB.QueryRow(ctx, `SELECT id FROM live_rooms WHERE meeting_external_id = $1`, meetingID).Scan(&roomID)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Zoom webhook room lookup failed for meeting %s: %v", meetingID, err)
		}
		return "", false
	}
	return roomID, roomID != ""
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
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
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
	meetingID := payload.Payload.Object.Id
	roomID, ok := h.resolveRoomID(r.Context(), meetingID)
	if !ok {
		log.Printf("Webhook: No live room mapping for Zoom meeting %s", meetingID)
		w.WriteHeader(http.StatusOK)
		return
	}
	deliveryID, ok := h.beginDelivery(r, payload, bodyBytes)
	if !ok {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Map Zoom business logic events to local Redis state mutations
	var mutationErr error
	switch payload.Event {
	case "meeting.started":
		log.Printf("Webhook: Meeting %s started", meetingID)
		if h.StateManager != nil {
			mutationErr = h.StateManager.SetRoomActiveState(r.Context(), roomID, true)
		}
	case "meeting.ended":
		log.Printf("Webhook: Meeting %s ended", meetingID)
		if h.StateManager != nil {
			mutationErr = h.StateManager.SetRoomActiveState(r.Context(), roomID, false)
		}
	default:
		log.Printf("Webhook: Unhandled event %s for meeting %s", payload.Event, meetingID)
	}
	if mutationErr != nil {
		log.Printf("Webhook: room state update failed for Zoom meeting %s mapped to room %s: %v", meetingID, roomID, mutationErr)
		h.finishDelivery(deliveryID, false)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	h.finishDelivery(deliveryID, true)

	w.WriteHeader(http.StatusOK)
}
