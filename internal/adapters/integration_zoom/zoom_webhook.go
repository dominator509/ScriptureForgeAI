package integration_zoom

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

type WebhookPayload struct {
	Event   string `json:"event"`
	Payload struct {
		Object struct {
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
	processedFIFO []string
}

const maxProcessedZoomDeliveries = 4096

type roomStateWriter interface {
	SetRoomActiveState(ctx context.Context, roomID string, active bool) error
}

func NewWebhookHandler(sm roomStateWriter, db ...*pgxpool.Pool) *WebhookHandler {
	handler := &WebhookHandler{
		StateManager: sm,
		processed:    map[string]struct{}{},
	}
	if len(db) > 0 {
		handler.DB = db[0]
	}
	return handler
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
	h.processed[deliveryID] = struct{}{}
	h.processedFIFO = append(h.processedFIFO, deliveryID)
	if len(h.processedFIFO) > maxProcessedZoomDeliveries {
		oldest := h.processedFIFO[0]
		h.processedFIFO = h.processedFIFO[1:]
		delete(h.processed, oldest)
	}
	return true
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

// verifyZoomSignature validates the Zoom webhook signature to ensure authenticity
func verifyZoomSignature(r *http.Request, body []byte) bool {
	zoomSignature := r.Header.Get("x-zm-signature")
	zoomTimestamp := r.Header.Get("x-zm-request-timestamp")
	zoomSecretToken := os.Getenv("ZOOM_WEBHOOK_SECRET_TOKEN")

	if zoomSignature == "" || zoomTimestamp == "" || zoomSecretToken == "" {
		return false
	}

	message := fmt.Sprintf("v0:%s:%s", zoomTimestamp, string(body))

	mac := hmac.New(sha256.New, []byte(zoomSecretToken))
	mac.Write([]byte(message))
	expectedSignature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSignature), []byte(zoomSignature))
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
	if !h.markDeliveryProcessed(r, payload, bodyBytes) {
		w.WriteHeader(http.StatusOK)
		return
	}

	meetingID := payload.Payload.Object.Id
	roomID := meetingID
	if h.ResolveRoomID != nil {
		if mappedRoomID, err := h.ResolveRoomID(r.Context(), meetingID); err == nil && mappedRoomID != "" {
			roomID = mappedRoomID
		}
	} else if h.DB != nil {
		_ = h.DB.QueryRow(r.Context(), `SELECT id FROM live_rooms WHERE meeting_external_id = $1`, meetingID).Scan(&roomID)
	}

	// Map Zoom business logic events to local Redis state mutations
	switch payload.Event {
	case "meeting.started":
		log.Printf("Webhook: Meeting %s started", meetingID)
		if h.StateManager != nil {
			_ = h.StateManager.SetRoomActiveState(r.Context(), roomID, true)
		}
	case "meeting.ended":
		log.Printf("Webhook: Meeting %s ended", meetingID)
		if h.StateManager != nil {
			_ = h.StateManager.SetRoomActiveState(r.Context(), roomID, false)
		}
	default:
		log.Printf("Webhook: Unhandled event %s for meeting %s", payload.Event, meetingID)
	}

	w.WriteHeader(http.StatusOK)
}
