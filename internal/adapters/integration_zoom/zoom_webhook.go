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
}

type roomStateWriter interface {
	SetRoomActiveState(ctx context.Context, roomID string, active bool) error
}

func NewWebhookHandler(sm roomStateWriter, db ...*pgxpool.Pool) *WebhookHandler {
	handler := &WebhookHandler{StateManager: sm}
	if len(db) > 0 {
		handler.DB = db[0]
	}
	return handler
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
