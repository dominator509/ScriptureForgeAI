package ports

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
)

type RoomEvent struct {
	Type     string          `json:"type"`
	RoomID   string          `json:"room_id"`
	Sequence int64           `json:"sequence"`
	Payload  json.RawMessage `json:"payload"`
	SentAt   time.Time       `json:"sent_at"`
}

const (
	maxWSMessageBytes = 64 * 1024
	wsPongWait        = 60 * time.Second
	wsPingInterval    = 30 * time.Second
	wsWriteWait       = 10 * time.Second
)

type SocketConnection struct {
	DB                  *pgxpool.Pool
	StateManager        roomEventStore
	Hub                 *RoomHub
	MembershipValidator func(r *http.Request, claims *auth.TokenClaims, roomID string) bool
}

type roomEventStore interface {
	AppendRoomEvent(ctx context.Context, roomID, eventJSON string) (int64, error)
}

func allowedWSOrigin(r *http.Request) bool {
	allowed := os.Getenv("ALLOWED_WS_ORIGINS")
	origin := r.Header.Get("Origin")
	if allowed == "" {
		return origin == "" || strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1")
	}
	for _, candidate := range strings.Split(allowed, ",") {
		if strings.TrimSpace(candidate) == origin {
			return true
		}
	}
	return false
}

func roomIDFromPath(path string) string {
	return strings.TrimPrefix(path, "/api/v1/rooms/stream/")
}

func (s *SocketConnection) validateRoomMembership(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
	if s.MembershipValidator != nil {
		return s.MembershipValidator(r, claims, roomID)
	}
	if roomID == "" || strings.Contains(roomID, "/") {
		return false
	}
	tx, err := s.DB.Begin(r.Context())
	if err != nil {
		return false
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		return false
	}
	var count int
	err = tx.QueryRow(
		r.Context(),
		`SELECT COUNT(*)
		 FROM room_participants
		 WHERE organization_id = $1 AND room_id = $2 AND user_id = $3`,
		claims.OrganizationID,
		roomID,
		claims.UserID,
	).Scan(&count)
	return err == nil && count > 0
}

func (s *SocketConnection) HandleLiveRoom(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}
	roomID := roomIDFromPath(r.URL.Path)
	if !s.validateRoomMembership(r, claims, roomID) {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room membership required", Code: http.StatusForbidden})
		return
	}
	hub := s.Hub
	if hub == nil {
		hub = NewRoomHub()
	}

	upgrader := websocket.Upgrader{CheckOrigin: allowedWSOrigin}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	defer conn.Close()

	events, unsubscribe := hub.Subscribe(roomID)
	defer unsubscribe()
	done := make(chan struct{})
	var writeMu sync.Mutex
	writeJSON := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		return conn.WriteJSON(v)
	}
	writeControl := func(messageType int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteControl(messageType, data, time.Now().Add(wsWriteWait))
	}
	defer close(done)
	go func() {
		for {
			select {
			case event, ok := <-events:
				if !ok {
					return
				}
				if err := writeJSON(event); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()
	pingTicker := time.NewTicker(wsPingInterval)
	defer pingTicker.Stop()
	go func() {
		for {
			select {
			case <-pingTicker.C:
				if err := writeControl(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	conn.SetReadLimit(maxWSMessageBytes)
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("read error:", err)
			break
		}
		var event RoomEvent
		if err := json.Unmarshal(message, &event); err != nil || event.Type == "" || event.RoomID != roomID {
			_ = writeJSON(map[string]string{"error": "invalid room event"})
			continue
		}
		event.SentAt = time.Now().UTC()
		event.Sequence = 0
		wire, err := json.Marshal(event)
		if err != nil {
			_ = writeJSON(map[string]string{"error": "invalid room event"})
			continue
		}
		seq, err := s.StateManager.AppendRoomEvent(r.Context(), roomID, string(wire))
		if err != nil {
			_ = writeJSON(map[string]string{"error": "failed to persist room event"})
			continue
		}
		event.Sequence = seq
		hub.Broadcast(roomID, event)
	}
}
