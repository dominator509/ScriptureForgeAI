package ports

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"scriptureforge/internal/domain/auth"
)

type fakeRoomEventStore struct {
	mu       sync.Mutex
	sequence int64
	latest   string
	appends  int
}

func (f *fakeRoomEventStore) AppendRoomEvent(ctx context.Context, roomID, eventJSON string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sequence++
	f.appends++
	var event RoomEvent
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return 0, err
	}
	event.Sequence = f.sequence
	wire, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}
	f.latest = string(wire)
	return f.sequence, nil
}

func (f *fakeRoomEventStore) SetRoomActiveState(ctx context.Context, roomID string, active bool) error {
	return nil
}

func (f *fakeRoomEventStore) GetLatestRoomEvent(ctx context.Context, roomID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latest == "" {
		return "{}", nil
	}
	return f.latest, nil
}

func (f *fakeRoomEventStore) appendCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.appends
}

func TestLiveRoomRejectsInvalidEventAndBroadcastsAcceptedEvent(t *testing.T) {
	store := &fakeRoomEventStore{}
	hub := NewRoomHub()
	socket := &SocketConnection{
		StateManager: store,
		Hub:          hub,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.UserID != ""
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-" + r.URL.Query().Get("client"), OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	}))
	defer server.Close()

	first := dialRoom(t, server.URL, "room-1", "a")
	defer first.Close()
	second := dialRoom(t, server.URL, "room-1", "b")
	defer second.Close()

	if err := first.WriteJSON(RoomEvent{Type: "cursor", RoomID: "wrong-room", Payload: json.RawMessage(`{"x":1}`)}); err != nil {
		t.Fatalf("write invalid event: %v", err)
	}
	var invalidResponse map[string]string
	if err := first.ReadJSON(&invalidResponse); err != nil {
		t.Fatalf("read invalid event response: %v", err)
	}
	if invalidResponse["error"] != "invalid room event" {
		t.Fatalf("invalid event response = %#v", invalidResponse)
	}
	if got := store.appendCount(); got != 0 {
		t.Fatalf("invalid event append count = %d, want 0", got)
	}

	if err := first.WriteJSON(RoomEvent{Type: "cursor", RoomID: "room-1", Payload: json.RawMessage(`{"verse":"John 1:1"}`)}); err != nil {
		t.Fatalf("write valid event: %v", err)
	}

	firstEvent := readRoomEvent(t, first)
	secondEvent := readRoomEvent(t, second)
	for _, event := range []RoomEvent{firstEvent, secondEvent} {
		if event.Type != "cursor" || event.RoomID != "room-1" || event.Sequence != 1 || event.SentAt.IsZero() {
			t.Fatalf("broadcast event = %#v", event)
		}
	}
}

func TestLiveRoomClosesOversizedEventWithoutPersisting(t *testing.T) {
	store := &fakeRoomEventStore{}
	socket := &SocketConnection{
		StateManager: store,
		Hub:          NewRoomHub(),
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.UserID != ""
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-oversized", OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	}))
	defer server.Close()

	conn := dialRoom(t, server.URL, "room-1", "oversized")
	defer conn.Close()

	oversized := bytes.Repeat([]byte("x"), maxWSMessageBytes+1)
	if err := conn.WriteMessage(websocket.TextMessage, oversized); err != nil {
		t.Fatalf("write oversized event: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("oversized event read returned nil error, want connection close")
	}
	if got := store.appendCount(); got != 0 {
		t.Fatalf("oversized event append count = %d, want 0", got)
	}
}

func TestLiveRoomReconnectReceivesFutureEventsAndPollingState(t *testing.T) {
	store := &fakeRoomEventStore{}
	hub := NewRoomHub()
	socket := &SocketConnection{
		StateManager: store,
		Hub:          hub,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.OrganizationID == "org-1"
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-" + r.URL.Query().Get("client"), OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	}))
	defer server.Close()

	initial := dialRoom(t, server.URL, "room-1", "reconnect")
	if err := initial.Close(); err != nil {
		t.Fatalf("close initial connection: %v", err)
	}

	reconnected := dialRoom(t, server.URL, "room-1", "reconnect")
	defer reconnected.Close()
	sender := dialRoom(t, server.URL, "room-1", "sender")
	defer sender.Close()

	if err := sender.WriteJSON(RoomEvent{Type: "focus", RoomID: "room-1", Payload: json.RawMessage(`{"verse":"Psalm 23:1"}`)}); err != nil {
		t.Fatalf("write post-reconnect event: %v", err)
	}

	senderEvent := readRoomEvent(t, sender)
	reconnectedEvent := readRoomEvent(t, reconnected)
	for _, event := range []RoomEvent{senderEvent, reconnectedEvent} {
		if event.Type != "focus" || event.RoomID != "room-1" || event.Sequence != 1 || !strings.Contains(string(event.Payload), "Psalm 23:1") {
			t.Fatalf("post-reconnect event = %#v", event)
		}
	}

	handler := &RoomHandler{
		StateManager: store,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.OrganizationID == "org-1"
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/state/room-1", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "user-reconnect",
		OrganizationID: "org-1",
		Role:           "member",
	}))
	recorder := httptest.NewRecorder()
	handler.RoomStateHandler(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("polling fallback after reconnect status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var polled RoomEvent
	if err := json.Unmarshal(recorder.Body.Bytes(), &polled); err != nil {
		t.Fatalf("decode polling fallback after reconnect: %v", err)
	}
	if polled.Sequence != 1 || polled.Type != "focus" || !strings.Contains(string(polled.Payload), "Psalm 23:1") {
		t.Fatalf("polling fallback after reconnect = %#v", polled)
	}
}

func TestLiveRoomRejectsDisallowedOrigin(t *testing.T) {
	t.Setenv("ALLOWED_WS_ORIGINS", "https://allowed.example.com")

	store := &fakeRoomEventStore{}
	socket := &SocketConnection{
		StateManager: store,
		Hub:          NewRoomHub(),
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.UserID != ""
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-disallowed", OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/room-1"
	wsHeader := http.Header{}
	wsHeader.Add("Origin", "https://bad.example.com")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, wsHeader)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected disallowed origin handshake failure")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("origin-reject status = %d", resp.StatusCode)
	}
}

func TestRoomStateHandlerReturnsLatestEventForPollingFallback(t *testing.T) {
	store := &fakeRoomEventStore{}
	_, err := store.AppendRoomEvent(context.Background(), "room-1", `{"type":"cursor","room_id":"room-1","sequence":0,"payload":{"verse":"Romans 8:1"},"sent_at":"2026-06-25T00:00:00Z"}`)
	if err != nil {
		t.Fatalf("seed latest event: %v", err)
	}
	handler := &RoomHandler{
		StateManager: store,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.OrganizationID == "org-1"
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/state/room-1", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "user-1",
		OrganizationID: "org-1",
		Role:           "member",
	}))
	recorder := httptest.NewRecorder()
	handler.RoomStateHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("polling fallback status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var event RoomEvent
	if err := json.Unmarshal(recorder.Body.Bytes(), &event); err != nil {
		t.Fatalf("decode polling fallback event: %v", err)
	}
	if event.Sequence != 1 || event.RoomID != "room-1" || !strings.Contains(string(event.Payload), "Romans 8:1") {
		t.Fatalf("polling fallback event = %#v", event)
	}
}

func dialRoom(t *testing.T, serverURL, roomID, client string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(serverURL, "http") + "/api/v1/rooms/stream/" + roomID + "?client=" + client
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial room websocket: %v", err)
	}
	return conn
}

func readRoomEvent(t *testing.T, conn *websocket.Conn) RoomEvent {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var event RoomEvent
	if err := conn.ReadJSON(&event); err != nil {
		t.Fatalf("read room event: %v", err)
	}
	return event
}
