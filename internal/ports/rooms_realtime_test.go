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
	"scriptureforge/internal/domain/observability"
)

type fakeRoomEventStore struct {
	mu       sync.Mutex
	sequence int64
	latest   string
	appends  int
	reads    int
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
	f.reads++
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

func (f *fakeRoomEventStore) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

func TestLiveRoomRejectsInvalidEventAndBroadcastsAcceptedEvent(t *testing.T) {
	store := &fakeRoomEventStore{}
	hub := NewRoomHub()
	observer := observability.NewObserver(observability.Options{})
	socket := &SocketConnection{
		StateManager: store,
		Hub:          hub,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.UserID != ""
		},
	}
	server := httptest.NewServer(observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-" + r.URL.Query().Get("client"), OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	})))
	defer server.Close()

	first := dialRoom(t, server.URL, "room-1", "a")
	defer first.Close()
	second := dialRoom(t, server.URL, "room-1", "b")
	defer second.Close()

	if err := first.WriteJSON(RoomEvent{Type: "cursor", RoomID: "wrong-room", Payload: json.RawMessage(`{"x":1}`)}); err != nil {
		t.Fatalf("write invalid event: %v", err)
	}
	if err := first.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set invalid event read deadline: %v", err)
	}
	_, _, err := first.ReadMessage()
	if err == nil {
		t.Fatal("invalid event read returned nil error, want policy-violation close")
	}
	if !websocket.IsCloseError(err, websocket.ClosePolicyViolation) {
		t.Fatalf("invalid event close error = %v, want policy violation", err)
	}
	if got := store.appendCount(); got != 0 {
		t.Fatalf("invalid event append count = %d, want 0", got)
	}

	replacement := dialRoom(t, server.URL, "room-1", "a2")
	defer replacement.Close()
	if err := replacement.WriteJSON(RoomEvent{Type: "cursor", RoomID: "room-1", Payload: json.RawMessage(`{"verse":"John 1:1"}`)}); err != nil {
		t.Fatalf("write valid event: %v", err)
	}

	firstEvent := readRoomEvent(t, replacement)
	secondEvent := readRoomEvent(t, second)
	for _, event := range []RoomEvent{firstEvent, secondEvent} {
		if event.Type != "cursor" || event.RoomID != "room-1" || event.Sequence != 1 || event.SentAt.IsZero() {
			t.Fatalf("broadcast event = %#v", event)
		}
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="redis",operation="room_append_event",status="success"} 1`) {
		t.Fatalf("websocket append dependency metric missing:\n%s", metrics)
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

func TestLiveRoomFailsClosedWhenStateManagerMissing(t *testing.T) {
	socket := &SocketConnection{
		Hub: NewRoomHub(),
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.UserID != ""
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-missing-state", OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/room-1"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("websocket without state manager upgraded successfully, want 503")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("websocket without state manager status = %d err = %v, want 503", status, err)
	}
}

func TestLiveRoomConcurrentSendersReceiveContiguousAcceptedBroadcasts(t *testing.T) {
	store := &fakeRoomEventStore{}
	hub := NewRoomHub()
	observer := observability.NewObserver(observability.Options{})
	socket := &SocketConnection{
		StateManager: store,
		Hub:          hub,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.OrganizationID == "org-1" && claims.UserID != ""
		},
	}
	server := httptest.NewServer(observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-" + r.URL.Query().Get("client"), OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	})))
	defer server.Close()

	const clients = 6
	connections := make([]*websocket.Conn, clients)
	for i := 0; i < clients; i++ {
		connections[i] = dialRoom(t, server.URL, "room-1", "concurrent-"+string(rune('a'+i)))
		defer connections[i].Close()
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, conn := range connections {
		wg.Add(1)
		go func(i int, conn *websocket.Conn) {
			defer wg.Done()
			<-start
			marker := "writer-" + string(rune('a'+i))
			if err := conn.WriteJSON(RoomEvent{Type: "cursor", RoomID: "room-1", Payload: json.RawMessage(`{"marker":"` + marker + `"}`)}); err != nil {
				t.Errorf("write concurrent event %s: %v", marker, err)
			}
		}(i, conn)
	}
	close(start)
	wg.Wait()

	seenSequences := map[int64]bool{}
	for i, conn := range connections {
		marker := "writer-" + string(rune('a'+i))
		event := readRoomEventWithPayload(t, conn, marker, clients)
		if event.Type != "cursor" || event.RoomID != "room-1" || event.SentAt.IsZero() {
			t.Fatalf("concurrent event for %s = %#v", marker, event)
		}
		if event.Sequence < 1 || event.Sequence > clients {
			t.Fatalf("sequence for %s = %d, want 1..%d", marker, event.Sequence, clients)
		}
		if seenSequences[event.Sequence] {
			t.Fatalf("duplicate accepted sequence %d", event.Sequence)
		}
		seenSequences[event.Sequence] = true
	}
	for seq := int64(1); seq <= clients; seq++ {
		if !seenSequences[seq] {
			t.Fatalf("missing accepted sequence %d from concurrent websocket senders", seq)
		}
	}
	if got := store.appendCount(); got != clients {
		t.Fatalf("append count = %d, want %d", got, clients)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="redis",operation="room_append_event",status="success"} 6`) {
		t.Fatalf("websocket append dependency metric for concurrent senders missing:\n%s", metrics)
	}
}

func TestLiveRoomFanOutDeliversEveryAcceptedEventToEverySubscriber(t *testing.T) {
	store := &fakeRoomEventStore{}
	hub := NewRoomHub()
	observer := observability.NewObserver(observability.Options{})
	socket := &SocketConnection{
		StateManager: store,
		Hub:          hub,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.OrganizationID == "org-1" && claims.UserID != ""
		},
	}
	server := httptest.NewServer(observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-" + r.URL.Query().Get("client"), OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	})))
	defer server.Close()

	const clients = 3
	connections := make([]*websocket.Conn, clients)
	for i := 0; i < clients; i++ {
		connections[i] = dialRoom(t, server.URL, "room-1", "fanout-"+string(rune('a'+i)))
		defer connections[i].Close()
	}
	waitForRoomSubscribers(t, hub, "room-1", clients)

	for i := 0; i < clients; i++ {
		marker := "fanout-" + string(rune('a'+i))
		if err := connections[i].WriteJSON(RoomEvent{Type: "cursor", RoomID: "room-1", Payload: json.RawMessage(`{"marker":"` + marker + `"}`)}); err != nil {
			t.Fatalf("write fan-out event %s: %v", marker, err)
		}
	}

	for clientIndex, conn := range connections {
		seenMarkers := map[string]bool{}
		for expectedSequence := int64(1); expectedSequence <= clients; expectedSequence++ {
			event := readRoomEvent(t, conn)
			if event.Type != "cursor" || event.RoomID != "room-1" || event.Sequence != expectedSequence || event.SentAt.IsZero() {
				t.Fatalf("client %d fan-out event %d = %#v", clientIndex, expectedSequence, event)
			}
			seenMarkers[string(event.Payload)] = true
		}
		for i := 0; i < clients; i++ {
			marker := `"marker":"fanout-` + string(rune('a'+i)) + `"`
			found := false
			for payload := range seenMarkers {
				if strings.Contains(payload, marker) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("client %d missing fan-out payload marker %s in %#v", clientIndex, marker, seenMarkers)
			}
		}
	}
	if got := store.appendCount(); got != clients {
		t.Fatalf("fan-out append count = %d, want %d", got, clients)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="success"} 3`) {
		t.Fatalf("websocket fan-out success metric missing:\n%s", metrics)
	}
	if strings.Contains(metrics, `dependency="websocket",operation="room_broadcast",status="dropped"`) {
		t.Fatalf("websocket fan-out dropped unexpectedly:\n%s", metrics)
	}
}

func TestLiveRoomReportsDroppedBroadcastForLaggingSubscriber(t *testing.T) {
	store := &fakeRoomEventStore{}
	hub := NewRoomHub()
	lagging, unsubscribeLagging := hub.Subscribe("room-1")
	defer unsubscribeLagging()
	for i := 0; i < 16; i++ {
		if result := hub.Broadcast("room-1", RoomEvent{Type: "seed", RoomID: "room-1"}); result.Delivered != 1 || result.Dropped != 0 {
			t.Fatalf("seed broadcast %d result = %+v", i+1, result)
		}
	}
	observer := observability.NewObserver(observability.Options{})
	socket := &SocketConnection{
		StateManager: store,
		Hub:          hub,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return roomID == "room-1" && claims.OrganizationID == "org-1" && claims.UserID != ""
		},
	}
	server := httptest.NewServer(observer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &auth.TokenClaims{UserID: "user-" + r.URL.Query().Get("client"), OrganizationID: "org-1", Role: "member"}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	})))
	defer server.Close()

	conn := dialRoom(t, server.URL, "room-1", "sender")
	defer conn.Close()
	if err := conn.WriteJSON(RoomEvent{Type: "cursor", RoomID: "room-1", Payload: json.RawMessage(`{"marker":"lagging-drop"}`)}); err != nil {
		t.Fatalf("write event with lagging subscriber: %v", err)
	}
	event := readRoomEventWithPayload(t, conn, "lagging-drop", 1)
	if event.Sequence != 1 || event.Type != "cursor" {
		t.Fatalf("sender broadcast after lagging drop = %#v", event)
	}
	received := 0
	for range lagging {
		received++
	}
	if received != 16 {
		t.Fatalf("lagging subscriber buffered events before eviction = %d, want 16", received)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped"} 1`) {
		t.Fatalf("dropped broadcast metric missing:\n%s", metrics)
	}
}

func TestLiveRoomRejectsDisallowedOrigin(t *testing.T) {
	t.Setenv("ALLOWED_WS_ORIGINS", "https://allowed.staging.scriptureforge.ai")

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
	wsHeader.Add("Origin", "https://bad.staging.scriptureforge.ai")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, wsHeader)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected disallowed origin handshake failure")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("origin-reject status = %d", resp.StatusCode)
	}
}

func TestAllowedWSOriginRequiresPublicHTTPSOriginsInStagingAndProduction(t *testing.T) {
	for _, environment := range []string{"staging", "production", "prod"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_ENVIRONMENT", environment)

			request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/stream/room-1", nil)
			request.Header.Set("Origin", "https://app.staging.scriptureforge.ai")
			t.Setenv("ALLOWED_WS_ORIGINS", "https://app.staging.scriptureforge.ai")
			if !allowedWSOrigin(request) {
				t.Fatalf("allowedWSOrigin rejected public HTTPS origin in %s", environment)
			}

			for _, tc := range []struct {
				name    string
				allowed string
				origin  string
			}{
				{name: "reserved example", allowed: "https://allowed.example.com", origin: "https://allowed.example.com"},
				{name: "reserved example.com", allowed: "https://app.example.com", origin: "https://app.example.com"},
				{name: "reserved test", allowed: "https://app.staging.test", origin: "https://app.staging.test"},
				{name: "reserved invalid", allowed: "https://app.invalid", origin: "https://app.invalid"},
				{name: "insecure public", allowed: "http://app.staging.scriptureforge.ai", origin: "http://app.staging.scriptureforge.ai"},
				{name: "local host", allowed: "https://localhost", origin: "https://localhost"},
				{name: "private ip", allowed: "https://10.0.0.20", origin: "https://10.0.0.20"},
				{name: "ipv4 mapped private", allowed: "https://[::ffff:10.0.0.20]", origin: "https://[::ffff:10.0.0.20]"},
				{name: "origin path", allowed: "https://app.staging.scriptureforge.ai/path", origin: "https://app.staging.scriptureforge.ai/path"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Setenv("ALLOWED_WS_ORIGINS", tc.allowed)
					request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/stream/room-1", nil)
					request.Header.Set("Origin", tc.origin)
					if allowedWSOrigin(request) {
						t.Fatalf("allowedWSOrigin accepted unsafe origin in %s: %s", environment, tc.origin)
					}
				})
			}
		})
	}
}

func TestAllowedWSOriginRequiresConfiguredOriginsInStagingAndProduction(t *testing.T) {
	for _, environment := range []string{"staging", "production", "prod"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_ENVIRONMENT", environment)
			t.Setenv("ALLOWED_WS_ORIGINS", "")
			request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/stream/room-1", nil)
			request.Header.Set("Origin", "http://localhost:3000")
			if allowedWSOrigin(request) {
				t.Fatalf("allowedWSOrigin accepted localhost origin in %s without ALLOWED_WS_ORIGINS", environment)
			}

			request.Header.Del("Origin")
			if allowedWSOrigin(request) {
				t.Fatalf("allowedWSOrigin accepted missing origin in %s without ALLOWED_WS_ORIGINS", environment)
			}
		})
	}
}

func TestAllowedWSOriginKeepsLocalDevelopmentFallback(t *testing.T) {
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "development")
	t.Setenv("ALLOWED_WS_ORIGINS", "")

	request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/stream/room-1", nil)
	if !allowedWSOrigin(request) {
		t.Fatal("allowedWSOrigin rejected missing origin in local development mode")
	}
	request.Header.Set("Origin", "http://localhost:3000")
	if !allowedWSOrigin(request) {
		t.Fatal("allowedWSOrigin rejected localhost origin in local development mode")
	}
	request.Header.Set("Origin", "https://evil.example.com")
	if allowedWSOrigin(request) {
		t.Fatal("allowedWSOrigin accepted non-local origin with no configured allowlist")
	}
}

func TestRoomStateHandlerReturnsLatestEventForPollingFallback(t *testing.T) {
	store := &fakeRoomEventStore{}
	observer := observability.NewObserver(observability.Options{})
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
	request = request.WithContext(observability.WithObserver(request.Context(), observer))
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
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="redis",operation="room_get_latest",status="success"} 1`) {
		t.Fatalf("polling dependency metric missing:\n%s", metrics)
	}
}

func TestRoomStateHandlerRejectsNonMemberBeforePollingState(t *testing.T) {
	store := &fakeRoomEventStore{}
	handler := &RoomHandler{
		StateManager: store,
		MembershipValidator: func(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
			return false
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/state/room-1", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "user-blocked",
		OrganizationID: "org-blocked",
		Role:           "member",
	}))
	recorder := httptest.NewRecorder()
	handler.RoomStateHandler(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("non-member polling fallback status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if got := store.readCount(); got != 0 {
		t.Fatalf("non-member polling fallback read state count = %d, want 0", got)
	}
}

func TestRoomStateHandlerFailsClosedWhenStateManagerMissing(t *testing.T) {
	handler := &RoomHandler{
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
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("polling fallback without state manager status = %d body = %s, want 503", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Room state manager is not configured") {
		t.Fatalf("polling fallback without state manager body = %s", recorder.Body.String())
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

func readRoomEventWithPayload(t *testing.T, conn *websocket.Conn, marker string, maxReads int) RoomEvent {
	t.Helper()
	for i := 0; i < maxReads; i++ {
		event := readRoomEvent(t, conn)
		if strings.Contains(string(event.Payload), marker) {
			return event
		}
	}
	t.Fatalf("did not receive broadcast containing %q within %d reads", marker, maxReads)
	return RoomEvent{}
}

func waitForRoomSubscribers(t *testing.T, hub *RoomHub, roomID string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := hub.subscriberCount(roomID); got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("room %s subscriber count = %d, want %d", roomID, hub.subscriberCount(roomID), want)
}
