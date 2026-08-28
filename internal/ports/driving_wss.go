package ports

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/abuse"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
)

type RoomEvent struct {
	Type     string          `json:"type"`
	RoomID   string          `json:"room_id"`
	Sequence int64           `json:"sequence"`
	Payload  json.RawMessage `json:"payload"`
	SentAt   time.Time       `json:"sent_at"`
}

type roomErrorEnvelope struct {
	Error string `json:"error"`
}

const (
	maxWSMessageBytes            = 64 * 1024
	maxRoomEventTypeBytes        = 64
	wsPongWait                   = 60 * time.Second
	wsPingInterval               = 30 * time.Second
	wsWriteWait                  = 10 * time.Second
	activeConnectionRenewTimeout = 5 * time.Second
	wsEventWindow                = time.Minute
	maxWSEventsPerWindow         = 120
	maxWSBytesPerWindow          = 4 << 20
)

type SocketConnection struct {
	DB                  *pgxpool.Pool
	StateManager        roomEventStore
	Hub                 *RoomHub
	MembershipValidator func(r *http.Request, claims *auth.TokenClaims, roomID string) bool
	ConnectionLimiter   *abuse.ActiveConnectionLimiter
	hubMu               sync.Mutex
	eventMu             sync.Mutex
	connectionsMu       sync.Mutex
	connections         map[*websocket.Conn]struct{}
	draining            bool
}

type roomEventStore interface {
	AppendRoomEvent(ctx context.Context, roomID, eventJSON string) (int64, error)
}

type roomEventPublisher interface {
	AppendRoomEventAndPublish(ctx context.Context, roomID, eventJSON, sourceID string) (int64, error)
}

func allowedWSOrigin(r *http.Request) bool {
	allowed := os.Getenv("ALLOWED_WS_ORIGINS")
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	strictOrigins := requiresConfiguredWSOrigins()
	if allowed == "" {
		if strictOrigins {
			return false
		}
		return origin == "" || isLocalDevelopmentOrigin(origin)
	}
	for _, candidate := range strings.Split(allowed, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if strictOrigins && (!isPublicHTTPSOrigin(candidate) || !isPublicHTTPSOrigin(origin)) {
			continue
		}
		if candidate == origin {
			return true
		}
	}
	return false
}

func isPublicHTTPSOrigin(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return false
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := parsed.Hostname()
	return !isReservedPlaceholderOriginHost(host) && !isLocalOrPrivateOriginHost(host)
}

func isReservedPlaceholderOriginHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	return normalized == "example" ||
		strings.HasSuffix(normalized, ".example") ||
		normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		normalized == "example.org" ||
		strings.HasSuffix(normalized, ".example.org") ||
		normalized == "example.net" ||
		strings.HasSuffix(normalized, ".example.net") ||
		normalized == "test" ||
		strings.HasSuffix(normalized, ".test") ||
		normalized == "invalid" ||
		strings.HasSuffix(normalized, ".invalid")
}

func isLocalOrPrivateOriginHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())
}

func isLocalDevelopmentOrigin(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(strings.Trim(parsed.Hostname(), "[]")), ".")
	return host == "localhost" || host == "127.0.0.1"
}

func requiresConfiguredWSOrigins() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOYMENT_ENVIRONMENT"))) {
	case "prod", "production", "staging":
		return true
	default:
		return false
	}
}

func roomIDFromPath(path string) string {
	return strings.TrimPrefix(path, "/api/v1/rooms/stream/")
}

func validRoomEventType(eventType string) bool {
	if eventType == "" || eventType != strings.TrimSpace(eventType) || len(eventType) > maxRoomEventTypeBytes {
		return false
	}
	for _, char := range eventType {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= '0' && char <= '9':
		case char == '_' || char == '-' || char == '.':
		default:
			return false
		}
	}
	return true
}

func decodeRoomEvent(message []byte) (RoomEvent, error) {
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()

	var event RoomEvent
	if err := decoder.Decode(&event); err != nil {
		return RoomEvent{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return RoomEvent{}, io.ErrUnexpectedEOF
		}
		return RoomEvent{}, err
	}
	return event, nil
}

func validRoomEventEnvelope(event RoomEvent, roomID string) bool {
	if event.RoomID != roomID || !validRoomEventType(event.Type) || event.Sequence != 0 {
		return false
	}
	if len(event.Payload) == 0 || bytes.Equal(bytes.TrimSpace(event.Payload), []byte("null")) {
		return false
	}
	return json.Valid(event.Payload)
}

func roomTokenExpiryDelay(claims *auth.TokenClaims, now time.Time) (time.Duration, bool) {
	if claims == nil || claims.ExpiresAt == nil {
		return 0, false
	}
	return claims.ExpiresAt.Time.Sub(now), true
}

func (s *SocketConnection) roomHub() *RoomHub {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	if s.Hub == nil {
		s.Hub = NewRoomHub()
	}
	return s.Hub
}

func (s *SocketConnection) closeRoomHub() {
	s.hubMu.Lock()
	hub := s.Hub
	s.hubMu.Unlock()
	if hub != nil {
		hub.Close()
	}
}

func (s *SocketConnection) activeConnectionLimiter() *abuse.ActiveConnectionLimiter {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	if s.ConnectionLimiter == nil {
		s.ConnectionLimiter = abuse.NewDefaultActiveConnectionLimiter()
	}
	return s.ConnectionLimiter
}

func (s *SocketConnection) isDraining() bool {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	return s.draining
}

func (s *SocketConnection) trackConnection(conn *websocket.Conn) bool {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	if s.draining {
		return false
	}
	if s.connections == nil {
		s.connections = make(map[*websocket.Conn]struct{})
	}
	s.connections[conn] = struct{}{}
	return true
}

func (s *SocketConnection) BeginShutdown() {
	s.connectionsMu.Lock()
	s.draining = true
	connections := make([]*websocket.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.connections = make(map[*websocket.Conn]struct{})
	s.connectionsMu.Unlock()

	for _, conn := range connections {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutting down"), time.Now().Add(wsWriteWait))
		_ = conn.Close()
	}
	s.closeRoomHub()
}

func (s *SocketConnection) untrackConnection(conn *websocket.Conn) {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	delete(s.connections, conn)
}

func (s *SocketConnection) validateRoomMembership(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
	if s.MembershipValidator != nil {
		return s.MembershipValidator(r, claims, roomID)
	}
	if roomID == "" || strings.Contains(roomID, "/") {
		return false
	}
	start := time.Now()
	status := "error"
	defer func() {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_membership", status, time.Since(start))
	}()
	if s.DB == nil {
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
	if err == nil && count > 0 {
		status = "success"
		return true
	}
	if err == nil {
		status = "denied"
	}
	return false
}

func (s *SocketConnection) HandleLiveRoom(w http.ResponseWriter, r *http.Request) {
	if s.isDraining() {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Server is shutting down", Code: http.StatusServiceUnavailable})
		return
	}
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
	if s.StateManager == nil {
		observability.ObserveDependencyFromContext(r.Context(), "redis", "room_append_event", "unavailable", 0)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room state manager is not configured", Code: http.StatusServiceUnavailable})
		return
	}
	hub := s.roomHub()
	releaseConnection, renewConnection, allowed, limiterErr := s.activeConnectionLimiter().AcquireContext(r.Context(), claims.OrganizationID, claims.UserID)
	if limiterErr != nil {
		observability.ObserveDependencyFromContext(r.Context(), "redis", "websocket_connection_limit", "unavailable", 0)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room connection capacity is unavailable", Code: http.StatusServiceUnavailable})
		return
	}
	if !allowed {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Too many active room connections", Code: http.StatusTooManyRequests})
		return
	}
	defer releaseConnection()

	upgrader := websocket.Upgrader{
		CheckOrigin:  allowedWSOrigin,
		Subprotocols: []string{auth.RoomWebSocketSubprotocol},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	if !s.trackConnection(conn) {
		_ = conn.Close()
		return
	}
	defer s.untrackConnection(conn)
	defer conn.Close()
	releaseActiveConnection := observability.ObserveWebSocketActiveConnectionFromContext(r.Context())
	defer releaseActiveConnection()

	events, unsubscribe := hub.Subscribe(roomID)
	defer unsubscribe()
	done := make(chan struct{})
	var writeMu sync.Mutex
	writeEventJSON := func(event RoomEvent) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		return conn.WriteJSON(event)
	}
	writeErrorJSON := func(message string) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		return conn.WriteJSON(roomErrorEnvelope{Error: message})
	}
	writeControl := func(messageType int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteControl(messageType, data, time.Now().Add(wsWriteWait))
	}
	closePolicyViolation := func(reason string) {
		_ = writeControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason))
	}
	tokenExpiryDelay, hasTokenExpiry := roomTokenExpiryDelay(claims, time.Now())
	if hasTokenExpiry && tokenExpiryDelay <= 0 {
		closePolicyViolation("room access token expired")
		return
	}
	if hasTokenExpiry {
		expiryDone := make(chan struct{})
		defer close(expiryDone)
		expiryTimer := time.NewTimer(tokenExpiryDelay)
		defer expiryTimer.Stop()
		go func() {
			select {
			case <-expiryTimer.C:
				closePolicyViolation("room access token expired")
				_ = conn.Close()
			case <-expiryDone:
			}
		}()
	}
	defer close(done)
	leaseDone := make(chan struct{})
	defer close(leaseDone)
	go func() {
		leaseTicker := time.NewTicker(wsPingInterval)
		defer leaseTicker.Stop()
		for {
			select {
			case <-leaseTicker.C:
				renewCtx, cancel := context.WithTimeout(context.Background(), activeConnectionRenewTimeout)
				err := renewConnection(renewCtx)
				cancel()
				if err != nil {
					observability.ObserveDependencyFromContext(r.Context(), "redis", "websocket_connection_lease", "unavailable", 0)
					closePolicyViolation("room connection lease unavailable")
					_ = conn.Close()
					return
				}
			case <-leaseDone:
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case event, ok := <-events:
				if !ok {
					return
				}
				if err := writeEventJSON(event); err != nil {
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
	eventWindowStarted := time.Now()
	eventsInWindow := 0
	bytesInWindow := 0
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("read error:", err)
			break
		}
		if time.Since(eventWindowStarted) >= wsEventWindow {
			eventWindowStarted = time.Now()
			eventsInWindow = 0
			bytesInWindow = 0
		}
		if eventsInWindow >= maxWSEventsPerWindow || bytesInWindow+len(message) > maxWSBytesPerWindow {
			closePolicyViolation("room event rate limit exceeded")
			break
		}
		eventsInWindow++
		bytesInWindow += len(message)
		event, decodeErr := decodeRoomEvent(message)
		if decodeErr != nil || !validRoomEventEnvelope(event, roomID) {
			closePolicyViolation("invalid room event")
			break
		}
		event.SentAt = time.Now().UTC()
		event.Sequence = 0
		wire, err := json.Marshal(event)
		if err != nil {
			closePolicyViolation("invalid room event")
			break
		}
		s.eventMu.Lock()
		start := time.Now()
		publisher, canPublish := s.StateManager.(roomEventPublisher)
		seq := int64(0)
		if canPublish {
			seq, err = publisher.AppendRoomEventAndPublish(r.Context(), roomID, string(wire), hub.InstanceID())
		} else {
			seq, err = s.StateManager.AppendRoomEvent(r.Context(), roomID, string(wire))
		}
		redisStatus := "success"
		if err != nil {
			redisStatus = "error"
			observability.ObserveDependencyFromContext(r.Context(), "redis", "room_append_event", redisStatus, time.Since(start))
			s.eventMu.Unlock()
			_ = writeErrorJSON("failed to persist room event")
			continue
		}
		observability.ObserveDependencyFromContext(r.Context(), "redis", "room_append_event", redisStatus, time.Since(start))
		event.Sequence = seq
		broadcastStart := time.Now()
		broadcastStatus := "success"
		if result := hub.Broadcast(roomID, event); result.Dropped > 0 {
			broadcastStatus = "dropped"
		}
		observability.ObserveDependencyFromContext(r.Context(), "websocket", "room_broadcast", broadcastStatus, time.Since(broadcastStart))
		s.eventMu.Unlock()
	}
}
