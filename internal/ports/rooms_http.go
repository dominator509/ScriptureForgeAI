package ports

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
)

type RoomHandler struct {
	DB                  *pgxpool.Pool
	StateManager        roomStateStore
	MembershipValidator func(r *http.Request, claims *auth.TokenClaims, roomID string) bool
}

type roomStateStore interface {
	SetRoomActiveState(ctx context.Context, roomID string, active bool) error
	GetLatestRoomEvent(ctx context.Context, roomID string) (string, error)
}

type CreateRoomRequest struct {
	Title string `json:"title"`
}

const (
	maxRoomRequestBodyBytes = 16 * 1024
	maxRoomTitleBytes       = 256
)

type RoomResponse struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at,omitempty"`
}

func scanActiveRoomRows(rows pgx.Rows) ([]RoomResponse, error) {
	rooms := []RoomResponse{}
	for rows.Next() {
		var roomResp RoomResponse
		if err := rows.Scan(&roomResp.ID, &roomResp.Title, &roomResp.IsActive, &roomResp.CreatedAt); err != nil {
			return nil, err
		}
		rooms = append(rooms, roomResp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rooms, nil
}

func (h *RoomHandler) validateRoomMembership(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
	if h.MembershipValidator != nil {
		return h.MembershipValidator(r, claims, roomID)
	}
	if roomID == "" || strings.Contains(roomID, "/") {
		return false
	}
	start := time.Now()
	status := "error"
	defer func() {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_membership", status, time.Since(start))
	}()
	if h.DB == nil {
		return false
	}
	tx, err := h.DB.Begin(r.Context())
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

func (h *RoomHandler) CreateRoomHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}
	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}
	var req CreateRoomRequest
	if pe := decodeBoundedJSON(w, r, maxRoomRequestBodyBytes, &req, auth.AuthorizationFault, "Invalid room payload"); pe != nil {
		sendAuthError(w, pe)
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room title is required", Code: http.StatusBadRequest})
		return
	}
	if len(title) > maxRoomTitleBytes {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room title is too long", Code: http.StatusBadRequest})
		return
	}
	if h.StateManager == nil {
		observability.ObserveDependencyFromContext(r.Context(), "redis", "room_set_active", "unavailable", 0)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room state manager is not configured", Code: http.StatusServiceUnavailable})
		return
	}

	start := time.Now()
	dbStatus := "error"
	if h.DB == nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_create", dbStatus, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room database is not configured", Code: http.StatusInternalServerError})
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_create", dbStatus, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to open tenant transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_create", dbStatus, time.Since(start))
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}

	var roomResp RoomResponse
	err = tx.QueryRow(
		r.Context(),
		`INSERT INTO live_rooms (organization_id, host_user_id, title, meeting_provider, meeting_metadata)
		 VALUES ($1, $2, $3, 'offline', '{"mode":"offline"}'::jsonb)
		 RETURNING id, title, is_active, created_at::text`,
		claims.OrganizationID,
		claims.UserID,
		title,
	).Scan(&roomResp.ID, &roomResp.Title, &roomResp.IsActive, &roomResp.CreatedAt)
	if err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_create", dbStatus, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to create room", Code: http.StatusInternalServerError})
		return
	}
	_, err = tx.Exec(
		r.Context(),
		`INSERT INTO room_participants (organization_id, room_id, user_id) VALUES ($1, $2, $3)`,
		claims.OrganizationID,
		roomResp.ID,
		claims.UserID,
	)
	if err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_create", dbStatus, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to join room host", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_create", dbStatus, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to commit room", Code: http.StatusInternalServerError})
		return
	}
	dbStatus = "success"
	observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_create", dbStatus, time.Since(start))
	redisStart := time.Now()
	redisStatus := "success"
	if err := h.StateManager.SetRoomActiveState(r.Context(), roomResp.ID, true); err != nil {
		redisStatus = "error"
	}
	observability.ObserveDependencyFromContext(r.Context(), "redis", "room_set_active", redisStatus, time.Since(redisStart))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(roomResp)
}

func (h *RoomHandler) ActiveRoomsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}
	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}
	start := time.Now()
	status := "error"
	if h.DB == nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "rooms_active", status, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room database is not configured", Code: http.StatusInternalServerError})
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "rooms_active", status, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to open tenant transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "rooms_active", status, time.Since(start))
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}
	rows, err := tx.Query(
		r.Context(),
		`SELECT id, title, is_active, created_at::text
		 FROM live_rooms
		 WHERE organization_id = $1
		   AND is_active = TRUE
		   AND id IN (
		       SELECT room_id
		       FROM room_participants
		       WHERE organization_id = $1 AND user_id = $2
		   )
		 ORDER BY created_at DESC
		 LIMIT 50`,
		claims.OrganizationID,
		claims.UserID,
	)
	if err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "rooms_active", status, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to list rooms", Code: http.StatusInternalServerError})
		return
	}
	defer rows.Close()
	rooms, err := scanActiveRoomRows(rows)
	if err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "rooms_active", status, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to read rooms", Code: http.StatusInternalServerError})
		return
	}
	status = "success"
	observability.ObserveDependencyFromContext(r.Context(), "postgres", "rooms_active", status, time.Since(start))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rooms)
}

func (h *RoomHandler) RoomStateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}
	roomID := strings.TrimPrefix(r.URL.Path, "/api/v1/rooms/state/")
	if roomID == "" || strings.Contains(roomID, "/") {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Invalid room id", Code: http.StatusBadRequest})
		return
	}
	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}
	if !h.validateRoomMembership(r, claims, roomID) {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room membership required", Code: http.StatusForbidden})
		return
	}
	if h.StateManager == nil {
		observability.ObserveDependencyFromContext(r.Context(), "redis", "room_get_latest", "unavailable", 0)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room state manager is not configured", Code: http.StatusServiceUnavailable})
		return
	}
	start := time.Now()
	status := "success"
	state, err := h.StateManager.GetLatestRoomEvent(r.Context(), roomID)
	if err != nil {
		status = "error"
		observability.ObserveDependencyFromContext(r.Context(), "redis", "room_get_latest", status, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to load room state", Code: http.StatusInternalServerError})
		return
	}
	observability.ObserveDependencyFromContext(r.Context(), "redis", "room_get_latest", status, time.Since(start))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(state))
}
