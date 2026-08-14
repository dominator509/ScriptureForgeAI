package ports

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/room"
)

type RoomHandler struct {
	DB           *pgxpool.Pool
	StateManager *room.RoomStateManager
}

type CreateRoomRequest struct {
	Title string `json:"title"`
}

type RoomResponse struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at,omitempty"`
}

func (h *RoomHandler) validateRoomMembership(r *http.Request, claims *auth.TokenClaims, roomID string) bool {
	if roomID == "" || strings.Contains(roomID, "/") {
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
	return err == nil && count > 0
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Title) == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Room title is required", Code: http.StatusBadRequest})
		return
	}

	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to open tenant transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
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
		strings.TrimSpace(req.Title),
	).Scan(&roomResp.ID, &roomResp.Title, &roomResp.IsActive, &roomResp.CreatedAt)
	if err != nil {
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
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to join room host", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to commit room", Code: http.StatusInternalServerError})
		return
	}
	_ = h.StateManager.SetRoomActiveState(r.Context(), roomResp.ID, true)

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
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to open tenant transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
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
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to list rooms", Code: http.StatusInternalServerError})
		return
	}
	defer rows.Close()
	rooms := []RoomResponse{}
	for rows.Next() {
		var roomResp RoomResponse
		if err := rows.Scan(&roomResp.ID, &roomResp.Title, &roomResp.IsActive, &roomResp.CreatedAt); err != nil {
			sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to decode room", Code: http.StatusInternalServerError})
			return
		}
		rooms = append(rooms, roomResp)
	}
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
	state, err := h.StateManager.GetLatestRoomEvent(r.Context(), roomID)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to load room state", Code: http.StatusInternalServerError})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(state))
}
