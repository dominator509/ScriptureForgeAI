package ports

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
	"scriptureforge/internal/domain/room"
)

type RoomHandler struct {
	DB                  *pgxpool.Pool
	StateManager        roomStateStore
	MeetingAdapter      room.MeetingAdapter
	MeetingProvider     string
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
	maxRoomRequestBodyBytes   = 16 * 1024
	maxRoomTitleBytes         = 256
	roomCleanupTimeout        = 5 * time.Second
	roomReconciliationTimeout = 2 * time.Second
)

type RoomResponse struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	IsActive        bool   `json:"is_active"`
	CreatedAt       string `json:"created_at,omitempty"`
	MeetingProvider string `json:"meeting_provider,omitempty"`
	MeetingID       string `json:"meeting_id,omitempty"`
	JoinURL         string `json:"join_url,omitempty"`
}

type roomMeetingMetadata struct {
	Mode    string `json:"mode"`
	JoinURL string `json:"join_url,omitempty"`
}

func offlineMeetingDetails(hostID string) *room.MeetingDetails {
	return &room.MeetingDetails{
		ID:       fmt.Sprintf("offline-%d", time.Now().UnixNano()),
		JoinURL:  "offline://in-person",
		StartURL: "offline://host/" + hostID,
	}
}

func (h *RoomHandler) provisionMeeting(ctx context.Context, title, hostID string) (*room.MeetingDetails, error) {
	if h.MeetingAdapter == nil {
		return offlineMeetingDetails(hostID), nil
	}
	return h.MeetingAdapter.CreateMeeting(ctx, room.MeetingConfig{
		Topic:    title,
		Duration: 60,
		HostID:   hostID,
	})
}

func persistedMeetingDetails(details *room.MeetingDetails, preferredProvider string) (string, string, []byte, error) {
	if details == nil || strings.TrimSpace(details.ID) == "" {
		return "", "", nil, fmt.Errorf("meeting adapter returned incomplete details")
	}

	provider := "offline"
	meetingID := ""
	metadata := roomMeetingMetadata{Mode: provider, JoinURL: strings.TrimSpace(details.JoinURL)}
	if metadata.JoinURL != "offline://in-person" && !strings.HasPrefix(details.ID, "offline-") {
		provider = strings.TrimSpace(preferredProvider)
		if provider == "" {
			provider = "external"
		}
		meetingID = strings.TrimSpace(details.ID)
		metadata.Mode = provider
	}
	rawMetadata, err := json.Marshal(metadata)
	if err != nil {
		return "", "", nil, err
	}
	return provider, meetingID, rawMetadata, nil
}

func applyRoomMeetingMetadata(response *RoomResponse, provider, meetingID, rawMetadata string) {
	response.MeetingProvider = provider
	response.MeetingID = meetingID
	var metadata roomMeetingMetadata
	if json.Unmarshal([]byte(rawMetadata), &metadata) == nil {
		response.JoinURL = metadata.JoinURL
	}
}

func (h *RoomHandler) terminateProvisionedMeeting(ctx context.Context, details *room.MeetingDetails) error {
	if h.MeetingAdapter == nil || details == nil || details.ID == "" || details.JoinURL == "offline://in-person" || strings.HasPrefix(details.ID, "offline-") {
		return nil
	}
	started := time.Now()
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), roomCleanupTimeout)
	defer cancel()
	err := h.MeetingAdapter.TerminateMeeting(cleanupCtx, details.ID)
	status := "success"
	if err != nil {
		status = "error"
	}
	observability.ObserveDependencyFromContext(ctx, "zoom", "terminate_meeting_cleanup", status, time.Since(started))
	return err
}

func (h *RoomHandler) deactivateRoomAfterStateFailure(ctx context.Context, claims *auth.TokenClaims, roomID string) error {
	tx, err := h.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := auth.SetTenantContext(ctx, tx, claims.OrganizationID); err != nil {
		return err
	}
	tag, err := tx.Exec(
		ctx,
		`UPDATE live_rooms
		 SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
		 WHERE organization_id = $1 AND id = $2`,
		claims.OrganizationID,
		roomID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("room state compensation affected %d rows", tag.RowsAffected())
	}
	return tx.Commit(ctx)
}

func isTerminalMeetingStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "ended", "cancelled", "canceled", "deleted":
		return true
	default:
		return false
	}
}

func shouldReconcileMeeting(roomResp RoomResponse) bool {
	return strings.TrimSpace(roomResp.MeetingID) != "" &&
		!strings.EqualFold(strings.TrimSpace(roomResp.MeetingProvider), "offline")
}

func (h *RoomHandler) deactivateReconciledRoom(ctx context.Context, claims *auth.TokenClaims, roomID, meetingID string) error {
	tx, err := h.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := auth.SetTenantContext(ctx, tx, claims.OrganizationID); err != nil {
		return err
	}
	if _, err := tx.Exec(
		ctx,
		`UPDATE live_rooms
		 SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
		 WHERE organization_id = $1
		   AND id = $2
		   AND meeting_external_id = $3
		   AND is_active = TRUE`,
		claims.OrganizationID,
		roomID,
		meetingID,
	); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if h.StateManager != nil {
		if err := h.StateManager.SetRoomActiveState(ctx, roomID, false); err != nil {
			return err
		}
	}
	return nil
}

// reconcileActiveRooms closes the stale-active window when a provider webhook
// is delayed or lost. Provider errors preserve the durable state because an
// unavailable provider is not evidence that a meeting has ended.
func (h *RoomHandler) reconcileActiveRooms(ctx context.Context, claims *auth.TokenClaims, rooms []RoomResponse) ([]RoomResponse, error) {
	if h.MeetingAdapter == nil || h.DB == nil || len(rooms) == 0 {
		return rooms, nil
	}
	reconcileCtx, cancel := context.WithTimeout(ctx, roomReconciliationTimeout)
	defer cancel()

	kept := make([]RoomResponse, 0, len(rooms))
	for _, roomResp := range rooms {
		if !shouldReconcileMeeting(roomResp) {
			kept = append(kept, roomResp)
			continue
		}
		started := time.Now()
		providerStatus, err := h.MeetingAdapter.GetMeetingStatus(reconcileCtx, roomResp.MeetingID)
		if err != nil {
			observability.ObserveDependencyFromContext(ctx, "zoom", "room_status_reconciliation", "error", time.Since(started))
			kept = append(kept, roomResp)
			continue
		}
		if !isTerminalMeetingStatus(providerStatus) {
			observability.ObserveDependencyFromContext(ctx, "zoom", "room_status_reconciliation", "active", time.Since(started))
			kept = append(kept, roomResp)
			continue
		}
		if err := h.deactivateReconciledRoom(reconcileCtx, claims, roomResp.ID, roomResp.MeetingID); err != nil {
			observability.ObserveDependencyFromContext(ctx, "zoom", "room_status_reconciliation", "error", time.Since(started))
			return nil, err
		}
		observability.ObserveDependencyFromContext(ctx, "zoom", "room_status_reconciliation", "terminal", time.Since(started))
	}
	return kept, nil
}

func scanActiveRoomRows(rows pgx.Rows) ([]RoomResponse, error) {
	rooms := []RoomResponse{}
	for rows.Next() {
		var roomResp RoomResponse
		var provider, meetingID, rawMetadata string
		if err := rows.Scan(&roomResp.ID, &roomResp.Title, &roomResp.IsActive, &roomResp.CreatedAt, &provider, &meetingID, &rawMetadata); err != nil {
			return nil, err
		}
		applyRoomMeetingMetadata(&roomResp, provider, meetingID, rawMetadata)
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
	meetingDetails, err := h.provisionMeeting(r.Context(), title, claims.UserID)
	if err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "zoom", "create_meeting", "error", 0)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to provision room meeting", Code: http.StatusServiceUnavailable})
		return
	}
	meetingProvider, meetingID, meetingMetadata, err := persistedMeetingDetails(meetingDetails, h.MeetingProvider)
	if err != nil {
		h.terminateProvisionedMeeting(r.Context(), meetingDetails)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Meeting provider returned invalid details", Code: http.StatusServiceUnavailable})
		return
	}
	roomInitialized := false
	defer func() {
		if !roomInitialized {
			h.terminateProvisionedMeeting(r.Context(), meetingDetails)
		}
	}()

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
		`INSERT INTO live_rooms (organization_id, host_user_id, title, meeting_provider, meeting_external_id, meeting_metadata)
		 VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6::jsonb)
		 RETURNING id, title, is_active, created_at::text`,
		claims.OrganizationID,
		claims.UserID,
		title,
		meetingProvider,
		meetingID,
		string(meetingMetadata),
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
		observability.ObserveDependencyFromContext(r.Context(), "redis", "room_set_active", redisStatus, time.Since(redisStart))

		compensationStart := time.Now()
		compensationStatus := "error"
		if compensationErr := h.deactivateRoomAfterStateFailure(r.Context(), claims, roomResp.ID); compensationErr == nil {
			compensationStatus = "success"
		}
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "room_state_compensation", compensationStatus, time.Since(compensationStart))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to initialize room state", Code: http.StatusServiceUnavailable})
		return
	}
	observability.ObserveDependencyFromContext(r.Context(), "redis", "room_set_active", redisStatus, time.Since(redisStart))
	applyRoomMeetingMetadata(&roomResp, meetingProvider, meetingID, string(meetingMetadata))
	roomInitialized = true

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
		`SELECT id, title, is_active, created_at::text, meeting_provider,
		        COALESCE(meeting_external_id, ''), meeting_metadata::text
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
	if err := tx.Commit(r.Context()); err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "rooms_active", status, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to finish room lookup", Code: http.StatusInternalServerError})
		return
	}
	rooms, err = h.reconcileActiveRooms(r.Context(), claims, rooms)
	if err != nil {
		observability.ObserveDependencyFromContext(r.Context(), "postgres", "rooms_active", status, time.Since(start))
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to reconcile room state", Code: http.StatusServiceUnavailable})
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
