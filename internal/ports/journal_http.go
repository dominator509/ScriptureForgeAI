package ports

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
)

type JournalHandler struct {
	DB *pgxpool.Pool
}

type JournalPayload struct {
	ID          string `json:"id,omitempty"`
	Ciphertext  string `json:"ciphertext"`
	IV          string `json:"iv"`
	SaltID      string `json:"salt_id"`
	SaltVersion int    `json:"salt_version"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type JournalBootstrapResponse struct {
	SaltID      string `json:"salt_id"`
	SaltVersion int    `json:"salt_version"`
}

func (h *JournalHandler) ServeJournalBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}
	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}
	saltID, err := journalSaltID(claims.OrganizationID, claims.UserID)
	if err != nil {
		sendAuthError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JournalBootstrapResponse{SaltID: saltID, SaltVersion: 1})
}

func journalSaltID(organizationID, userID string) (string, *auth.PlatformException) {
	secret := os.Getenv("JOURNAL_SALT_SECRET")
	if secret == "" {
		secret = os.Getenv("JWT_SECRET_KEY")
	}
	if secret == "" {
		return "", &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Journal salt secret is not configured", Code: http.StatusInternalServerError}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(organizationID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(userID))
	digest := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "journal:v1:" + digest, nil
}

func (h *JournalHandler) ServeJournalEntries(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listJournalEntries(w, r)
	case http.MethodPost:
		h.createJournalEntry(w, r)
	default:
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
	}
}

func (h *JournalHandler) ServeJournalEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}
	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/journal_entries/")
	if id == "" || strings.Contains(id, "/") {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Invalid journal entry id", Code: http.StatusBadRequest})
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

	var entry JournalPayload
	err = tx.QueryRow(
		r.Context(),
		`SELECT id, ciphertext, iv, salt_id, salt_version, created_at::text
		 FROM journal_entries
		 WHERE id = $1 AND organization_id = $2 AND user_id = $3`,
		id,
		claims.OrganizationID,
		claims.UserID,
	).Scan(&entry.ID, &entry.Ciphertext, &entry.IV, &entry.SaltID, &entry.SaltVersion, &entry.CreatedAt)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Journal entry not found", Code: http.StatusNotFound})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entry)
}

func (h *JournalHandler) createJournalEntry(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}

	var req JournalPayload
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.Ciphertext == "" || req.IV == "" || req.SaltID == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Invalid encrypted journal payload", Code: http.StatusBadRequest})
		return
	}
	if req.SaltVersion == 0 {
		req.SaltVersion = 1
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

	err = tx.QueryRow(
		r.Context(),
		`INSERT INTO journal_entries (organization_id, user_id, ciphertext, iv, salt_id, salt_version)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, created_at::text`,
		claims.OrganizationID,
		claims.UserID,
		req.Ciphertext,
		req.IV,
		req.SaltID,
		req.SaltVersion,
	).Scan(&req.ID, &req.CreatedAt)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to persist encrypted journal payload", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to commit journal payload", Code: http.StatusInternalServerError})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(req)
}

func (h *JournalHandler) listJournalEntries(w http.ResponseWriter, r *http.Request) {
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
		`SELECT id, ciphertext, iv, salt_id, salt_version, created_at::text
		 FROM journal_entries
		 WHERE organization_id = $1 AND user_id = $2
		 ORDER BY created_at DESC
		 LIMIT 100`,
		claims.OrganizationID,
		claims.UserID,
	)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to list journal entries", Code: http.StatusInternalServerError})
		return
	}
	defer rows.Close()

	entries := []JournalPayload{}
	for rows.Next() {
		var entry JournalPayload
		if err := rows.Scan(&entry.ID, &entry.Ciphertext, &entry.IV, &entry.SaltID, &entry.SaltVersion, &entry.CreatedAt); err != nil {
			sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to decode journal entry", Code: http.StatusInternalServerError})
			return
		}
		entries = append(entries, entry)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}
