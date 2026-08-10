package ports

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
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

const (
	journalAESGCMIVBytes          = 12
	maxJournalRequestBodyBytes    = 256 * 1024
	maxJournalCiphertextBytes     = 128 * 1024
	maxJournalCiphertextTextBytes = ((maxJournalCiphertextBytes + 2) / 3) * 4
	maxJournalIVTextBytes         = 64
	maxJournalSaltIDBytes         = 128
)

func observeJournalPostgres(r *http.Request, operation, status string, start time.Time) {
	observability.ObserveDependencyFromContext(r.Context(), "postgres", operation, status, time.Since(start))
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

	start := time.Now()
	status := "error"
	if h.DB == nil {
		observeJournalPostgres(r, "journal_read", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Journal database is not configured", Code: http.StatusInternalServerError})
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		observeJournalPostgres(r, "journal_read", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to open tenant transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		observeJournalPostgres(r, "journal_read", status, start)
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
		status = "not_found"
		observeJournalPostgres(r, "journal_read", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Journal entry not found", Code: http.StatusNotFound})
		return
	}
	status = "success"
	observeJournalPostgres(r, "journal_read", status, start)

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
	if pe := decodeBoundedJSON(w, r, maxJournalRequestBodyBytes, &req, auth.AuthorizationFault, "Invalid encrypted journal payload"); pe != nil {
		sendAuthError(w, pe)
		return
	}
	if req.Ciphertext == "" || req.IV == "" || req.SaltID == "" ||
		len(req.Ciphertext) > maxJournalCiphertextTextBytes ||
		len(req.IV) > maxJournalIVTextBytes ||
		len(req.SaltID) > maxJournalSaltIDBytes {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Invalid encrypted journal payload", Code: http.StatusBadRequest})
		return
	}
	if req.SaltVersion == 0 {
		req.SaltVersion = 1
	}
	if err := validateEncryptedJournalPayload(req); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: err.Error(), Code: http.StatusBadRequest})
		return
	}

	start := time.Now()
	status := "error"
	if h.DB == nil {
		observeJournalPostgres(r, "journal_create", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Journal database is not configured", Code: http.StatusInternalServerError})
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		observeJournalPostgres(r, "journal_create", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to open tenant transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		observeJournalPostgres(r, "journal_create", status, start)
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
		observeJournalPostgres(r, "journal_create", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to persist encrypted journal payload", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		observeJournalPostgres(r, "journal_create", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to commit journal payload", Code: http.StatusInternalServerError})
		return
	}
	status = "success"
	observeJournalPostgres(r, "journal_create", status, start)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(req)
}

func validateEncryptedJournalPayload(payload JournalPayload) error {
	if len(payload.Ciphertext) > maxJournalCiphertextTextBytes || len(payload.IV) > maxJournalIVTextBytes || len(payload.SaltID) > maxJournalSaltIDBytes {
		return fmt.Errorf("Invalid encrypted journal payload")
	}
	ciphertext, err := decodeStrictBase64(payload.Ciphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > maxJournalCiphertextBytes {
		return fmt.Errorf("Invalid encrypted journal payload")
	}
	iv, err := decodeStrictBase64(payload.IV)
	if err != nil || len(iv) != journalAESGCMIVBytes {
		return fmt.Errorf("Invalid encrypted journal payload")
	}
	if !strings.HasPrefix(payload.SaltID, "journal:v") || !strings.Contains(payload.SaltID, ":") {
		return fmt.Errorf("Invalid encrypted journal payload")
	}
	if payload.SaltVersion < 1 {
		return fmt.Errorf("Invalid encrypted journal payload")
	}
	return nil
}

func decodeStrictBase64(value string) ([]byte, error) {
	if strings.TrimSpace(value) != value || value == "" {
		return nil, fmt.Errorf("invalid base64")
	}
	if decoded, err := base64.StdEncoding.Strict().DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.Strict().DecodeString(value)
}

func (h *JournalHandler) listJournalEntries(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}

	start := time.Now()
	status := "error"
	if h.DB == nil {
		observeJournalPostgres(r, "journal_list", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Journal database is not configured", Code: http.StatusInternalServerError})
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		observeJournalPostgres(r, "journal_list", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to open tenant transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		observeJournalPostgres(r, "journal_list", status, start)
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
		observeJournalPostgres(r, "journal_list", status, start)
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to list journal entries", Code: http.StatusInternalServerError})
		return
	}
	defer rows.Close()

	entries := []JournalPayload{}
	for rows.Next() {
		var entry JournalPayload
		if err := rows.Scan(&entry.ID, &entry.Ciphertext, &entry.IV, &entry.SaltID, &entry.SaltVersion, &entry.CreatedAt); err != nil {
			observeJournalPostgres(r, "journal_list", status, start)
			sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Failed to decode journal entry", Code: http.StatusInternalServerError})
			return
		}
		entries = append(entries, entry)
	}
	status = "success"
	observeJournalPostgres(r, "journal_list", status, start)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}
