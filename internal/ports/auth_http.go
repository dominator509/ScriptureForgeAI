package ports

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
)

type AuthHandler struct {
	DB *pgxpool.Pool
}

type RegisterRequest struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	OrganizationID string `json:"organization_id"`
	// Role removed from public request to prevent privilege escalation
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)

func sendAuthError(w http.ResponseWriter, pe *auth.PlatformException) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(pe.Code)
	json.NewEncoder(w).Encode(pe)
}

func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid request payload", Code: http.StatusBadRequest})
		return
	}

	if !emailRegex.MatchString(req.Email) || len(req.Password) < 8 || req.OrganizationID == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Validation failed: invalid email, short password, or missing required fields", Code: http.StatusBadRequest})
		return
	}

	// 1. Hash Password
	hashedPassword, err := auth.HashPassword(req.Password, auth.DefaultHashConfig)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: "INTERNAL_ERROR", Message: "Failed to process credentials", Code: http.StatusInternalServerError})
		return
	}

	// 2. Persist User - Forcing Role to 'member' to prevent privilege escalation
	forcedRole := "member"
	query := `INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id`
	var newUserID string
	err = h.DB.QueryRow(r.Context(), query, req.OrganizationID, req.Email, hashedPassword, forcedRole).Scan(&newUserID)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Registration failed (email may already exist or org invalid)", Code: http.StatusConflict})
		return
	}

	// 3. Issue Token
	token, err := auth.GenerateToken(newUserID, req.OrganizationID, forcedRole, 2*time.Hour)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue token", Code: http.StatusInternalServerError})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"token": token, "user_id": newUserID})
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid request payload", Code: http.StatusBadRequest})
		return
	}

	var userID, orgID, role, hash string
	query := `SELECT id, organization_id, role, password_hash FROM users WHERE email = $1`
	err := h.DB.QueryRow(r.Context(), query, req.Email).Scan(&userID, &orgID, &role, &hash)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid credentials", Code: http.StatusUnauthorized})
		return
	}

	match, err := auth.VerifyPassword(req.Password, hash)
	if err != nil || !match {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid credentials", Code: http.StatusUnauthorized})
		return
	}

	token, err := auth.GenerateToken(userID, orgID, role, 2*time.Hour)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue token", Code: http.StatusInternalServerError})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": token, "user_id": userID})
}
