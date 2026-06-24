package ports

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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
}

type LoginRequest struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	OrganizationID string `json:"organization_id"`
	MFACode        string `json:"mfa_code,omitempty"`
}

type RefreshRequest struct {
	RefreshToken   string `json:"refresh_token"`
	OrganizationID string `json:"organization_id"`
}

type AuthResponse struct {
	Token          string `json:"token,omitempty"`
	RefreshToken   string `json:"refresh_token,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	RequiresMFA    bool   `json:"requires_mfa,omitempty"`
}

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour
)

var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)

func sendAuthError(w http.ResponseWriter, pe *auth.PlatformException) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(pe.Code)
	_ = json.NewEncoder(w).Encode(pe)
}

func generateOpaqueToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func privilegedRole(role string) bool {
	switch strings.ToLower(role) {
	case "admin", "tenant_admin", "super_admin":
		return true
	default:
		return false
	}
}

func generateMFASecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func verifyTOTP(secret, code string, now time.Time) bool {
	if secret == "" || code == "" {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	for skew := int64(-1); skew <= 1; skew++ {
		counter := uint64(now.Unix()/30 + skew)
		var msg [8]byte
		binary.BigEndian.PutUint64(msg[:], counter)
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(msg[:])
		sum := mac.Sum(nil)
		offset := sum[len(sum)-1] & 0x0f
		binCode := (int(sum[offset])&0x7f)<<24 |
			(int(sum[offset+1])&0xff)<<16 |
			(int(sum[offset+2])&0xff)<<8 |
			(int(sum[offset+3]) & 0xff)
		expected := fmt.Sprintf("%06d", binCode%1000000)
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

func storeRefreshToken(ctx context.Context, tx pgx.Tx, userID, orgID string, rotatedFrom *string) (string, error) {
	refreshToken, err := generateOpaqueToken()
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(
		ctx,
		`INSERT INTO refresh_tokens (organization_id, user_id, token_hash, expires_at, rotated_from)
		 VALUES ($1, $2, $3, $4, $5)`,
		orgID,
		userID,
		hashToken(refreshToken),
		time.Now().Add(refreshTokenTTL),
		rotatedFrom,
	)
	if err != nil {
		return "", err
	}
	return refreshToken, nil
}

func (h *AuthHandler) issueRefreshToken(r *http.Request, userID, orgID string, rotatedFrom *string) (string, error) {
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		return "", err
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, orgID); err != nil {
		return "", err
	}
	refreshToken, err := storeRefreshToken(r.Context(), tx, userID, orgID, rotatedFrom)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(r.Context()); err != nil {
		return "", err
	}
	return refreshToken, nil
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
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !emailRegex.MatchString(req.Email) || len(req.Password) < 8 || req.OrganizationID == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Validation failed: invalid email, short password, or missing required fields", Code: http.StatusBadRequest})
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password, auth.DefaultHashConfig)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to process credentials", Code: http.StatusInternalServerError})
		return
	}

	forcedRole := "member"
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to open registration transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, req.OrganizationID); err != nil {
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}

	var newUserID string
	err = tx.QueryRow(
		r.Context(),
		`INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id`,
		req.OrganizationID,
		req.Email,
		hashedPassword,
		forcedRole,
	).Scan(&newUserID)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Registration failed (email may already exist or org invalid)", Code: http.StatusConflict})
		return
	}

	token, err := auth.GenerateToken(newUserID, req.OrganizationID, forcedRole, accessTokenTTL)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue token", Code: http.StatusInternalServerError})
		return
	}
	refreshToken, err := storeRefreshToken(r.Context(), tx, newUserID, req.OrganizationID, nil)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue refresh token", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to commit registration", Code: http.StatusInternalServerError})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(AuthResponse{Token: token, RefreshToken: refreshToken, UserID: newUserID, OrganizationID: req.OrganizationID})
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
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.OrganizationID == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Organization ID is required", Code: http.StatusBadRequest})
		return
	}

	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to open login transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, req.OrganizationID); err != nil {
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}

	var userID, orgID, role, hash, mfaSecret string
	var mfaEnabled bool
	err = tx.QueryRow(
		r.Context(),
		`SELECT id, organization_id, role, password_hash, COALESCE(mfa_secret, ''), mfa_enabled
		 FROM users
		 WHERE email = $1 AND organization_id = $2`,
		req.Email,
		req.OrganizationID,
	).Scan(&userID, &orgID, &role, &hash, &mfaSecret, &mfaEnabled)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid credentials", Code: http.StatusUnauthorized})
		return
	}

	match, err := auth.VerifyPassword(req.Password, hash)
	if err != nil || !match {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid credentials", Code: http.StatusUnauthorized})
		return
	}

	if privilegedRole(role) && (!mfaEnabled || !verifyTOTP(mfaSecret, req.MFACode, time.Now())) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(AuthResponse{UserID: userID, OrganizationID: orgID, RequiresMFA: true})
		return
	}

	token, err := auth.GenerateToken(userID, orgID, role, accessTokenTTL)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue token", Code: http.StatusInternalServerError})
		return
	}
	refreshToken, err := h.issueRefreshToken(r, userID, orgID, nil)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue refresh token", Code: http.StatusInternalServerError})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AuthResponse{Token: token, RefreshToken: refreshToken, UserID: userID, OrganizationID: orgID})
}

func (h *AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" || req.OrganizationID == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid refresh payload", Code: http.StatusBadRequest})
		return
	}

	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to open refresh transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, req.OrganizationID); err != nil {
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}

	var tokenID, userID, orgID, role string
	err = tx.QueryRow(
		r.Context(),
		`SELECT rt.id, rt.user_id, rt.organization_id, u.role
		 FROM refresh_tokens rt
		 JOIN users u ON u.id = rt.user_id
		 WHERE rt.token_hash = $1
		   AND rt.organization_id = $2
		   AND rt.revoked_at IS NULL
		   AND rt.expires_at > CURRENT_TIMESTAMP`,
		hashToken(req.RefreshToken),
		req.OrganizationID,
	).Scan(&tokenID, &userID, &orgID, &role)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid or expired refresh token", Code: http.StatusUnauthorized})
		return
	}

	if _, err := tx.Exec(r.Context(), `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1`, tokenID); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to rotate refresh token", Code: http.StatusInternalServerError})
		return
	}

	token, err := auth.GenerateToken(userID, orgID, role, accessTokenTTL)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue token", Code: http.StatusInternalServerError})
		return
	}
	refreshToken, err := storeRefreshToken(r.Context(), tx, userID, orgID, &tokenID)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue refresh token", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to commit refresh rotation", Code: http.StatusInternalServerError})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AuthResponse{Token: token, RefreshToken: refreshToken, UserID: userID, OrganizationID: orgID})
}

func (h *AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" || req.OrganizationID == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid logout payload", Code: http.StatusBadRequest})
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to open logout transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, req.OrganizationID); err != nil {
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}
	_, _ = tx.Exec(r.Context(), `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = $1 AND organization_id = $2`, hashToken(req.RefreshToken), req.OrganizationID)
	_ = tx.Commit(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) MFAEnrollHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil || !privilegedRole(claims.Role) {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "MFA enrollment requires a privileged role", Code: http.StatusForbidden})
		return
	}

	secret, err := generateMFASecret()
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to generate MFA secret", Code: http.StatusInternalServerError})
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to open MFA transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE users SET mfa_secret = $1, mfa_enabled = TRUE WHERE id = $2 AND organization_id = $3`, secret, claims.UserID, claims.OrganizationID); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to enable MFA", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to commit MFA enrollment", Code: http.StatusInternalServerError})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"secret": secret})
}
