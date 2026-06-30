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
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/abuse"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
)

type AuthHandler struct {
	DB             *pgxpool.Pool
	AccountLimiter *abuse.Limiter
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

type MFAVerifyRequest struct {
	MFACode string `json:"mfa_code"`
}

type WorkspaceSwitchRequest struct {
	OrganizationID string `json:"organization_id"`
}

type WorkspaceSwitchResponse struct {
	OrganizationID string `json:"organization_id"`
}

type AuthResponse struct {
	Token          string `json:"token,omitempty"`
	RefreshToken   string `json:"refresh_token,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	RequiresMFA    bool   `json:"requires_mfa,omitempty"`
}

type MFAVerifyResponse struct {
	Verified bool `json:"verified"`
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

func observeAuthPostgres(ctx context.Context, operation string, started time.Time, status *string) {
	observability.ObserveDependencyFromContext(ctx, "postgres", operation, *status, time.Since(started))
}

func observeAuthLimiter(ctx context.Context, status string, started time.Time) {
	observability.ObserveDependencyFromContext(ctx, "abuse_limiter", abuse.ProfileAuthAccount, status, time.Since(started))
}

func accountLimitIdentity(email, orgID string) string {
	return "account:" + hashToken(strings.ToLower(strings.TrimSpace(orgID))+"|"+strings.ToLower(strings.TrimSpace(email)))
}

func refreshLimitIdentity(refreshToken, orgID string) string {
	return "refresh:" + hashToken(strings.ToLower(strings.TrimSpace(orgID))+"|"+hashToken(strings.TrimSpace(refreshToken)))
}

func (h *AuthHandler) enforceAuthAccountLimit(w http.ResponseWriter, r *http.Request, email, orgID string) bool {
	return h.enforceAuthCredentialLimit(w, r, accountLimitIdentity(email, orgID), "Too many login attempts for this account; retry after the rate-limit window")
}

func (h *AuthHandler) enforceRefreshTokenLimit(w http.ResponseWriter, r *http.Request, refreshToken, orgID string) bool {
	return h.enforceAuthCredentialLimit(w, r, refreshLimitIdentity(refreshToken, orgID), "Too many refresh attempts for this token; retry after the rate-limit window")
}

func (h *AuthHandler) enforceAuthCredentialLimit(w http.ResponseWriter, r *http.Request, identity, message string) bool {
	if h.AccountLimiter == nil {
		return true
	}
	started := time.Now()
	result, enforced := h.AccountLimiter.Check(abuse.ProfileAuthAccount, identity)
	if !enforced {
		return true
	}
	status := "allowed"
	if !result.Allowed {
		status = "limited"
	}
	observeAuthLimiter(r.Context(), status, started)
	writeAuthAccountLimitHeaders(w, result)
	if result.Allowed {
		return true
	}
	if result.RetryAfter < time.Second {
		result.RetryAfter = time.Second
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Round(time.Second).Seconds())))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(auth.PlatformException{
		Category: "ABUSE_RATE_LIMIT_FAULT",
		Message:  message,
		Code:     http.StatusTooManyRequests,
	})
	return false
}

func writeAuthAccountLimitHeaders(w http.ResponseWriter, result abuse.Result) {
	remaining := result.Remaining
	if remaining < 0 {
		remaining = 0
	}
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	if !result.ResetAt.IsZero() {
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
	}
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
	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_issue_refresh_token", started, &metricStatus)

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
	metricStatus = "success"
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

	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_register", started, &metricStatus)

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
		metricStatus = "conflict"
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

	metricStatus = "success"
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
	if !h.enforceAuthAccountLimit(w, r, req.Email, req.OrganizationID) {
		return
	}

	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_login", started, &metricStatus)

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
		metricStatus = "invalid_credentials"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid credentials", Code: http.StatusUnauthorized})
		return
	}

	match, err := auth.VerifyPassword(req.Password, hash)
	if err != nil || !match {
		metricStatus = "invalid_credentials"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid credentials", Code: http.StatusUnauthorized})
		return
	}

	if privilegedRole(role) && (!mfaEnabled || !verifyTOTP(mfaSecret, req.MFACode, time.Now())) {
		metricStatus = "mfa_required"
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

	metricStatus = "success"
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
	if !h.enforceRefreshTokenLimit(w, r, req.RefreshToken, req.OrganizationID) {
		return
	}

	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_refresh", started, &metricStatus)

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
		metricStatus = "invalid_or_expired"
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

	metricStatus = "success"
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
	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_logout", started, &metricStatus)

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
	if _, err := tx.Exec(r.Context(), `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = $1 AND organization_id = $2`, hashToken(req.RefreshToken), req.OrganizationID); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to revoke refresh token", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to commit logout", Code: http.StatusInternalServerError})
		return
	}
	metricStatus = "success"
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) WorkspaceSwitchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req WorkspaceSwitchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.OrganizationID) == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid workspace switch payload", Code: http.StatusBadRequest})
		return
	}

	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Missing authenticated user context", Code: http.StatusUnauthorized})
		return
	}

	requestedOrgID := strings.TrimSpace(req.OrganizationID)
	if requestedOrgID != claims.OrganizationID {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Workspace switch denied", Code: http.StatusForbidden})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(WorkspaceSwitchResponse{OrganizationID: claims.OrganizationID})
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
	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_mfa_enroll", started, &metricStatus)

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

	metricStatus = "success"
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"secret": secret})
}

func (h *AuthHandler) MFAVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}
	if !privilegedRole(claims.Role) {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "MFA verification is available only for privileged users", Code: http.StatusForbidden})
		return
	}

	var req MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.MFACode) == "" {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid MFA verification payload", Code: http.StatusBadRequest})
		return
	}

	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_mfa_verify", started, &metricStatus)

	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to open MFA verification transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}

	var mfaSecret string
	var mfaEnabled bool
	err = tx.QueryRow(
		r.Context(),
		`SELECT COALESCE(mfa_secret, ''), COALESCE(mfa_enabled, false)
		 FROM users
		 WHERE id = $1 AND organization_id = $2`,
		claims.UserID,
		claims.OrganizationID,
	).Scan(&mfaSecret, &mfaEnabled)
	if err != nil {
		metricStatus = "not_configured"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "MFA not configured", Code: http.StatusNotFound})
		return
	}
	if !mfaEnabled || mfaSecret == "" {
		metricStatus = "not_enabled"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "MFA is not enabled", Code: http.StatusBadRequest})
		return
	}

	if !verifyTOTP(mfaSecret, req.MFACode, time.Now()) {
		metricStatus = "invalid_code"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "MFA code verification failed", Code: http.StatusUnauthorized})
		return
	}

	metricStatus = "success"
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(MFAVerifyResponse{Verified: true})
}
