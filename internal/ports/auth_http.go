package ports

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/abuse"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
)

type AuthHandler struct {
	DB               *pgxpool.Pool
	AccountLimiter   *abuse.Limiter
	MFAEncryptionKey []byte
}

type RegisterRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	OrganizationName string `json:"organization_name"`
	RequestedRole    string `json:"role,omitempty"`
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
	accessTokenTTL               = 15 * time.Minute
	refreshTokenTTL              = 30 * 24 * time.Hour
	refreshCookieName            = "scriptureforge_refresh"
	maxAuthRequestBodyBytes      = 64 * 1024
	maxAuthEmailBytes            = 320
	maxAuthPasswordBytes         = 1024
	maxAuthOrganizationBytes     = 128
	maxAuthOrganizationNameBytes = 255
	maxAuthRefreshTokenBytes     = 512
	maxAuthMFACodeBytes          = 16
	mfaCiphertextPrefix          = "v1."
)

var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)

func isWebAuthClient(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-ScriptureForge-Client")), "web")
}

func secureRefreshCookie(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOYMENT_ENVIRONMENT"))) {
	case "staging", "production", "prod":
		return true
	default:
		return r.TLS != nil
	}
}

func setRefreshCookie(w http.ResponseWriter, r *http.Request, refreshToken string) {
	if !isWebAuthClient(r) || refreshToken == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    refreshToken,
		Path:     "/api",
		MaxAge:   int(refreshTokenTTL.Seconds()),
		HttpOnly: true,
		Secure:   secureRefreshCookie(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func clearRefreshCookie(w http.ResponseWriter, r *http.Request) {
	if !isWebAuthClient(r) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/api",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureRefreshCookie(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func refreshTokenFromRequest(r *http.Request, bodyToken string) string {
	if strings.TrimSpace(bodyToken) != "" {
		return strings.TrimSpace(bodyToken)
	}
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func writeAuthResponse(w http.ResponseWriter, r *http.Request, response AuthResponse, status int) {
	setRefreshCookie(w, r, response.RefreshToken)
	if isWebAuthClient(r) {
		response.RefreshToken = ""
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func sendAuthError(w http.ResponseWriter, pe *auth.PlatformException) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(pe.Code)
	_ = json.NewEncoder(w).Encode(pe)
}

func (h *AuthHandler) requireDatabase(w http.ResponseWriter) bool {
	if h.DB != nil {
		return true
	}
	sendAuthError(w, &auth.PlatformException{
		Category: auth.AuthenticationFault,
		Message:  "Authentication database is not configured",
		Code:     http.StatusServiceUnavailable,
	})
	return false
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
	result, enforced, err := h.AccountLimiter.CheckContext(r.Context(), abuse.ProfileAuthAccount, identity)
	if !enforced {
		return true
	}
	if err != nil {
		observeAuthLimiter(r.Context(), "unavailable", started)
		writeAuthAccountLimitHeaders(w, result)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(auth.PlatformException{
			Category: "ABUSE_LIMITER_UNAVAILABLE",
			Message:  "authentication temporarily unavailable",
			Code:     http.StatusServiceUnavailable,
		})
		return false
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

func validAuthFieldLengths(email, password, organizationID string) bool {
	return len(email) <= maxAuthEmailBytes &&
		len(password) <= maxAuthPasswordBytes &&
		len(organizationID) <= maxAuthOrganizationBytes
}

func validRegistrationFieldLengths(email, password, organizationName string) bool {
	return len(email) <= maxAuthEmailBytes &&
		len(password) <= maxAuthPasswordBytes &&
		len(organizationName) <= maxAuthOrganizationNameBytes
}

func validMFACode(code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 || len(code) > maxAuthMFACodeBytes {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func generateMFASecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func deriveMFAEncryptionKey(key []byte) ([]byte, error) {
	if len(key) < auth.MinimumSecretBytes {
		return nil, fmt.Errorf("MFA encryption key must be at least %d bytes", auth.MinimumSecretBytes)
	}
	sum := sha256.Sum256(append([]byte("scriptureforge:mfa:v1:"), key...))
	return sum[:], nil
}

// EncryptMFASecret returns an application-encrypted TOTP seed for persistence.
// The caller must keep the key outside the database and secret-bearing mounts.
func EncryptMFASecret(secret string, key []byte) (string, error) {
	derivedKey, err := deriveMFAEncryptionKey(key)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	envelope := append(nonce, ciphertext...)
	return mfaCiphertextPrefix + base64.RawURLEncoding.EncodeToString(envelope), nil
}

func decryptMFASecret(envelope string, key []byte) (string, error) {
	if !strings.HasPrefix(envelope, mfaCiphertextPrefix) {
		return "", fmt.Errorf("MFA seed is not encrypted")
	}
	derivedKey, err := deriveMFAEncryptionKey(key)
	if err != nil {
		return "", err
	}
	encoded := strings.TrimPrefix(envelope, mfaCiphertextPrefix)
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("MFA seed envelope is malformed")
	}
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("MFA seed envelope is truncated")
	}
	plaintext, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("MFA seed envelope failed authentication")
	}
	return string(plaintext), nil
}

func (h *AuthHandler) mfaEncryptionKey() []byte {
	if len(h.MFAEncryptionKey) > 0 {
		return h.MFAEncryptionKey
	}
	return []byte(os.Getenv("MFA_ENCRYPTION_KEY"))
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

func storeRefreshToken(ctx context.Context, tx pgx.Tx, userID, orgID string, rotatedFrom *string, mfaVerified bool) (string, error) {
	refreshToken, err := generateOpaqueToken()
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(
		ctx,
		`INSERT INTO refresh_tokens (organization_id, user_id, token_hash, expires_at, rotated_from, mfa_verified_at)
		 VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 THEN CURRENT_TIMESTAMP ELSE NULL END)`,
		orgID,
		userID,
		hashToken(refreshToken),
		time.Now().Add(refreshTokenTTL),
		rotatedFrom,
		mfaVerified,
	)
	if err != nil {
		return "", err
	}
	return refreshToken, nil
}

func revokeRefreshTokenFamily(ctx context.Context, tx pgx.Tx, tokenHash, orgID string) (int64, error) {
	result, err := tx.Exec(ctx, `
		WITH RECURSIVE token_family AS (
			SELECT id
			  FROM refresh_tokens
			 WHERE token_hash = $1 AND organization_id = $2
			 UNION ALL
			SELECT child.id
			  FROM refresh_tokens child
			  JOIN token_family parent ON child.rotated_from = parent.id
			 WHERE child.organization_id = $2
		)
		UPDATE refresh_tokens
		   SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
		 WHERE id IN (SELECT id FROM token_family)
		   AND organization_id = $2
		   AND revoked_at IS NULL`,
		tokenHash,
		orgID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req RegisterRequest
	if pe := decodeBoundedJSON(w, r, maxAuthRequestBodyBytes, &req, auth.AuthenticationFault, "Invalid request payload"); pe != nil {
		sendAuthError(w, pe)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.OrganizationName = strings.TrimSpace(req.OrganizationName)
	if !emailRegex.MatchString(req.Email) || len(req.Password) < 8 || req.OrganizationName == "" ||
		!validRegistrationFieldLengths(req.Email, req.Password, req.OrganizationName) {
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
	if !h.requireDatabase(w) {
		return
	}

	forcedRole := "member"
	organizationID := uuid.NewString()
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to open registration transaction", Code: http.StatusInternalServerError})
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, organizationID); err != nil {
		sendAuthError(w, err.(*auth.PlatformException))
		return
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO organizations (id, name) VALUES ($1, $2)`, organizationID, req.OrganizationName); err != nil {
		metricStatus = "conflict"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Registration failed while creating workspace", Code: http.StatusConflict})
		return
	}

	var newUserID string
	err = tx.QueryRow(
		r.Context(),
		`INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id`,
		organizationID,
		req.Email,
		hashedPassword,
		forcedRole,
	).Scan(&newUserID)
	if err != nil {
		metricStatus = "conflict"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Registration failed (email may already exist)", Code: http.StatusConflict})
		return
	}

	token, err := auth.GenerateToken(newUserID, organizationID, forcedRole, accessTokenTTL)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue token", Code: http.StatusInternalServerError})
		return
	}
	refreshToken, err := storeRefreshToken(r.Context(), tx, newUserID, organizationID, nil, false)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue refresh token", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to commit registration", Code: http.StatusInternalServerError})
		return
	}

	metricStatus = "success"
	writeAuthResponse(w, r, AuthResponse{Token: token, RefreshToken: refreshToken, UserID: newUserID, OrganizationID: organizationID}, http.StatusCreated)
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req LoginRequest
	if pe := decodeBoundedJSON(w, r, maxAuthRequestBodyBytes, &req, auth.AuthenticationFault, "Invalid request payload"); pe != nil {
		sendAuthError(w, pe)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.OrganizationID == "" || req.Password == "" || !validAuthFieldLengths(req.Email, req.Password, req.OrganizationID) || (req.MFACode != "" && !validMFACode(req.MFACode)) {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Organization ID is required", Code: http.StatusBadRequest})
		return
	}
	if !h.enforceAuthAccountLimit(w, r, req.Email, req.OrganizationID) {
		return
	}

	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_login", started, &metricStatus)
	if !h.requireDatabase(w) {
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

	var userID, orgID, role, hash, encryptedMFASecret string
	var mfaEnabled bool
	err = tx.QueryRow(
		r.Context(),
		`SELECT id, organization_id, role, password_hash, COALESCE(mfa_secret, ''), mfa_enabled
		 FROM users
		 WHERE email = $1 AND organization_id = $2`,
		req.Email,
		req.OrganizationID,
	).Scan(&userID, &orgID, &role, &hash, &encryptedMFASecret, &mfaEnabled)
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

	mfaVerified := false
	if privilegedRole(role) && mfaEnabled {
		mfaSecret, decryptErr := decryptMFASecret(encryptedMFASecret, h.mfaEncryptionKey())
		if decryptErr != nil {
			metricStatus = "mfa_unavailable"
			sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "MFA verification is unavailable", Code: http.StatusServiceUnavailable})
			return
		}
		if !verifyTOTP(mfaSecret, req.MFACode, time.Now()) {
			metricStatus = "mfa_required"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(AuthResponse{UserID: userID, OrganizationID: orgID, RequiresMFA: true})
			return
		}
	}
	if privilegedRole(role) && !mfaEnabled {
		metricStatus = "mfa_required"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(AuthResponse{UserID: userID, OrganizationID: orgID, RequiresMFA: true})
		return
	}
	if privilegedRole(role) {
		mfaVerified = true
	}

	token, err := auth.GenerateToken(userID, orgID, role, accessTokenTTL)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue token", Code: http.StatusInternalServerError})
		return
	}
	refreshMetricStatus := "error"
	refreshStarted := time.Now()
	refreshToken, err := storeRefreshToken(r.Context(), tx, userID, orgID, nil, mfaVerified)
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err == nil {
		refreshMetricStatus = "success"
	}
	observeAuthPostgres(r.Context(), "auth_issue_refresh_token", refreshStarted, &refreshMetricStatus)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue refresh token", Code: http.StatusInternalServerError})
		return
	}

	metricStatus = "success"
	writeAuthResponse(w, r, AuthResponse{Token: token, RefreshToken: refreshToken, UserID: userID, OrganizationID: orgID}, http.StatusOK)
}

func (h *AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req RefreshRequest
	if pe := decodeBoundedJSON(w, r, maxAuthRequestBodyBytes, &req, auth.AuthenticationFault, "Invalid refresh payload"); pe != nil {
		sendAuthError(w, pe)
		return
	}
	req.RefreshToken = refreshTokenFromRequest(r, req.RefreshToken)
	if req.RefreshToken == "" || len(req.RefreshToken) > maxAuthRefreshTokenBytes || req.OrganizationID == "" || len(req.OrganizationID) > maxAuthOrganizationBytes {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid refresh payload", Code: http.StatusBadRequest})
		return
	}
	if !h.enforceRefreshTokenLimit(w, r, req.RefreshToken, req.OrganizationID) {
		return
	}

	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_refresh", started, &metricStatus)
	if !h.requireDatabase(w) {
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

	var tokenID, userID, orgID, role, encryptedMFASecret string
	var mfaVerified, mfaEnabled bool
	err = tx.QueryRow(
		r.Context(),
		`SELECT rt.id, rt.user_id, rt.organization_id, u.role, COALESCE(u.mfa_secret, ''), rt.mfa_verified_at IS NOT NULL, u.mfa_enabled
			 FROM refresh_tokens rt
			 JOIN users u ON u.id = rt.user_id
		 WHERE rt.token_hash = $1
		   AND rt.organization_id = $2
		   AND rt.revoked_at IS NULL
		   AND rt.expires_at > CURRENT_TIMESTAMP
		 FOR UPDATE`,
		hashToken(req.RefreshToken),
		req.OrganizationID,
	).Scan(&tokenID, &userID, &orgID, &role, &encryptedMFASecret, &mfaVerified, &mfaEnabled)
	if err != nil {
		// A revoked token may be a replay of a rotated credential. Revoke its
		// descendants so a stolen refresh family cannot be advanced further.
		if _, revokeErr := revokeRefreshTokenFamily(r.Context(), tx, hashToken(req.RefreshToken), req.OrganizationID); revokeErr != nil {
			sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to contain refresh-token reuse", Code: http.StatusInternalServerError})
			return
		}
		metricStatus = "invalid_or_expired"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid or expired refresh token", Code: http.StatusUnauthorized})
		return
	}
	if privilegedRole(role) && (!mfaEnabled || !mfaVerified) {
		metricStatus = "mfa_required"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(AuthResponse{UserID: userID, OrganizationID: orgID, RequiresMFA: true})
		return
	}
	if privilegedRole(role) {
		if _, decryptErr := decryptMFASecret(encryptedMFASecret, h.mfaEncryptionKey()); decryptErr != nil {
			_, _ = revokeRefreshTokenFamily(r.Context(), tx, hashToken(req.RefreshToken), orgID)
			metricStatus = "mfa_unavailable"
			sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "MFA verification is unavailable", Code: http.StatusServiceUnavailable})
			return
		}
	}

	result, err := tx.Exec(r.Context(), `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL`, tokenID, orgID)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to rotate refresh token", Code: http.StatusInternalServerError})
		return
	}
	if result.RowsAffected() != 1 {
		metricStatus = "invalid_or_expired"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid or expired refresh token", Code: http.StatusUnauthorized})
		return
	}

	token, err := auth.GenerateToken(userID, orgID, role, accessTokenTTL)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue token", Code: http.StatusInternalServerError})
		return
	}
	refreshToken, err := storeRefreshToken(r.Context(), tx, userID, orgID, &tokenID, privilegedRole(role) && mfaVerified)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to issue refresh token", Code: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to commit refresh rotation", Code: http.StatusInternalServerError})
		return
	}

	metricStatus = "success"
	writeAuthResponse(w, r, AuthResponse{Token: token, RefreshToken: refreshToken, UserID: userID, OrganizationID: orgID}, http.StatusOK)
}

func (h *AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req RefreshRequest
	if pe := decodeBoundedJSON(w, r, maxAuthRequestBodyBytes, &req, auth.AuthenticationFault, "Invalid logout payload"); pe != nil {
		sendAuthError(w, pe)
		return
	}
	req.RefreshToken = refreshTokenFromRequest(r, req.RefreshToken)
	if req.RefreshToken == "" || len(req.RefreshToken) > maxAuthRefreshTokenBytes || req.OrganizationID == "" || len(req.OrganizationID) > maxAuthOrganizationBytes {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid logout payload", Code: http.StatusBadRequest})
		return
	}
	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_logout", started, &metricStatus)
	if !h.requireDatabase(w) {
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
	rowsRevoked, err := revokeRefreshTokenFamily(r.Context(), tx, hashToken(req.RefreshToken), req.OrganizationID)
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to revoke refresh token", Code: http.StatusInternalServerError})
		return
	}
	if rowsRevoked == 0 {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid or already revoked refresh token", Code: http.StatusUnauthorized})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to commit logout", Code: http.StatusInternalServerError})
		return
	}
	metricStatus = "success"
	clearRefreshCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) WorkspaceSwitchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	var req WorkspaceSwitchRequest
	if pe := decodeBoundedJSON(w, r, maxAuthRequestBodyBytes, &req, auth.AuthenticationFault, "Invalid workspace switch payload"); pe != nil {
		sendAuthError(w, pe)
		return
	}
	if strings.TrimSpace(req.OrganizationID) == "" || len(req.OrganizationID) > maxAuthOrganizationBytes {
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
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.Method != http.MethodPost {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil || !privilegedRole(claims.Role) {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "MFA enrollment requires a privileged role", Code: http.StatusForbidden})
		return
	}
	if !h.requireDatabase(w) {
		return
	}

	secret, err := generateMFASecret()
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to generate MFA secret", Code: http.StatusInternalServerError})
		return
	}
	encryptedSecret, err := EncryptMFASecret(secret, h.mfaEncryptionKey())
	if err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "MFA encryption is not configured", Code: http.StatusServiceUnavailable})
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
	var mfaEnabled bool
	if err = tx.QueryRow(r.Context(), `SELECT COALESCE(mfa_enabled, false) FROM users WHERE id = $1 AND organization_id = $2`, claims.UserID, claims.OrganizationID).Scan(&mfaEnabled); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "MFA enrollment account was not found", Code: http.StatusNotFound})
		return
	}
	if mfaEnabled {
		metricStatus = "already_enabled"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "MFA is already enabled; verify the existing factor before replacing it", Code: http.StatusConflict})
		return
	}
	// Keep the seed staged until the caller proves possession with a valid TOTP code.
	if _, err = tx.Exec(r.Context(), `UPDATE users SET mfa_secret = $1, mfa_enabled = FALSE WHERE id = $2 AND organization_id = $3`, encryptedSecret, claims.UserID, claims.OrganizationID); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to stage MFA enrollment", Code: http.StatusInternalServerError})
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
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
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
	if pe := decodeBoundedJSON(w, r, maxAuthRequestBodyBytes, &req, auth.AuthenticationFault, "Invalid MFA verification payload"); pe != nil {
		sendAuthError(w, pe)
		return
	}
	if !validMFACode(req.MFACode) {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Invalid MFA verification payload", Code: http.StatusBadRequest})
		return
	}

	metricStatus := "error"
	started := time.Now()
	defer observeAuthPostgres(r.Context(), "auth_mfa_verify", started, &metricStatus)
	if !h.requireDatabase(w) {
		return
	}

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

	var encryptedMFASecret string
	var mfaEnabled bool
	err = tx.QueryRow(
		r.Context(),
		`SELECT COALESCE(mfa_secret, ''), COALESCE(mfa_enabled, false)
		 FROM users
		 WHERE id = $1 AND organization_id = $2`,
		claims.UserID,
		claims.OrganizationID,
	).Scan(&encryptedMFASecret, &mfaEnabled)
	if err != nil || encryptedMFASecret == "" {
		metricStatus = "not_configured"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthorizationFault, Message: "MFA not configured", Code: http.StatusNotFound})
		return
	}
	mfaSecret, decryptErr := decryptMFASecret(encryptedMFASecret, h.mfaEncryptionKey())
	if decryptErr != nil {
		metricStatus = "mfa_unavailable"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "MFA verification is unavailable", Code: http.StatusServiceUnavailable})
		return
	}

	if !verifyTOTP(mfaSecret, req.MFACode, time.Now()) {
		metricStatus = "invalid_code"
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "MFA code verification failed", Code: http.StatusUnauthorized})
		return
	}
	if !mfaEnabled {
		if _, err = tx.Exec(r.Context(), `UPDATE users SET mfa_enabled = TRUE WHERE id = $1 AND organization_id = $2 AND mfa_secret = $3`, claims.UserID, claims.OrganizationID, encryptedMFASecret); err != nil {
			sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to activate MFA enrollment", Code: http.StatusInternalServerError})
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		sendAuthError(w, &auth.PlatformException{Category: auth.AuthenticationFault, Message: "Failed to commit MFA verification", Code: http.StatusInternalServerError})
		return
	}

	metricStatus = "success"
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(MFAVerifyResponse{Verified: true})
}
