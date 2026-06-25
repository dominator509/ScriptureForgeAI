package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/ports"
)

const (
	authOrgID      = "55555555-5555-4555-8555-555555555555"
	authAdminID    = "66666666-6666-4666-8666-666666666666"
	authUserEmail  = "auth-member@example.test"
	authAdminEmail = "auth-admin@example.test"
	authPassword   = "CorrectHorseBatteryStaple!42"
	authMFASecret  = "JBSWY3DPEHPK3PXP"
)

func cleanupAuthFixtures(ctx context.Context, t *testing.T, tx pgx.Tx) {
	t.Helper()
	if _, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, authOrgID); err != nil {
		t.Fatalf("cleanup auth fixtures: %v", err)
	}
}

func seedAuthOrganization(ctx context.Context, t *testing.T, tx pgx.Tx) {
	t.Helper()
	cleanupAuthFixtures(ctx, t, tx)
	if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'Auth Test Org')`, authOrgID); err != nil {
		t.Fatalf("seed auth org: %v", err)
	}
}

func authJSONRequest(method, target string, payload any) *http.Request {
	body, _ := json.Marshal(payload)
	return httptest.NewRequest(method, target, bytes.NewReader(body))
}

func decodeAuthResponse(t *testing.T, recorder *httptest.ResponseRecorder) ports.AuthResponse {
	t.Helper()
	var response ports.AuthResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode auth response %d %q: %v", recorder.Code, recorder.Body.String(), err)
	}
	return response
}

func totpCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", binCode%1000000)
}

func TestAuthRegisterLoginRefreshRotationAndLogout(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "test-secret-long-enough-for-auth-session-tests")
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	setTenantForTest(ctx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
		seedAuthOrganization(ctx, t, tx)
	})
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		setTenantForTest(cleanupCtx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
			cleanupAuthFixtures(ctx, t, tx)
		})
	})

	handler := &ports.AuthHandler{DB: db}
	registerRecorder := httptest.NewRecorder()
	handler.RegisterHandler(registerRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":           authUserEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
		"role":            "admin",
	}))
	if registerRecorder.Code != http.StatusCreated {
		t.Fatalf("register status = %d body = %s", registerRecorder.Code, registerRecorder.Body.String())
	}
	registered := decodeAuthResponse(t, registerRecorder)
	if registered.Token == "" || registered.RefreshToken == "" || registered.UserID == "" || registered.OrganizationID != authOrgID {
		t.Fatalf("register response missing token data: %#v", registered)
	}

	claims, err := auth.ValidateToken(registered.Token)
	if err != nil {
		t.Fatalf("validate registration access token: %v", err)
	}
	if claims.Role != "member" {
		t.Fatalf("registration role = %q, want forced member", claims.Role)
	}
	if ttl := time.Until(claims.ExpiresAt.Time); ttl <= 14*time.Minute || ttl > 16*time.Minute {
		t.Fatalf("access token ttl = %s, want approximately 15 minutes", ttl)
	}

	setTenantForTest(ctx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
		var role string
		if err := tx.QueryRow(ctx, `SELECT role FROM users WHERE email = $1 AND organization_id = $2`, authUserEmail, authOrgID).Scan(&role); err != nil {
			t.Fatalf("query registered role: %v", err)
		}
		if role != "member" {
			t.Fatalf("stored registration role = %q, want member", role)
		}
	})

	setTenantForTest(ctx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 minute' WHERE user_id = $1 AND organization_id = $2`, registered.UserID, authOrgID); err != nil {
			t.Fatalf("expire registration refresh token: %v", err)
		}
	})
	expiredRecorder := httptest.NewRecorder()
	handler.RefreshHandler(expiredRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   registered.RefreshToken,
		"organization_id": authOrgID,
	}))
	if expiredRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expired refresh token status = %d body = %s, want 401", expiredRecorder.Code, expiredRecorder.Body.String())
	}

	loginRecorder := httptest.NewRecorder()
	handler.LoginHandler(loginRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":           authUserEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
	}))
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status = %d body = %s", loginRecorder.Code, loginRecorder.Body.String())
	}
	login := decodeAuthResponse(t, loginRecorder)
	if login.RefreshToken == "" || login.RefreshToken == registered.RefreshToken {
		t.Fatalf("login refresh token = %q, want a new opaque token", login.RefreshToken)
	}

	refreshRecorder := httptest.NewRecorder()
	handler.RefreshHandler(refreshRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   login.RefreshToken,
		"organization_id": authOrgID,
	}))
	if refreshRecorder.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body = %s", refreshRecorder.Code, refreshRecorder.Body.String())
	}
	refreshed := decodeAuthResponse(t, refreshRecorder)
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == login.RefreshToken {
		t.Fatalf("rotated refresh token = %q, want replacement for old token", refreshed.RefreshToken)
	}

	oldTokenRecorder := httptest.NewRecorder()
	handler.RefreshHandler(oldTokenRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   login.RefreshToken,
		"organization_id": authOrgID,
	}))
	if oldTokenRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("old refresh token status = %d body = %s, want 401", oldTokenRecorder.Code, oldTokenRecorder.Body.String())
	}

	crossTenantRecorder := httptest.NewRecorder()
	handler.RefreshHandler(crossTenantRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   refreshed.RefreshToken,
		"organization_id": tenantOrgB,
	}))
	if crossTenantRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant refresh status = %d body = %s, want 401", crossTenantRecorder.Code, crossTenantRecorder.Body.String())
	}

	logoutRecorder := httptest.NewRecorder()
	handler.LogoutHandler(logoutRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/logout", map[string]any{
		"refresh_token":   refreshed.RefreshToken,
		"organization_id": authOrgID,
	}))
	if logoutRecorder.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d body = %s", logoutRecorder.Code, logoutRecorder.Body.String())
	}

	revokedRecorder := httptest.NewRecorder()
	handler.RefreshHandler(revokedRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   refreshed.RefreshToken,
		"organization_id": authOrgID,
	}))
	if revokedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("revoked refresh token status = %d body = %s, want 401", revokedRecorder.Code, revokedRecorder.Body.String())
	}
}

func TestPrivilegedLoginRequiresAndVerifiesMFA(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "test-secret-long-enough-for-auth-mfa-tests")
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	setTenantForTest(ctx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
		seedAuthOrganization(ctx, t, tx)
	})
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		setTenantForTest(cleanupCtx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
			cleanupAuthFixtures(ctx, t, tx)
		})
	})

	passwordHash, err := auth.HashPassword(authPassword, auth.DefaultHashConfig)
	if err != nil {
		t.Fatalf("hash admin password: %v", err)
	}
	setTenantForTest(ctx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO users (id, organization_id, email, password_hash, role, mfa_secret, mfa_enabled)
			 VALUES ($1, $2, $3, $4, 'admin', $5, TRUE)`,
			authAdminID,
			authOrgID,
			authAdminEmail,
			passwordHash,
			authMFASecret,
		); err != nil {
			t.Fatalf("seed admin user: %v", err)
		}
	})

	handler := &ports.AuthHandler{DB: db}
	missingMFARecorder := httptest.NewRecorder()
	handler.LoginHandler(missingMFARecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":           authAdminEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
	}))
	if missingMFARecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing MFA login status = %d body = %s, want 401", missingMFARecorder.Code, missingMFARecorder.Body.String())
	}
	missingMFA := decodeAuthResponse(t, missingMFARecorder)
	if !missingMFA.RequiresMFA || missingMFA.Token != "" || missingMFA.RefreshToken != "" {
		t.Fatalf("missing MFA response = %#v, want requires_mfa without tokens", missingMFA)
	}

	verifiedRecorder := httptest.NewRecorder()
	handler.LoginHandler(verifiedRecorder, authJSONRequest(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":           authAdminEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
		"mfa_code":        totpCode(t, authMFASecret, time.Now()),
	}))
	if verifiedRecorder.Code != http.StatusOK {
		t.Fatalf("verified MFA login status = %d body = %s", verifiedRecorder.Code, verifiedRecorder.Body.String())
	}
	verified := decodeAuthResponse(t, verifiedRecorder)
	if verified.Token == "" || verified.RefreshToken == "" {
		t.Fatalf("verified MFA response missing tokens: %#v", verified)
	}
	claims, err := auth.ValidateToken(verified.Token)
	if err != nil {
		t.Fatalf("validate MFA access token: %v", err)
	}
	if claims.Role != "admin" || claims.OrganizationID != authOrgID || claims.UserID != authAdminID {
		t.Fatalf("verified MFA claims = %#v", claims)
	}
}
