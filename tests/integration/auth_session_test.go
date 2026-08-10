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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
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

func authObservedJSONRequest(method, target string, payload any, observer *observability.Observer) *http.Request {
	req := authJSONRequest(method, target, payload)
	return req.WithContext(observability.WithObserver(req.Context(), observer))
}

func decodeAuthResponse(t *testing.T, recorder *httptest.ResponseRecorder) ports.AuthResponse {
	t.Helper()
	var response ports.AuthResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode auth response %d %q: %v", recorder.Code, recorder.Body.String(), err)
	}
	return response
}

func decodeWorkspaceSwitchResponse(t *testing.T, recorder *httptest.ResponseRecorder) ports.WorkspaceSwitchResponse {
	t.Helper()
	var response ports.WorkspaceSwitchResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode workspace switch response %d %q: %v", recorder.Code, recorder.Body.String(), err)
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
	observer := observability.NewObserver(observability.Options{})
	registerRecorder := httptest.NewRecorder()
	handler.RegisterHandler(registerRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":           authUserEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
		"role":            "admin",
	}, observer))
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
	handler.RefreshHandler(expiredRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   registered.RefreshToken,
		"organization_id": authOrgID,
	}, observer))
	if expiredRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expired refresh token status = %d body = %s, want 401", expiredRecorder.Code, expiredRecorder.Body.String())
	}

	loginRecorder := httptest.NewRecorder()
	handler.LoginHandler(loginRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":           authUserEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
	}, observer))
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status = %d body = %s", loginRecorder.Code, loginRecorder.Body.String())
	}
	login := decodeAuthResponse(t, loginRecorder)
	if login.RefreshToken == "" || login.RefreshToken == registered.RefreshToken {
		t.Fatalf("login refresh token = %q, want a new opaque token", login.RefreshToken)
	}

	raceLoginRecorder := httptest.NewRecorder()
	handler.LoginHandler(raceLoginRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":           authUserEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
	}, observer))
	if raceLoginRecorder.Code != http.StatusOK {
		t.Fatalf("concurrent refresh setup login status = %d body = %s", raceLoginRecorder.Code, raceLoginRecorder.Body.String())
	}
	raceLogin := decodeAuthResponse(t, raceLoginRecorder)
	var refreshWG sync.WaitGroup
	raceResults := make(chan int, 2)
	for i := 0; i < 2; i++ {
		refreshWG.Add(1)
		go func() {
			defer refreshWG.Done()
			recorder := httptest.NewRecorder()
			handler.RefreshHandler(recorder, authJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
				"refresh_token":   raceLogin.RefreshToken,
				"organization_id": authOrgID,
			}))
			raceResults <- recorder.Code
		}()
	}
	refreshWG.Wait()
	close(raceResults)
	var raceSuccesses, raceDenials int
	for status := range raceResults {
		switch status {
		case http.StatusOK:
			raceSuccesses++
		case http.StatusUnauthorized:
			raceDenials++
		default:
			t.Fatalf("concurrent refresh status = %d, want one 200 and one 401", status)
		}
	}
	if raceSuccesses != 1 || raceDenials != 1 {
		t.Fatalf("concurrent refresh results successes=%d denials=%d, want 1/1", raceSuccesses, raceDenials)
	}

	refreshRecorder := httptest.NewRecorder()
	handler.RefreshHandler(refreshRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   login.RefreshToken,
		"organization_id": authOrgID,
	}, observer))
	if refreshRecorder.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body = %s", refreshRecorder.Code, refreshRecorder.Body.String())
	}
	refreshed := decodeAuthResponse(t, refreshRecorder)
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == login.RefreshToken {
		t.Fatalf("rotated refresh token = %q, want replacement for old token", refreshed.RefreshToken)
	}

	oldTokenRecorder := httptest.NewRecorder()
	handler.RefreshHandler(oldTokenRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   login.RefreshToken,
		"organization_id": authOrgID,
	}, observer))
	if oldTokenRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("old refresh token status = %d body = %s, want 401", oldTokenRecorder.Code, oldTokenRecorder.Body.String())
	}

	crossTenantRecorder := httptest.NewRecorder()
	handler.RefreshHandler(crossTenantRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   refreshed.RefreshToken,
		"organization_id": tenantOrgB,
	}, observer))
	if crossTenantRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant refresh status = %d body = %s, want 401", crossTenantRecorder.Code, crossTenantRecorder.Body.String())
	}

	logoutRecorder := httptest.NewRecorder()
	handler.LogoutHandler(logoutRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/logout", map[string]any{
		"refresh_token":   refreshed.RefreshToken,
		"organization_id": authOrgID,
	}, observer))
	if logoutRecorder.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d body = %s", logoutRecorder.Code, logoutRecorder.Body.String())
	}

	revokedRecorder := httptest.NewRecorder()
	handler.RefreshHandler(revokedRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token":   refreshed.RefreshToken,
		"organization_id": authOrgID,
	}, observer))
	if revokedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("revoked refresh token status = %d body = %s, want 401", revokedRecorder.Code, revokedRecorder.Body.String())
	}

	metrics := observer.Snapshot()
	for _, expected := range []string{
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_register",status="success"} 1`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_login",status="success"} 2`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_refresh",status="success"} 1`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_refresh",status="invalid_or_expired"} 4`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_logout",status="success"} 1`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("auth/session dependency metrics missing %s:\n%s", expected, metrics)
		}
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
	observer := observability.NewObserver(observability.Options{})
	missingMFARecorder := httptest.NewRecorder()
	handler.LoginHandler(missingMFARecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":           authAdminEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
	}, observer))
	if missingMFARecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing MFA login status = %d body = %s, want 401", missingMFARecorder.Code, missingMFARecorder.Body.String())
	}
	missingMFA := decodeAuthResponse(t, missingMFARecorder)
	if !missingMFA.RequiresMFA || missingMFA.Token != "" || missingMFA.RefreshToken != "" {
		t.Fatalf("missing MFA response = %#v, want requires_mfa without tokens", missingMFA)
	}

	verifiedRecorder := httptest.NewRecorder()
	handler.LoginHandler(verifiedRecorder, authObservedJSONRequest(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":           authAdminEmail,
		"password":        authPassword,
		"organization_id": authOrgID,
		"mfa_code":        totpCode(t, authMFASecret, time.Now()),
	}, observer))
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
	metrics := observer.Snapshot()
	for _, expected := range []string{
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_login",status="mfa_required"} 1`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_login",status="success"} 1`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_issue_refresh_token",status="success"} 1`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("privileged auth dependency metrics missing %s:\n%s", expected, metrics)
		}
	}
}

func TestWorkspaceSwitchRequiresAuthenticatedOrgMatch(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "test-secret-long-enough-for-workspace-switch")
	token, err := auth.GenerateToken("member-user-id", authOrgID, "member", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	handler := &ports.AuthHandler{}
	workspaceClaims := &auth.TokenClaims{
		UserID:         "member-user-id",
		OrganizationID: authOrgID,
		Role:           "member",
	}
	claimsRequest := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/switch", strings.NewReader(`{"organization_id":"`+authOrgID+`"}`))
	claimsRequest.Header.Set("Authorization", "Bearer "+token)
	claimsRequest = claimsRequest.WithContext(context.WithValue(claimsRequest.Context(), auth.ContextKeyUser, workspaceClaims))
	allowed := httptest.NewRecorder()
	handler.WorkspaceSwitchHandler(allowed, claimsRequest)
	if allowed.Code != http.StatusOK {
		t.Fatalf("workspace switch status = %d body = %s", allowed.Code, allowed.Body.String())
	}
	result := decodeWorkspaceSwitchResponse(t, allowed)
	if result.OrganizationID != authOrgID {
		t.Fatalf("workspace switch org = %q, want %q", result.OrganizationID, authOrgID)
	}

	crossTenantReq := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/switch", strings.NewReader(`{"organization_id":"55555555-0000-4555-8555-555555555555"}`))
	crossTenantReq.Header.Set("Authorization", "Bearer "+token)
	crossTenantReq = crossTenantReq.WithContext(context.WithValue(crossTenantReq.Context(), auth.ContextKeyUser, workspaceClaims))
	forbidden := httptest.NewRecorder()
	handler.WorkspaceSwitchHandler(forbidden, crossTenantReq)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("workspace switch cross-tenant status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
}

func TestMFAEnrollAndVerifyFlowForPrivilegedUsers(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "test-secret-long-enough-for-mfa-flow")
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	setTenantForTest(ctx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
		seedAuthOrganization(ctx, t, tx)
		_, _ = tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, authAdminID)
		passwordHash, err := auth.HashPassword(authPassword, auth.DefaultHashConfig)
		if err != nil {
			t.Fatalf("hash admin password: %v", err)
		}
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO users (id, organization_id, email, password_hash, role)
			 VALUES ($1, $2, $3, $4, 'admin')`,
			authAdminID,
			authOrgID,
			authAdminEmail,
			passwordHash,
		); err != nil {
			t.Fatalf("seed admin without mfa: %v", err)
		}
	})
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		setTenantForTest(cleanupCtx, t, db, authOrgID, func(ctx context.Context, tx pgx.Tx) {
			cleanupAuthFixtures(ctx, t, tx)
			_, _ = tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, authAdminID)
		})
	})

	handler := &ports.AuthHandler{DB: db}
	observer := observability.NewObserver(observability.Options{})
	adminClaims := &auth.TokenClaims{
		UserID:         authAdminID,
		OrganizationID: authOrgID,
		Role:           "admin",
	}

	enrollReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/enroll", strings.NewReader(`{}`))
	enrollReq = enrollReq.WithContext(context.WithValue(enrollReq.Context(), auth.ContextKeyUser, adminClaims))
	enrollReq = enrollReq.WithContext(observability.WithObserver(enrollReq.Context(), observer))
	enrollRec := httptest.NewRecorder()
	handler.MFAEnrollHandler(enrollRec, enrollReq)
	if enrollRec.Code != http.StatusOK {
		t.Fatalf("mfa enroll status = %d body = %s", enrollRec.Code, enrollRec.Body.String())
	}
	var enrollResp map[string]any
	if err := json.NewDecoder(enrollRec.Body).Decode(&enrollResp); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}
	rawSecret := fmt.Sprintf("%v", enrollResp["secret"])
	if rawSecret == "" || rawSecret == "<nil>" {
		t.Fatalf("enroll response missing secret: %#v", enrollResp)
	}

	verifyWrongReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", strings.NewReader(`{"mfa_code":"000000"}`))
	verifyWrongReq = verifyWrongReq.WithContext(context.WithValue(verifyWrongReq.Context(), auth.ContextKeyUser, adminClaims))
	verifyWrongReq = verifyWrongReq.WithContext(observability.WithObserver(verifyWrongReq.Context(), observer))
	verifyWrongRec := httptest.NewRecorder()
	handler.MFAVerifyHandler(verifyWrongRec, verifyWrongReq)
	if verifyWrongRec.Code != http.StatusUnauthorized {
		t.Fatalf("mfa verify wrong-code status = %d body = %s", verifyWrongRec.Code, verifyWrongRec.Body.String())
	}

	currentCode := totpCode(t, rawSecret, time.Now())
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", strings.NewReader(`{"mfa_code":"`+currentCode+`"}`))
	verifyReq = verifyReq.WithContext(context.WithValue(verifyReq.Context(), auth.ContextKeyUser, adminClaims))
	verifyReq = verifyReq.WithContext(observability.WithObserver(verifyReq.Context(), observer))
	verifyRec := httptest.NewRecorder()
	handler.MFAVerifyHandler(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("mfa verify status = %d body = %s", verifyRec.Code, verifyRec.Body.String())
	}
	var verifyResp map[string]any
	if err := json.NewDecoder(verifyRec.Body).Decode(&verifyResp); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if verified, ok := verifyResp["verified"].(bool); !ok || !verified {
		t.Fatalf("expected verified=true, got %#v", verifyResp["verified"])
	}

	memberClaims := &auth.TokenClaims{
		UserID:         "33333333-3333-4333-8333-333333333333",
		OrganizationID: authOrgID,
		Role:           "member",
	}
	memberVerifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", strings.NewReader(`{"mfa_code":"`+currentCode+`"}`))
	memberVerifyReq = memberVerifyReq.WithContext(context.WithValue(memberVerifyReq.Context(), auth.ContextKeyUser, memberClaims))
	memberVerifyReq = memberVerifyReq.WithContext(observability.WithObserver(memberVerifyReq.Context(), observer))
	memberVerifyRec := httptest.NewRecorder()
	handler.MFAVerifyHandler(memberVerifyRec, memberVerifyReq)
	if memberVerifyRec.Code != http.StatusForbidden {
		t.Fatalf("member mfa verify status = %d body = %s, want 403", memberVerifyRec.Code, memberVerifyRec.Body.String())
	}
	metrics := observer.Snapshot()
	for _, expected := range []string{
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_mfa_enroll",status="success"} 1`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_mfa_verify",status="invalid_code"} 1`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="auth_mfa_verify",status="success"} 1`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("MFA dependency metrics missing %s:\n%s", expected, metrics)
		}
	}
}
