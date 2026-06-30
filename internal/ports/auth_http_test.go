package ports

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scriptureforge/internal/domain/abuse"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
)

func testAuthAccountLimiter(limit int) *abuse.Limiter {
	limiter := abuse.NewLimiter(abuse.Policy{Profiles: map[string]abuse.Profile{
		abuse.ProfileAuthAccount: {Name: abuse.ProfileAuthAccount, Limit: limit, Window: time.Minute},
	}})
	return limiter
}

func TestAuthAccountLimitRejectsRepeatedLoginAttemptsAcrossClientIPs(t *testing.T) {
	handler := &AuthHandler{AccountLimiter: testAuthAccountLimiter(1)}
	observer := observability.NewObserver(observability.Options{})

	first := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	firstRequest.RemoteAddr = "198.51.100.10:49152"
	firstRequest = firstRequest.WithContext(observability.WithObserver(firstRequest.Context(), observer))
	if !handler.enforceAuthAccountLimit(first, firstRequest, "Member@Example.Test", "org-a") {
		t.Fatal("first account attempt should be allowed")
	}
	if first.Header().Get("X-RateLimit-Limit") != "1" || first.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("first account headers limit=%q remaining=%q", first.Header().Get("X-RateLimit-Limit"), first.Header().Get("X-RateLimit-Remaining"))
	}

	second := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	secondRequest.RemoteAddr = "198.51.100.11:49152"
	secondRequest = secondRequest.WithContext(observability.WithObserver(secondRequest.Context(), observer))
	if handler.enforceAuthAccountLimit(second, secondRequest, "member@example.test", "org-a") {
		t.Fatal("second account attempt should be limited even from a different client IP")
	}
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("limited account status = %d, want 429", second.Code)
	}
	if second.Header().Get("Retry-After") == "" || second.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatalf("limited account headers Retry-After=%q Reset=%q", second.Header().Get("Retry-After"), second.Header().Get("X-RateLimit-Reset"))
	}
	var response auth.PlatformException
	if err := json.NewDecoder(second.Body).Decode(&response); err != nil {
		t.Fatalf("decode account limit response: %v", err)
	}
	if response.Code != http.StatusTooManyRequests || response.Category != "ABUSE_RATE_LIMIT_FAULT" || !strings.Contains(response.Message, "login attempts") {
		t.Fatalf("account limit response = %#v", response)
	}

	metrics := observer.Snapshot()
	for _, expected := range []string{
		`scriptureforge_dependency_operations_total{dependency="abuse_limiter",operation="auth_account",status="allowed"} 1`,
		`scriptureforge_dependency_operations_total{dependency="abuse_limiter",operation="auth_account",status="limited"} 1`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("account limiter metrics missing %s:\n%s", expected, metrics)
		}
	}
	for _, forbidden := range []string{"member@example.test", "Member@Example.Test", "org-a", "198.51.100.10", "198.51.100.11"} {
		if strings.Contains(metrics, forbidden) {
			t.Fatalf("account limiter metrics leaked %q:\n%s", forbidden, metrics)
		}
	}
}

func TestAuthAccountLimitScopesByOrganization(t *testing.T) {
	handler := &AuthHandler{AccountLimiter: testAuthAccountLimiter(1)}

	first := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	if !handler.enforceAuthAccountLimit(first, firstRequest, "member@example.test", "org-a") {
		t.Fatal("first org account attempt should be allowed")
	}

	otherOrg := httptest.NewRecorder()
	otherOrgRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	if !handler.enforceAuthAccountLimit(otherOrg, otherOrgRequest, "member@example.test", "org-b") {
		t.Fatal("same email in another organization should have an independent account bucket")
	}
}

func TestRefreshTokenLimitRejectsRepeatedRefreshAttemptsAcrossClientIPs(t *testing.T) {
	handler := &AuthHandler{AccountLimiter: testAuthAccountLimiter(1)}
	observer := observability.NewObserver(observability.Options{})

	first := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	firstRequest.RemoteAddr = "198.51.100.20:49152"
	firstRequest = firstRequest.WithContext(observability.WithObserver(firstRequest.Context(), observer))
	if !handler.enforceRefreshTokenLimit(first, firstRequest, "opaque-refresh-token", "org-a") {
		t.Fatal("first refresh attempt should be allowed")
	}
	if first.Header().Get("X-RateLimit-Limit") != "1" || first.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("first refresh headers limit=%q remaining=%q", first.Header().Get("X-RateLimit-Limit"), first.Header().Get("X-RateLimit-Remaining"))
	}

	second := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	secondRequest.RemoteAddr = "198.51.100.21:49152"
	secondRequest = secondRequest.WithContext(observability.WithObserver(secondRequest.Context(), observer))
	if handler.enforceRefreshTokenLimit(second, secondRequest, "opaque-refresh-token", "org-a") {
		t.Fatal("second refresh attempt should be limited even from a different client IP")
	}
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("limited refresh status = %d, want 429", second.Code)
	}
	if second.Header().Get("Retry-After") == "" || second.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatalf("limited refresh headers Retry-After=%q Reset=%q", second.Header().Get("Retry-After"), second.Header().Get("X-RateLimit-Reset"))
	}
	var response auth.PlatformException
	if err := json.NewDecoder(second.Body).Decode(&response); err != nil {
		t.Fatalf("decode refresh limit response: %v", err)
	}
	if response.Code != http.StatusTooManyRequests || response.Category != "ABUSE_RATE_LIMIT_FAULT" || !strings.Contains(response.Message, "refresh attempts") {
		t.Fatalf("refresh limit response = %#v", response)
	}

	otherToken := httptest.NewRecorder()
	otherTokenRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	otherTokenRequest = otherTokenRequest.WithContext(observability.WithObserver(otherTokenRequest.Context(), observer))
	if !handler.enforceRefreshTokenLimit(otherToken, otherTokenRequest, "different-refresh-token", "org-a") {
		t.Fatal("different refresh token should have an independent bucket")
	}

	metrics := observer.Snapshot()
	for _, expected := range []string{
		`scriptureforge_dependency_operations_total{dependency="abuse_limiter",operation="auth_account",status="allowed"} 2`,
		`scriptureforge_dependency_operations_total{dependency="abuse_limiter",operation="auth_account",status="limited"} 1`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("refresh limiter metrics missing %s:\n%s", expected, metrics)
		}
	}
	for _, forbidden := range []string{"opaque-refresh-token", "different-refresh-token", "org-a", "198.51.100.20", "198.51.100.21"} {
		if strings.Contains(metrics, forbidden) {
			t.Fatalf("refresh limiter metrics leaked %q:\n%s", forbidden, metrics)
		}
	}
}

func TestAuthAccountLimitIdentityIsHashedAndStable(t *testing.T) {
	first := accountLimitIdentity("Member@Example.Test", "Org-A")
	second := accountLimitIdentity(" member@example.test ", " org-a ")
	if first != second {
		t.Fatalf("normalized account identity mismatch: %q != %q", first, second)
	}
	if strings.Contains(first, "member@example.test") || strings.Contains(first, "org-a") {
		t.Fatalf("account identity leaked raw account data: %q", first)
	}
}

func TestRefreshLimitIdentityIsHashedStableAndOrgScoped(t *testing.T) {
	first := refreshLimitIdentity(" opaque-refresh-token ", "Org-A")
	second := refreshLimitIdentity("opaque-refresh-token", " org-a ")
	otherOrg := refreshLimitIdentity("opaque-refresh-token", "org-b")
	if first != second {
		t.Fatalf("normalized refresh identity mismatch: %q != %q", first, second)
	}
	if first == otherOrg {
		t.Fatal("refresh identity should be scoped by organization")
	}
	if strings.Contains(first, "opaque-refresh-token") || strings.Contains(first, "org-a") {
		t.Fatalf("refresh identity leaked raw token or org data: %q", first)
	}
}
