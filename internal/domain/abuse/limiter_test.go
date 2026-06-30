package abuse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
)

func testLimiter(profileName string, limit int, window time.Duration) *Limiter {
	limiter := NewLimiter(Policy{Profiles: map[string]Profile{
		profileName: {Name: profileName, Limit: limit, Window: window},
	}})
	fixedNow := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return fixedNow }
	return limiter
}

func TestLimiterRejectsExcessAuthRequestsByClientIP(t *testing.T) {
	limiter := testLimiter(ProfileAuth, 2, time.Minute)
	var passed int
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passed++
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		request.RemoteAddr = "203.0.113.10:49152"
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("request %d status = %d, want 204", i+1, recorder.Code)
		}
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "203.0.113.10:49152"
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("third auth request status = %d, want 429", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("rate-limited response did not include Retry-After")
	}
	if recorder.Header().Get("X-RateLimit-Limit") != "2" {
		t.Fatalf("X-RateLimit-Limit = %q, want 2", recorder.Header().Get("X-RateLimit-Limit"))
	}
	if recorder.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("X-RateLimit-Remaining = %q, want 0", recorder.Header().Get("X-RateLimit-Remaining"))
	}
	if recorder.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatal("rate-limited response did not include X-RateLimit-Reset")
	}
	if passed != 2 {
		t.Fatalf("downstream handler ran %d times, want 2", passed)
	}
}

func TestLimiterEmitsLowCardinalityAbuseMetrics(t *testing.T) {
	limiter := testLimiter(ProfileAuth, 1, time.Minute)
	observer := observability.NewObserver(observability.Options{})
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	firstRequest.RemoteAddr = "203.0.113.50:49152"
	firstRequest = firstRequest.WithContext(observability.WithObserver(firstRequest.Context(), observer))
	handler.ServeHTTP(first, firstRequest)
	if first.Code != http.StatusNoContent {
		t.Fatalf("first auth status = %d, want 204", first.Code)
	}

	limited := httptest.NewRecorder()
	limitedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	limitedRequest.RemoteAddr = "203.0.113.50:49152"
	limitedRequest = limitedRequest.WithContext(observability.WithObserver(limitedRequest.Context(), observer))
	handler.ServeHTTP(limited, limitedRequest)
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("limited auth status = %d, want 429", limited.Code)
	}

	metrics := observer.Snapshot()
	for _, expected := range []string{
		`scriptureforge_dependency_operations_total{dependency="abuse_limiter",operation="auth",status="allowed"} 1`,
		`scriptureforge_dependency_operations_total{dependency="abuse_limiter",operation="auth",status="limited"} 1`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("abuse limiter metrics missing %s:\n%s", expected, metrics)
		}
	}
	for _, forbidden := range []string{"203.0.113.50", "49152"} {
		if strings.Contains(metrics, forbidden) {
			t.Fatalf("abuse limiter metrics leaked request identity %q:\n%s", forbidden, metrics)
		}
	}
}

func TestLimiterEmitsMetricsForAllProductionProfiles(t *testing.T) {
	for _, profileName := range []string{ProfileAuth, ProfileAI, ProfileJournal, ProfileRooms, ProfileWebSocket} {
		t.Run(profileName, func(t *testing.T) {
			limiter := testLimiter(profileName, 1, time.Minute)
			observer := observability.NewObserver(observability.Options{})
			handler := limiter.Middleware(profileName, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			for i := 0; i < 2; i++ {
				recorder := httptest.NewRecorder()
				request := requestWithClaims("profile-user", "profile-org")
				request = request.WithContext(observability.WithObserver(request.Context(), observer))
				handler.ServeHTTP(recorder, request)
			}

			metrics := observer.Snapshot()
			if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="abuse_limiter",operation="`+profileName+`",status="limited"} 1`) {
				t.Fatalf("%s limiter metrics missing limited counter:\n%s", profileName, metrics)
			}
		})
	}
}

func TestLimiterEmitsRateLimitHeadersForAllowedRequests(t *testing.T) {
	limiter := testLimiter(ProfileRooms, 3, time.Minute)
	handler := limiter.Middleware(ProfileRooms, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/active", nil)
	request.RemoteAddr = "203.0.113.11:49152"
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("first room request status = %d, want 204", recorder.Code)
	}
	if recorder.Header().Get("X-RateLimit-Limit") != "3" {
		t.Fatalf("X-RateLimit-Limit = %q, want 3", recorder.Header().Get("X-RateLimit-Limit"))
	}
	if recorder.Header().Get("X-RateLimit-Remaining") != "2" {
		t.Fatalf("X-RateLimit-Remaining = %q, want 2", recorder.Header().Get("X-RateLimit-Remaining"))
	}
	if recorder.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatal("allowed response did not include X-RateLimit-Reset")
	}
}

func TestLimiterScopesProtectedRequestsByTenantAndUser(t *testing.T) {
	limiter := testLimiter(ProfileJournal, 1, time.Minute)
	handler := limiter.Middleware(ProfileJournal, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	firstUser := requestWithClaims("user-a", "org-a")
	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, firstUser)
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first protected request status = %d, want 204", firstRecorder.Code)
	}

	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, requestWithClaims("user-a", "org-a"))
	if secondRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second same-user protected request status = %d, want 429", secondRecorder.Code)
	}

	otherUserRecorder := httptest.NewRecorder()
	handler.ServeHTTP(otherUserRecorder, requestWithClaims("user-b", "org-a"))
	if otherUserRecorder.Code != http.StatusNoContent {
		t.Fatalf("other-user protected request status = %d, want 204", otherUserRecorder.Code)
	}

	otherTenantRecorder := httptest.NewRecorder()
	handler.ServeHTTP(otherTenantRecorder, requestWithClaims("user-a", "org-b"))
	if otherTenantRecorder.Code != http.StatusNoContent {
		t.Fatalf("other-tenant protected request status = %d, want 204", otherTenantRecorder.Code)
	}
}

func TestLimiterIgnoresForwardedHeadersUnlessTrusted(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "false")
	limiter := testLimiter(ProfileAuth, 1, time.Minute)
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := authRequestFromProxy("198.51.100.10")
	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first proxied request status = %d, want 204", firstRecorder.Code)
	}

	second := authRequestFromProxy("198.51.100.11")
	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, second)
	if secondRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second proxied request status = %d, want shared proxy 429", secondRecorder.Code)
	}
}

func TestLimiterUsesForwardedClientIPWhenProxyHeadersAreTrusted(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	limiter := testLimiter(ProfileAuth, 1, time.Minute)
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, authRequestFromProxy("198.51.100.10"))
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first forwarded client status = %d, want 204", firstRecorder.Code)
	}

	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, authRequestFromProxy("198.51.100.11"))
	if secondRecorder.Code != http.StatusNoContent {
		t.Fatalf("different forwarded client status = %d, want independent 204", secondRecorder.Code)
	}

	repeatRecorder := httptest.NewRecorder()
	handler.ServeHTTP(repeatRecorder, authRequestFromProxy("198.51.100.10"))
	if repeatRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("repeated forwarded client status = %d, want 429", repeatRecorder.Code)
	}
}

func TestLimiterIgnoresPrivateForwardedClientIPsWhenProxyHeadersAreTrusted(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	limiter := testLimiter(ProfileAuth, 1, time.Minute)
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	firstRecorder := httptest.NewRecorder()
	first := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	first.RemoteAddr = "10.0.0.25:49152"
	first.Header.Set("X-Forwarded-For", "10.1.2.3, 127.0.0.1, 169.254.1.1")
	first.Header.Set("X-Real-IP", "192.168.1.20")
	handler.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first private-forwarded request status = %d, want 204", firstRecorder.Code)
	}

	secondRecorder := httptest.NewRecorder()
	second := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	second.RemoteAddr = "10.0.0.25:49152"
	second.Header.Set("X-Forwarded-For", "10.9.8.7, ::1")
	second.Header.Set("X-Real-IP", "172.16.0.10")
	handler.ServeHTTP(secondRecorder, second)
	if secondRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second private-forwarded request status = %d, want shared proxy 429", secondRecorder.Code)
	}
}

func TestLimiterUsesFirstPublicForwardedClientIPWhenPrivateProxiesArePresent(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	limiter := testLimiter(ProfileAuth, 1, time.Minute)
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	firstRecorder := httptest.NewRecorder()
	first := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	first.RemoteAddr = "10.0.0.25:49152"
	first.Header.Set("X-Forwarded-For", "10.1.2.3, 198.51.100.20, 10.0.0.25")
	handler.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first mixed-forwarded request status = %d, want 204", firstRecorder.Code)
	}

	secondRecorder := httptest.NewRecorder()
	second := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	second.RemoteAddr = "10.0.0.25:49152"
	second.Header.Set("X-Forwarded-For", "10.9.8.7, 198.51.100.21, 10.0.0.25")
	handler.ServeHTTP(secondRecorder, second)
	if secondRecorder.Code != http.StatusNoContent {
		t.Fatalf("different public forwarded request status = %d, want independent 204", secondRecorder.Code)
	}

	repeatRecorder := httptest.NewRecorder()
	repeat := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	repeat.RemoteAddr = "10.0.0.25:49152"
	repeat.Header.Set("X-Forwarded-For", "10.4.5.6, 198.51.100.20, 10.0.0.25")
	handler.ServeHTTP(repeatRecorder, repeat)
	if repeatRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("repeated public forwarded request status = %d, want 429", repeatRecorder.Code)
	}
}

func TestLimiterResetsAfterWindow(t *testing.T) {
	limiter := NewLimiter(Policy{Profiles: map[string]Profile{
		ProfileAI: {Name: ProfileAI, Limit: 1, Window: time.Minute},
	}})
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	handler := limiter.Middleware(ProfileAI, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, requestWithClaims("ai-user", "org-a"))
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first AI request status = %d, want 204", firstRecorder.Code)
	}

	limitedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(limitedRecorder, requestWithClaims("ai-user", "org-a"))
	if limitedRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("limited AI request status = %d, want 429", limitedRecorder.Code)
	}

	now = now.Add(time.Minute)
	resetRecorder := httptest.NewRecorder()
	handler.ServeHTTP(resetRecorder, requestWithClaims("ai-user", "org-a"))
	if resetRecorder.Code != http.StatusNoContent {
		t.Fatalf("post-window AI request status = %d, want 204", resetRecorder.Code)
	}
}

func TestLimiterPrunesExpiredBuckets(t *testing.T) {
	limiter := NewLimiter(Policy{Profiles: map[string]Profile{
		ProfileAuth: {Name: ProfileAuth, Limit: 1, Window: time.Minute},
	}, MaxBuckets: 10})
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	firstRecorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "203.0.113.30:49152"
	handler.ServeHTTP(firstRecorder, request)
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first auth status = %d, want 204", firstRecorder.Code)
	}
	if len(limiter.buckets) != 1 {
		t.Fatalf("bucket count after first request = %d, want 1", len(limiter.buckets))
	}

	now = now.Add(time.Minute)
	secondRecorder := httptest.NewRecorder()
	second := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	second.RemoteAddr = "203.0.113.31:49152"
	handler.ServeHTTP(secondRecorder, second)
	if secondRecorder.Code != http.StatusNoContent {
		t.Fatalf("second auth status = %d, want 204", secondRecorder.Code)
	}
	if len(limiter.buckets) != 1 {
		t.Fatalf("bucket count after pruning = %d, want 1", len(limiter.buckets))
	}
}

func TestLimiterCapsIdentitySprayWithOverflowBucket(t *testing.T) {
	limiter := NewLimiter(Policy{Profiles: map[string]Profile{
		ProfileAuth: {Name: ProfileAuth, Limit: 1, Window: time.Minute},
	}, MaxBuckets: 1})
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	firstRequest.RemoteAddr = "203.0.113.40:49152"
	handler.ServeHTTP(first, firstRequest)
	if first.Code != http.StatusNoContent {
		t.Fatalf("first identity status = %d, want 204", first.Code)
	}

	overflowAllowed := httptest.NewRecorder()
	overflowRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	overflowRequest.RemoteAddr = "203.0.113.41:49152"
	handler.ServeHTTP(overflowAllowed, overflowRequest)
	if overflowAllowed.Code != http.StatusNoContent {
		t.Fatalf("first overflow status = %d, want 204", overflowAllowed.Code)
	}

	overflowLimited := httptest.NewRecorder()
	overflowRepeat := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	overflowRepeat.RemoteAddr = "203.0.113.42:49152"
	handler.ServeHTTP(overflowLimited, overflowRepeat)
	if overflowLimited.Code != http.StatusTooManyRequests {
		t.Fatalf("second overflow status = %d, want 429", overflowLimited.Code)
	}
	if len(limiter.buckets) > limiter.maxBuckets+1 {
		t.Fatalf("bucket count = %d, want bounded by max bucket plus overflow", len(limiter.buckets))
	}
}

func TestPolicyFromEnvConfiguresMaxBuckets(t *testing.T) {
	t.Setenv("ABUSE_LIMIT_MAX_BUCKETS", "42")
	policy := PolicyFromEnv()
	if policy.MaxBuckets != 42 {
		t.Fatalf("MaxBuckets = %d, want 42", policy.MaxBuckets)
	}

	t.Setenv("ABUSE_LIMIT_MAX_BUCKETS", strconv.Itoa(-1))
	limiter := NewLimiter(PolicyFromEnv())
	if limiter.maxBuckets != 100000 {
		t.Fatalf("invalid maxBuckets fallback = %d, want 100000", limiter.maxBuckets)
	}
}

func authRequestFromProxy(forwardedFor string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "10.0.0.25:49152"
	request.Header.Set("X-Forwarded-For", forwardedFor+", 10.0.0.25")
	return request
}

func requestWithClaims(userID, orgID string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/journal_entries", nil)
	request.RemoteAddr = "203.0.113.20:49152"
	ctx := context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         userID,
		OrganizationID: orgID,
		Role:           "member",
	})
	return request.WithContext(ctx)
}
