package abuse

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

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
	for _, profileName := range []string{ProfileAuth, ProfileAI, ProfileJournal, ProfileRooms, ProfileWebSocket, ProfileZoomWebhook} {
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

func TestLimiterFallsBackToClientIdentityWhenClaimsAreIncomplete(t *testing.T) {
	limiter := testLimiter(ProfileJournal, 1, time.Minute)
	handler := limiter.Middleware(ProfileJournal, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := requestWithClaims("", "org-a")
	first.RemoteAddr = "203.0.113.70:49152"
	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first incomplete-claims request status = %d, want 204", firstRecorder.Code)
	}

	otherClient := requestWithClaims("", "org-a")
	otherClient.RemoteAddr = "203.0.113.71:49152"
	otherClientRecorder := httptest.NewRecorder()
	handler.ServeHTTP(otherClientRecorder, otherClient)
	if otherClientRecorder.Code != http.StatusNoContent {
		t.Fatalf("different client with incomplete claims status = %d, want independent 204", otherClientRecorder.Code)
	}

	repeat := requestWithClaims("", "org-a")
	repeat.RemoteAddr = "203.0.113.70:49152"
	repeatRecorder := httptest.NewRecorder()
	handler.ServeHTTP(repeatRecorder, repeat)
	if repeatRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("repeat incomplete-claims client status = %d, want 429", repeatRecorder.Code)
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
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
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
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
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
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
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

func TestLimiterIgnoresForwardedHeadersFromUnlistedProxy(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	t.Setenv("TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
	limiter := testLimiter(ProfileAuth, 1, time.Minute)
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := authRequestFromProxy("198.51.100.10")
	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first unlisted-proxy request status = %d, want 204", firstRecorder.Code)
	}

	second := authRequestFromProxy("198.51.100.11")
	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, second)
	if secondRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second unlisted-proxy request status = %d, want shared 429", secondRecorder.Code)
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
	t.Setenv("ABUSE_LIMIT_ZOOM_WEBHOOK_REQUESTS", "17")
	t.Setenv("ABUSE_LIMIT_ZOOM_WEBHOOK_WINDOW_SECONDS", "45")
	policy := PolicyFromEnv()
	zoomProfile, ok := policy.Profiles[ProfileZoomWebhook]
	if !ok {
		t.Fatal("PolicyFromEnv missing zoom webhook profile")
	}
	if zoomProfile.Limit != 17 || zoomProfile.Window != 45*time.Second {
		t.Fatalf("zoom webhook profile = %+v, want limit 17 and window 45s", zoomProfile)
	}
	t.Setenv("ABUSE_LIMIT_AI_REQUESTS", "999999")
	t.Setenv("ABUSE_LIMIT_AI_WINDOW_SECONDS", strconv.Itoa(int((48 * time.Hour).Seconds())))
	policy = PolicyFromEnv()
	aiProfile := policy.Profiles[ProfileAI]
	if aiProfile.Limit != maxProfileRequests || aiProfile.Window != maxProfileWindow {
		t.Fatalf("AI profile = %+v, want bounded limit/window", aiProfile)
	}

	t.Setenv("ABUSE_LIMIT_MAX_BUCKETS", "42")
	policy = PolicyFromEnv()
	if policy.MaxBuckets != 42 {
		t.Fatalf("MaxBuckets = %d, want 42", policy.MaxBuckets)
	}

	t.Setenv("ABUSE_LIMIT_MAX_BUCKETS", strconv.Itoa(-1))
	limiter := NewLimiter(PolicyFromEnv())
	if limiter.maxBuckets != 100000 {
		t.Fatalf("invalid maxBuckets fallback = %d, want 100000", limiter.maxBuckets)
	}
}

func TestActiveConnectionLimiterCapsAndReleases(t *testing.T) {
	limiter := NewActiveConnectionLimiter(1, 2, 2)

	releaseFirst, ok := limiter.Acquire("org-a", "user-a")
	if !ok {
		t.Fatal("first connection should be accepted")
	}
	if _, ok := limiter.Acquire("org-a", "user-a"); ok {
		t.Fatal("same user should be capped")
	}
	releaseSecond, ok := limiter.Acquire("org-a", "user-b")
	if !ok {
		t.Fatal("second tenant connection should be accepted")
	}
	if _, ok := limiter.Acquire("org-a", "user-c"); ok {
		t.Fatal("global connection cap should be enforced")
	}

	releaseFirst()
	releaseFirst()
	if _, ok := limiter.Acquire("org-a", "user-a"); !ok {
		t.Fatal("released user connection should be reusable")
	}
	releaseSecond()
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

func TestRedisLimiterSharesWindowsAcrossInstances(t *testing.T) {
	server := miniredis.RunT(t)
	clientOne := redis.NewClient(&redis.Options{Addr: server.Addr()})
	clientTwo := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = clientOne.Close() })
	t.Cleanup(func() { _ = clientTwo.Close() })
	policy := Policy{Profiles: map[string]Profile{
		ProfileAuth: {Name: ProfileAuth, Limit: 2, Window: time.Minute},
	}, MaxBuckets: 32}
	one := NewRedisLimiter(policy, clientOne)
	two := NewRedisLimiter(policy, clientTwo)

	first, enforced, err := one.CheckContext(context.Background(), ProfileAuth, "ip:203.0.113.10")
	if err != nil || !enforced || !first.Allowed {
		t.Fatalf("first Redis decision = %+v enforced=%v err=%v, want allowed", first, enforced, err)
	}
	second, enforced, err := two.CheckContext(context.Background(), ProfileAuth, "ip:203.0.113.10")
	if err != nil || !enforced || !second.Allowed || second.Remaining != 0 {
		t.Fatalf("second Redis decision = %+v enforced=%v err=%v, want allowed with zero remaining", second, enforced, err)
	}
	third, enforced, err := one.CheckContext(context.Background(), ProfileAuth, "ip:203.0.113.10")
	if err != nil || !enforced || third.Allowed || third.RetryAfter <= 0 {
		t.Fatalf("third Redis decision = %+v enforced=%v err=%v, want shared-window denial", third, enforced, err)
	}
}

func TestRedisLimiterCapsRemoteIdentitySprayWithOverflowBucket(t *testing.T) {
	server := miniredis.RunT(t)
	clientOne := redis.NewClient(&redis.Options{Addr: server.Addr()})
	clientTwo := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = clientOne.Close() })
	t.Cleanup(func() { _ = clientTwo.Close() })
	policy := Policy{Profiles: map[string]Profile{
		ProfileAuth: {Name: ProfileAuth, Limit: 1, Window: time.Minute},
	}, MaxBuckets: 1}
	one := NewRedisLimiter(policy, clientOne)
	two := NewRedisLimiter(policy, clientTwo)

	first, _, err := one.CheckContext(context.Background(), ProfileAuth, "ip:203.0.113.11")
	if err != nil || !first.Allowed {
		t.Fatalf("first identity decision = %+v err=%v, want allowed", first, err)
	}
	second, _, err := two.CheckContext(context.Background(), ProfileAuth, "ip:203.0.113.12")
	if err != nil || !second.Allowed {
		t.Fatalf("first overflow decision = %+v err=%v, want allowed", second, err)
	}
	third, _, err := one.CheckContext(context.Background(), ProfileAuth, "ip:203.0.113.13")
	if err != nil || third.Allowed {
		t.Fatalf("second overflow decision = %+v err=%v, want shared overflow denial", third, err)
	}
}

func TestRedisLimiterFailsClosedWhenBackendIsUnavailable(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	server.Close()

	limiter := NewRedisLimiter(Policy{Profiles: map[string]Profile{
		ProfileAuth: {Name: ProfileAuth, Limit: 1, Window: time.Minute},
	}}, client)
	passed := false
	handler := limiter.Middleware(ProfileAuth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passed = true
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "203.0.113.20:49152"
	handler.ServeHTTP(recorder, request)

	if passed {
		t.Fatal("request reached handler while Redis limiter backend was unavailable")
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable Redis limiter status = %d, want 503", recorder.Code)
	}
	var response rateLimitError
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode unavailable Redis limiter response: %v", err)
	}
	if response.Category != "ABUSE_LIMITER_UNAVAILABLE" {
		t.Fatalf("unavailable Redis limiter category = %q, want ABUSE_LIMITER_UNAVAILABLE", response.Category)
	}
}

func TestRedisActiveConnectionLimiterSharesCapsAcrossInstances(t *testing.T) {
	server := miniredis.RunT(t)
	clientOne := redis.NewClient(&redis.Options{Addr: server.Addr()})
	clientTwo := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = clientOne.Close() })
	t.Cleanup(func() { _ = clientTwo.Close() })
	one := NewRedisActiveConnectionLimiter(1, 2, 2, clientOne)
	two := NewRedisActiveConnectionLimiter(1, 2, 2, clientTwo)

	releaseFirst, renewFirst, allowed, err := one.AcquireContext(context.Background(), "org-a", "user-a")
	if err != nil || !allowed || renewFirst == nil {
		t.Fatalf("first Redis connection lease allowed=%v renew=%v err=%v, want allowed lease", allowed, renewFirst != nil, err)
	}
	if _, _, allowed, err := two.AcquireContext(context.Background(), "org-a", "user-a"); err != nil || allowed {
		t.Fatalf("same-user second lease allowed=%v err=%v, want shared user cap denial", allowed, err)
	}
	releaseSecond, _, allowed, err := two.AcquireContext(context.Background(), "org-a", "user-b")
	if err != nil || !allowed {
		t.Fatalf("second tenant lease allowed=%v err=%v, want allowed", allowed, err)
	}
	if _, _, allowed, err := one.AcquireContext(context.Background(), "org-a", "user-c"); err != nil || allowed {
		t.Fatalf("global cap lease allowed=%v err=%v, want shared global cap denial", allowed, err)
	}

	releaseFirst()
	if _, _, allowed, err := two.AcquireContext(context.Background(), "org-a", "user-c"); err != nil || !allowed {
		t.Fatalf("released lease replacement allowed=%v err=%v, want allowed", allowed, err)
	}
	releaseSecond()
}

func TestRedisActiveConnectionLimiterRenewsAndExpiresLeases(t *testing.T) {
	server := miniredis.RunT(t)
	start := time.Now().Truncate(time.Second)
	server.SetTime(start)
	clientOne := redis.NewClient(&redis.Options{Addr: server.Addr()})
	clientTwo := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = clientOne.Close() })
	t.Cleanup(func() { _ = clientTwo.Close() })
	one := NewRedisActiveConnectionLimiter(1, 1, 1, clientOne)
	two := NewRedisActiveConnectionLimiter(1, 1, 1, clientTwo)

	release, renew, allowed, err := one.AcquireContext(context.Background(), "org-a", "user-a")
	if err != nil || !allowed {
		t.Fatalf("initial lease allowed=%v err=%v, want allowed", allowed, err)
	}
	server.SetTime(start.Add(90 * time.Second))
	if err := renew(context.Background()); err != nil {
		t.Fatalf("renew lease: %v", err)
	}
	server.SetTime(start.Add(180 * time.Second))
	if _, _, allowed, err := two.AcquireContext(context.Background(), "org-a", "user-b"); err != nil || allowed {
		t.Fatalf("renewed lease replacement allowed=%v err=%v, want denial", allowed, err)
	}

	server.SetTime(start.Add(211 * time.Second))
	releaseReplacement, _, allowed, err := two.AcquireContext(context.Background(), "org-a", "user-b")
	if err != nil || !allowed {
		t.Fatalf("expired lease replacement allowed=%v err=%v, want allowed", allowed, err)
	}
	releaseReplacement()
	release()
}

func TestRedisActiveConnectionLimiterFailsClosedWhenBackendIsUnavailable(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	server.Close()

	limiter := NewRedisActiveConnectionLimiter(1, 1, 1, client)
	_, _, allowed, err := limiter.AcquireContext(context.Background(), "org-a", "user-a")
	if allowed {
		t.Fatal("connection lease was allowed while Redis backend was unavailable")
	}
	if !errors.Is(err, ErrActiveConnectionBackendUnavailable) {
		t.Fatalf("unavailable backend error = %v, want ErrActiveConnectionBackendUnavailable", err)
	}
}
