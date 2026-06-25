package abuse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"scriptureforge/internal/domain/auth"
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
	if passed != 2 {
		t.Fatalf("downstream handler ran %d times, want 2", passed)
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
