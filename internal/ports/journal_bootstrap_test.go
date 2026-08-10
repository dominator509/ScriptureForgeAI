package ports

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scriptureforge/internal/domain/auth"
)

func TestJournalBootstrapReturnsOpaqueStableSalt(t *testing.T) {
	t.Setenv("JOURNAL_SALT_SECRET", "test-journal-salt-secret-0123456789")
	handler := &JournalHandler{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/journal/bootstrap", nil)
	claims := &auth.TokenClaims{
		UserID:         "user-123",
		OrganizationID: "org-456",
		Role:           "member",
	}
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, claims))

	first := httptest.NewRecorder()
	handler.ServeJournalBootstrap(first, request)
	if first.Code != http.StatusOK {
		t.Fatalf("first bootstrap status = %d body = %s", first.Code, first.Body.String())
	}

	var firstPayload JournalBootstrapResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstPayload); err != nil {
		t.Fatalf("decode first bootstrap: %v", err)
	}
	if firstPayload.SaltVersion != 1 || !strings.HasPrefix(firstPayload.SaltID, "journal:v1:") {
		t.Fatalf("bootstrap payload = %#v, want versioned journal salt", firstPayload)
	}
	if strings.Contains(firstPayload.SaltID, claims.UserID) || strings.Contains(firstPayload.SaltID, claims.OrganizationID) {
		t.Fatalf("bootstrap salt id leaked raw tenant identity: %s", firstPayload.SaltID)
	}

	second := httptest.NewRecorder()
	handler.ServeJournalBootstrap(second, request)
	var secondPayload JournalBootstrapResponse
	if err := json.Unmarshal(second.Body.Bytes(), &secondPayload); err != nil {
		t.Fatalf("decode second bootstrap: %v", err)
	}
	if firstPayload != secondPayload {
		t.Fatalf("bootstrap salt changed across calls: first=%#v second=%#v", firstPayload, secondPayload)
	}
}

func TestJournalBootstrapRequiresConfiguredSecret(t *testing.T) {
	t.Setenv("JOURNAL_SALT_SECRET", "")
	t.Setenv("JWT_SECRET_KEY", "")
	handler := &JournalHandler{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/journal/bootstrap", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "user-123",
		OrganizationID: "org-456",
		Role:           "member",
	}))

	recorder := httptest.NewRecorder()
	handler.ServeJournalBootstrap(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("bootstrap without secret status = %d body = %s, want 500", recorder.Code, recorder.Body.String())
	}
}

func TestJournalBootstrapDoesNotReuseJWTSecret(t *testing.T) {
	secret := "shared-test-secret-012345678901234567"
	t.Setenv("JOURNAL_SALT_SECRET", "")
	t.Setenv("JWT_SECRET_KEY", secret)
	handler := &JournalHandler{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/journal/bootstrap", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "user-123",
		OrganizationID: "org-456",
		Role:           "member",
	}))

	recorder := httptest.NewRecorder()
	handler.ServeJournalBootstrap(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("bootstrap with only JWT secret status = %d body = %s, want 500", recorder.Code, recorder.Body.String())
	}
}

func TestJournalCreateRejectsMalformedEncryptedEnvelopeBeforeDatabase(t *testing.T) {
	handler := &JournalHandler{}
	claims := &auth.TokenClaims{
		UserID:         "user-123",
		OrganizationID: "org-456",
		Role:           "member",
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "plaintext ciphertext",
			body: `{"ciphertext":"Lord, help me","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:test","salt_version":1}`,
		},
		{
			name: "short iv",
			body: `{"ciphertext":"c2VhbGVkLWNpcGhlcnRleHQtYmxvYg==","iv":"AQID","salt_id":"journal:v1:test","salt_version":1}`,
		},
		{
			name: "unversioned salt",
			body: `{"ciphertext":"c2VhbGVkLWNpcGhlcnRleHQtYmxvYg==","iv":"AQIDBAUGBwgJCgsM","salt_id":"test","salt_version":1}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/journal_entries", strings.NewReader(tc.body))
			request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, claims))
			recorder := httptest.NewRecorder()

			handler.ServeJournalEntries(recorder, request)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("malformed journal envelope status = %d body = %s, want 400", recorder.Code, recorder.Body.String())
			}
		})
	}

	validRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/journal_entries",
		strings.NewReader(`{"ciphertext":"c2VhbGVkLWNpcGhlcnRleHQtYmxvYg==","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:test","salt_version":1}`),
	)
	validRequest = validRequest.WithContext(context.WithValue(validRequest.Context(), auth.ContextKeyUser, claims))
	validRecorder := httptest.NewRecorder()

	handler.ServeJournalEntries(validRecorder, validRequest)

	if validRecorder.Code != http.StatusInternalServerError {
		t.Fatalf("valid encrypted envelope status = %d body = %s, want DB configuration error 500", validRecorder.Code, validRecorder.Body.String())
	}
}

func TestJournalCreateRejectsOversizedEncryptedPayloadBeforeDatabase(t *testing.T) {
	handler := &JournalHandler{}
	claims := &auth.TokenClaims{UserID: "user-123", OrganizationID: "org-456", Role: "member"}
	oversizedCiphertext := strings.Repeat("A", maxJournalCiphertextTextBytes+1)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/journal_entries",
		strings.NewReader(`{"ciphertext":"`+oversizedCiphertext+`","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:test","salt_version":1}`),
	)
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, claims))
	recorder := httptest.NewRecorder()
	handler.ServeJournalEntries(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversized journal ciphertext status = %d body = %s, want 400", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(
		http.MethodPost,
		"/api/v1/journal_entries",
		strings.NewReader(`{"ciphertext":"c2VhbGVkLWNpcGhlcnRleHQtYmxvYg==","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:test","salt_version":1}`),
	)
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, claims))
	recorder = httptest.NewRecorder()
	request.Body = http.MaxBytesReader(recorder, request.Body, 32)
	handler.ServeJournalEntries(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized journal request status = %d body = %s, want 413", recorder.Code, recorder.Body.String())
	}
}
