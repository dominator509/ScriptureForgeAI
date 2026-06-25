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
	t.Setenv("JOURNAL_SALT_SECRET", "test-journal-salt-secret")
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
