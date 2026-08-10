package ports

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scriptureforge/internal/domain/auth"
)

func aiRequestWithClaims(body []byte) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ai/generate/study", bytes.NewReader(body))
	return request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "11111111-1111-4111-8111-111111111111",
		OrganizationID: "22222222-2222-4222-8222-222222222222",
		Role:           "member",
	}))
}

func TestGenerateCurriculumHandlerRejectsOversizedRequestBody(t *testing.T) {
	handler := &AIHandler{}
	recorder := httptest.NewRecorder()
	body := append([]byte(`{"topic":"`), bytes.Repeat([]byte("x"), maxAIRequestBodyBytes)...)
	body = append(body, []byte(`"}`)...)
	handler.GenerateCurriculumHandler(recorder, aiRequestWithClaims(body))

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized AI body status = %d, want 413", recorder.Code)
	}
}

func TestGenerateCurriculumHandlerRejectsOversizedTopicBeforeWork(t *testing.T) {
	body, err := json.Marshal(CurriculumRequest{Topic: strings.Repeat("x", maxAITopicCharacters+1)})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	(&AIHandler{}).GenerateCurriculumHandler(recorder, aiRequestWithClaims(body))

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized AI topic status = %d, want 413", recorder.Code)
	}
}

func TestGenerateCurriculumHandlerRejectsUnknownFields(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&AIHandler{}).GenerateCurriculumHandler(recorder, aiRequestWithClaims([]byte(`{"topic":"study","unexpected":"value"}`)))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown AI field status = %d, want 400", recorder.Code)
	}
}
