package ports

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/adapters/llm"
	"scriptureforge/internal/domain/ai"
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

func TestGenerateCurriculumHandlerFailsClosedWhenDependenciesAreMissing(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&AIHandler{}).GenerateCurriculumHandler(recorder, aiRequestWithClaims([]byte(`{"topic":"study"}`)))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing AI dependencies status = %d body = %s, want 503", recorder.Code, recorder.Body.String())
	}
	var response ai.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode missing dependency response: %v", err)
	}
	if response.Category != "AI_CONFIGURATION_FAULT" {
		t.Fatalf("missing dependency category = %q, want AI_CONFIGURATION_FAULT", response.Category)
	}
}

func TestGenerateCurriculumHandlerFailsClosedWhenNestedDependenciesAreIncomplete(t *testing.T) {
	newHandler := func() *AIHandler {
		return &AIHandler{
			DB:              new(pgxpool.Pool),
			RAGEngine:       ai.NewRAGEngine(ai.UnavailableVectorDB{}),
			Verifier:        ai.NewResponseVerificationSubsystem(),
			LLMClient:       &llm.LLMClient{APIKey: "test-key", Endpoint: "https://provider.example", Model: "test-model", HTTPClient: http.DefaultClient},
			MapReduceWorker: ai.NewMapReduceWorker(4000),
		}
	}

	tests := []struct {
		name   string
		mutate func(*AIHandler)
	}{
		{name: "RAG vector database missing", mutate: func(handler *AIHandler) { handler.RAGEngine.Database = nil }},
		{name: "LLM API key missing", mutate: func(handler *AIHandler) { handler.LLMClient.APIKey = "  " }},
		{name: "LLM endpoint missing", mutate: func(handler *AIHandler) { handler.LLMClient.Endpoint = "  " }},
		{name: "LLM model missing", mutate: func(handler *AIHandler) { handler.LLMClient.Model = "  " }},
		{name: "LLM HTTP client missing", mutate: func(handler *AIHandler) { handler.LLMClient.HTTPClient = nil }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newHandler()
			test.mutate(handler)
			recorder := httptest.NewRecorder()
			handler.GenerateCurriculumHandler(recorder, aiRequestWithClaims([]byte(`{"topic":"study"}`)))

			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("incomplete nested dependency status = %d body = %s, want 503", recorder.Code, recorder.Body.String())
			}
			var response ai.PlatformException
			if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
				t.Fatalf("decode incomplete dependency response: %v", err)
			}
			if response.Category != "AI_CONFIGURATION_FAULT" {
				t.Fatalf("incomplete dependency category = %q, want AI_CONFIGURATION_FAULT", response.Category)
			}
		})
	}
}

func TestWriteAIRequestLogReturnsErrorWhenDatabaseIsMissing(t *testing.T) {
	err := (&AIHandler{}).writeAIRequestLog(
		httptest.NewRequest(http.MethodPost, "/api/v1/ai/generate/study", nil),
		&auth.TokenClaims{UserID: "user-1", OrganizationID: "org-1"},
		"study", "failed", "error", "",
	)
	if err == nil {
		t.Fatal("writeAIRequestLog returned nil error without a database")
	}
}
