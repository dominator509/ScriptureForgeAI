package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scriptureforge/internal/domain/ai"
	"scriptureforge/internal/domain/observability"
)

func TestExecuteFailsClosedWhenAPIKeyMissingEvenInTesting(t *testing.T) {
	t.Setenv("GO_ENV", "testing")
	client := &LLMClient{
		Endpoint:   "http://127.0.0.1/should-not-be-called",
		Model:      "test-model",
		HTTPClient: http.DefaultClient,
		MaxRetries: 0,
	}

	response, err := client.Execute(context.Background(), "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
	if err == nil {
		t.Fatalf("Execute returned nil error and response %q, want fail-closed missing-key error", response)
	}
	pe, ok := err.(*ai.PlatformException)
	if !ok {
		t.Fatalf("Execute error = %T %v, want *ai.PlatformException", err, err)
	}
	if pe.Category != "AI_CONFIGURATION_FAULT" || pe.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing-key error = %#v, want AI_CONFIGURATION_FAULT 503", pe)
	}
}

func TestExecuteUsesBoundedHTTPClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"[Genesis 1:1] delayed"}}]}`))
	}))
	defer server.Close()

	client := &LLMClient{
		APIKey:     "test-key",
		Endpoint:   server.URL,
		Model:      "test-model",
		HTTPClient: &http.Client{Timeout: 10 * time.Millisecond},
		MaxRetries: 0,
	}

	observer := observability.NewObserver(observability.Options{})
	ctx := observability.WithObserver(context.Background(), observer)
	_, err := client.Execute(ctx, "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
	if err == nil {
		t.Fatal("Execute returned nil error, want timeout fault")
	}
	pe, ok := err.(*ai.PlatformException)
	if !ok {
		t.Fatalf("Execute timeout error = %T %v, want *ai.PlatformException", err, err)
	}
	if pe.Category != "AI_ORCHESTRATION_ENGINE_FAULT" || pe.Code != http.StatusServiceUnavailable {
		t.Fatalf("timeout error = %#v, want AI_ORCHESTRATION_ENGINE_FAULT 503", pe)
	}
	if !strings.Contains(pe.Message, "LLM request failed") {
		t.Fatalf("timeout message = %q, want LLM request failed", pe.Message)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="ai_provider",operation="chat_completion",status="timeout_or_network_error"} 1`) {
		t.Fatalf("AI timeout dependency metric missing:\n%s", metrics)
	}
}

func TestExecuteRejectsCitationFreeAndHallucinatedResponses(t *testing.T) {
	tests := []struct {
		name            string
		modelResponse   string
		wantMessagePart string
	}{
		{
			name:            "citation-free",
			modelResponse:   "God created the heavens and the earth.",
			wantMessagePart: "did not include any source citation",
		},
		{
			name:            "hallucinated-citation",
			modelResponse:   "As written, [Exodus 3:14] I AM has sent me.",
			wantMessagePart: "hallucinated citation [Exodus 3:14]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
					t.Fatalf("Authorization header = %q", got)
				}
				var request openaiRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatalf("decode LLM request: %v", err)
				}
				if request.Model != "test-model" || len(request.Messages) != 2 {
					t.Fatalf("LLM request = %#v", request)
				}
				_ = json.NewEncoder(w).Encode(openaiResponse{
					Choices: []struct {
						Message openaiMessage `json:"message"`
					}{
						{Message: openaiMessage{Role: "assistant", Content: tt.modelResponse}},
					},
				})
			}))
			defer server.Close()

			client := &LLMClient{
				APIKey:     "test-key",
				Endpoint:   server.URL,
				Model:      "test-model",
				HTTPClient: server.Client(),
				MaxRetries: 0,
			}

			observer := observability.NewObserver(observability.Options{})
			ctx := observability.WithObserver(context.Background(), observer)
			_, err := client.Execute(ctx, "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
			if err == nil {
				t.Fatal("Execute returned nil error, want verification fault")
			}
			pe, ok := err.(*ai.PlatformException)
			if !ok {
				t.Fatalf("verification error = %T %v, want *ai.PlatformException", err, err)
			}
			if pe.Code != http.StatusForbidden || pe.Category != "AI_ORCHESTRATION_ENGINE_FAULT" {
				t.Fatalf("verification error = %#v, want AI_ORCHESTRATION_ENGINE_FAULT 403", pe)
			}
			if !strings.Contains(pe.Message, tt.wantMessagePart) {
				t.Fatalf("verification message = %q, want %q", pe.Message, tt.wantMessagePart)
			}
			metrics := observer.Snapshot()
			if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="ai_provider",operation="chat_completion",status="verification_failed"} 1`) {
				t.Fatalf("AI verification dependency metric missing:\n%s", metrics)
			}
		})
	}
}

func TestExecuteReturnsVerifiedCitationResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(openaiResponse{
			Choices: []struct {
				Message openaiMessage `json:"message"`
			}{
				{Message: openaiMessage{Role: "assistant", Content: "The passage begins creation with God. [Genesis 1:1]"}},
			},
		})
	}))
	defer server.Close()

	client := &LLMClient{
		APIKey:     "test-key",
		Endpoint:   server.URL,
		Model:      "test-model",
		HTTPClient: server.Client(),
		MaxRetries: 0,
	}

	observer := observability.NewObserver(observability.Options{})
	ctx := observability.WithObserver(context.Background(), observer)
	response, err := client.Execute(ctx, "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
	if err != nil {
		t.Fatalf("Execute verified response error: %v", err)
	}
	if !strings.Contains(response, "[Genesis 1:1]") {
		t.Fatalf("verified response = %q, want expected citation", response)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="ai_provider",operation="chat_completion",status="success"} 1`) {
		t.Fatalf("AI success dependency metric missing:\n%s", metrics)
	}
}
