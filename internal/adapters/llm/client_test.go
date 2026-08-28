package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scriptureforge/internal/domain/ai"
	"scriptureforge/internal/domain/observability"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

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

func TestExecuteFailsClosedWhenClientConfigurationIsIncomplete(t *testing.T) {
	for _, test := range []struct {
		name   string
		client *LLMClient
	}{
		{name: "nil client", client: nil},
		{name: "missing endpoint", client: &LLMClient{APIKey: "test-key", Model: "test-model", HTTPClient: http.DefaultClient}},
		{name: "missing model", client: &LLMClient{APIKey: "test-key", Endpoint: "https://provider.example", HTTPClient: http.DefaultClient}},
		{name: "missing bounded HTTP client", client: &LLMClient{APIKey: "test-key", Endpoint: "https://provider.example", Model: "test-model"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.client.Execute(context.Background(), "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
			var platformErr *ai.PlatformException
			if !errors.As(err, &platformErr) {
				t.Fatalf("Execute error = %T %v, want PlatformException", err, err)
			}
			if platformErr.Category != "AI_CONFIGURATION_FAULT" || platformErr.Code != http.StatusServiceUnavailable {
				t.Fatalf("configuration fault = %#v, want AI_CONFIGURATION_FAULT 503", platformErr)
			}
		})
	}
}

func TestExecuteUsesBoundedHTTPClientTimeout(t *testing.T) {
	allowLoopbackProvider(t)
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
	if pe.Message != "LLM request failed" {
		t.Fatalf("timeout message = %q, want sanitized LLM request failed", pe.Message)
	}
	if strings.Contains(pe.Message, server.URL) || strings.Contains(pe.Message, "deadline exceeded") {
		t.Fatalf("timeout message leaked provider details: %q", pe.Message)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="ai_provider",operation="chat_completion",status="timeout_or_network_error"} 1`) {
		t.Fatalf("AI timeout dependency metric missing:\n%s", metrics)
	}
}

func TestExecuteRedactsNetworkErrorDetails(t *testing.T) {
	t.Setenv("AI_ALLOWED_PROVIDER_HOSTS", "provider.example.invalid")
	client := &LLMClient{
		APIKey:   "test-key",
		Endpoint: "https://provider.example.invalid/v1/chat/completions",
		Model:    "test-model",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport detail: bearer-token-should-not-leak")
		})},
		MaxRetries: 0,
	}

	_, err := client.Execute(context.Background(), "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
	pe, ok := err.(*ai.PlatformException)
	if !ok {
		t.Fatalf("network error = %T %v, want *ai.PlatformException", err, err)
	}
	if pe.Message != "LLM request failed" {
		t.Fatalf("network error message = %q, want sanitized message", pe.Message)
	}
	if strings.Contains(pe.Message, "bearer-token") || strings.Contains(pe.Message, "provider.example.invalid") {
		t.Fatalf("network error leaked provider details: %q", pe.Message)
	}
}

func TestExecuteNormalizesMalformedAndEmptyProviderResponses(t *testing.T) {
	allowLoopbackProvider(t)
	tests := []struct {
		name    string
		body    string
		message string
	}{
		{name: "malformed", body: `{"choices":`, message: "LLM provider returned a malformed response"},
		{name: "empty", body: `{"choices":[]}`, message: "LLM provider returned an empty response"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := &LLMClient{
				APIKey:     "test-key",
				Endpoint:   server.URL,
				Model:      "test-model",
				HTTPClient: server.Client(),
				MaxRetries: 0,
			}
			_, err := client.Execute(context.Background(), "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
			pe, ok := err.(*ai.PlatformException)
			if !ok || pe.Code != http.StatusServiceUnavailable || pe.Message != tt.message {
				t.Fatalf("%s response error = %#v, want sanitized 503 %q", tt.name, err, tt.message)
			}
		})
	}
}

func TestExecuteRetriesWithFreshRequestBody(t *testing.T) {
	allowLoopbackProvider(t)
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		var request openaiRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode retry request: %v", err)
		}
		if request.Model != "test-model" || len(request.Messages) != 2 || request.MaxTokens != ai.DefaultMaxOutputTokens {
			t.Fatalf("retry request = %#v", request)
		}
		if attempts == 1 {
			http.Error(w, "transient provider failure", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(openaiResponse{
			Choices: []struct {
				Message openaiMessage `json:"message"`
			}{
				{Message: openaiMessage{Role: "assistant", Content: "Grounded answer [Genesis 1:1]"}},
			},
		})
	}))
	defer server.Close()

	client := &LLMClient{
		APIKey:     "test-key",
		Endpoint:   server.URL,
		Model:      "test-model",
		HTTPClient: server.Client(),
		MaxRetries: 1,
	}
	response, err := client.Execute(context.Background(), "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
	if err != nil {
		t.Fatalf("Execute retry error: %v", err)
	}
	if attempts != 2 || !strings.Contains(response, "[Genesis 1:1]") {
		t.Fatalf("retry attempts=%d response=%q, want two valid attempts", attempts, response)
	}
}

func TestExecuteRetryStopsWhenContextIsCanceled(t *testing.T) {
	allowLoopbackProvider(t)
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "transient provider failure", http.StatusBadGateway)
	}))
	defer server.Close()

	client := &LLMClient{
		APIKey:     "test-key",
		Endpoint:   server.URL,
		Model:      "test-model",
		HTTPClient: server.Client(),
		MaxRetries: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.Execute(ctx, "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
	if err == nil {
		t.Fatal("Execute returned nil error after context cancellation")
	}
	pe, ok := err.(*ai.PlatformException)
	if !ok || pe.Code != http.StatusServiceUnavailable || pe.Category != "AI_ORCHESTRATION_ENGINE_FAULT" {
		t.Fatalf("canceled retry error = %#v, want typed 503 AI fault", err)
	}
	if attempts != 1 {
		t.Fatalf("canceled retry attempts = %d, want 1", attempts)
	}
}

func TestExecuteRejectsOversizedProviderResponse(t *testing.T) {
	allowLoopbackProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", int(ai.MaxProviderResponseBytes+1))))
	}))
	defer server.Close()

	client := &LLMClient{
		APIKey:     "test-key",
		Endpoint:   server.URL,
		Model:      "test-model",
		HTTPClient: server.Client(),
		MaxRetries: 0,
	}
	_, err := client.Execute(context.Background(), "study genesis", "[Genesis 1:1] In the beginning", ai.NewResponseVerificationSubsystem())
	if err == nil {
		t.Fatal("Execute accepted an oversized provider response")
	}
	pe, ok := err.(*ai.PlatformException)
	if !ok || pe.Code != http.StatusServiceUnavailable || !strings.Contains(pe.Message, "size limit") {
		t.Fatalf("oversized response error = %#v, want bounded AI fault", err)
	}
}

func TestExecuteRejectsCitationFreeAndHallucinatedResponses(t *testing.T) {
	allowLoopbackProvider(t)
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
	allowLoopbackProvider(t)
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

func allowLoopbackProvider(t *testing.T) {
	t.Helper()
	t.Setenv("AI_ALLOWED_PROVIDER_HOSTS", "127.0.0.1")
}
