package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"scriptureforge/internal/domain/ai"
	"scriptureforge/internal/domain/observability"
)

// LLMClient represents a network-isolated execution engine connector.
type LLMClient struct {
	APIKey               string
	Endpoint             string
	Model                string
	HTTPClient           *http.Client
	MaxRetries           int
	AllowedProviderHosts []string
}

type openaiRequest struct {
	Model    string          `json:"model"`
	Messages []openaiMessage `json:"messages"`
	Temp     float32         `json:"temperature"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponse struct {
	Choices []struct {
		Message openaiMessage `json:"message"`
	} `json:"choices"`
}

// NewLLMClient initializes the explicit boundary client.
func NewLLMClient() *LLMClient {
	key := os.Getenv("OPENAI_API_KEY")
	endpoint := os.Getenv("AI_CHAT_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/chat/completions"
	}
	model := os.Getenv("AI_CHAT_MODEL")
	if model == "" {
		model = "gpt-4"
	}
	providerConfig := ai.LoadProviderHTTPConfig()
	return &LLMClient{
		APIKey:               key,
		Endpoint:             endpoint,
		Model:                model,
		HTTPClient:           ai.NewProviderHTTPClient(providerConfig),
		MaxRetries:           providerConfig.MaxRetries,
		AllowedProviderHosts: ai.LoadAllowedProviderHosts(),
	}
}

// BuildRigorousPrompt constructs explicit prompt structures binding execution engines to verified vector boundaries.
func (c *LLMClient) BuildRigorousPrompt(safePrompt string, compiledContext string) []openaiMessage {
	var sys strings.Builder

	// Explicit execution bounds preventing model variation outside citation inputs
	sys.WriteString("You are a secure theological assistant. ")
	sys.WriteString("You MUST base your entire response strictly upon the 'VALIDATED SCRIPTURAL CONTEXT' provided below. ")
	sys.WriteString("Do NOT include external theological commentary, and do NOT hallucinate scripture verses. ")
	sys.WriteString("If you quote the text, you MUST append the exact bracketed citation (e.g., [Genesis 1:1]) provided in the context.\n\n")
	sys.WriteString(compiledContext)

	return []openaiMessage{
		{Role: "system", Content: sys.String()},
		{Role: "user", Content: safePrompt},
	}
}

// Execute triggers the network call, processes the boundaries, and runs verification.
func (c *LLMClient) Execute(ctx context.Context, safePrompt string, compiledContext string, verifier *ai.ResponseVerificationSubsystem) (string, error) {
	if c == nil {
		return "", &ai.PlatformException{
			Category: "AI_CONFIGURATION_FAULT",
			Message:  "LLM client is not configured",
			Code:     503,
		}
	}
	start := time.Now()
	status := "error"
	defer func() {
		duration := time.Since(start)
		observability.ObserveDependencyFromContext(ctx, "ai_provider", "chat_completion", status, duration)
		observability.ObserveAIInferenceFromContext(ctx, c.Model, status, duration)
	}()
	if c.APIKey == "" {
		status = "configuration_error"
		return "", &ai.PlatformException{
			Category: "AI_CONFIGURATION_FAULT",
			Message:  "OPENAI_API_KEY is not configured",
			Code:     503,
		}
	}
	if strings.TrimSpace(c.Endpoint) == "" || strings.TrimSpace(c.Model) == "" || c.HTTPClient == nil {
		status = "configuration_error"
		return "", &ai.PlatformException{
			Category: "AI_CONFIGURATION_FAULT",
			Message:  "LLM client is not fully configured",
			Code:     503,
		}
	}
	if err := ai.ValidateProviderEndpoint(c.Endpoint, c.AllowedProviderHosts); err != nil {
		status = "configuration_error"
		return "", &ai.PlatformException{
			Category: "AI_CONFIGURATION_FAULT",
			Message:  "AI provider endpoint is not allowed",
			Code:     503,
		}
	}
	if verifier == nil {
		status = "configuration_error"
		return "", &ai.PlatformException{
			Category: "AI_CONFIGURATION_FAULT",
			Message:  "AI response verifier is not configured",
			Code:     503,
		}
	}

	messages := c.BuildRigorousPrompt(safePrompt, compiledContext)

	reqBody := openaiRequest{
		Model:    c.Model,
		Messages: messages,
		Temp:     0.0, // Zero temperature for deterministic output bounding
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		status = "request_encode_error"
		return "", &ai.PlatformException{
			Category: "AI_ORCHESTRATION_ENGINE_FAULT",
			Message:  "LLM request could not be encoded",
			Code:     http.StatusServiceUnavailable,
		}
	}

	resp, err := ai.DoProviderRequest(ctx, c.HTTPClient, c.MaxRetries, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(jsonBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		return req, nil
	})
	if err != nil {
		status = "timeout_or_network_error"
		return "", &ai.PlatformException{
			Category: "AI_ORCHESTRATION_ENGINE_FAULT",
			Message:  "LLM request failed",
			Code:     503,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		status = strconv.Itoa(resp.StatusCode)
		_, _ = ai.ReadProviderResponseBody(resp)
		return "", &ai.PlatformException{
			Category: "AI_ORCHESTRATION_ENGINE_FAULT",
			Message:  fmt.Sprintf("LLM provider returned status %d", resp.StatusCode),
			Code:     http.StatusServiceUnavailable,
		}
	}

	bodyBytes, err := ai.ReadProviderResponseBody(resp)
	if err != nil {
		status = "response_too_large"
		return "", &ai.PlatformException{
			Category: "AI_ORCHESTRATION_ENGINE_FAULT",
			Message:  "LLM provider response exceeded the configured size limit",
			Code:     http.StatusServiceUnavailable,
		}
	}
	var aiResp openaiResponse
	if err := json.Unmarshal(bodyBytes, &aiResp); err != nil {
		status = "response_decode_error"
		return "", &ai.PlatformException{
			Category: "AI_ORCHESTRATION_ENGINE_FAULT",
			Message:  "LLM provider returned a malformed response",
			Code:     http.StatusServiceUnavailable,
		}
	}

	if len(aiResp.Choices) == 0 {
		status = "empty_response"
		return "", &ai.PlatformException{
			Category: "AI_ORCHESTRATION_ENGINE_FAULT",
			Message:  "LLM provider returned an empty response",
			Code:     http.StatusServiceUnavailable,
		}
	}

	generatedResponse := aiResp.Choices[0].Message.Content

	// Explicit Response Verification Subsystem Integration
	if err := verifier.Verify(generatedResponse, compiledContext); err != nil {
		status = "verification_failed"
		return "", err // Output score dropped, fault returned immediately
	}

	status = "success"
	return generatedResponse, nil
}
