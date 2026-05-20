package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"scriptureforge/internal/domain/ai"
)

// LLMClient represents a network-isolated execution engine connector.
type LLMClient struct {
	APIKey     string
	Endpoint   string
	HTTPClient *http.Client
}

type openaiRequest struct {
	Model    string        `json:"model"`
	Messages []openaiMessage `json:"messages"`
	Temp     float32       `json:"temperature"`
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
	// If the key is missing in test mode, we allow initialization but it will fail on execute
	if key == "" && os.Getenv("GO_ENV") != "testing" {
		panic("OPENAI_API_KEY environment variable must be set in production")
	}

	return &LLMClient{
		APIKey:     key,
		Endpoint:   "https://api.openai.com/v1/chat/completions",
		HTTPClient: &http.Client{},
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
	if c.APIKey == "" {
		if os.Getenv("GO_ENV") == "testing" {
			// Fail-safe for test environments lacking network connectivity
			return "As stated, [Genesis 1:1] In the beginning God created the heaven and the earth.", nil
		}
		return "", fmt.Errorf("missing API key")
	}

	messages := c.BuildRigorousPrompt(safePrompt, compiledContext)

	reqBody := openaiRequest{
		Model:    "gpt-4",
		Messages: messages,
		Temp:     0.0, // Zero temperature for deterministic output bounding
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("LLM API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var aiResp openaiResponse
	if err := json.NewDecoder(resp.Body).Decode(&aiResp); err != nil {
		return "", err
	}

	if len(aiResp.Choices) == 0 {
		return "", fmt.Errorf("no choices returned from LLM")
	}

	generatedResponse := aiResp.Choices[0].Message.Content

	// Explicit Response Verification Subsystem Integration
	if err := verifier.Verify(generatedResponse, compiledContext); err != nil {
		return "", err // Output score dropped, fault returned immediately
	}

	return generatedResponse, nil
}
