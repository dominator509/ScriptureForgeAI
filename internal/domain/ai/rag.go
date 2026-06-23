package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"scriptureforge/scriptureforge/proto/engine"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// SearchResult models the expected return from the scripture engine
type SearchResult struct {
	Book            string
	Chapter         int
	Verse           int
	TextContent     string
	SimilarityScore float32
}

// VectorDB defines the required behavior for interacting with semantic space
type VectorDB interface {
	Search(ctx context.Context, orgID string, query string, topK int) ([]SearchResult, error)
}

type UnavailableVectorDB struct {
	Reason string
}

func (u UnavailableVectorDB) Search(ctx context.Context, orgID string, query string, topK int) ([]SearchResult, error) {
	if u.Reason == "" {
		u.Reason = "scripture vector engine is unavailable"
	}
	return nil, &PlatformException{
		Category: "RAG_SEARCH_FAULT",
		Message:  u.Reason,
		Code:     503,
	}
}

// GRPCScriptureClient implements VectorDB using the Rust gRPC engine
type GRPCScriptureClient struct {
	client engine.ScriptureEngineClient
	conn   *grpc.ClientConn
}

// NewGRPCScriptureClient connects to the Rust engine
func NewGRPCScriptureClient(address string) (*GRPCScriptureClient, error) {
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	client := engine.NewScriptureEngineClient(conn)
	return &GRPCScriptureClient{client: client, conn: conn}, nil
}

func (g *GRPCScriptureClient) Close() error {
	return g.conn.Close()
}

// generateEmbedding calls OpenAI to turn the query string into a 1536-dimensional vector
func generateEmbedding(ctx context.Context, text string) ([]float32, error) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		if os.Getenv("GO_ENV") == "testing" {
			// Mock 1536d vector for testing environments without network access
			return make([]float32, 1536), nil
		}
		return nil, fmt.Errorf("OPENAI_API_KEY is required for embedding generation")
	}

	type embedRequest struct {
		Input string `json:"input"`
		Model string `json:"model"`
	}

	model := os.Getenv("AI_EMBEDDING_MODEL")
	if model == "" {
		model = "text-embedding-3-small"
	}
	endpoint := os.Getenv("AI_EMBEDDING_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/embeddings"
	}
	timeout := 3500 * time.Millisecond
	if configured := os.Getenv("AI_HTTP_TIMEOUT_MS"); configured != "" {
		if millis, err := strconv.Atoi(configured); err == nil && millis > 0 {
			timeout = time.Duration(millis) * time.Millisecond
		}
	}

	reqBody := embedRequest{
		Input: text,
		Model: model,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embeddings API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var embedResp struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&embedResp); err != nil {
		return nil, err
	}

	if len(embedResp.Data) == 0 {
		return nil, fmt.Errorf("no embedding returned")
	}

	return embedResp.Data[0].Embedding, nil
}

// Search maps the Go request to the Rust gRPC protobuf request
func (g *GRPCScriptureClient) Search(ctx context.Context, orgID string, query string, topK int) ([]SearchResult, error) {
	// Call OpenAI to get the actual float32 vector embedding
	realVector, err := generateEmbedding(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to generate embedding: %v", err)
	}

	req := &engine.VectorSearchRequest{
		OrganizationId:             orgID,
		QueryVector:                realVector,
		TopKResults:                int32(topK),
		MinimumSimilarityThreshold: 0.7,
	}

	resp, err := g.client.SearchByVector(ctx, req)
	if err != nil {
		return nil, err
	}

	var results []SearchResult
	for _, r := range resp.Results {
		results = append(results, SearchResult{
			Book:            r.Book,
			Chapter:         int(r.Chapter),
			Verse:           int(r.Verse),
			TextContent:     r.TextContent,
			SimilarityScore: r.SimilarityScore,
		})
	}
	return results, nil
}

// RAGEngine manages the context compilation layout engine.
type RAGEngine struct {
	Database VectorDB
}

// NewRAGEngine initializes a production-ready RAG compiler.
func NewRAGEngine(db VectorDB) *RAGEngine {
	return &RAGEngine{Database: db}
}

// CompileContext interacts with the semantic vector space to assemble validated resource segments.
func (r *RAGEngine) CompileContext(ctx context.Context, orgID string, prompt string) (string, error) {
	// 1. Sanitize incoming prompt
	safePrompt, err := SanitizeInput(prompt)
	if err != nil {
		return "", err
	}

	// 2. Query Vector DB for highly relevant segments
	results, err := r.Database.Search(ctx, orgID, safePrompt, 5)
	if err != nil {
		return "", &PlatformException{
			Category: "RAG_SEARCH_FAULT",
			Message:  fmt.Sprintf("vector search failed: %v", err),
			Code:     500,
		}
	}

	if len(results) == 0 {
		return "", &PlatformException{
			Category: "RAG_CONTEXT_FAULT",
			Message:  "insufficient contextual matches found to ground generation",
			Code:     404,
		}
	}

	// 3. Assemble validated resource segments securely
	var contextBuilder strings.Builder
	contextBuilder.WriteString("VALIDATED SCRIPTURAL CONTEXT:\n\n")

	for _, res := range results {
		// Strict citation structural format required by the Verification Subsystem
		citation := fmt.Sprintf("[%s %d:%d]", res.Book, res.Chapter, res.Verse)
		segment := fmt.Sprintf("%s %s\n", citation, res.TextContent)
		contextBuilder.WriteString(segment)
	}

	return contextBuilder.String(), nil
}
