package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"scriptureforge/internal/domain/observability"
	"scriptureforge/scriptureforge/proto/engine"
)

const (
	grpcMaxMessageBytes     = 1024 * 1024
	grpcAuthorizationHeader = "authorization"
	grpcTenantHeader        = "x-scriptureforge-organization-id"
	grpcReadinessTimeout    = 2 * time.Second
	scriptureEngineService  = "scriptureforge.engine.ScriptureEngine"
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

// ReadinessChecker identifies dependencies that must be healthy before staging
// or production traffic should be routed to the API.
type ReadinessChecker interface {
	CheckReadiness(ctx context.Context) error
}

type UnavailableVectorDB struct {
	Reason string
}

func (u UnavailableVectorDB) Search(ctx context.Context, orgID string, query string, topK int) ([]SearchResult, error) {
	return nil, newRAGSearchFault()
}

func (u UnavailableVectorDB) CheckReadiness(context.Context) error {
	return errors.New("scripture engine is unavailable")
}

const ragUnavailableMessage = "scriptural retrieval is temporarily unavailable"

func newRAGSearchFault() *PlatformException {
	return &PlatformException{
		Category: RAGSearchFault,
		Message:  ragUnavailableMessage,
		Code:     http.StatusServiceUnavailable,
	}
}

// sanitizeRAGSearchError keeps provider and transport details out of API errors.
func sanitizeRAGSearchError(err error) *PlatformException {
	var platformErr *PlatformException
	if errors.As(err, &platformErr) && platformErr != nil && platformErr.Category == RAGSearchFault && platformErr.Code == http.StatusServiceUnavailable {
		return &PlatformException{
			Category: RAGSearchFault,
			Message:  ragUnavailableMessage,
			Code:     http.StatusServiceUnavailable,
			TraceID:  platformErr.TraceID,
		}
	}
	return newRAGSearchFault()
}

// GRPCScriptureClient implements VectorDB using the Rust gRPC engine
type GRPCScriptureClient struct {
	client       engine.ScriptureEngineClient
	conn         *grpc.ClientConn
	sharedSecret string
	embeddingFn  func(context.Context, string) ([]float32, error)
}

// NewGRPCScriptureClient connects to the Rust engine
func NewGRPCScriptureClient(address string) (*GRPCScriptureClient, error) {
	return NewGRPCScriptureClientWithConfig(
		address,
		os.Getenv("GRPC_ENGINE_SHARED_SECRET"),
		os.Getenv("GRPC_ENGINE_TLS_CA_PEM"),
		os.Getenv("GRPC_ENGINE_TLS_CLIENT_CERT_PEM"),
		os.Getenv("GRPC_ENGINE_TLS_CLIENT_KEY_PEM"),
		os.Getenv("GRPC_ENGINE_TLS_SERVER_NAME"),
	)
}

func NewGRPCScriptureClientWithConfig(address, sharedSecret, caPEM, clientCertPEM, clientKeyPEM, serverName string) (*GRPCScriptureClient, error) {
	transportCredentials, err := grpcTransportCredentials(caPEM, clientCertPEM, clientKeyPEM, serverName)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(
		address,
		grpc.WithTransportCredentials(transportCredentials),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(grpcMaxMessageBytes),
			grpc.MaxCallRecvMsgSize(grpcMaxMessageBytes),
		),
	)
	if err != nil {
		return nil, err
	}
	client := engine.NewScriptureEngineClient(conn)
	return &GRPCScriptureClient{client: client, conn: conn, sharedSecret: strings.TrimSpace(sharedSecret), embeddingFn: generateEmbedding}, nil
}

// CheckReadiness performs a bounded standard gRPC health check. grpc.Dial is
// intentionally non-blocking, so a successful dial alone is not readiness.
func (c *GRPCScriptureClient) CheckReadiness(ctx context.Context) error {
	if c == nil || c.conn == nil {
		return errors.New("scripture engine connection is unavailable")
	}
	readinessCtx, cancel := context.WithTimeout(ctx, grpcReadinessTimeout)
	defer cancel()
	response, err := grpc_health_v1.NewHealthClient(c.conn).Check(readinessCtx, &grpc_health_v1.HealthCheckRequest{
		Service: scriptureEngineService,
	})
	if err != nil {
		return err
	}
	if response.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("scripture engine health status is %s", response.GetStatus().String())
	}
	return nil
}

func grpcTransportCredentials(caPEM, clientCertPEM, clientKeyPEM, serverName string) (credentials.TransportCredentials, error) {
	caPEM = strings.TrimSpace(caPEM)
	clientCertPEM = strings.TrimSpace(clientCertPEM)
	clientKeyPEM = strings.TrimSpace(clientKeyPEM)
	serverName = strings.TrimSpace(serverName)
	if caPEM == "" && clientCertPEM == "" && clientKeyPEM == "" {
		return insecure.NewCredentials(), nil
	}
	if caPEM == "" || clientCertPEM == "" || clientKeyPEM == "" || serverName == "" {
		return nil, fmt.Errorf("GRPC_ENGINE_TLS_CA_PEM, GRPC_ENGINE_TLS_CLIENT_CERT_PEM, GRPC_ENGINE_TLS_CLIENT_KEY_PEM, and GRPC_ENGINE_TLS_SERVER_NAME must be configured together")
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("GRPC_ENGINE_TLS_CA_PEM does not contain a valid certificate")
	}
	clientCertificate, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid gRPC client certificate: %w", err)
	}

	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCertificate},
		ServerName:   serverName,
	}), nil
}

func (g *GRPCScriptureClient) Close() error {
	return g.conn.Close()
}

// generateEmbedding calls OpenAI to turn the query string into a 1536-dimensional vector
func generateEmbedding(ctx context.Context, text string) ([]float32, error) {
	apiKey := strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	if apiKey == "" {
		return nil, newRAGSearchFault()
	}

	type embedRequest struct {
		Input string `json:"input"`
		Model string `json:"model"`
	}

	model := strings.TrimSpace(os.Getenv("AI_EMBEDDING_MODEL"))
	if model == "" {
		model = "text-embedding-3-small"
	}
	endpoint := strings.TrimSpace(os.Getenv("AI_EMBEDDING_ENDPOINT"))
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/embeddings"
	}
	if err := ValidateProviderEndpoint(endpoint, LoadAllowedProviderHosts()); err != nil {
		return nil, newRAGSearchFault()
	}
	reqBody := embedRequest{
		Input: text,
		Model: model,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, newRAGSearchFault()
	}

	providerConfig := LoadProviderHTTPConfig()
	resp, err := DoProviderRequest(ctx, NewProviderHTTPClient(providerConfig), providerConfig.MaxRetries, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		return req, nil
	})
	if err != nil {
		return nil, newRAGSearchFault()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = ReadProviderResponseBody(resp)
		return nil, newRAGSearchFault()
	}

	bodyBytes, err := ReadProviderResponseBody(resp)
	if err != nil {
		return nil, newRAGSearchFault()
	}

	var embedResp struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}

	if err := json.Unmarshal(bodyBytes, &embedResp); err != nil {
		return nil, newRAGSearchFault()
	}

	if len(embedResp.Data) == 0 || len(embedResp.Data[0].Embedding) == 0 {
		return nil, newRAGSearchFault()
	}

	return embedResp.Data[0].Embedding, nil
}

// Search maps the Go request to the Rust gRPC protobuf request
func (g *GRPCScriptureClient) Search(ctx context.Context, orgID string, query string, topK int) ([]SearchResult, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("organization ID is required for Rust gRPC requests")
	}
	started := time.Now()
	status := "success"
	defer func() {
		observability.ObserveDependencyFromContext(ctx, "rust_engine", "vector_search", status, time.Since(started))
	}()

	// Call the configured provider in production; tests inject a local embedding function.
	embeddingFn := g.embeddingFn
	if embeddingFn == nil {
		embeddingFn = generateEmbedding
	}
	realVector, err := embeddingFn(ctx, query)
	if err != nil {
		status = "embedding_error"
		return nil, sanitizeRAGSearchError(err)
	}

	req := &engine.VectorSearchRequest{
		OrganizationId:             orgID,
		QueryVector:                realVector,
		TopKResults:                int32(topK),
		MinimumSimilarityThreshold: 0.7,
	}

	metadataValues := []string{grpcTenantHeader, orgID}
	if g.sharedSecret != "" {
		metadataValues = append(metadataValues, grpcAuthorizationHeader, "Bearer "+g.sharedSecret)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, metadataValues...)
	resp, err := g.client.SearchByVector(ctx, req)
	if err != nil {
		status = "grpc_error"
		return nil, newRAGSearchFault()
	}
	if resp == nil {
		status = "grpc_error"
		return nil, newRAGSearchFault()
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
	if r == nil || r.Database == nil {
		return "", newRAGSearchFault()
	}

	// 1. Sanitize incoming prompt
	safePrompt, err := SanitizeInput(prompt)
	if err != nil {
		return "", err
	}

	// 2. Query Vector DB for highly relevant segments
	results, err := r.Database.Search(ctx, orgID, safePrompt, 5)
	if err != nil {
		return "", sanitizeRAGSearchError(err)
	}

	if len(results) == 0 {
		return "", &PlatformException{
			Category: RAGContextFault,
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
		// Keep source text on the segment's line so embedded citation-like text cannot
		// be interpreted as another source label by the verification boundary.
		textContent := strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ").Replace(res.TextContent)
		segment := fmt.Sprintf("%s %s\n", citation, textContent)
		contextBuilder.WriteString(segment)
	}

	return contextBuilder.String(), nil
}
