package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"scriptureforge/internal/domain/observability"
	"scriptureforge/scriptureforge/proto/engine"
)

type fakeScriptureEngineClient struct {
	response *engine.VectorSearchResponse
	err      error
	ctx      context.Context
}

type fakeVectorDB struct {
	results []SearchResult
	err     error
}

func (f fakeVectorDB) Search(context.Context, string, string, int) ([]SearchResult, error) {
	return f.results, f.err
}

func (f *fakeScriptureEngineClient) ProcessTextEmbedding(context.Context, *engine.EmbedTextRequest, ...grpc.CallOption) (*engine.EmbedTextResponse, error) {
	return nil, nil
}

func (f *fakeScriptureEngineClient) SearchByVector(ctx context.Context, _ *engine.VectorSearchRequest, _ ...grpc.CallOption) (*engine.VectorSearchResponse, error) {
	f.ctx = ctx
	return f.response, f.err
}

func TestGRPCScriptureClientRecordsRustEngineVectorSearchMetric(t *testing.T) {
	observer := observability.NewObserver(observability.Options{})
	ctx := observability.WithObserver(context.Background(), observer)
	fakeClient := &fakeScriptureEngineClient{
		response: &engine.VectorSearchResponse{
			Results: []*engine.SearchResult{{
				Book:            "Genesis",
				Chapter:         1,
				Verse:           1,
				TextContent:     "In the beginning",
				SimilarityScore: 0.95,
			}},
		},
	}
	client := &GRPCScriptureClient{
		client:       fakeClient,
		sharedSecret: "01234567890123456789012345678901",
		embeddingFn: func(context.Context, string) ([]float32, error) {
			return make([]float32, 1536), nil
		},
	}

	results, err := client.Search(ctx, "org-1", "creation", 1)
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Search returned %d results, want 1", len(results))
	}
	values, ok := metadata.FromOutgoingContext(fakeClient.ctx)
	tenantValues := values.Get(grpcTenantHeader)
	authorizationValues := values.Get(grpcAuthorizationHeader)
	if !ok || len(tenantValues) != 1 || tenantValues[0] != "org-1" || len(authorizationValues) != 1 || authorizationValues[0] != "Bearer 01234567890123456789012345678901" {
		t.Fatalf("gRPC metadata = %#v, want tenant and service credentials", values)
	}

	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"} 1`) {
		t.Fatalf("missing rust engine vector search success metric:\n%s", metrics)
	}
}

func TestGRPCScriptureClientRejectsMissingTenant(t *testing.T) {
	client := &GRPCScriptureClient{client: &fakeScriptureEngineClient{}}
	if _, err := client.Search(context.Background(), "", "creation", 1); err == nil {
		t.Fatal("Search accepted an empty organization ID")
	}
}

func TestGenerateEmbeddingFailsClosedWithoutAPIKey(t *testing.T) {
	t.Setenv("GO_ENV", "testing")
	t.Setenv("OPENAI_API_KEY", "")

	embedding, err := generateEmbedding(context.Background(), "creation")
	if embedding != nil {
		t.Fatalf("generateEmbedding returned a synthetic vector without a provider key: %v", embedding)
	}
	var platformErr *PlatformException
	if !errors.As(err, &platformErr) {
		t.Fatalf("generateEmbedding error = %T %v, want PlatformException", err, err)
	}
	if platformErr.Code != http.StatusServiceUnavailable || platformErr.Category != RAGSearchFault {
		t.Fatalf("embedding fault = %+v, want sanitized 503 RAG fault", platformErr)
	}
	if strings.Contains(platformErr.Message, "OPENAI_API_KEY") {
		t.Fatalf("embedding fault leaked provider configuration: %q", platformErr.Message)
	}
}

func TestGRPCScriptureClientSanitizesEmbeddingFailure(t *testing.T) {
	client := &GRPCScriptureClient{
		client: &fakeScriptureEngineClient{},
		embeddingFn: func(context.Context, string) ([]float32, error) {
			return nil, errors.New("provider response contained secret details")
		},
	}

	_, err := client.Search(context.Background(), "org-1", "creation", 1)
	var platformErr *PlatformException
	if !errors.As(err, &platformErr) {
		t.Fatalf("Search error = %T %v, want PlatformException", err, err)
	}
	if platformErr.Code != http.StatusServiceUnavailable || strings.Contains(platformErr.Message, "secret details") {
		t.Fatalf("Search fault = %+v, want sanitized 503", platformErr)
	}
}

func TestRAGEngineSanitizesAndPreservesSearchFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "raw provider failure", err: errors.New("provider response contained secret details")},
		{name: "typed service failure", err: &PlatformException{Category: RAGSearchFault, Message: "internal provider detail", Code: http.StatusServiceUnavailable, TraceID: "trace-1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := NewRAGEngine(fakeVectorDB{err: test.err})
			_, err := engine.CompileContext(context.Background(), "org-1", "creation")
			var platformErr *PlatformException
			if !errors.As(err, &platformErr) {
				t.Fatalf("CompileContext error = %T %v, want PlatformException", err, err)
			}
			if platformErr.Code != http.StatusServiceUnavailable || platformErr.Category != RAGSearchFault {
				t.Fatalf("CompileContext fault = %+v, want sanitized 503 RAG fault", platformErr)
			}
			if strings.Contains(platformErr.Message, "provider") || strings.Contains(platformErr.Message, "internal") {
				t.Fatalf("CompileContext leaked search detail: %q", platformErr.Message)
			}
			if test.name == "typed service failure" && platformErr.TraceID != "trace-1" {
				t.Fatalf("CompileContext lost trace ID: %+v", platformErr)
			}
		})
	}
}

func TestGenerateEmbeddingRetriesWithFreshRequestBody(t *testing.T) {
	t.Setenv("GO_ENV", "production")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("AI_MAX_RETRIES", "1")
	t.Setenv("AI_HTTP_TIMEOUT_MS", "1000")
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		var request struct {
			Input string `json:"input"`
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode embedding request: %v", err)
		}
		if request.Input != "creation" || request.Model != "text-embedding-3-small" {
			t.Fatalf("embedding request = %#v", request)
		}
		if attempts == 1 {
			http.Error(w, "transient embedding failure", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"embedding": []float32{0.25, 0.5}}},
		})
	}))
	defer server.Close()
	t.Setenv("AI_EMBEDDING_ENDPOINT", server.URL)

	embedding, err := generateEmbedding(context.Background(), "creation")
	if err != nil {
		t.Fatalf("generateEmbedding retry error: %v", err)
	}
	if attempts != 2 || len(embedding) != 2 || embedding[0] != 0.25 || embedding[1] != 0.5 {
		t.Fatalf("embedding attempts=%d value=%v, want two valid attempts", attempts, embedding)
	}
}

func TestGRPCTransportCredentialsRejectPartialTLSConfiguration(t *testing.T) {
	if _, err := grpcTransportCredentials("ca", "", "key", "rust-engine"); err == nil {
		t.Fatal("partial gRPC TLS configuration was accepted")
	}
	if _, err := grpcTransportCredentials("not-a-certificate", "cert", "key", "rust-engine"); err == nil {
		t.Fatal("invalid gRPC CA material was accepted")
	}
}
