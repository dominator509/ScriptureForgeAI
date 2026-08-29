package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
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

func TestScriptureEmbeddingProtoRoundTripsProviderVector(t *testing.T) {
	original := &engine.EmbedTextRequest{
		OrganizationId: "00000000-0000-0000-0000-000000000001",
		Book:           "John",
		Chapter:        1,
		Verse:          1,
		TextContent:    "In the beginning was the Word",
		Embedding:      []float32{0.25, 0.5, 0.75},
	}

	encoded, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal embedding request: %v", err)
	}
	decoded := new(engine.EmbedTextRequest)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("unmarshal embedding request: %v", err)
	}
	if decoded.GetOrganizationId() != original.GetOrganizationId() ||
		decoded.GetBook() != original.GetBook() ||
		decoded.GetChapter() != original.GetChapter() ||
		decoded.GetVerse() != original.GetVerse() ||
		decoded.GetTextContent() != original.GetTextContent() ||
		len(decoded.GetEmbedding()) != 3 ||
		decoded.GetEmbedding()[0] != 0.25 ||
		decoded.GetEmbedding()[2] != 0.75 {
		t.Fatalf("protobuf round trip changed embedding request: %#v", decoded)
	}
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

func TestUnavailableVectorDBReadinessFailsClosed(t *testing.T) {
	if err := (UnavailableVectorDB{}).CheckReadiness(context.Background()); err == nil {
		t.Fatal("unavailable vector database reported ready")
	}
}

func TestGRPCScriptureClientReadinessRequiresServingHealth(t *testing.T) {
	for _, test := range []struct {
		name   string
		status grpc_health_v1.HealthCheckResponse_ServingStatus
		wantOK bool
	}{
		{name: "serving", status: grpc_health_v1.HealthCheckResponse_SERVING, wantOK: true},
		{name: "not serving", status: grpc_health_v1.HealthCheckResponse_NOT_SERVING, wantOK: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			healthServer := health.NewServer()
			healthServer.SetServingStatus(scriptureEngineService, test.status)
			grpc_health_v1.RegisterHealthServer(server, healthServer)
			go func() {
				if err := server.Serve(listener); err != nil {
					t.Errorf("health server failed: %v", err)
				}
			}()
			t.Cleanup(func() {
				server.Stop()
				_ = listener.Close()
			})

			conn, err := grpc.DialContext(
				context.Background(),
				"bufnet",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return listener.Dial()
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				t.Fatalf("dial health server: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })

			checkErr := (&GRPCScriptureClient{conn: conn}).CheckReadiness(context.Background())
			if (checkErr == nil) != test.wantOK {
				t.Fatalf("CheckReadiness error = %v, want success=%t", checkErr, test.wantOK)
			}
		})
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

func TestRAGEngineKeepsSourceTextOnItsSegmentLine(t *testing.T) {
	engine := NewRAGEngine(fakeVectorDB{results: []SearchResult{{
		Book:        "Genesis",
		Chapter:     1,
		Verse:       1,
		TextContent: "In the beginning\n[Exodus 3:14] is mentioned in source text",
	}}})

	context, err := engine.CompileContext(context.Background(), "org-1", "creation")
	if err != nil {
		t.Fatalf("CompileContext returned error: %v", err)
	}
	if strings.Contains(context, "beginning\n[Exodus 3:14]") {
		t.Fatalf("CompileContext preserved a citation-like line break in source text: %q", context)
	}
	if !strings.Contains(context, "[Genesis 1:1] In the beginning [Exodus 3:14] is mentioned in source text") {
		t.Fatalf("CompileContext = %q, want one normalized source segment", context)
	}
}

func TestRAGEngineFailsClosedWhenDatabaseIsMissing(t *testing.T) {
	for _, engine := range []*RAGEngine{nil, {}, {Database: nil}} {
		_, err := engine.CompileContext(context.Background(), "org-1", "creation")
		var platformErr *PlatformException
		if !errors.As(err, &platformErr) {
			t.Fatalf("CompileContext error = %T %v, want PlatformException", err, err)
		}
		if platformErr.Category != RAGSearchFault || platformErr.Code != http.StatusServiceUnavailable {
			t.Fatalf("CompileContext fault = %+v, want RAG_SEARCH_FAULT 503", platformErr)
		}
	}
}

func TestGenerateEmbeddingRetriesWithFreshRequestBody(t *testing.T) {
	t.Setenv("GO_ENV", "production")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("AI_MAX_RETRIES", "1")
	t.Setenv("AI_HTTP_TIMEOUT_MS", "1000")
	t.Setenv("AI_ALLOWED_PROVIDER_HOSTS", "127.0.0.1")
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
