package ai

import (
	"context"
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

func (f *fakeScriptureEngineClient) ProcessTextEmbedding(context.Context, *engine.EmbedTextRequest, ...grpc.CallOption) (*engine.EmbedTextResponse, error) {
	return nil, nil
}

func (f *fakeScriptureEngineClient) SearchByVector(ctx context.Context, _ *engine.VectorSearchRequest, _ ...grpc.CallOption) (*engine.VectorSearchResponse, error) {
	f.ctx = ctx
	return f.response, f.err
}

func TestGRPCScriptureClientRecordsRustEngineVectorSearchMetric(t *testing.T) {
	t.Setenv("GO_ENV", "testing")
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

func TestGRPCTransportCredentialsRejectPartialTLSConfiguration(t *testing.T) {
	if _, err := grpcTransportCredentials("ca", "", "key", "rust-engine"); err == nil {
		t.Fatal("partial gRPC TLS configuration was accepted")
	}
	if _, err := grpcTransportCredentials("not-a-certificate", "cert", "key", "rust-engine"); err == nil {
		t.Fatal("invalid gRPC CA material was accepted")
	}
}
