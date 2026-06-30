package ai

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"scriptureforge/internal/domain/observability"
	"scriptureforge/scriptureforge/proto/engine"
)

type fakeScriptureEngineClient struct {
	response *engine.VectorSearchResponse
	err      error
}

func (f fakeScriptureEngineClient) ProcessTextEmbedding(context.Context, *engine.EmbedTextRequest, ...grpc.CallOption) (*engine.EmbedTextResponse, error) {
	return nil, nil
}

func (f fakeScriptureEngineClient) SearchByVector(context.Context, *engine.VectorSearchRequest, ...grpc.CallOption) (*engine.VectorSearchResponse, error) {
	return f.response, f.err
}

func TestGRPCScriptureClientRecordsRustEngineVectorSearchMetric(t *testing.T) {
	t.Setenv("GO_ENV", "testing")
	observer := observability.NewObserver(observability.Options{})
	ctx := observability.WithObserver(context.Background(), observer)
	client := &GRPCScriptureClient{
		client: fakeScriptureEngineClient{
			response: &engine.VectorSearchResponse{
				Results: []*engine.SearchResult{{
					Book:            "Genesis",
					Chapter:         1,
					Verse:           1,
					TextContent:     "In the beginning",
					SimilarityScore: 0.95,
				}},
			},
		},
	}

	results, err := client.Search(ctx, "org-1", "creation", 1)
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Search returned %d results, want 1", len(results))
	}

	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"} 1`) {
		t.Fatalf("missing rust engine vector search success metric:\n%s", metrics)
	}
}
