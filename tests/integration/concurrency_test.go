package integration

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scriptureforge/internal/domain/ai"
)

// TestHighConcurrencyMapReduce validates that the MapReduce worker
// remains thread-safe under heavy asynchronous load.
func TestHighConcurrencyMapReduce(t *testing.T) {
	worker := ai.NewMapReduceWorker(50)

	// Generate a massive text payload
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("This is a simulated large block of text. It must be processed safely.\n\n")
	}
	massiveText := sb.String()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var counter int32

	processor := func(ctx context.Context, chunk string) (string, error) {
		atomic.AddInt32(&counter, 1)
		// Simulate network latency during semantic search/LLM embedding
		time.Sleep(2 * time.Millisecond)
		return chunk, nil
	}

	results, err := worker.Process(ctx, massiveText, processor)

	if err != nil {
		t.Fatalf("High concurrency processing failed: %v", err)
	}

	if len(results) == 0 {
		t.Errorf("Expected massive text to be chunked into multiple results")
	}

	if atomic.LoadInt32(&counter) != int32(len(results)) {
		t.Errorf("Race condition detected: Processed count (%d) does not match result count (%d)", counter, len(results))
	}
}
