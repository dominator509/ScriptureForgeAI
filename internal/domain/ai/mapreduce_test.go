package ai

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestChunkGuaranteesConfiguredUTF8SafeLimit(t *testing.T) {
	worker := NewMapReduceWorker(10)
	input := strings.Repeat("界", 13) + strings.Repeat("Genesis 1:1 ", 8)
	chunks := worker.Chunk(input)
	if len(chunks) < 2 {
		t.Fatalf("chunk count = %d, want multiple chunks", len(chunks))
	}
	for index, chunk := range chunks {
		if len(chunk) > worker.MaxChunkSize {
			t.Fatalf("chunk %d byte length = %d, want <= %d", index, len(chunk), worker.MaxChunkSize)
		}
		if !utf8.ValidString(chunk) {
			t.Fatalf("chunk %d is not valid UTF-8: %q", index, chunk)
		}
	}
}

func TestProcessBoundsConcurrentProcessorsAndPreservesOrder(t *testing.T) {
	worker := NewMapReduceWorker(1)
	worker.MaxConcurrent = 3
	input := strings.Repeat("x", 24)
	var active int32
	var maxActive int32
	results, err := worker.Process(context.Background(), input, func(ctx context.Context, chunk string) (string, error) {
		current := atomic.AddInt32(&active, 1)
		for {
			previous := atomic.LoadInt32(&maxActive)
			if current <= previous || atomic.CompareAndSwapInt32(&maxActive, previous, current) {
				break
			}
		}
		defer atomic.AddInt32(&active, -1)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Millisecond):
			return chunk, nil
		}
	})
	if err != nil {
		t.Fatalf("bounded processing returned error: %v", err)
	}
	if maxActive > 3 {
		t.Fatalf("maximum concurrent processors = %d, want <= 3", maxActive)
	}
	if got, want := len(results), len(worker.Chunk(input)); got != want {
		t.Fatalf("result count = %d, want %d", got, want)
	}
	if strings.Join(results, "") != input {
		t.Fatalf("result order/content = %q, want %q", strings.Join(results, ""), input)
	}
}

func TestProcessFailsClosedForInvalidInputs(t *testing.T) {
	worker := NewMapReduceWorker(8)
	if _, err := worker.Process(context.Background(), "text", nil); err == nil {
		t.Fatal("nil processor returned nil error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := worker.Process(ctx, "text", func(context.Context, string) (string, error) {
		t.Fatal("processor ran after context cancellation")
		return "", nil
	}); err == nil {
		t.Fatal("cancelled context returned nil error")
	}
	if _, err := worker.Process(context.Background(), "text", func(context.Context, string) (string, error) {
		return "", errors.New("processor failure")
	}); err == nil {
		t.Fatal("processor failure returned nil error")
	} else if fault, ok := err.(*PlatformException); !ok || fault.Category != "MAPREDUCE_PROCESSING_FAULT" {
		t.Fatalf("processor failure = %#v, want MAPREDUCE_PROCESSING_FAULT", err)
	}
}
