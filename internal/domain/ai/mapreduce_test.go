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

type captureCompletionService struct {
	request CompletionRequest
	err     error
}

func (s *captureCompletionService) CreateCompletion(_ context.Context, request CompletionRequest) (string, error) {
	s.request = request
	if s.err != nil {
		return "", s.err
	}
	return "generated", nil
}

func TestMapReducePipelineUsesConfiguredChatModel(t *testing.T) {
	t.Setenv("AI_CHAT_MODEL", "env-model")
	service := &captureCompletionService{}
	pipeline := &MapReducePipeline{LLM: service}

	response, err := pipeline.executeReduce(context.Background(), "prompt")
	if err != nil {
		t.Fatalf("executeReduce returned error: %v", err)
	}
	if response != "generated" {
		t.Fatalf("response = %q, want generated", response)
	}
	if service.request.Model != "env-model" {
		t.Fatalf("model = %q, want env-model", service.request.Model)
	}
}

func TestMapReducePipelineModelFieldOverridesEnvironment(t *testing.T) {
	t.Setenv("AI_CHAT_MODEL", "env-model")
	service := &captureCompletionService{}
	pipeline := &MapReducePipeline{LLM: service, Model: "configured-model"}

	if _, err := pipeline.executeReduce(context.Background(), "prompt"); err != nil {
		t.Fatalf("executeReduce returned error: %v", err)
	}
	if service.request.Model != "configured-model" {
		t.Fatalf("model = %q, want configured-model", service.request.Model)
	}
}

func TestMapReducePipelineKeepsCurrentDefaultModel(t *testing.T) {
	t.Setenv("AI_CHAT_MODEL", "")
	service := &captureCompletionService{}
	pipeline := &MapReducePipeline{LLM: service}

	if _, err := pipeline.executeReduce(context.Background(), "prompt"); err != nil {
		t.Fatalf("executeReduce returned error: %v", err)
	}
	if service.request.Model != defaultMapReduceModel {
		t.Fatalf("model = %q, want %q", service.request.Model, defaultMapReduceModel)
	}
}

func TestMapReducePipelineDoesNotExposeCompletionErrorDetails(t *testing.T) {
	service := &captureCompletionService{err: errors.New("provider secret should not escape")}
	pipeline := &MapReducePipeline{LLM: service}

	_, err := pipeline.executeReduce(context.Background(), "prompt")
	if err == nil {
		t.Fatal("executeReduce returned nil error")
	}
	if strings.Contains(err.Error(), "provider secret") {
		t.Fatalf("completion error leaked through mapreduce fault: %v", err)
	}
	if fault, ok := err.(*PlatformException); !ok || fault.Category != "MAPREDUCE_PROCESSING_FAULT" {
		t.Fatalf("error = %#v, want MAPREDUCE_PROCESSING_FAULT", err)
	}
}
