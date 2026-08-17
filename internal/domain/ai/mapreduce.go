package ai

import (
	"context"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	defaultMapReduceChunkSize   = 4000
	defaultMapReduceConcurrency = 4
	maxMapReduceConcurrency     = 8
)

// MapReduceWorker asynchronously divides extensive textual outlines into manageable chunks.
type MapReduceWorker struct {
	MaxChunkSize  int
	MaxConcurrent int
}

// NewMapReduceWorker initializes a worker to protect context window capacities.
func NewMapReduceWorker(maxChunkSize int) *MapReduceWorker {
	if maxChunkSize <= 0 {
		maxChunkSize = defaultMapReduceChunkSize
	}
	return &MapReduceWorker{MaxChunkSize: maxChunkSize, MaxConcurrent: defaultMapReduceConcurrency}
}

// Chunk splits a large string into smaller slices based on the configured MaxChunkSize.
// It prefers paragraph, sentence, and word boundaries while guaranteeing a UTF-8-safe byte limit.
func (m *MapReduceWorker) Chunk(text string) []string {
	maxChunkSize := defaultMapReduceChunkSize
	if m != nil && m.MaxChunkSize > 0 {
		maxChunkSize = m.MaxChunkSize
	}
	if len(text) <= maxChunkSize {
		return []string{text}
	}

	var chunks []string
	remaining := text
	for len(remaining) > 0 {
		end := len(remaining)
		if end > maxChunkSize {
			end = safeChunkBoundary(remaining, maxChunkSize)
		}
		chunk := strings.TrimSpace(remaining[:end])
		if chunk != "" {
			chunks = append(chunks, chunk)
		}
		remaining = strings.TrimSpace(remaining[end:])
	}
	return chunks
}

func safeChunkBoundary(text string, maxBytes int) int {
	boundary := maxBytes
	for boundary > 0 && boundary < len(text) && !utf8.RuneStart(text[boundary]) {
		boundary--
	}
	if boundary <= 0 {
		return maxBytes
	}

	segment := text[:boundary]
	for _, marker := range []string{"\n\n", ". ", " "} {
		if index := strings.LastIndex(segment, marker); index >= boundary/2 {
			return index + len(marker)
		}
	}
	return boundary
}

// Process concurrently executes a defined task function over a slice of textual chunks.
func (m *MapReduceWorker) Process(ctx context.Context, text string, processor func(ctx context.Context, chunk string) (string, error)) ([]string, error) {
	if ctx == nil {
		return nil, mapReduceFault("processing context is required")
	}
	if processor == nil {
		return nil, mapReduceFault("chunk processor is required")
	}
	chunks := m.Chunk(text)
	results := make([]string, len(chunks))
	if len(chunks) == 0 {
		return results, nil
	}

	workerCount := defaultMapReduceConcurrency
	if m != nil && m.MaxConcurrent > 0 {
		workerCount = m.MaxConcurrent
	}
	if workerCount > maxMapReduceConcurrency {
		workerCount = maxMapReduceConcurrency
	}
	if workerCount > len(chunks) {
		workerCount = len(chunks)
	}

	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type workItem struct {
		index int
		chunk string
	}
	jobs := make(chan workItem)
	var wg sync.WaitGroup
	var firstErr error
	var firstErrOnce sync.Once
	recordError := func(err error) {
		if err == nil {
			return
		}
		firstErrOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-processCtx.Done():
					return
				case item, ok := <-jobs:
					if !ok {
						return
					}
					res, err := processor(processCtx, item.chunk)
					if err != nil {
						recordError(err)
						return
					}
					results[item.index] = res
				}
			}
		}()
	}

sendLoop:
	for index, chunk := range chunks {
		select {
		case <-processCtx.Done():
			break sendLoop
		case jobs <- workItem{index: index, chunk: chunk}:
		}
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil || ctx.Err() != nil {
		return nil, mapReduceFault("failed to process one or more chunks")
	}
	return results, nil
}

func mapReduceFault(message string) *PlatformException {
	return &PlatformException{Category: "MAPREDUCE_PROCESSING_FAULT", Message: message, Code: 500}
}

// CompletionRequest is the narrow contract used by the reduce stage.
type CompletionRequest struct {
	Model       string
	Prompt      string
	Temperature float32
}

// LLMService keeps map/reduce orchestration independent from a provider SDK.
type LLMService interface {
	CreateCompletion(ctx context.Context, req CompletionRequest) (string, error)
}

type MapReducePipeline struct {
	LLM LLMService
}

func (mr *MapReducePipeline) executeReduce(ctx context.Context, prompt string) (string, error) {
	if mr == nil || mr.LLM == nil {
		return "", mapReduceFault("LLM service is not configured")
	}
	if prompt == "" {
		return "", mapReduceFault("prompt cannot be empty")
	}

	response, err := mr.LLM.CreateCompletion(ctx, CompletionRequest{
		Model:       "gpt-4-turbo",
		Prompt:      prompt,
		Temperature: 0.2,
	})
	if err != nil {
		return "", mapReduceFault("failed to execute reduce: " + err.Error())
	}
	return response, nil
}
