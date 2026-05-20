package ai

import (
	"context"
	"strings"
	"sync"
	"unicode/utf8"
)

// MapReduceWorker asynchronously divides extensive textual outlines into manageable chunks.
type MapReduceWorker struct {
	MaxChunkSize int
}

// NewMapReduceWorker initializes a worker to protect context window capacities.
func NewMapReduceWorker(maxChunkSize int) *MapReduceWorker {
	if maxChunkSize <= 0 {
		maxChunkSize = 4000 // Default safe character limit per chunk
	}
	return &MapReduceWorker{MaxChunkSize: maxChunkSize}
}

// Chunk splits a large string into smaller slices based on the configured MaxChunkSize.
// It uses rune slicing to ensure safe UTF-8 boundaries.
func (m *MapReduceWorker) Chunk(text string) []string {
	if utf8.RuneCountInString(text) <= m.MaxChunkSize {
		return []string{text}
	}

	var chunks []string
	var currentChunk strings.Builder

	paragraphs := strings.Split(text, "\n\n")

	for _, p := range paragraphs {
		pRuneCount := utf8.RuneCountInString(p)
		currRuneCount := utf8.RuneCountInString(currentChunk.String())

		if currRuneCount+pRuneCount > m.MaxChunkSize && currRuneCount > 0 {
			chunks = append(chunks, currentChunk.String())
			currentChunk.Reset()
		}

		// If a single paragraph exceeds the chunk size, we must hard split it
		if pRuneCount > m.MaxChunkSize {
			sentences := strings.Split(p, ". ")
			for _, s := range sentences {
				sRuneCount := utf8.RuneCountInString(s)
				currRuneCount = utf8.RuneCountInString(currentChunk.String())

				if currRuneCount+sRuneCount > m.MaxChunkSize && currRuneCount > 0 {
					chunks = append(chunks, currentChunk.String())
					currentChunk.Reset()
				}

				// Handle extremely long sentences that are larger than MaxChunkSize
				if sRuneCount > m.MaxChunkSize {
					runes := []rune(s)
					for i := 0; i < len(runes); i += m.MaxChunkSize {
						end := i + m.MaxChunkSize
						if end > len(runes) {
							end = len(runes)
						}
						chunks = append(chunks, string(runes[i:end]))
					}
					// Add the final period space if there are more sentences
					currentChunk.WriteString(". ")
				} else {
					currentChunk.WriteString(s + ". ")
				}
			}
		} else {
			currentChunk.WriteString(p + "\n\n")
		}
	}

	if currentChunk.Len() > 0 {
		chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
	}

	return chunks
}

// Process concurrently executes a defined task function over a slice of textual chunks.
func (m *MapReduceWorker) Process(ctx context.Context, text string, processor func(ctx context.Context, chunk string) (string, error)) ([]string, error) {
	chunks := m.Chunk(text)
	results := make([]string, len(chunks))
	errs := make([]error, len(chunks))

	var wg sync.WaitGroup

	for i, c := range chunks {
		wg.Add(1)
		go func(index int, chunk string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				errs[index] = ctx.Err()
				return
			default:
				res, err := processor(ctx, chunk)
				if err != nil {
					errs[index] = err
					return
				}
				results[index] = res
			}
		}(i, c)
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, &PlatformException{
				Category: "MAPREDUCE_PROCESSING_FAULT",
				Message:  "failed to process one or more chunks",
				Code:     500,
			}
		}
	}

	return results, nil
}
