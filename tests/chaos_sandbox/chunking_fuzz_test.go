package chaos_sandbox

import (
	"strings"
	"testing"
	"unicode/utf8"

	"scriptureforge/internal/domain/ai"
)

func FuzzMapReduceChunking(f *testing.F) {
	// Provide initial valid seeds
	testcases := []string{
		"In the beginning God created the heavens and the earth.",
		"Jesus wept.",
		"For God so loved the world that he gave his one and only Son.",
		"",
		strings.Repeat("A", 10000), // Large string
	}

	for _, tc := range testcases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Goal: Ensure chunking doesn't panic or produce chunks larger than the limit
		limit := 500

		chunks := ai.ChunkText(input, limit)

		// If the original string is valid UTF-8, the chunks should theoretically be valid too
		// (though we might break in the middle of a word depending on the implementation,
		// it shouldn't produce invalid unicode runes if it splits on runes)
		isValidOrig := utf8.ValidString(input)

		totalLen := 0
		for _, chunk := range chunks {
			if len(chunk) > limit {
				t.Errorf("Chunk length %d exceeds limit %d", len(chunk), limit)
			}
			if isValidOrig && !utf8.ValidString(chunk) {
				t.Errorf("Chunk produced invalid UTF-8 string: %q", chunk)
			}
			totalLen += len(chunk)
		}
	})
}
