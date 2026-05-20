package chaos_sandbox

import (
	"testing"
	"unicode/utf8"

	"scriptureforge/internal/domain/ai"
)

func FuzzMapReduceChunking(f *testing.F) {
	testcases := []string{
		"In the beginning God created the heavens and the earth.",
		"Jesus wept.",
		"For God so loved the world that he gave his one and only Son.",
		"",
	}

	for _, tc := range testcases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, input string) {
		limit := 500
		worker := ai.NewMapReduceWorker(limit)
		chunks := worker.Chunk(input)

		isValidOrig := utf8.ValidString(input)

		for _, chunk := range chunks {
			if isValidOrig && !utf8.ValidString(chunk) {
				t.Errorf("Chunk produced invalid UTF-8 string: %q", chunk)
			}
		}
	})
}
