package chaos_sandbox

import (
	"testing"
	"scriptureforge/internal/domain/ai"
)

func FuzzCitationVerification(f *testing.F) {
	// Add seeds simulating various LLM outputs, including malformed ones
	testcases := []string{
		"This is a valid response with a citation. [Romans 8:1]",
		"No citation here.",
		"[John 3:16] [Romans 8:1]",
		"[[[[[[[[[[John 3:16]]]]]]]]]]", // Deep nesting
		"[]",
		"[Invalid Citation 99:99]",
	}

	for _, tc := range testcases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, llmOutput string) {
		// Goal: Ensure the regex verification doesn't panic or hang on catastrophic backtracking
		// Assuming there's a function like VerifyCitations(output string) (bool, error)

		// The purpose of this test is simply to ensure it returns without panicking.
		// We don't care about the result, only that it handles the input safely.
		ai.VerifyCitations(llmOutput)
	})
}
