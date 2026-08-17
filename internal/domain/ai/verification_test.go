package ai

import (
	"strings"
	"testing"
)

func TestResponseVerificationRejectsMalformedCitationAlongsideValidCitation(t *testing.T) {
	err := NewResponseVerificationSubsystem().Verify(
		"Grounded [Genesis 1:1] but malformed [Exodus 3:14a]",
		"[Genesis 1:1] In the beginning",
	)
	if err == nil || !strings.Contains(err.Error(), "malformed source citation") {
		t.Fatalf("Verify error = %v, want malformed citation fault", err)
	}
}

func TestResponseVerificationAcceptsNumberedBookCitation(t *testing.T) {
	err := NewResponseVerificationSubsystem().Verify(
		"The passage is grounded in [1 Samuel 3:10]",
		"[1 Samuel 3:10] Speak, for your servant hears",
	)
	if err != nil {
		t.Fatalf("Verify returned error for valid numbered-book citation: %v", err)
	}
}

func TestResponseVerificationSubsystem_Verify(t *testing.T) {
	v := NewResponseVerificationSubsystem()
	tests := []struct {
		name            string
		generatedText   string
		providedContext string
		wantErr         bool
		errContains     string
	}{
		{
			name:            "single citation",
			generatedText:   "In the beginning, God created the heavens and the earth [Genesis 1:1].",
			providedContext: "Here is the context: [Genesis 1:1] In the beginning God created the heaven and the earth.",
		},
		{
			name:            "multiple citations",
			generatedText:   "In the beginning [Genesis 1:1], the earth was without form [Genesis 1:2].",
			providedContext: "Here is the context: [Genesis 1:1] In the beginning God created the heaven and the earth. [Genesis 1:2] And the earth was without form, and void.",
		},
		{
			name:            "citation free",
			generatedText:   "God created the heavens and the earth.",
			providedContext: "Here is the context: [Genesis 1:1] In the beginning God created the heaven and the earth.",
			wantErr:         true,
			errContains:     "did not include any source citation",
		},
		{
			name:            "hallucinated citation",
			generatedText:   "God created the heavens and the earth [Genesis 1:1], and light [Genesis 1:3].",
			providedContext: "Here is the context: [Genesis 1:1] In the beginning God created the heaven and the earth.",
			wantErr:         true,
			errContains:     "hallucinated citation [Genesis 1:3]",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := v.Verify(testCase.generatedText, testCase.providedContext)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %v", err, testCase.wantErr)
			}
			if testCase.wantErr && !strings.Contains(err.Error(), testCase.errContains) {
				t.Fatalf("Verify() error = %q, want substring %q", err.Error(), testCase.errContains)
			}
		})
	}
}
