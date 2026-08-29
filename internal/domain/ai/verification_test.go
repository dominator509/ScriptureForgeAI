package ai

import (
	"reflect"
	"strings"
	"testing"
)

func TestResponseVerificationRejectsMalformedCitationAlongsideValidCitation(t *testing.T) {
	err := NewResponseVerificationSubsystem().Verify(
		"Grounded [Genesis 1:1] but malformed [Exodus 3:14a]",
		"VALIDATED SCRIPTURAL CONTEXT:\n\n[Genesis 1:1] In the beginning",
	)
	if err == nil || !strings.Contains(err.Error(), "malformed source citation") {
		t.Fatalf("Verify error = %v, want malformed citation fault", err)
	}
}

func TestResponseVerificationAcceptsNumberedBookCitation(t *testing.T) {
	err := NewResponseVerificationSubsystem().Verify(
		"The passage is grounded in [1 Samuel 3:10]",
		"VALIDATED SCRIPTURAL CONTEXT:\n\n[1 Samuel 3:10] Speak, for your servant hears",
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
			providedContext: "VALIDATED SCRIPTURAL CONTEXT:\n\n[Genesis 1:1] In the beginning God created the heaven and the earth.",
		},
		{
			name:            "multiple citations",
			generatedText:   "In the beginning [Genesis 1:1], the earth was without form [Genesis 1:2].",
			providedContext: "VALIDATED SCRIPTURAL CONTEXT:\n\n[Genesis 1:1] In the beginning God created the heaven and the earth.\n[Genesis 1:2] And the earth was without form, and void.",
		},
		{
			name:            "citation free",
			generatedText:   "God created the heavens and the earth.",
			providedContext: "VALIDATED SCRIPTURAL CONTEXT:\n\n[Genesis 1:1] In the beginning God created the heaven and the earth.",
			wantErr:         true,
			errContains:     "did not include any source citation",
		},
		{
			name:            "hallucinated citation",
			generatedText:   "God created the heavens and the earth [Genesis 1:1], and light [Genesis 1:3].",
			providedContext: "VALIDATED SCRIPTURAL CONTEXT:\n\n[Genesis 1:1] In the beginning God created the heaven and the earth.",
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

func TestResponseVerificationRejectsCitationMentionedOnlyInsideSourceText(t *testing.T) {
	err := NewResponseVerificationSubsystem().Verify(
		"The passage is grounded in [Genesis 1:1]",
		"VALIDATED SCRIPTURAL CONTEXT:\n\n[Genesis 1:2] This verse refers to [Genesis 1:1] as an earlier passage.",
	)
	if err == nil || !strings.Contains(err.Error(), "hallucinated citation [Genesis 1:1]") {
		t.Fatalf("Verify error = %v, want citation outside a segment label to be rejected", err)
	}
}

func TestExtractContextCitationsOnlyReturnsSegmentLabels(t *testing.T) {
	got := ExtractContextCitations("VALIDATED SCRIPTURAL CONTEXT:\n\n[Genesis 1:1] In the beginning [Exodus 3:14].\n[1 Samuel 3:10] Speak, for your servant hears.")
	want := []string{"[Genesis 1:1]", "[1 Samuel 3:10]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractContextCitations() = %#v, want %#v", got, want)
	}
}
