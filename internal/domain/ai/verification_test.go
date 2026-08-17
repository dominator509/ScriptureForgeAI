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
