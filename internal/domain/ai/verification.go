package ai

import (
	"fmt"
	"regexp"
	"strings"
)

// ResponseVerificationSubsystem matches text references from model outputs against reliable DB coordinates.
type ResponseVerificationSubsystem struct{}

var citationRegex = regexp.MustCompile(`\[([a-zA-Z\s]+)\s(\d+):(\d+)\]`)

// NewResponseVerificationSubsystem initializes the verification guardrail.
func NewResponseVerificationSubsystem() *ResponseVerificationSubsystem {
	return &ResponseVerificationSubsystem{}
}

// Verify ensures every citation in the generated text actually exists within the permitted source context.
// Halts execution and returns a fault if an unmatched reference or hallucination is captured.
func (v *ResponseVerificationSubsystem) Verify(generatedText string, providedContext string) error {
	matches := citationRegex.FindAllStringSubmatch(generatedText, -1)

	if len(matches) == 0 {
		return nil // No citations generated, valid.
	}

	for _, match := range matches {
		if len(match) != 4 {
			continue
		}

		fullCitation := match[0]

		// Deterministic Verification Logic:
		// The exact citation MUST appear in the provided structured context.
		// If the LLM generates a citation not given to it by the RAG engine, it is hallucinating.
		if !strings.Contains(providedContext, fullCitation) {
			return &PlatformException{
				Category: "AI_ORCHESTRATION_ENGINE_FAULT", // Changed to cast correctly if needed or redefined ErrorCategory
				Message:  fmt.Sprintf("verification failed: hallucinated citation %s detected outside explicit data boundaries", fullCitation),
				Code:     403,
			}
		}
	}

	return nil
}
