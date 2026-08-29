package ai

import (
	"fmt"
	"regexp"
)

// ResponseVerificationSubsystem matches text references from model outputs against reliable DB coordinates.
type ResponseVerificationSubsystem struct{}

var citationRegex = regexp.MustCompile(`\[(?:[1-3]\s+)?[A-Za-z][A-Za-z' -]{0,99}\s+[1-9][0-9]{0,2}:[1-9][0-9]{0,2}\]`)
var citationLikeRegex = regexp.MustCompile(`\[[^\]\r\n]{0,160}[0-9]+\s*:\s*[0-9]+[^\]\r\n]{0,160}\]`)
var contextCitationRegex = regexp.MustCompile(`(?m)^\s*(\[(?:[1-3]\s+)?[A-Za-z][A-Za-z' -]{0,99}\s+[1-9][0-9]{0,2}:[1-9][0-9]{0,2}\])(?:\s|$)`)

// ExtractCitations returns only citations accepted by the verification grammar.
// Callers should invoke Verify before treating these citations as trusted.
func ExtractCitations(text string) []string {
	return citationRegex.FindAllString(text, -1)
}

// ExtractContextCitations returns citation labels that begin a validated RAG segment.
// A citation mentioned inside another segment's text is not a permitted source label.
func ExtractContextCitations(text string) []string {
	matches := contextCitationRegex.FindAllStringSubmatch(text, -1)
	citations := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			citations = append(citations, match[1])
		}
	}
	return citations
}

// NewResponseVerificationSubsystem initializes the verification guardrail.
func NewResponseVerificationSubsystem() *ResponseVerificationSubsystem {
	return &ResponseVerificationSubsystem{}
}

// Verify ensures every citation in the generated text actually exists within the permitted source context.
// Halts execution and returns a fault if an unmatched reference or hallucination is captured.
func (v *ResponseVerificationSubsystem) Verify(generatedText string, providedContext string) error {
	matches := ExtractCitations(generatedText)
	citationLikeMatches := citationLikeRegex.FindAllString(generatedText, -1)
	contextCitations := ExtractContextCitations(providedContext)

	if len(matches) == 0 {
		if len(citationLikeMatches) > 0 {
			return &PlatformException{
				Category: "AI_ORCHESTRATION_ENGINE_FAULT",
				Message:  "verification failed: response included a malformed source citation",
				Code:     403,
			}
		}
		return &PlatformException{
			Category: "AI_ORCHESTRATION_ENGINE_FAULT",
			Message:  "verification failed: citation-first response did not include any source citation",
			Code:     403,
		}
	}

	for _, citationLike := range citationLikeMatches {
		if !containsExactCitation(matches, citationLike) {
			return &PlatformException{
				Category: "AI_ORCHESTRATION_ENGINE_FAULT",
				Message:  "verification failed: response included a malformed source citation",
				Code:     403,
			}
		}
	}

	for _, fullCitation := range matches {

		// Deterministic Verification Logic:
		// The exact citation MUST label a segment in the provided structured context.
		// Matching only segment boundaries prevents source text from masquerading as metadata.
		// If the LLM generates a citation not given to it by the RAG engine, it is hallucinating.
		if !containsExactCitation(contextCitations, fullCitation) {
			return &PlatformException{
				Category: "AI_ORCHESTRATION_ENGINE_FAULT",
				Message:  fmt.Sprintf("verification failed: hallucinated citation %s detected outside explicit data boundaries", fullCitation),
				Code:     403,
			}
		}
	}

	return nil
}

func containsExactCitation(citations []string, candidate string) bool {
	for _, citation := range citations {
		if citation == candidate {
			return true
		}
	}
	return false
}
