package ai

import (
	"regexp"
)

type ErrorCategory string

const (
	PromptInjectionFault ErrorCategory = "PROMPT_INJECTION_FAULT"
)

type PlatformException struct {
	Category ErrorCategory `json:"category"`
	Message  string        `json:"message"`
	Code     int           `json:"code"`
	TraceID  string        `json:"trace_id"`
}

func (e *PlatformException) Error() string {
	return e.Message
}

var escapeRegex = regexp.MustCompile(`(?i)(ignore previous instructions|system:|assistant:|system prompt)`)

// SanitizeInput provides an active prompt ingestion filtering component
func SanitizeInput(input string) (string, error) {
	if escapeRegex.MatchString(input) {
		return "", &PlatformException{
			Category: PromptInjectionFault,
			Message:  "detected potential prompt escape sequence",
			Code:     400,
		}
	}
	return input, nil
}
