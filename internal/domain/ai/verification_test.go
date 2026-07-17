package ai

import (
	"strings"
	"testing"
)

func TestResponseVerificationSubsystem_Verify(t *testing.T) {
	v := NewResponseVerificationSubsystem()

	tests := []struct {
		name            string
		generatedText   string
		providedContext string
		wantErr         bool
		errCategory     ErrorCategory
		errContains     string
	}{
		{
			name:            "Happy Path (Single Citation)",
			generatedText:   "In the beginning, God created the heavens and the earth [Genesis 1:1].",
			providedContext: "Here is the context: [Genesis 1:1] In the beginning God created the heaven and the earth.",
			wantErr:         false,
		},
		{
			name:            "Happy Path (Multiple Citations)",
			generatedText:   "In the beginning [Genesis 1:1], the earth was without form [Genesis 1:2].",
			providedContext: "Here is the context: [Genesis 1:1] In the beginning God created the heaven and the earth. [Genesis 1:2] And the earth was without form, and void; and darkness was upon the face of the deep.",
			wantErr:         false,
		},
		{
			name:            "Failure (No Citation)",
			generatedText:   "God created the heavens and the earth.",
			providedContext: "Here is the context: [Genesis 1:1] In the beginning God created the heaven and the earth.",
			wantErr:         true,
			errCategory:     "AI_ORCHESTRATION_ENGINE_FAULT",
			errContains:     "verification failed: citation-first response did not include any source citation",
		},
		{
			name:            "Failure (Hallucinated Citation)",
			generatedText:   "God created the heavens and the earth [Genesis 1:1], and light [Genesis 1:3].",
			providedContext: "Here is the context: [Genesis 1:1] In the beginning God created the heaven and the earth.",
			wantErr:         true,
			errCategory:     "AI_ORCHESTRATION_ENGINE_FAULT",
			errContains:     "verification failed: hallucinated citation [Genesis 1:3] detected outside explicit data boundaries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Verify(tt.generatedText, tt.providedContext)

			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				pe, ok := err.(*PlatformException)
				if !ok {
					t.Errorf("Verify() error type = %T, want *PlatformException", err)
					return
				}

				if pe.Category != tt.errCategory {
					t.Errorf("Verify() error category = %v, want %v", pe.Category, tt.errCategory)
				}

				if !strings.Contains(pe.Message, tt.errContains) {
					t.Errorf("Verify() error message = %q, want contains %q", pe.Message, tt.errContains)
				}
			}
		})
	}
}
