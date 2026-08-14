package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"scriptureforge/internal/adapters/llm"
	"scriptureforge/internal/domain/ai"
)

// TestAILogicBoundary isolates the AI Domain's LLM Execution boundaries
func TestAILogicBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	verifier := ai.NewResponseVerificationSubsystem()
	client := llm.NewLLMClient()

	// Test 1: Valid Citation provided in Context (Expected Success)
	validContext := "VALIDATED SCRIPTURAL CONTEXT:\n\n[Genesis 1:1] In the beginning God created the heaven and the earth."
	_, err := client.CreateCompletion(ctx, "Tell me about creation", validContext, verifier)
	if err != nil {
		pe, ok := err.(*ai.PlatformException)
		if !ok || pe.Category != "AI_CONFIGURATION_FAULT" || !strings.Contains(pe.Message, "OPENAI_API_KEY") {
			t.Errorf("Expected success or AI configuration fault due to missing mock config, got: %v", err)
		}
	}

	// Test 2: Verify hallucination rejection directly on the verifier
	// Instead of mocking the Execute block, we test the Verifier directly
	generatedText := "As stated, [Genesis 1:1] In the beginning God created the heaven and the earth."
	emptyContext := ""

	err = verifier.Verify(generatedText, emptyContext)
	if err == nil {
		t.Errorf("Expected ResponseVerificationSubsystem to throw hallucination fault")
	} else {
		pe, ok := err.(*ai.PlatformException)
		if !ok || pe.Category != "AI_ORCHESTRATION_ENGINE_FAULT" {
			t.Errorf("Expected PlatformException with AI_ORCHESTRATION_ENGINE_FAULT, got: %v", err)
		}
	}

	if err := verifier.Verify("This answer has no citations.", validContext); err == nil {
		t.Errorf("Expected citation-first verifier to reject responses without citations")
	}
}
