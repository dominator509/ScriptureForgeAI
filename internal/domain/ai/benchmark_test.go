package ai

import (
	"strings"
	"testing"
)

// PlatformException stub for tests (if it's not defined in the ai package but in auth, we need to redefine a mock here if it's imported poorly, but it seems to be defined in auth. For now, let's just see if this compiles or we need to add the stub)

func BenchmarkVerificationSubsystem_Valid(b *testing.B) {
	v := NewResponseVerificationSubsystem()
	providedContext := "[Genesis 1:1] In the beginning God created the heaven and the earth. [John 3:16] For God so loved the world..."
	generatedText := "As it says in [Genesis 1:1], God created the world. Furthermore, [John 3:16] talks about love."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := v.Verify(generatedText, providedContext)
		if err != nil {
			b.Fatalf("Verification failed: %v", err)
		}
	}
}

func BenchmarkVerificationSubsystem_Hallucination(b *testing.B) {
	v := NewResponseVerificationSubsystem()
	providedContext := "[Genesis 1:1] In the beginning God created the heaven and the earth."
	generatedText := "God is love [John 3:16]." // Hallucinated citation

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := v.Verify(generatedText, providedContext)
		if err == nil {
			b.Fatalf("Expected verification to fail, but it passed")
		}
	}
}

func BenchmarkVerificationSubsystem_NoCitations(b *testing.B) {
	v := NewResponseVerificationSubsystem()
	providedContext := "[Genesis 1:1] In the beginning God created the heaven and the earth."
	generatedText := "This is a response without any specific book, chapter, and verse references."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := v.Verify(generatedText, providedContext)
		if err != nil {
			b.Fatalf("Verification failed: %v", err)
		}
	}
}

func BenchmarkVerificationSubsystem_LargeText(b *testing.B) {
	v := NewResponseVerificationSubsystem()

	// Create a large context
	contextParts := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		contextParts[i] = "[Psalm 119:1] Blessed are the undefiled in the way, who walk in the law of the LORD."
	}
	providedContext := strings.Join(contextParts, " ")

	// Create large generated text with some valid citations
	textParts := make([]string, 500)
	for i := 0; i < 500; i++ {
		if i%10 == 0 {
			textParts[i] = "As seen in [Psalm 119:1], obedience is key."
		} else {
			textParts[i] = "The text continues to emphasize this point repeatedly."
		}
	}
	generatedText := strings.Join(textParts, " ")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := v.Verify(generatedText, providedContext)
		if err != nil {
			b.Fatalf("Verification failed: %v", err)
		}
	}
}
