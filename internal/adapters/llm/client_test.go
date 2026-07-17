package llm

import (
	"strings"
	"testing"
)

func TestBuildRigorousPrompt(t *testing.T) {
	client := NewLLMClient()

	safePrompt := "What does the text say about light?"
	compiledContext := "In the beginning God created the heaven and the earth. [Genesis 1:1]"

	messages := client.BuildRigorousPrompt(safePrompt, compiledContext)

	if len(messages) != 2 {
		t.Fatalf("Expected 2 messages, got %d", len(messages))
	}

	sysMessage := messages[0]
	if sysMessage.Role != "system" {
		t.Errorf("Expected first message role to be 'system', got '%s'", sysMessage.Role)
	}

	expectedSysPrefix := "You are a secure theological assistant."
	if !strings.HasPrefix(sysMessage.Content, expectedSysPrefix) {
		t.Errorf("System message content missing required prefix: expected to start with '%s', got '%s'", expectedSysPrefix, sysMessage.Content)
	}

	if !strings.HasSuffix(sysMessage.Content, compiledContext) {
		t.Errorf("System message content missing compiled context: expected to end with '%s', got '%s'", compiledContext, sysMessage.Content)
	}

	userMessage := messages[1]
	if userMessage.Role != "user" {
		t.Errorf("Expected second message role to be 'user', got '%s'", userMessage.Role)
	}

	if userMessage.Content != safePrompt {
		t.Errorf("Expected user message content to be '%s', got '%s'", safePrompt, userMessage.Content)
	}
}
