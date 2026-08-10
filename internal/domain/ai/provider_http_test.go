package ai

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestLoadProviderHTTPConfigClampsEnvironmentValues(t *testing.T) {
	t.Setenv("AI_HTTP_TIMEOUT_MS", "999999")
	t.Setenv("AI_MAX_RETRIES", "999")

	config := LoadProviderHTTPConfig()
	if config.Timeout != MaxProviderTimeout {
		t.Fatalf("provider timeout = %s, want %s", config.Timeout, MaxProviderTimeout)
	}
	if config.MaxRetries != MaxProviderRetries {
		t.Fatalf("provider retries = %d, want %d", config.MaxRetries, MaxProviderRetries)
	}
}

func TestReadProviderResponseBodyRejectsOversizedPayload(t *testing.T) {
	response := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat("x", int(MaxProviderResponseBytes+1))))}
	if _, err := ReadProviderResponseBody(response); err == nil {
		t.Fatal("ReadProviderResponseBody accepted an oversized payload")
	}
}
