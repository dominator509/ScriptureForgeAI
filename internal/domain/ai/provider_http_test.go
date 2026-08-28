package ai

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadProviderHTTPConfigClampsEnvironmentValues(t *testing.T) {
	t.Setenv("AI_HTTP_TIMEOUT_MS", "999999")
	t.Setenv("AI_MAX_RETRIES", "999")
	t.Setenv("AI_MAX_OUTPUT_TOKENS", "999999")

	config := LoadProviderHTTPConfig()
	if config.Timeout != MaxProviderTimeout {
		t.Fatalf("provider timeout = %s, want %s", config.Timeout, MaxProviderTimeout)
	}
	if config.MaxRetries != MaxProviderRetries {
		t.Fatalf("provider retries = %d, want %d", config.MaxRetries, MaxProviderRetries)
	}
	if config.MaxOutputTokens != MaxOutputTokens {
		t.Fatalf("provider max output tokens = %d, want %d", config.MaxOutputTokens, MaxOutputTokens)
	}
}

func TestValidateProviderEndpointRequiresExactAllowlistAndHTTPS(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		allowed  []string
		wantErr  bool
	}{
		{name: "default provider", endpoint: "https://api.openai.com/v1/embeddings", allowed: nil},
		{name: "unlisted provider", endpoint: "https://evil.example/v1/chat", allowed: []string{"api.openai.com"}, wantErr: true},
		{name: "userinfo", endpoint: "https://api.openai.com@evil.example/v1/chat", allowed: []string{"evil.example"}, wantErr: true},
		{name: "explicit loopback test server", endpoint: "http://127.0.0.1:1234/v1/chat", allowed: []string{"127.0.0.1"}},
		{name: "non TLS non loopback", endpoint: "http://api.openai.com/v1/chat", allowed: []string{"api.openai.com"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProviderEndpoint(tt.endpoint, tt.allowed)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateProviderEndpoint(%q) error = %v, wantErr=%v", tt.endpoint, err, tt.wantErr)
			}
		})
	}
}

func TestLoadAllowedProviderHostsUsesExplicitEnvironment(t *testing.T) {
	t.Setenv("AI_ALLOWED_PROVIDER_HOSTS", "api.openai.com, azure.example ")
	hosts := LoadAllowedProviderHosts()
	if len(hosts) != 2 || hosts[0] != "api.openai.com" || hosts[1] != "azure.example" {
		t.Fatalf("allowed provider hosts = %#v, want normalized configured hosts", hosts)
	}
}

func TestReadProviderResponseBodyRejectsOversizedPayload(t *testing.T) {
	response := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat("x", int(MaxProviderResponseBytes+1))))}
	if _, err := ReadProviderResponseBody(response); err == nil {
		t.Fatal("ReadProviderResponseBody accepted an oversized payload")
	}
}

func TestProviderHTTPClientDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9/redirect-target", http.StatusFound)
	}))
	defer server.Close()

	client := NewProviderHTTPClient(ProviderHTTPConfig{})
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("provider client request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("provider redirect status = %d, want %d", response.StatusCode, http.StatusFound)
	}
}
