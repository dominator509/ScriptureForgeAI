package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresAllArtifacts(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "AI proof requires") {
		t.Fatalf("expected artifact requirement error, got %v", err)
	}
}

func TestRunEmitsAIEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_CHAT_MODEL=gpt-staging AI_CHAT_ENDPOINT=https://provider.example AI_HTTP_TIMEOUT_MS=3500 AI_MAX_RETRIES=1"))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated tenant request returned 200 generated_curriculum with [Genesis 1:1]`))
		case "/degradation":
			_, _ = w.Write([]byte("timeout degradation retry exhausted returned 503 AI_ORCHESTRATION_ENGINE_FAULT"))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected; hallucinated citation rejected; verified citation accepted"))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProviderArtifactURL:    server.URL + "/provider",
		GenerationArtifactURL:  server.URL + "/generation",
		DegradationArtifactURL: server.URL + "/degradation",
		CitationArtifactURL:    server.URL + "/citation",
		AuditArtifactURL:       server.URL + "/audit",
		Timeout:                time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("AI probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if len(result.EvidenceItems) != 1 || result.EvidenceItems[0] != "EXT-AI-001" {
		t.Fatalf("unexpected evidence items: %+v", result.EvidenceItems)
	}
}

func TestRunFailsWhenProviderArtifactLeaksAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY=sk-testsecret"))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated tenant 200 generated_curriculum [Genesis 1:1]`))
		case "/degradation":
			_, _ = w.Write([]byte("timeout degradation retry 503 AI_ORCHESTRATION_ENGINE_FAULT"))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation verified citation"))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id organization_id user_id succeeded failed citation_trails verified"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProviderArtifactURL:    server.URL + "/provider",
		GenerationArtifactURL:  server.URL + "/generation",
		DegradationArtifactURL: server.URL + "/degradation",
		CitationArtifactURL:    server.URL + "/citation",
		AuditArtifactURL:       server.URL + "/audit",
		Timeout:                time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected provider secret leak to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenAuditArtifactMissingCitationTrails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES"))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated tenant 200 generated_curriculum [Genesis 1:1]`))
		case "/degradation":
			_, _ = w.Write([]byte("timeout degradation retry 503 AI_ORCHESTRATION_ENGINE_FAULT"))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation verified citation"))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id organization_id user_id succeeded failed verified"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProviderArtifactURL:    server.URL + "/provider",
		GenerationArtifactURL:  server.URL + "/generation",
		DegradationArtifactURL: server.URL + "/degradation",
		CitationArtifactURL:    server.URL + "/citation",
		AuditArtifactURL:       server.URL + "/audit",
		Timeout:                time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected incomplete audit artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-audit-persistence") {
		t.Fatalf("report missing audit probe:\n%s", output.String())
	}
}

func TestRunFailsWhenGenerationArtifactMissingTenantAuthProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES"))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study 200 generated_curriculum [Genesis 1:1]`))
		case "/degradation":
			_, _ = w.Write([]byte("timeout degradation retry 503 AI_ORCHESTRATION_ENGINE_FAULT"))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation verified citation"))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id organization_id user_id succeeded failed citation_trails verified"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProviderArtifactURL:    server.URL + "/provider",
		GenerationArtifactURL:  server.URL + "/generation",
		DegradationArtifactURL: server.URL + "/degradation",
		CitationArtifactURL:    server.URL + "/citation",
		AuditArtifactURL:       server.URL + "/audit",
		Timeout:                time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected missing tenant/auth generation proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-generation-route") {
		t.Fatalf("report missing generation probe:\n%s", output.String())
	}
}
