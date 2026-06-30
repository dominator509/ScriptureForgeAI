package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var requiredAIProbeSummaryMarkers = map[string][]string{
	"ai-provider-config":       {"staging artifact", "AI_PROVIDER", "AI_CHAT_MODEL", "AI_CHAT_ENDPOINT", "AI_HTTP_TIMEOUT_MS", "AI_MAX_RETRIES", "OPENAI_API_KEY redacted", "configured", "release_candidate=sha-ai", "service_version=scriptureforge-api:sha-ai"},
	"ai-generation-route":      {"staging artifact", "/api/v1/ai/generate/study", "authenticated", "JWT claims", "organization_id=", "user_id=", "request_id=", "200", "generated_curriculum", "[Genesis 1:1]", "release_candidate=sha-ai", "service_version=scriptureforge-api:sha-ai"},
	"ai-timeout-degradation":   {"staging artifact", "provider timeout", "degradation", "retry exhausted", "503", "fail closed", "AI_ORCHESTRATION_ENGINE_FAULT", "release_candidate=sha-ai", "service_version=scriptureforge-api:sha-ai"},
	"ai-citation-verification": {"staging artifact", "no-citation rejected", "hallucinated citation rejected", "verified citation accepted", "citation_trails", "citation_id=", "release_candidate=sha-ai", "service_version=scriptureforge-api:sha-ai"},
	"ai-audit-persistence":     {"staging artifact", "ai_request_logs", "citation_trails", "organization_id=", "user_id=", "request_id=", "citation_id=", "succeeded", "failed", "verified", "tenant rls", "cross-tenant hidden", "distinct_ai_artifacts=true", "release_candidate=sha-ai", "service_version=scriptureforge-api:sha-ai"},
}

const aiReleaseMarkers = " release_candidate=sha-ai service_version=scriptureforge-api:sha-ai"

func stagingAIConfig(timeout time.Duration) config {
	return config{
		ProviderArtifactURL:    "https://ai-artifacts.staging.scriptureforge.ai/ai/provider",
		GenerationArtifactURL:  "https://ai-artifacts.staging.scriptureforge.ai/ai/generation",
		DegradationArtifactURL: "https://ai-artifacts.staging.scriptureforge.ai/ai/degradation",
		CitationArtifactURL:    "https://ai-artifacts.staging.scriptureforge.ai/ai/citation",
		AuditArtifactURL:       "https://ai-artifacts.staging.scriptureforge.ai/ai/audit",
		ReleaseCandidate:       "sha-ai",
		ServiceVersion:         "scriptureforge-api:sha-ai",
		Timeout:                timeout,
	}
}

func TestRunRequiresAllArtifacts(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "AI proof requires") {
		t.Fatalf("expected artifact requirement error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	var output bytes.Buffer
	cfg := stagingAIConfig(time.Second)
	cfg.ReleaseCandidate = ""
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "release-candidate") {
		t.Fatalf("expected release identity error, got %v", err)
	}
}

func TestRunRejectsDuplicateAIArtifactURLs(t *testing.T) {
	var output bytes.Buffer
	cfg := stagingAIConfig(time.Second)
	cfg.AuditArtifactURL = cfg.CitationArtifactURL
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "audit-artifact-url must be a distinct artifact URL") {
		t.Fatalf("expected duplicate artifact URL error, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateAIArtifactURLs(t *testing.T) {
	var output bytes.Buffer
	cfg := stagingAIConfig(time.Second)
	cfg.CitationArtifactURL = "https://AI-ARTIFACTS.staging.scriptureforge.ai:443/ai/shared-proof?b=2&a=1"
	cfg.AuditArtifactURL = "https://ai-artifacts.staging.scriptureforge.ai/ai/shared-proof?a=1&b=2"
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "audit-artifact-url must be a distinct artifact URL") {
		t.Fatalf("expected canonical duplicate artifact URL error, got %v", err)
	}
}

func TestRunEmitsAIEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER=openai AI_CHAT_MODEL=gpt-staging AI_CHAT_ENDPOINT=https://provider.example AI_HTTP_TIMEOUT_MS=3500 AI_MAX_RETRIES=1 OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 returned 200 generated_curriculum with [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted returned 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected; hallucinated citation rejected; verified citation accepted; citation_trails persisted citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden distinct_ai_artifacts=true" + aiReleaseMarkers))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
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
	if result.ReleaseCandidate != "sha-ai" || result.ServiceVersion != "scriptureforge-api:sha-ai" {
		t.Fatalf("report missing release identity: %+v", result)
	}
	if len(result.EvidenceItems) != 1 || result.EvidenceItems[0] != "EXT-AI-001" {
		t.Fatalf("unexpected evidence items: %+v", result.EvidenceItems)
	}
	assertProbeSummariesIncludeMarkers(t, result.Probes, requiredAIProbeSummaryMarkers)
	assertAIGenerationRequestID(t, result.Probes, "req-123")
	assertAIAuditRequestID(t, result.Probes, "req-123")
	assertAICitationID(t, result.Probes, "cite-123")
	assertAITenantPrincipals(t, result.Probes, "org-123", "user-123")
}

func assertAIGenerationRequestID(t *testing.T, probes []probeResult, want string) {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == "ai-generation-route" {
			if probe.RequestID != want {
				t.Fatalf("ai-generation-route request_id = %q, want %q", probe.RequestID, want)
			}
			return
		}
	}
	t.Fatal("missing ai-generation-route probe")
}

func assertAIAuditRequestID(t *testing.T, probes []probeResult, want string) {
	t.Helper()
	for _, probe := range probes {
		if probe.Name == "ai-audit-persistence" {
			if probe.RequestID != want {
				t.Fatalf("ai-audit-persistence request_id = %q, want %q", probe.RequestID, want)
			}
			return
		}
	}
	t.Fatal("missing ai-audit-persistence probe")
}

func assertAICitationID(t *testing.T, probes []probeResult, want string) {
	t.Helper()
	sawCitation := false
	sawAudit := false
	for _, probe := range probes {
		switch probe.Name {
		case "ai-citation-verification":
			sawCitation = true
			if probe.CitationID != want {
				t.Fatalf("ai-citation-verification citation_id = %q, want %q", probe.CitationID, want)
			}
		case "ai-audit-persistence":
			sawAudit = true
			if probe.CitationID != want {
				t.Fatalf("ai-audit-persistence citation_id = %q, want %q", probe.CitationID, want)
			}
		}
	}
	if !sawCitation || !sawAudit {
		t.Fatalf("missing citation/audit probes: citation=%v audit=%v", sawCitation, sawAudit)
	}
}

func assertAITenantPrincipals(t *testing.T, probes []probeResult, wantOrgID, wantUserID string) {
	t.Helper()
	sawGeneration := false
	sawAudit := false
	for _, probe := range probes {
		switch probe.Name {
		case "ai-generation-route":
			sawGeneration = true
			if probe.OrganizationID != wantOrgID || probe.UserID != wantUserID {
				t.Fatalf("ai-generation-route principals = organization_id:%q user_id:%q, want %q/%q", probe.OrganizationID, probe.UserID, wantOrgID, wantUserID)
			}
		case "ai-audit-persistence":
			sawAudit = true
			if probe.OrganizationID != wantOrgID || probe.UserID != wantUserID {
				t.Fatalf("ai-audit-persistence principals = organization_id:%q user_id:%q, want %q/%q", probe.OrganizationID, probe.UserID, wantOrgID, wantUserID)
			}
		}
	}
	if !sawGeneration || !sawAudit {
		t.Fatalf("missing generation/audit probes: generation=%v audit=%v", sawGeneration, sawAudit)
	}
}

func assertProbeSummariesIncludeMarkers(t *testing.T, probes []probeResult, required map[string][]string) {
	t.Helper()
	seen := make(map[string]bool, len(probes))
	for _, probe := range probes {
		markers, ok := required[probe.Name]
		if !ok {
			t.Fatalf("unexpected probe %s", probe.Name)
		}
		seen[probe.Name] = true
		summary := strings.ToLower(probe.ResultSummary)
		for _, marker := range markers {
			if !strings.Contains(summary, strings.ToLower(marker)) {
				t.Fatalf("%s summary missing marker %q: %s", probe.Name, marker, probe.ResultSummary)
			}
		}
	}
	for name := range required {
		if !seen[name] {
			t.Fatalf("missing probe summary for %s", name)
		}
	}
}

func TestRunFailsWhenProviderArtifactLeaksAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY=sk-testsecret" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
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
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id organization_id=org-123 user_id=user-123 succeeded failed verified" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
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
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing tenant/auth generation proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-generation-route") {
		t.Fatalf("report missing generation probe:\n%s", output.String())
	}
}

func TestRunFailsWhenProviderArtifactLacksRedactionProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing provider redaction proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-provider-config") {
		t.Fatalf("report missing provider probe:\n%s", output.String())
	}
}

func TestRunFailsWhenAuditArtifactLacksTenantRLSProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing tenant RLS audit proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-audit-persistence") {
		t.Fatalf("report missing audit probe:\n%s", output.String())
	}
}

func TestRunFailsWhenCitationVerificationArtifactDisablesCitations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123; citation verification disabled" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden distinct_ai_artifacts=true" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected disabled citation verification proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-citation-verification") {
		t.Fatalf("report missing citation probe:\n%s", output.String())
	}
}

func TestRunFailsWhenCitationVerificationArtifactMissingCitationID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden distinct_ai_artifacts=true" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing citation_id proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-citation-verification") {
		t.Fatalf("report missing citation probe:\n%s", output.String())
	}
}

func TestRunFailsWhenAuditCitationIDDoesNotMatchCitationVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-other organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden distinct_ai_artifacts=true" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched citation_id proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "does not match citation verification citation_id") {
		t.Fatalf("report did not explain citation_id mismatch:\n%s", output.String())
	}
}

func TestRunFailsWhenAuditRequestIDDoesNotMatchGeneration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-generation 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-audit citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden distinct_ai_artifacts=true" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched request_id proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "does not match generation request_id") {
		t.Fatalf("report did not explain request_id mismatch:\n%s", output.String())
	}
}

func TestRunFailsWhenAuditOrganizationIDDoesNotMatchGeneration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-generation user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-audit user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden distinct_ai_artifacts=true" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched organization_id proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "does not match generation organization_id") {
		t.Fatalf("report did not explain organization_id mismatch:\n%s", output.String())
	}
}

func TestRunFailsWhenAuditUserIDDoesNotMatchGeneration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-generation request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-audit succeeded failed citation_trails verified tenant rls cross-tenant hidden distinct_ai_artifacts=true" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched user_id proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "does not match generation user_id") {
		t.Fatalf("report did not explain user_id mismatch:\n%s", output.String())
	}
}

func TestRunFailsWhenAuditArtifactDisablesAuditLogging(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden distinct_ai_artifacts=true; audit logging disabled" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected disabled audit logging proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-audit-persistence") {
		t.Fatalf("report missing audit probe:\n%s", output.String())
	}
}

func TestRunFailsWhenArtifactsAreMarkedMockOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider":
			_, _ = w.Write([]byte("configured AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted" + aiReleaseMarkers))
		case "/generation":
			_, _ = w.Write([]byte(`/api/v1/ai/generate/study authenticated JWT claims organization_id=org-123 user_id=user-123 request_id=req-123 200 generated_curriculum [Genesis 1:1]` + aiReleaseMarkers))
		case "/degradation":
			_, _ = w.Write([]byte("provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT" + aiReleaseMarkers))
		case "/citation":
			_, _ = w.Write([]byte("mock artifact: no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123" + aiReleaseMarkers))
		case "/audit":
			_, _ = w.Write([]byte("ai_request_logs request_id=req-123 citation_id=cite-123 organization_id=org-123 user_id=user-123 succeeded failed citation_trails verified tenant rls cross-tenant hidden" + aiReleaseMarkers))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingAIConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mock-only citation artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "ai-citation-verification") {
		t.Fatalf("report missing citation probe:\n%s", output.String())
	}
}

func TestRunRejectsLocalOrInsecureArtifactURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{
			name: "insecure provider artifact",
			edit: func(cfg *config) {
				cfg.ProviderArtifactURL = "http://ai-artifacts.staging.scriptureforge.ai/ai/provider"
			},
			want: "provider-artifact-url",
		},
		{
			name: "reserved example provider artifact",
			edit: func(cfg *config) {
				cfg.ProviderArtifactURL = "https://artifacts.staging.example/ai/provider"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved example.com generation artifact",
			edit: func(cfg *config) {
				cfg.GenerationArtifactURL = "https://ai.example.com/ai/generation"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved test degradation artifact",
			edit: func(cfg *config) {
				cfg.DegradationArtifactURL = "https://ai-artifacts.staging.test/ai/degradation"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved invalid audit artifact",
			edit: func(cfg *config) {
				cfg.AuditArtifactURL = "https://ai-artifacts.invalid/ai/audit"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "loopback degradation artifact",
			edit: func(cfg *config) {
				cfg.DegradationArtifactURL = "https://127.0.0.1/ai/degradation"
			},
			want: "degradation-artifact-url",
		},
		{
			name: "private generation artifact",
			edit: func(cfg *config) {
				cfg.GenerationArtifactURL = "https://10.0.0.15/ai/generation"
			},
			want: "generation-artifact-url",
		},
		{
			name: "IPv4-mapped private generation artifact",
			edit: func(cfg *config) {
				cfg.GenerationArtifactURL = "https://[::ffff:10.0.0.15]/ai/generation"
			},
			want: "generation-artifact-url",
		},
		{
			name: "link-local citation artifact",
			edit: func(cfg *config) {
				cfg.CitationArtifactURL = "https://169.254.10.20/ai/citation"
			},
			want: "citation-artifact-url",
		},
		{
			name: "unspecified provider artifact",
			edit: func(cfg *config) {
				cfg.ProviderArtifactURL = "https://0.0.0.0/ai/provider"
			},
			want: "provider-artifact-url",
		},
		{
			name: "localhost audit artifact",
			edit: func(cfg *config) {
				cfg.AuditArtifactURL = "https://localhost/ai/audit"
			},
			want: "audit-artifact-url",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stagingAIConfig(time.Second)
			tc.edit(&cfg)
			var output bytes.Buffer
			err := runWithClient(cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q URL validation error, got %v", tc.want, err)
			}
		})
	}
}

func clientForHTTPServer(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("invalid test server URL: %v", err)
	}
	baseClient := server.Client()
	baseTransport := baseClient.Transport
	return &http.Client{
		Timeout: baseClient.Timeout,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			cloned.URL.Scheme = serverURL.Scheme
			cloned.URL.Host = serverURL.Host
			cloned.URL.Path = strings.TrimPrefix(cloned.URL.Path, "/ai")
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
