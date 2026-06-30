package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const securityReleaseCandidate = "abc123"
const securityServiceVersion = "scriptureforge-api:abc123"
const securityReleaseMarkersText = " release_candidate=" + securityReleaseCandidate + " service_version=" + securityServiceVersion
const securityServiceAccountIdentityText = "staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets"

func stagingSecurityConfig(timeout time.Duration) config {
	return config{
		ProbeSecrets:      true,
		ServiceAccountURL: "https://security-artifacts.staging.scriptureforge.ai/security/service-account",
		SecretProviderURL: "https://security-artifacts.staging.scriptureforge.ai/security/secret-provider",
		SyncedSecretURL:   "https://security-artifacts.staging.scriptureforge.ai/security/synced-secret",
		IAMPolicyURL:      "https://security-artifacts.staging.scriptureforge.ai/security/iam",
		AccessTestURL:     "https://security-artifacts.staging.scriptureforge.ai/security/access-test",
		ReleaseCandidate:  securityReleaseCandidate,
		ServiceVersion:    securityServiceVersion,
		Timeout:           timeout,
	}
}

func TestRunRequiresProbeMode(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "probe-secrets") {
		t.Fatalf("expected probe mode error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	cfg := stagingSecurityConfig(time.Second)
	cfg.ReleaseCandidate = ""
	var output bytes.Buffer
	err := run(cfg, &output)
	if err == nil || !strings.Contains(err.Error(), "release-candidate and service-version") {
		t.Fatalf("expected release identity requirement error, got %v", err)
	}
}

func TestConcreteIAMRoleARNRequiresAccountAndRolePath(t *testing.T) {
	got := concreteIAMRoleARN(`role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets`)
	if got != "arn:aws:iam::123456789012:role/scriptureforge-app-secrets" {
		t.Fatalf("unexpected concrete role ARN: %q", got)
	}
	for _, weak := range []string{
		"role_arn=arn:aws:iam::",
		"role_arn=arn:aws:iam::123456789012",
		"role_arn=arn:aws:iam::123456789012:policy/scriptureforge-app-secrets",
	} {
		if concreteIAMRoleARN(weak) != "" {
			t.Fatalf("expected weak role ARN marker to be rejected: %q", weak)
		}
	}
}

func TestDatabaseUserGrantContractCoversRuntimeTables(t *testing.T) {
	expectedTables := []string{
		"organizations",
		"users",
		"scripture_texts",
		"refresh_tokens",
		"journal_entries",
		"live_rooms",
		"room_participants",
		"ai_request_logs",
		"citation_trails",
	}
	if strings.Join(requiredApplicationGrantTables, ",") != strings.Join(expectedTables, ",") {
		t.Fatalf("unexpected application grant table contract: %v", requiredApplicationGrantTables)
	}
	expectedPrivileges := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	if strings.Join(requiredApplicationGrantPrivileges, ",") != strings.Join(expectedPrivileges, ",") {
		t.Fatalf("unexpected application grant privilege contract: %v", requiredApplicationGrantPrivileges)
	}
}

func TestRunEmitsSecretsEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets metadata: {name: scriptureforge-api, annotations: {"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/scriptureforge-app-secrets"}} trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets
kind: SecretProviderClass
driver: secrets-store.csi.k8s.io
provider: aws
parameters:
  objects:
  - objectName: arn:aws:secretsmanager:us-east-1:123456789012:secret:scriptureforge/staging/database-url
    objectType: secretsmanager
    objectAlias: database_url
  - objectName: arn:aws:secretsmanager:us-east-1:123456789012:secret:scriptureforge/staging/zoom
    objectType: secretsmanager
    jmesPath:
    - path: webhook_secret_token
      objectAlias: zoom_webhook_secret_token
secretObjects:
- secretName: scriptureforge-runtime-secrets
  type: Opaque
  data:
- data:
  - key: DATABASE_URL
  - key: JWT_SECRET_KEY
  - key: OPENAI_API_KEY
  - key: ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`staging artifact namespace=staging
name: scriptureforge-runtime-secrets
type: Opaque
data:
  DATABASE_URL: REDACTED
  JWT_SECRET_KEY: REDACTED
  OPENAI_API_KEY: REDACTED
  ZOOM_WEBHOOK_SECRET_TOKEN: REDACTED
stringData absent
managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true`))
		case "/iam":
			_, _ = w.Write([]byte(`staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets {"Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],"Resource":"arn:aws:secretsmanager:us-east-1:123456789012:secret:scriptureforge/staging/*"} scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets allowed configured secret DATABASE_URL; denied unscoped secret /other/app/master using AccessDenied distinct_secret_artifacts=true`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("security probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if !containsItem(result.EvidenceItems, "SEC-SECRETS-001") {
		t.Fatalf("report missing SEC-SECRETS-001: %+v", result.EvidenceItems)
	}
	if result.ReleaseCandidate != securityReleaseCandidate || result.ServiceVersion != securityServiceVersion {
		t.Fatalf("unexpected release identity: %+v", result)
	}
	expectedMarkers := map[string][]string{
		"irsa-service-account":            {"staging artifact", "namespace=staging", "service_account=scriptureforge-api", "role_arn=arn:aws:iam::", "role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets", "eks.amazonaws.com/role-arn", "scriptureforge", "trust policy", "sts:AssumeRoleWithWebIdentity", "release_candidate=" + securityReleaseCandidate, "service_version=" + securityServiceVersion},
		"secret-provider-class":           {"staging artifact", "namespace=staging", "service_account=scriptureforge-api", "role_arn=arn:aws:iam::", "role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets", "SecretProviderClass", "secrets-store.csi.k8s.io", "provider", "aws", "objects", "objectName", "objectType", "secretsmanager", "objectAlias", "jmesPath", "secretObjects", "type", "Opaque", "DATABASE_URL", "JWT_SECRET_KEY", "OPENAI_API_KEY", "ZOOM_WEBHOOK_SECRET_TOKEN", "release_candidate=" + securityReleaseCandidate, "service_version=" + securityServiceVersion},
		"synced-secret-metadata-redacted": {"staging artifact", "namespace=staging", "scriptureforge-runtime-secrets", "type", "Opaque", "DATABASE_URL", "JWT_SECRET_KEY", "OPENAI_API_KEY", "ZOOM_WEBHOOK_SECRET_TOKEN", "redacted", "stringData absent", "managed by secrets-store.csi.k8s.io", "ownerReferences", "secrets-store.csi.k8s.io/managed=true", "release_candidate=" + securityReleaseCandidate, "service_version=" + securityServiceVersion},
		"iam-secrets-policy":              {"staging artifact", "role_arn=arn:aws:iam::", "role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets", "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "arn:aws:secretsmanager:", "scoped resource", "no wildcard resources", "release_candidate=" + securityReleaseCandidate, "service_version=" + securityServiceVersion},
		"scoped-secrets-access-test":      {"staging artifact", "namespace=staging", "service_account=scriptureforge-api", "role_arn=arn:aws:iam::", "role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets", "allowed", "configured secret", "denied", "unscoped secret", "AccessDenied", "distinct_secret_artifacts=true", "release_candidate=" + securityReleaseCandidate, "service_version=" + securityServiceVersion},
	}
	for _, probe := range result.Probes {
		for _, marker := range expectedMarkers[probe.Name] {
			if !strings.Contains(probe.ResultSummary, marker) {
				t.Fatalf("probe %s summary missing marker %q: %s", probe.Name, marker, probe.ResultSummary)
			}
		}
	}
}

func TestRunFailsWhenSecretRoleARNsDoNotMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`staging artifact namespace=staging scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true`))
		case "/iam":
			_, _ = w.Write([]byte(`staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-other-secrets secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets allowed configured secret denied unscoped secret AccessDenied distinct_secret_artifacts=true`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched role ARNs to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "role_arn_mismatch=true") {
		t.Fatalf("report missing role mismatch marker:\n%s", output.String())
	}
}

func TestRunRejectsDuplicateSecretArtifactURLs(t *testing.T) {
	cfg := stagingSecurityConfig(time.Second)
	cfg.SecretProviderURL = cfg.ServiceAccountURL

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-secret-provider-url must be a distinct artifact URL from -service-account-url") {
		t.Fatalf("expected duplicate secret artifact URL rejection, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateSecretArtifactURLs(t *testing.T) {
	cfg := stagingSecurityConfig(time.Second)
	cfg.ServiceAccountURL = "https://SECURITY-ARTIFACTS.staging.scriptureforge.ai:443/security/shared-secret-proof?b=2&a=1"
	cfg.SecretProviderURL = "https://security-artifacts.staging.scriptureforge.ai/security/shared-secret-proof?a=1&b=2"

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-secret-provider-url must be a distinct artifact URL from -service-account-url") {
		t.Fatalf("expected canonical duplicate secret artifact URL rejection, got %v", err)
	}
}

func TestRunFailsWhenArtifactLacksReleaseMarkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServerWithoutReleaseMarkers(t, server))
	if err == nil {
		t.Fatalf("expected missing release markers to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenArtifactLacksStagingProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied distinct_secret_artifacts=true`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServerWithoutStagingProvenance(t, server))
	if err == nil {
		t.Fatalf("expected missing staging artifact provenance to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenSecretProviderClassLacksAWSObjectSyncProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected weak SecretProviderClass proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "secret-provider-class") {
		t.Fatalf("report missing SecretProviderClass probe:\n%s", output.String())
	}
}

func TestRunFailsWhenSyncedSecretMetadataLacksRedactionProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets DATABASE_URL JWT_SECRET_KEY`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected weak synced-secret metadata proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "synced-secret-metadata-redacted") {
		t.Fatalf("report missing synced-secret probe:\n%s", output.String())
	}
}

func TestRunFailsWhenSyncedSecretMetadataLacksOwnershipProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`staging artifact namespace=staging scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io`))
		case "/iam":
			_, _ = w.Write([]byte(`staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets allowed configured secret denied unscoped secret AccessDenied distinct_secret_artifacts=true`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected synced-secret metadata without ownership proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "synced-secret-metadata-redacted") {
		t.Fatalf("report missing synced-secret probe:\n%s", output.String())
	}
}

func TestRunFailsWhenSyncedSecretLeaksPlaintext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets DATABASE_URL JWT_SECRET_KEY postgres://scriptureforge_app:secret@example/db`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected leaked synced secret to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenSyncedSecretLeaksBase64EncodedValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io data:
  DATABASE_URL: cG9zdGdyZXM6Ly9zY3JpcHR1cmVmb3JnZV9hcHA6c2VjcmV0QGRiL3NjcmlwdHVyZWZvcmdl
  OPENAI_API_KEY: c2stbGl2ZS1zaG91bGQtYmUtcmVqZWN0ZWQ=`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected base64 leaked synced secret to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "synced-secret-metadata-redacted") {
		t.Fatalf("report missing synced-secret probe:\n%s", output.String())
	}
}

func TestRunFailsWhenSyncedSecretContainsStringData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io
stringData:
  DATABASE_URL: REDACTED`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected stringData synced secret to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "synced-secret-metadata-redacted") {
		t.Fatalf("report missing synced-secret probe:\n%s", output.String())
	}
}

func TestRunFailsWhenScopedAccessTestDoesNotDenyUnscopedSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret but unscoped secret probe was not executed`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing unscoped denial proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "scoped-secrets-access-test") {
		t.Fatalf("report missing access test probe:\n%s", output.String())
	}
}

func TestRunFailsWhenIAMPolicyUsesWildcardResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true`))
		case "/iam":
			_, _ = w.Write([]byte(`{"Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],"Resource":"*"} scoped resource no wildcard resources arn:aws:secretsmanager:`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingSecurityConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected wildcard IAM policy proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "iam-secrets-policy") {
		t.Fatalf("report missing IAM policy probe:\n%s", output.String())
	}
}

func TestDatabasePrincipalRejectsPrivilegedNames(t *testing.T) {
	for _, rawURL := range []string{
		"postgres://postgres:secret@example.test/scriptureforge",
		"postgres://rdsadmin:secret@example.test/scriptureforge",
		"postgres://scriptureforge_admin:secret@example.test/scriptureforge",
	} {
		user, err := databasePrincipal(rawURL)
		if err != nil {
			t.Fatalf("databasePrincipal(%q) returned error: %v", rawURL, err)
		}
		if !isPrivilegedPrincipal(user) {
			t.Fatalf("expected %q to be privileged", user)
		}
	}
}

func TestRunRejectsLocalOrInsecureArtifactURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{
			name: "insecure service account artifact",
			edit: func(cfg *config) {
				cfg.ServiceAccountURL = "http://security-artifacts.staging.scriptureforge.ai/security/service-account"
			},
			want: "service-account-url",
		},
		{
			name: "loopback synced secret artifact",
			edit: func(cfg *config) {
				cfg.SyncedSecretURL = "https://127.0.0.1/security/synced-secret"
			},
			want: "synced-secret-url",
		},
		{
			name: "private service account artifact",
			edit: func(cfg *config) {
				cfg.ServiceAccountURL = "https://10.0.0.25/security/service-account"
			},
			want: "service-account-url",
		},
		{
			name: "IPv4-mapped private service account artifact",
			edit: func(cfg *config) {
				cfg.ServiceAccountURL = "https://[::ffff:10.0.0.25]/security/service-account"
			},
			want: "service-account-url",
		},
		{
			name: "link-local secret provider artifact",
			edit: func(cfg *config) {
				cfg.SecretProviderURL = "https://169.254.10.20/security/secret-provider"
			},
			want: "secret-provider-url",
		},
		{
			name: "unspecified IAM policy artifact",
			edit: func(cfg *config) {
				cfg.IAMPolicyURL = "https://0.0.0.0/security/iam"
			},
			want: "iam-policy-url",
		},
		{
			name: "localhost access test artifact",
			edit: func(cfg *config) {
				cfg.AccessTestURL = "https://localhost/security/access-test"
			},
			want: "access-test-url",
		},
		{
			name: "private access test artifact",
			edit: func(cfg *config) {
				cfg.AccessTestURL = "https://172.16.20.5/security/access-test"
			},
			want: "access-test-url",
		},
		{
			name: "reserved example service account artifact",
			edit: func(cfg *config) {
				cfg.ServiceAccountURL = "https://artifacts.staging.example/security/service-account"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved example.com secret provider artifact",
			edit: func(cfg *config) {
				cfg.SecretProviderURL = "https://artifacts.example.com/security/secret-provider"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved test synced secret artifact",
			edit: func(cfg *config) {
				cfg.SyncedSecretURL = "https://security-artifacts.staging.test/security/synced-secret"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved invalid access test artifact",
			edit: func(cfg *config) {
				cfg.AccessTestURL = "https://security-artifacts.invalid/security/access-test"
			},
			want: "reserved placeholder artifact host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stagingSecurityConfig(time.Second)
			tc.edit(&cfg)
			var output bytes.Buffer
			err := runWithClient(cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q URL validation error, got %v", tc.want, err)
			}
		})
	}
}

func TestDatabasePrincipalAcceptsScopedAppUser(t *testing.T) {
	user, err := databasePrincipal("postgres://scriptureforge_app:secret@example.test/scriptureforge")
	if err != nil {
		t.Fatalf("databasePrincipal returned error: %v", err)
	}
	if user != "scriptureforge_app" || isPrivilegedPrincipal(user) {
		t.Fatalf("expected scoped app user, got %q", user)
	}
}

func containsItem(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}

func clientForHTTPServer(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	return clientForHTTPServerWithMarkers(t, server, true, true)
}

func clientForHTTPServerWithoutReleaseMarkers(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	return clientForHTTPServerWithMarkers(t, server, true, false)
}

func clientForHTTPServerWithoutStagingProvenance(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	return clientForHTTPServerWithMarkers(t, server, false, true)
}

func clientForHTTPServerWithMarkers(t *testing.T, server *httptest.Server, appendStagingProvenance bool, appendReleaseMarkers bool) *http.Client {
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
			cloned.URL.Path = strings.TrimPrefix(cloned.URL.Path, "/security")
			resp, err := baseTransport.RoundTrip(cloned)
			if err != nil || resp == nil {
				return resp, err
			}
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return resp, nil
			}
			_ = resp.Body.Close()
			bodyText := string(body)
			if appendStagingProvenance {
				bodyText += " staging artifact"
			}
			if appendReleaseMarkers {
				bodyText += securityReleaseMarkersText
			}
			resp.Body = io.NopCloser(strings.NewReader(bodyText))
			resp.ContentLength = -1
			resp.Header.Del("Content-Length")
			return resp, nil
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
