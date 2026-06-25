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

func TestRunRequiresProbeMode(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "probe-secrets") {
		t.Fatalf("expected probe mode error, got %v", err)
	}
}

func TestRunEmitsSecretsEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`metadata: {name: scriptureforge-api, annotations: {"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/scriptureforge-app-secrets"}}`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`kind: SecretProviderClass
driver: secrets-store.csi.k8s.io
secretObjects:
- data:
  - key: DATABASE_URL
  - key: JWT_SECRET_KEY
  - key: OPENAI_API_KEY
  - key: ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`name: scriptureforge-runtime-secrets
type: Opaque
data:
  DATABASE_URL: REDACTED
  JWT_SECRET_KEY: REDACTED`))
		case "/iam":
			_, _ = w.Write([]byte(`{"Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],"Resource":"arn:aws:secretsmanager:us-east-1:123456789012:secret:scriptureforge/staging/*"}`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret DATABASE_URL; denied unscoped secret /other/app/master using AccessDenied`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeSecrets:      true,
		ServiceAccountURL: server.URL + "/service-account",
		SecretProviderURL: server.URL + "/secret-provider",
		SyncedSecretURL:   server.URL + "/synced-secret",
		IAMPolicyURL:      server.URL + "/iam",
		AccessTestURL:     server.URL + "/access-test",
		Timeout:           time.Second,
	}, &output)
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
}

func TestRunFailsWhenSyncedSecretLeaksPlaintext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets DATABASE_URL JWT_SECRET_KEY postgres://scriptureforge_app:secret@example/db`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager:`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret; denied unscoped secret AccessDenied`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeSecrets:      true,
		ServiceAccountURL: server.URL + "/service-account",
		SecretProviderURL: server.URL + "/secret-provider",
		SyncedSecretURL:   server.URL + "/synced-secret",
		IAMPolicyURL:      server.URL + "/iam",
		AccessTestURL:     server.URL + "/access-test",
		Timeout:           time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected leaked synced secret to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenScopedAccessTestDoesNotDenyUnscopedSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-account":
			_, _ = w.Write([]byte(`eks.amazonaws.com/role-arn scriptureforge`))
		case "/secret-provider":
			_, _ = w.Write([]byte(`SecretProviderClass secrets-store.csi.k8s.io DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN`))
		case "/synced-secret":
			_, _ = w.Write([]byte(`scriptureforge-runtime-secrets DATABASE_URL JWT_SECRET_KEY`))
		case "/iam":
			_, _ = w.Write([]byte(`secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager:`))
		case "/access-test":
			_, _ = w.Write([]byte(`allowed configured secret but unscoped secret probe was not executed`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeSecrets:      true,
		ServiceAccountURL: server.URL + "/service-account",
		SecretProviderURL: server.URL + "/secret-provider",
		SyncedSecretURL:   server.URL + "/synced-secret",
		IAMPolicyURL:      server.URL + "/iam",
		AccessTestURL:     server.URL + "/access-test",
		Timeout:           time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected missing unscoped denial proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "scoped-secrets-access-test") {
		t.Fatalf("report missing access test probe:\n%s", output.String())
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
