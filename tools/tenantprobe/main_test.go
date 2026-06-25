package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunRequiresTokens(t *testing.T) {
	var output bytes.Buffer
	err := run(config{APIBase: "https://api.example.test", Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "owner-token") {
		t.Fatalf("expected owner-token error, got %v", err)
	}
}

func TestRunProvesOwnerReadAndBlockedDenial(t *testing.T) {
	var mu sync.Mutex
	entries := map[string]journalPayload{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/db-rls-proof" {
			_, _ = w.Write([]byte(`current_user=scriptureforge_app non-superuser app.current_org_id set row_security on FORCE ROW LEVEL SECURITY journal_entries live_rooms ai_request_logs citation_trails cross-tenant write denied`))
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "owner-token" && token != "blocked-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/journal_entries":
			if token != "owner-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var payload journalPayload
			_ = json.NewDecoder(r.Body).Decode(&payload)
			payload.ID = "entry-1"
			mu.Lock()
			entries[payload.ID] = payload
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(payload)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries/entry-1":
			if token == "blocked-token" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			mu.Lock()
			payload := entries["entry-1"]
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(payload)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries":
			if token == "blocked-token" {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":"entry-1"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		APIBase:          server.URL,
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		DBRLSArtifactURL: server.URL + "/db-rls-proof",
		Timeout:          time.Second,
	}, &output)
	if err != nil {
		t.Fatalf("tenant probe failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"DATA-RLS-001"`) {
		t.Fatalf("report missing DATA-RLS-001:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"blocked-read-created-journal"`) {
		t.Fatalf("report missing blocked read probe:\n%s", output.String())
	}
}

func TestRunFailsWhenBlockedTokenCanReadEntry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"entry-1","ciphertext":"cipher","iv":"iv","salt_id":"salt","salt_version":1}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries/entry-1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"entry-1"}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{APIBase: server.URL, OwnerToken: "owner", BlockedToken: "blocked", DBRLSArtifactURL: server.URL + "/db-rls-proof", Timeout: time.Second}, &output)
	if err == nil {
		t.Fatalf("expected cross-token read to fail threshold:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestCreateJournalEntryRejectsPlaintextLeakInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"entry-1","ciphertext":"plaintext leaked","iv":"iv","salt_id":"salt","salt_version":1}`))
	}))
	defer server.Close()

	_, result := createJournalEntry(server.Client(), server.URL, "owner", journalPayload{Ciphertext: "cipher", IV: "iv", SaltID: "salt", SaltVersion: 1})
	if result.Passed {
		t.Fatalf("create probe passed despite plaintext marker: %+v", result)
	}
}

func TestRunFailsWhenDBRLSArtifactMissingContextProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/journal_entries":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"entry-1","ciphertext":"cipher","iv":"iv","salt_id":"salt","salt_version":1}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries/entry-1":
			if strings.Contains(r.Header.Get("Authorization"), "blocked") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"id":"entry-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries":
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && r.URL.Path == "/db-rls-proof":
			_, _ = w.Write([]byte(`current_user=scriptureforge_app row_security on journal_entries`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		APIBase:          server.URL,
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		DBRLSArtifactURL: server.URL + "/db-rls-proof",
		Timeout:          time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected weak DB RLS artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "database-rls-context-proof") {
		t.Fatalf("report missing DB RLS proof probe:\n%s", output.String())
	}
}

func TestDBRLSArtifactRejectsLeakedDatabaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`current_user=scriptureforge_app non-superuser app.current_org_id set row_security on FORCE ROW LEVEL SECURITY journal_entries live_rooms ai_request_logs citation_trails cross-tenant write denied postgres://scriptureforge_app:secret@example/db`))
	}))
	defer server.Close()

	result := probeDBRLSArtifact(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite leaked database URL: %+v", result)
	}
}
