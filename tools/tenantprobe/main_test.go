package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testOwnerOrgID   = "11111111-1111-4111-8111-111111111111"
	testBlockedOrgID = "22222222-2222-4222-8222-222222222222"
	testLoadRunID    = "tenant-load-run-123"
)

func TestRunRequiresTokens(t *testing.T) {
	var output bytes.Buffer
	err := run(config{APIBase: "https://api-tenant.staging.scriptureforge.ai", Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "owner-token") {
		t.Fatalf("expected owner-token error, got %v", err)
	}
}

func TestRunRequiresReleaseIdentity(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:          "https://api-tenant.staging.scriptureforge.ai",
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		OwnerOrgID:       testOwnerOrgID,
		BlockedOrgID:     testBlockedOrgID,
		DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof",
		Timeout:          time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "release-candidate") {
		t.Fatalf("expected release-candidate error, got %v", err)
	}
}

func TestRunRequiresLoadRunID(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:          "https://api-tenant.staging.scriptureforge.ai",
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		OwnerOrgID:       testOwnerOrgID,
		BlockedOrgID:     testBlockedOrgID,
		DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof",
		ReleaseCandidate: "sha-tenant",
		ServiceVersion:   "scriptureforge-api:sha-tenant",
		Timeout:          time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "load-run-id") {
		t.Fatalf("expected load-run-id error, got %v", err)
	}
}

func TestRunRequiresDistinctTenantPair(t *testing.T) {
	var output bytes.Buffer
	err := run(config{
		APIBase:          "https://api-tenant.staging.scriptureforge.ai",
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof",
		ReleaseCandidate: "sha-tenant",
		ServiceVersion:   "scriptureforge-api:sha-tenant",
		LoadRunID:        testLoadRunID,
		Timeout:          time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "owner-org-id") {
		t.Fatalf("expected owner-org-id error, got %v", err)
	}

	err = run(config{
		APIBase:          "https://api-tenant.staging.scriptureforge.ai",
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		OwnerOrgID:       testOwnerOrgID,
		BlockedOrgID:     testOwnerOrgID,
		DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof",
		ReleaseCandidate: "sha-tenant",
		ServiceVersion:   "scriptureforge-api:sha-tenant",
		Timeout:          time.Second,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "different organizations") {
		t.Fatalf("expected distinct tenant pair error, got %v", err)
	}
}

func TestRunRequiresUUIDTenantPair(t *testing.T) {
	var output bytes.Buffer
	base := config{
		APIBase:          "https://api-tenant.staging.scriptureforge.ai",
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		OwnerOrgID:       testOwnerOrgID,
		BlockedOrgID:     testBlockedOrgID,
		DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof",
		ReleaseCandidate: "sha-tenant",
		ServiceVersion:   "scriptureforge-api:sha-tenant",
		LoadRunID:        testLoadRunID,
		Timeout:          time.Second,
	}

	ownerBad := base
	ownerBad.OwnerOrgID = "owner-org"
	err := run(ownerBad, &output)
	if err == nil || !strings.Contains(err.Error(), "owner-org-id must be a UUID") {
		t.Fatalf("expected owner UUID error, got %v", err)
	}

	blockedBad := base
	blockedBad.BlockedOrgID = "blocked-org"
	err = run(blockedBad, &output)
	if err == nil || !strings.Contains(err.Error(), "blocked-org-id must be a UUID") {
		t.Fatalf("expected blocked UUID error, got %v", err)
	}
}

func TestRunProvesOwnerReadAndBlockedDenial(t *testing.T) {
	var mu sync.Mutex
	entries := map[string]journalPayload{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/db-rls-proof" {
			_, _ = w.Write([]byte(fullDBRLSProofArtifact()))
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
			if rejectPlaintextJournalEnvelopeForTest(w, r) {
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
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/rooms/create":
			if token != "owner-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var payload struct {
				Title string `json:"title"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if strings.TrimSpace(payload.Title) == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"room-1","title":"` + payload.Title + `"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/rooms/active":
			if token == "blocked-token" {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":"room-1","title":"Tenant Isolation Room"}]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/rooms/state/"):
			if token == "blocked-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"type":"state_sync","room_id":"room-1"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:          "https://api-tenant.staging.scriptureforge.ai",
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		OwnerOrgID:       testOwnerOrgID,
		BlockedOrgID:     testBlockedOrgID,
		DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof",
		ReleaseCandidate: "sha-tenant",
		ServiceVersion:   "scriptureforge-api:sha-tenant",
		LoadRunID:        testLoadRunID,
		Timeout:          time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("tenant probe failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"DATA-RLS-001"`) {
		t.Fatalf("report missing DATA-RLS-001:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"blocked-read-created-journal"`) {
		t.Fatalf("report missing blocked read probe:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"owner-list-contains-created-journal"`) {
		t.Fatalf("report missing owner journal list probe:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"blocked-journal-tenant-override-write-denied"`) {
		t.Fatalf("report missing blocked journal write-denial probe:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"owner-create-room"`) {
		t.Fatalf("report missing room create probe:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"blocked-room-tenant-override-write-denied"`) {
		t.Fatalf("report missing blocked room write-denial probe:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"blocked-room-state-denied"`) {
		t.Fatalf("report missing blocked room state probe:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "distinct_db_rls_artifact=true") {
		t.Fatalf("report missing distinct DB RLS artifact marker:\n%s", output.String())
	}

	var decoded report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode tenant probe report: %v\n%s", err, output.String())
	}
	if !decoded.ThresholdPass {
		t.Fatalf("tenant probe report threshold_pass=false: %+v", decoded)
	}
	if decoded.OwnerOrgID != testOwnerOrgID || decoded.BlockedOrgID != testBlockedOrgID {
		t.Fatalf("tenant probe report did not preserve tenant pair: owner=%q blocked=%q", decoded.OwnerOrgID, decoded.BlockedOrgID)
	}
	if decoded.LoadRunID != testLoadRunID {
		t.Fatalf("tenant probe report did not preserve load_run_id: %q", decoded.LoadRunID)
	}
	if decoded.CreatedJournalID != "entry-1" {
		t.Fatalf("tenant probe report did not preserve created_journal_id: %q", decoded.CreatedJournalID)
	}
	if decoded.CreatedRoomID != "room-1" {
		t.Fatalf("tenant probe report did not preserve created_room_id: %q", decoded.CreatedRoomID)
	}
	requireProbe := func(name string) probeResult {
		t.Helper()
		for _, probe := range decoded.Probes {
			if probe.Name == name {
				if !probe.Passed {
					t.Fatalf("%s did not pass: %+v", name, probe)
				}
				if !strings.Contains(probe.ResultSummary, "load_run_id="+testLoadRunID) {
					t.Fatalf("%s summary did not bind to load_run_id: %s", name, probe.ResultSummary)
				}
				return probe
			}
		}
		t.Fatalf("report missing probe %s: %+v", name, decoded.Probes)
		return probeResult{}
	}
	for _, name := range []string{
		"owner-create-encrypted-journal",
		"owner-read-created-journal",
		"owner-list-contains-created-journal",
		"blocked-read-created-journal",
		"blocked-list-excludes-created-journal",
	} {
		probe := requireProbe(name)
		if probe.JournalID != "entry-1" {
			t.Fatalf("%s did not bind to created journal_id entry-1: %+v", name, probe)
		}
	}
	for _, name := range []string{
		"owner-create-room",
		"owner-active-rooms-contains-created-room",
		"blocked-active-rooms-excludes-created-room",
		"owner-room-state",
		"blocked-room-state-denied",
	} {
		probe := requireProbe(name)
		if probe.RoomID != "room-1" {
			t.Fatalf("%s did not bind to created room_id room-1: %+v", name, probe)
		}
	}
	if probe := requireProbe("blocked-journal-tenant-override-write-denied"); probe.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked journal write override did not prove HTTP 403 denial: %+v", probe)
	}
	if probe := requireProbe("blocked-room-tenant-override-write-denied"); probe.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked room write override did not prove HTTP 403 denial: %+v", probe)
	}
	if probe := requireProbe("blocked-room-state-denied"); probe.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked room state did not prove HTTP 403 denial: %+v", probe)
	}
	dbRLSProbe := requireProbe("database-rls-context-proof")
	if dbRLSProbe.ApplicationRole != "scriptureforge_app" {
		t.Fatalf("database RLS probe did not expose structured application_role: %+v", dbRLSProbe)
	}
	if dbRLSProbe.RowSecurity != "on" {
		t.Fatalf("database RLS probe did not expose structured row_security=on: %+v", dbRLSProbe)
	}
	if dbRLSProbe.RLSTablesVerified != 9 || dbRLSProbe.RLSForcedTables != 9 {
		t.Fatalf("database RLS probe did not expose structured RLS table counts: %+v", dbRLSProbe)
	}
	if dbRLSProbe.RLSPolicyScope != "app.current_org_id" {
		t.Fatalf("database RLS probe did not expose structured policy scope: %+v", dbRLSProbe)
	}
}

func TestRunFailsWhenTenantOverrideWritesAreAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/journal_entries":
			if rejectPlaintextJournalEnvelopeForTest(w, r) {
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"entry-1","ciphertext":"cipher","iv":"iv","salt_id":"salt","salt_version":1}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries/entry-1":
			if strings.Contains(r.Header.Get("Authorization"), "blocked") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"id":"entry-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries":
			if strings.Contains(r.Header.Get("Authorization"), "blocked") {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":"entry-1"}]`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/rooms/create":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"room-1","title":"Test Room"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/rooms/active":
			if strings.Contains(r.Header.Get("Authorization"), "blocked") {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":"room-1","title":"Test Room"}]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/rooms/state/"):
			if strings.Contains(r.Header.Get("Authorization"), "blocked") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"type":"state_sync","room_id":"room-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/db-rls-proof":
			_, _ = w.Write([]byte(fullDBRLSProofArtifact()))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner-token", BlockedToken: "blocked-token", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", ReleaseCandidate: "sha-tenant", ServiceVersion: "scriptureforge-api:sha-tenant", LoadRunID: testLoadRunID, Timeout: time.Second}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected accepted tenant override writes to fail threshold:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "blocked-journal-tenant-override-write-denied") || !strings.Contains(output.String(), "blocked-room-tenant-override-write-denied") {
		t.Fatalf("report missing tenant override write-denial probes:\n%s", output.String())
	}
}

func TestRunFailsWhenOwnerListDoesNotReturnCreatedEntry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/journal_entries":
			if rejectPlaintextJournalEnvelopeForTest(w, r) {
				return
			}
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
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/rooms/create":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"room-1","title":"Test Room"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/rooms/active":
			if strings.Contains(r.Header.Get("Authorization"), "blocked") {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":"room-1","title":"Test Room"}]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/rooms/state/"):
			if strings.Contains(r.Header.Get("Authorization"), "blocked") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"type":"state_sync","room_id":"room-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/db-rls-proof":
			_, _ = w.Write([]byte(fullDBRLSProofArtifact()))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner-token", BlockedToken: "blocked-token", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", ReleaseCandidate: "sha-tenant", ServiceVersion: "scriptureforge-api:sha-tenant", LoadRunID: testLoadRunID, Timeout: time.Second}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing owner list visibility to fail threshold:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "owner-list-contains-created-journal") {
		t.Fatalf("report missing owner list probe:\n%s", output.String())
	}
}

func TestRunFailsWhenBlockedTokenCanReadEntry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/rooms/create":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"room-1","title":"Test Room"}`))
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"entry-1","ciphertext":"cipher","iv":"iv","salt_id":"salt","salt_version":1}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries/entry-1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"entry-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/journal_entries":
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/rooms/active":
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/rooms/state/"):
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", ReleaseCandidate: "sha-tenant", ServiceVersion: "scriptureforge-api:sha-tenant", LoadRunID: testLoadRunID, Timeout: time.Second}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected cross-token read to fail threshold:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestOwnerJournalReadRequiresCreatedJournalIDInBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"entry-other"}`))
	}))
	defer server.Close()

	result := getJournalEntry(server.Client(), server.URL, "owner-token", "entry-1", http.StatusOK, "owner-read-created-journal")
	if result.Passed {
		t.Fatalf("owner journal read passed despite mismatched body id: %+v", result)
	}
	if result.JournalID != "entry-1" {
		t.Fatalf("owner journal read did not preserve created journal_id: %+v", result)
	}
}

func TestOwnerRoomStateRequiresCreatedRoomIDInBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"state_sync","room_id":"room-other"}`))
	}))
	defer server.Close()

	result := getRoomState(server.Client(), server.URL, "owner-token", "room-1", "owner-room-state", http.StatusOK)
	if result.Passed {
		t.Fatalf("owner room state passed despite mismatched body room_id: %+v", result)
	}
	if result.RoomID != "room-1" {
		t.Fatalf("owner room state did not preserve created room_id: %+v", result)
	}
}

func TestCreateJournalEntryRejectsPlaintextLeakInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rejectPlaintextJournalEnvelopeForTest(w, r) {
			return
		}
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
			if rejectPlaintextJournalEnvelopeForTest(w, r) {
				return
			}
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
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/rooms/create":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"room-1","title":"Test Room"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/rooms/active":
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/rooms/state/"):
			w.WriteHeader(http.StatusForbidden)
		case r.Method == http.MethodGet && r.URL.Path == "/db-rls-proof":
			_, _ = w.Write([]byte(`current_user=scriptureforge_app row_security on journal_entries`))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(config{
		APIBase:          "https://api-tenant.staging.scriptureforge.ai",
		OwnerToken:       "owner-token",
		BlockedToken:     "blocked-token",
		OwnerOrgID:       testOwnerOrgID,
		BlockedOrgID:     testBlockedOrgID,
		DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof",
		ReleaseCandidate: "sha-tenant",
		ServiceVersion:   "scriptureforge-api:sha-tenant",
		LoadRunID:        testLoadRunID,
		Timeout:          time.Second,
	}, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected weak DB RLS artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "database-rls-context-proof") {
		t.Fatalf("report missing DB RLS proof probe:\n%s", output.String())
	}
}

func TestDBRLSArtifactRejectsLeakedDatabaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fullDBRLSProofArtifact() + ` postgres://scriptureforge_app:secret@example/db`))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite leaked database URL: %+v", result)
	}
}

func TestDBRLSArtifactRejectsMockOnlyProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fullDBRLSProofArtifact() + ` mock placeholder dry-run`))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite mock/placeholder marker: %+v", result)
	}
}

func TestDBRLSArtifactRejectsLocalOnlyProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fullDBRLSProofArtifact() + ` local-only`))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite local-only marker: %+v", result)
	}
}

func TestDBRLSArtifactRequiresEveryTenantScopedTable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.ReplaceAll(fullDBRLSProofArtifact(), "room_participants ", "")))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite missing tenant-scoped table marker: %+v", result)
	}
}

func TestDBRLSArtifactRequiresTableAndForceCounts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker string
	}{
		{name: "table count", marker: "rls_tables_verified=9 "},
		{name: "forced table count", marker: "rls_forced_tables=9 "},
		{name: "policy scope", marker: "rls_policy_scope=app.current_org_id "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(strings.ReplaceAll(fullDBRLSProofArtifact(), tc.marker, "")))
			}))
			defer server.Close()

			result := probeDBRLSArtifactForTest(server.Client(), server.URL)
			if result.Passed {
				t.Fatalf("DB RLS proof passed despite missing %s marker: %+v", tc.marker, result)
			}
		})
	}
}

func TestDBRLSArtifactRequiresReadVisibilityProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.ReplaceAll(fullDBRLSProofArtifact(), "cross-tenant read hidden ", "")))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite missing cross-tenant read visibility marker: %+v", result)
	}
}

func TestDBRLSArtifactRequiresBypassRLSDisabledProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.ReplaceAll(fullDBRLSProofArtifact(), "bypassrls=false ", "")))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite missing bypassrls=false marker: %+v", result)
	}
}

func rejectPlaintextJournalEnvelopeForTest(w http.ResponseWriter, r *http.Request) bool {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	var payload journalPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	if payload.Ciphertext != "Lord, help me" {
		return false
	}
	w.WriteHeader(http.StatusBadRequest)
	return true
}

func TestDBRLSArtifactRequiresRowSecurityOnProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.ReplaceAll(fullDBRLSProofArtifact(), "row_security=on ", "")))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite missing row_security=on marker: %+v", result)
	}
}

func TestDBRLSArtifactRequiresCurrentSettingProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.ReplaceAll(fullDBRLSProofArtifact(), "current_setting('app.current_org_id') ", "")))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite missing current_setting marker: %+v", result)
	}
}

func TestDBRLSArtifactSummarizesVerifiedTenantScopedTables(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fullDBRLSProofArtifact()))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if !result.Passed {
		t.Fatalf("DB RLS proof failed: %+v", result)
	}
	if result.ApplicationRole != "scriptureforge_app" || result.RowSecurity != "on" || result.RLSTablesVerified != 9 || result.RLSForcedTables != 9 || !slices.Equal(result.RLSTableNames, tenantScopedRLSTables) || result.RLSPolicyScope != "app.current_org_id" {
		t.Fatalf("DB RLS proof missing structured fields: %+v", result)
	}
	for _, marker := range []string{
		"staging artifact",
		"current_user=scriptureforge_app",
		"non-superuser",
		"superuser=false",
		"bypassrls=false",
		"app.current_org_id",
		"current_setting('app.current_org_id')",
		"row_security=on",
		"FORCE ROW LEVEL SECURITY",
		"organizations",
		"users",
		"scripture_texts",
		"refresh_tokens",
		"journal_entries",
		"live_rooms",
		"room_participants",
		"ai_request_logs",
		"citation_trails",
		"same-tenant read visible",
		"cross-tenant read hidden",
		"cross-tenant write denied",
		"auth_refresh_session_rls=true",
		"auth_mfa_rls=true",
		"workspace_switch_tenant_match=true",
		"privileged_mfa_enrollment_rls=true",
		"ai_audit_rls=true",
		"generated_curriculum_audit_rls=true",
		"load_run_id=" + testLoadRunID,
	} {
		if !strings.Contains(result.ResultSummary, marker) {
			t.Fatalf("DB RLS proof summary missing marker %q: %s", marker, result.ResultSummary)
		}
	}
}

func TestRunRejectsLocalOrInsecureTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config
		want string
	}{
		{
			name: "insecure API base",
			cfg:  config{APIBase: "http://api.staging.example", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", Timeout: time.Second},
			want: "api-base",
		},
		{
			name: "loopback API base",
			cfg:  config{APIBase: "https://127.0.0.1", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", Timeout: time.Second},
			want: "api-base",
		},
		{
			name: "private API base",
			cfg:  config{APIBase: "https://10.0.0.15", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", Timeout: time.Second},
			want: "api-base",
		},
		{
			name: "IPv4-mapped private API base",
			cfg:  config{APIBase: "https://[::ffff:10.0.0.15]", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", Timeout: time.Second},
			want: "api-base",
		},
		{
			name: "reserved example API base",
			cfg:  config{APIBase: "https://api.staging.example", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", Timeout: time.Second},
			want: "reserved placeholder",
		},
		{
			name: "reserved example.com API base",
			cfg:  config{APIBase: "https://api.example.com", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.scriptureforge.ai/db-rls-proof", Timeout: time.Second},
			want: "reserved placeholder",
		},
		{
			name: "insecure DB RLS artifact",
			cfg:  config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "http://artifacts.staging.example/db-rls-proof", Timeout: time.Second},
			want: "db-rls-artifact-url",
		},
		{
			name: "link-local DB RLS artifact",
			cfg:  config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://169.254.10.20/db-rls-proof", Timeout: time.Second},
			want: "db-rls-artifact-url",
		},
		{
			name: "IPv4-mapped private DB RLS artifact",
			cfg:  config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://[::ffff:10.0.0.20]/db-rls-proof", Timeout: time.Second},
			want: "db-rls-artifact-url",
		},
		{
			name: "unspecified DB RLS artifact",
			cfg:  config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://0.0.0.0/db-rls-proof", Timeout: time.Second},
			want: "db-rls-artifact-url",
		},
		{
			name: "localhost DB RLS artifact",
			cfg:  config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://localhost/db-rls-proof", Timeout: time.Second},
			want: "db-rls-artifact-url",
		},
		{
			name: "reserved test DB RLS artifact",
			cfg:  config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.staging.test/db-rls-proof", Timeout: time.Second},
			want: "reserved placeholder",
		},
		{
			name: "reserved invalid DB RLS artifact",
			cfg:  config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://tenant-artifacts.invalid/db-rls-proof", Timeout: time.Second},
			want: "reserved placeholder",
		},
		{
			name: "DB RLS artifact on API host",
			cfg:  config{APIBase: "https://api-tenant.staging.scriptureforge.ai", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://api-tenant.staging.scriptureforge.ai/db-rls-proof", Timeout: time.Second},
			want: "distinct evidence host from api-base",
		},
		{
			name: "DB RLS artifact on API host alias",
			cfg:  config{APIBase: "https://API-Tenant.Staging.ScriptureForge.AI.", OwnerToken: "owner", BlockedToken: "blocked", OwnerOrgID: testOwnerOrgID, BlockedOrgID: testBlockedOrgID, DBRLSArtifactURL: "https://api-tenant.staging.scriptureforge.ai./db-rls-proof", Timeout: time.Second},
			want: "distinct evidence host from api-base",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := runWithClient(tc.cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q URL validation error, got %v", tc.want, err)
			}
		})
	}
}

func TestDBRLSProofRequiresApplicationRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.ReplaceAll(fullDBRLSProofArtifact(), "current_user=scriptureforge_app", "current_user")))
	}))
	defer server.Close()

	result := probeDBRLSArtifactForTest(server.Client(), server.URL)
	if result.Passed {
		t.Fatalf("DB RLS proof passed despite missing application role marker: %+v", result)
	}
	if !strings.Contains(result.ResultSummary, "current_user=scriptureforge_app") {
		t.Fatalf("failure summary should name missing application role marker: %s", result.ResultSummary)
	}
}

func TestDBRLSProofRequiresAuthAndAIAuditSemanticMarkers(t *testing.T) {
	for _, marker := range []string{
		"auth_refresh_session_rls=true ",
		"auth_mfa_rls=true ",
		"workspace_switch_tenant_match=true ",
		"privileged_mfa_enrollment_rls=true ",
		"ai_audit_rls=true ",
		"generated_curriculum_audit_rls=true ",
	} {
		t.Run(strings.TrimSpace(marker), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.ReplaceAll(fullDBRLSProofArtifact(), marker, "")))
			}))
			defer server.Close()

			result := probeDBRLSArtifactForTest(server.Client(), server.URL)
			if result.Passed {
				t.Fatalf("DB RLS proof passed despite missing semantic marker %q: %+v", marker, result)
			}
		})
	}
}

func fullDBRLSProofArtifact() string {
	return `staging artifact current_user=scriptureforge_app non-superuser superuser=false bypassrls=false app.current_org_id set app.current_org_id=` + testOwnerOrgID + ` current_setting('app.current_org_id') blocked_org_id=` + testBlockedOrgID + ` row_security=on FORCE ROW LEVEL SECURITY rls_tables_verified=9 rls_forced_tables=9 rls_policy_scope=app.current_org_id organizations users scripture_texts refresh_tokens journal_entries live_rooms room_participants ai_request_logs citation_trails same-tenant read visible cross-tenant read hidden cross-tenant write denied auth_refresh_session_rls=true auth_mfa_rls=true workspace_switch_tenant_match=true privileged_mfa_enrollment_rls=true ai_audit_rls=true generated_curriculum_audit_rls=true release_candidate=sha-tenant service_version=scriptureforge-api:sha-tenant load_run_id=` + testLoadRunID
}

func probeDBRLSArtifactForTest(client *http.Client, target string) probeResult {
	return probeDBRLSArtifact(client, target, "sha-tenant", "scriptureforge-api:sha-tenant", testLoadRunID, testOwnerOrgID, testBlockedOrgID)
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
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
