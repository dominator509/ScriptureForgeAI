package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/ports"
)

const (
	tenantOrgA    = "11111111-1111-4111-8111-111111111111"
	tenantOrgB    = "22222222-2222-4222-8222-222222222222"
	tenantUserA   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tenantUserB   = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	tenantUserC   = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	tenantRoomA   = "33333333-3333-4333-8333-333333333333"
	tenantRoomB   = "44444444-4444-4444-8444-444444444444"
	tenantRLSRole = "scriptureforge_rls_test"
)

func openTenantIsolationDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" || strings.Contains(databaseURL, "${") {
		if os.Getenv("REQUIRE_DATABASE_URL") == "true" {
			t.Fatal("DATABASE_URL is required when REQUIRE_DATABASE_URL=true for handler-level Postgres/RLS tenant isolation proof")
		}
		t.Skip("DATABASE_URL is required for handler-level Postgres/RLS tenant isolation proof")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("create db pool: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		t.Fatalf("ping db: %v", err)
	}
	ensureTenantRLSRole(ctx, t, db)
	t.Cleanup(db.Close)
	return db
}

func ensureTenantRLSRole(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	var isSuperuser bool
	if err := db.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuperuser); err != nil {
		t.Fatalf("check current user role: %v", err)
	}
	if !isSuperuser {
		return
	}
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire RLS test role setup connection: %v", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin RLS test role setup: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(774411)`); err != nil {
		t.Fatalf("lock RLS test role setup: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scriptureforge_rls_test') THEN
				CREATE ROLE scriptureforge_rls_test;
			END IF;
		END $$;
		GRANT USAGE ON SCHEMA public TO scriptureforge_rls_test;
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO scriptureforge_rls_test;
		GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO scriptureforge_rls_test;
	`); err != nil {
		t.Fatalf("ensure RLS test role: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit RLS test role setup: %v", err)
	}
}

func setTenantForTest(ctx context.Context, t *testing.T, db *pgxpool.Pool, orgID string, fn func(context.Context, pgx.Tx)) {
	t.Helper()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tenant transaction: %v", err)
	}
	defer tx.Rollback(ctx)
	if err := auth.SetTenantContext(ctx, tx, orgID); err != nil {
		t.Fatalf("set tenant context %s: %v", orgID, err)
	}
	var isSuperuser bool
	if err := tx.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuperuser); err != nil {
		t.Fatalf("check tenant transaction role: %v", err)
	}
	if isSuperuser {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE scriptureforge_rls_test`); err != nil {
			t.Fatalf("set local RLS test role: %v", err)
		}
	}
	fn(ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tenant transaction %s: %v", orgID, err)
	}
}

func cleanupTenantFixtures(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	for _, orgID := range []string{tenantOrgA, tenantOrgB} {
		setTenantForTest(ctx, t, db, orgID, func(ctx context.Context, tx pgx.Tx) {
			if _, err := tx.Exec(ctx, `DELETE FROM citation_trails WHERE organization_id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s citation trails: %v", orgID, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM ai_request_logs WHERE organization_id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s ai request logs: %v", orgID, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM room_participants WHERE organization_id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s room participants: %v", orgID, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM live_rooms WHERE organization_id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s live rooms: %v", orgID, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM journal_entries WHERE organization_id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s journal entries: %v", orgID, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE organization_id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s refresh tokens: %v", orgID, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM scripture_texts WHERE organization_id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s scripture texts: %v", orgID, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM users WHERE organization_id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s users: %v", orgID, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID); err != nil {
				t.Fatalf("cleanup tenant %s: %v", orgID, err)
			}
		})
	}
}

func seedTenantFixtures(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	cleanupTenantFixtures(ctx, t, db)

	setTenantForTest(ctx, t, db, tenantOrgA, func(ctx context.Context, tx pgx.Tx) {
		mustExecTenant(t, ctx, tx, `INSERT INTO organizations (id, name) VALUES ($1, 'Tenant A')`, tenantOrgA)
		mustExecTenant(t, ctx, tx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'tenant-a@example.test', 'hash', 'member')`, tenantUserA, tenantOrgA)
		mustExecTenant(t, ctx, tx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'tenant-a-peer@example.test', 'hash', 'member')`, tenantUserC, tenantOrgA)
		mustExecTenant(t, ctx, tx, `INSERT INTO live_rooms (id, organization_id, host_user_id, title) VALUES ($1, $2, $3, 'Tenant A Room')`, tenantRoomA, tenantOrgA, tenantUserA)
		mustExecTenant(t, ctx, tx, `INSERT INTO room_participants (organization_id, room_id, user_id) VALUES ($1, $2, $3)`, tenantOrgA, tenantRoomA, tenantUserA)
	})

	setTenantForTest(ctx, t, db, tenantOrgB, func(ctx context.Context, tx pgx.Tx) {
		mustExecTenant(t, ctx, tx, `INSERT INTO organizations (id, name) VALUES ($1, 'Tenant B')`, tenantOrgB)
		mustExecTenant(t, ctx, tx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'tenant-b@example.test', 'hash', 'member')`, tenantUserB, tenantOrgB)
		mustExecTenant(t, ctx, tx, `INSERT INTO live_rooms (id, organization_id, host_user_id, title) VALUES ($1, $2, $3, 'Tenant B Room')`, tenantRoomB, tenantOrgB, tenantUserB)
		mustExecTenant(t, ctx, tx, `INSERT INTO room_participants (organization_id, room_id, user_id) VALUES ($1, $2, $3)`, tenantOrgB, tenantRoomB, tenantUserB)
	})
}

func mustExecTenant(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("seed tenant fixture: %v", err)
	}
}

func requestWithClaims(method, target string, body []byte, userID, orgID string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         userID,
		OrganizationID: orgID,
		Role:           "member",
	}))
}

func TestTenantScopedJournalHandlersEnforceRLS(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantFixtures(cleanupCtx, t, db)
	})

	handler := &ports.JournalHandler{DB: db}
	payload := []byte(`{"ciphertext":"c2VhbGVkLWNpcGhlcnRleHQtYmxvYg==","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:test-a","salt_version":1}`)

	plaintextPayload := []byte(`{"ciphertext":"c2VhbGVkLWNpcGhlcnRleHQtYmxvYg==","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:test-a","salt_version":1,"plaintext":"Lord, help me","passphrase":"do-not-store"}`)
	plaintextRecorder := httptest.NewRecorder()
	handler.ServeJournalEntries(plaintextRecorder, requestWithClaims(http.MethodPost, "/api/v1/journal_entries", plaintextPayload, tenantUserA, tenantOrgA))
	if plaintextRecorder.Code != http.StatusBadRequest {
		t.Fatalf("plaintext journal payload status = %d body = %s, want 400", plaintextRecorder.Code, plaintextRecorder.Body.String())
	}

	plaintextCiphertextPayload := []byte(`{"ciphertext":"Lord, help me","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:test-a","salt_version":1}`)
	plaintextCiphertextRecorder := httptest.NewRecorder()
	handler.ServeJournalEntries(plaintextCiphertextRecorder, requestWithClaims(http.MethodPost, "/api/v1/journal_entries", plaintextCiphertextPayload, tenantUserA, tenantOrgA))
	if plaintextCiphertextRecorder.Code != http.StatusBadRequest {
		t.Fatalf("plaintext ciphertext journal payload status = %d body = %s, want 400", plaintextCiphertextRecorder.Code, plaintextCiphertextRecorder.Body.String())
	}
	setTenantForTest(ctx, t, db, tenantOrgA, func(ctx context.Context, tx pgx.Tx) {
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM journal_entries WHERE organization_id = $1 AND user_id = $2`, tenantOrgA, tenantUserA).Scan(&count); err != nil {
			t.Fatalf("count journals after plaintext rejection: %v", err)
		}
		if count != 0 {
			t.Fatalf("plaintext journal payload persisted %d rows, want 0", count)
		}
	})

	createRecorder := httptest.NewRecorder()
	handler.ServeJournalEntries(createRecorder, requestWithClaims(http.MethodPost, "/api/v1/journal_entries", payload, tenantUserA, tenantOrgA))
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("same-tenant journal create status = %d body = %s", createRecorder.Code, createRecorder.Body.String())
	}
	var created ports.JournalPayload
	if err := json.NewDecoder(createRecorder.Body).Decode(&created); err != nil {
		t.Fatalf("decode created journal entry: %v", err)
	}
	if created.ID == "" {
		t.Fatal("same-tenant journal create did not return an id")
	}
	if strings.Contains(createRecorder.Body.String(), "Lord, help me") || strings.Contains(createRecorder.Body.String(), "do-not-store") {
		t.Fatalf("journal create response leaked plaintext material: %s", createRecorder.Body.String())
	}
	setTenantForTest(ctx, t, db, tenantOrgA, func(ctx context.Context, tx pgx.Tx) {
		var leakedCount int
		if err := tx.QueryRow(
			ctx,
			`SELECT COUNT(*)
			 FROM journal_entries
			 WHERE organization_id = $1
			   AND user_id = $2
			   AND (ciphertext ILIKE '%Lord, help me%' OR ciphertext ILIKE '%do-not-store%' OR iv ILIKE '%Lord, help me%' OR salt_id ILIKE '%do-not-store%')`,
			tenantOrgA,
			tenantUserA,
		).Scan(&leakedCount); err != nil {
			t.Fatalf("query plaintext leak markers: %v", err)
		}
		if leakedCount != 0 {
			t.Fatalf("journal table contains plaintext leak markers in %d rows", leakedCount)
		}
	})

	listRecorder := httptest.NewRecorder()
	handler.ServeJournalEntries(listRecorder, requestWithClaims(http.MethodGet, "/api/v1/journal_entries", nil, tenantUserA, tenantOrgA))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("same-tenant journal list status = %d body = %s", listRecorder.Code, listRecorder.Body.String())
	}
	var entries []ports.JournalPayload
	if err := json.NewDecoder(listRecorder.Body).Decode(&entries); err != nil {
		t.Fatalf("decode same-tenant journal list: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != created.ID {
		t.Fatalf("same-tenant journal list = %#v, want only %s", entries, created.ID)
	}

	crossUserRecorder := httptest.NewRecorder()
	handler.ServeJournalEntry(crossUserRecorder, requestWithClaims(http.MethodGet, "/api/v1/journal_entries/"+created.ID, nil, tenantUserC, tenantOrgA))
	if crossUserRecorder.Code != http.StatusNotFound {
		t.Fatalf("same-tenant different-user read status = %d, want 404", crossUserRecorder.Code)
	}

	crossTenantRecorder := httptest.NewRecorder()
	handler.ServeJournalEntry(crossTenantRecorder, requestWithClaims(http.MethodGet, "/api/v1/journal_entries/"+created.ID, nil, tenantUserB, tenantOrgB))
	if crossTenantRecorder.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant journal read status = %d, want 404", crossTenantRecorder.Code)
	}

	mismatchedClaimRecorder := httptest.NewRecorder()
	handler.ServeJournalEntries(mismatchedClaimRecorder, requestWithClaims(http.MethodPost, "/api/v1/journal_entries", payload, tenantUserA, tenantOrgB))
	if mismatchedClaimRecorder.Code == http.StatusCreated {
		t.Fatal("mismatched tenant/user claims created a cross-tenant journal entry")
	}
	setTenantForTest(ctx, t, db, tenantOrgA, func(ctx context.Context, tx pgx.Tx) {
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM journal_entries WHERE organization_id = $1 AND salt_id = 'journal:v1:test-a'`, tenantOrgA).Scan(&count); err != nil {
			t.Fatalf("count tenant A journals after mismatched create: %v", err)
		}
		if count != 1 {
			t.Fatalf("tenant A journal count after mismatched create = %d, want original one row", count)
		}
	})
	setTenantForTest(ctx, t, db, tenantOrgB, func(ctx context.Context, tx pgx.Tx) {
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM journal_entries WHERE organization_id = $1 AND salt_id = 'journal:v1:test-a'`, tenantOrgB).Scan(&count); err != nil {
			t.Fatalf("count tenant B journals after mismatched create: %v", err)
		}
		if count != 0 {
			t.Fatalf("mismatched tenant/user journal create persisted %d tenant B rows, want 0", count)
		}
	})
}

func TestTenantScopedRoomActiveHandlerEnforcesRLS(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantFixtures(cleanupCtx, t, db)
	})

	handler := &ports.RoomHandler{DB: db}

	orgARecorder := httptest.NewRecorder()
	handler.ActiveRoomsHandler(orgARecorder, requestWithClaims(http.MethodGet, "/api/v1/rooms/active", nil, tenantUserA, tenantOrgA))
	if orgARecorder.Code != http.StatusOK {
		t.Fatalf("tenant A active rooms status = %d body = %s", orgARecorder.Code, orgARecorder.Body.String())
	}
	var orgARooms []ports.RoomResponse
	if err := json.NewDecoder(orgARecorder.Body).Decode(&orgARooms); err != nil {
		t.Fatalf("decode tenant A rooms: %v", err)
	}
	if len(orgARooms) != 1 || orgARooms[0].ID != tenantRoomA {
		t.Fatalf("tenant A rooms = %#v, want only %s", orgARooms, tenantRoomA)
	}

	orgBRecorder := httptest.NewRecorder()
	handler.ActiveRoomsHandler(orgBRecorder, requestWithClaims(http.MethodGet, "/api/v1/rooms/active", nil, tenantUserB, tenantOrgB))
	if orgBRecorder.Code != http.StatusOK {
		t.Fatalf("tenant B active rooms status = %d body = %s", orgBRecorder.Code, orgBRecorder.Body.String())
	}
	var orgBRooms []ports.RoomResponse
	if err := json.NewDecoder(orgBRecorder.Body).Decode(&orgBRooms); err != nil {
		t.Fatalf("decode tenant B rooms: %v", err)
	}
	if len(orgBRooms) != 1 || orgBRooms[0].ID != tenantRoomB {
		t.Fatalf("tenant B rooms = %#v, want only %s", orgBRooms, tenantRoomB)
	}

	mismatchedRecorder := httptest.NewRecorder()
	handler.ActiveRoomsHandler(mismatchedRecorder, requestWithClaims(http.MethodGet, "/api/v1/rooms/active", nil, tenantUserA, tenantOrgB))
	if mismatchedRecorder.Code != http.StatusOK {
		t.Fatalf("mismatched tenant/user active rooms status = %d body = %s", mismatchedRecorder.Code, mismatchedRecorder.Body.String())
	}
	var mismatchedRooms []ports.RoomResponse
	if err := json.NewDecoder(mismatchedRecorder.Body).Decode(&mismatchedRooms); err != nil {
		t.Fatalf("decode mismatched rooms: %v", err)
	}
	if len(mismatchedRooms) != 0 {
		t.Fatalf("mismatched tenant/user rooms = %#v, want none", mismatchedRooms)
	}
}

func TestTenantScopedRoomStateHandlerEnforcesRLS(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantFixtures(cleanupCtx, t, db)
	})

	stateStore := &tenantRoomStateStore{}
	handler := &ports.RoomHandler{
		DB:           db,
		StateManager: stateStore,
	}

	crossTenantRecorder := httptest.NewRecorder()
	handler.RoomStateHandler(crossTenantRecorder, requestWithClaims(http.MethodGet, "/api/v1/rooms/state/"+tenantRoomA, nil, tenantUserB, tenantOrgB))
	if crossTenantRecorder.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant room state status = %d body = %s, want 403", crossTenantRecorder.Code, crossTenantRecorder.Body.String())
	}
	if stateStore.calls != 0 {
		t.Fatalf("cross-tenant room state reached polling store %d times, want 0", stateStore.calls)
	}

	sameTenantRecorder := httptest.NewRecorder()
	handler.RoomStateHandler(sameTenantRecorder, requestWithClaims(http.MethodGet, "/api/v1/rooms/state/"+tenantRoomA, nil, tenantUserA, tenantOrgA))
	if sameTenantRecorder.Code != http.StatusOK {
		t.Fatalf("same-tenant room state status = %d body = %s, want 200", sameTenantRecorder.Code, sameTenantRecorder.Body.String())
	}
	if stateStore.calls != 1 {
		t.Fatalf("same-tenant room state polling store calls = %d, want 1", stateStore.calls)
	}
	if body := sameTenantRecorder.Body.String(); !strings.Contains(body, tenantRoomA) || strings.Contains(body, tenantRoomB) {
		t.Fatalf("same-tenant room state body = %s, want only tenant A room id", body)
	}
}

type tenantRoomStateStore struct {
	calls int
}

func (s *tenantRoomStateStore) SetRoomActiveState(context.Context, string, bool) error {
	return nil
}

func (s *tenantRoomStateStore) GetLatestRoomEvent(_ context.Context, roomID string) (string, error) {
	s.calls++
	return `{"type":"state_sync","room_id":"` + roomID + `"}`, nil
}
