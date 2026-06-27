package ports

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
)

const (
	tenantIsolationOrgA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tenantIsolationOrgB    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	tenantIsolationUserA   = "11111111-1111-4111-8111-111111111111"
	tenantIsolationUserB   = "22222222-2222-4222-8222-222222222222"
	tenantIsolationRLSRole = "scriptureforge_rls_test"
)

func openTenantIsolationDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" || strings.Contains(databaseURL, "${") {
		t.Skip("DATABASE_URL is required for tenant isolation Postgres/RLS proof")
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
	ensureTenantIsolationRLSRole(ctx, t, db)
	t.Cleanup(db.Close)
	return db
}

func ensureTenantIsolationRLSRole(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	var isSuperuser bool
	if err := db.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuperuser); err != nil {
		t.Fatalf("check current user role: %v", err)
	}
	if !isSuperuser {
		return
	}
	if _, err := db.Exec(ctx, `SELECT pg_advisory_lock(774412)`); err != nil {
		t.Fatalf("lock tenant isolation RLS test role setup: %v", err)
	}
	defer func() {
		if _, err := db.Exec(ctx, `SELECT pg_advisory_unlock(774412)`); err != nil {
			t.Fatalf("unlock tenant isolation RLS test role setup: %v", err)
		}
	}()
	if _, err := db.Exec(ctx, `
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
		t.Fatalf("ensure tenant isolation RLS test role: %v", err)
	}
}

func withTenantIsolationContext(ctx context.Context, t *testing.T, db *pgxpool.Pool, orgID string, fn func(context.Context, pgx.Tx)) {
	t.Helper()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tenant tx: %v", err)
	}
	defer tx.Rollback(ctx)
	if err := auth.SetTenantContext(ctx, tx, orgID); err != nil {
		t.Fatalf("set tenant context %s: %v", orgID, err)
	}
	var isSuperuser bool
	if err := tx.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuperuser); err != nil {
		t.Fatalf("check tenant tx role: %v", err)
	}
	if isSuperuser {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+tenantIsolationRLSRole); err != nil {
			t.Fatalf("set local tenant isolation RLS role: %v", err)
		}
	}
	fn(ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tenant tx %s: %v", orgID, err)
	}
}

func seedTenantIsolationFixtures(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgA, func(ctx context.Context, tx pgx.Tx) {
		_, _ = tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, tenantIsolationOrgA)
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'Tenant Isolation A')`, tenantIsolationOrgA)
		if err != nil {
			t.Fatalf("seed tenant A org: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'tenant-a@example.test', 'hash', 'member')`, tenantIsolationUserA, tenantIsolationOrgA); err != nil {
			t.Fatalf("seed tenant A user: %v", err)
		}
	})
	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgB, func(ctx context.Context, tx pgx.Tx) {
		_, _ = tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, tenantIsolationOrgB)
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'Tenant Isolation B')`, tenantIsolationOrgB)
		if err != nil {
			t.Fatalf("seed tenant B org: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'tenant-b@example.test', 'hash', 'member')`, tenantIsolationUserB, tenantIsolationOrgB); err != nil {
			t.Fatalf("seed tenant B user: %v", err)
		}
	})
}

func cleanupTenantIsolationFixtures(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	for _, orgID := range []string{tenantIsolationOrgA, tenantIsolationOrgB} {
		withTenantIsolationContext(ctx, t, db, orgID, func(ctx context.Context, tx pgx.Tx) {
			_, _ = tx.Exec(ctx, `DELETE FROM users WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)
		})
	}
}

func TestJournalHandlersHonorTenantIsolation(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantIsolationFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantIsolationFixtures(cleanupCtx, t, db)
	})

	journal := &JournalHandler{DB: db}
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/journal_entries", strings.NewReader(`{"ciphertext":"tenant-a-payload","iv":"tenant-a-iv","salt_id":"tenant-a-salt","salt_version":1}`))
	createReq = createReq.WithContext(context.WithValue(createReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgA,
		Role:           "member",
	}))
	createRec := httptest.NewRecorder()
	journal.ServeJournalEntries(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("tenant A journal create status = %d body = %s", createRec.Code, createRec.Body.String())
	}
	var created JournalPayload
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode tenant A journal create response: %v", err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/journal_entries/"+created.ID, nil)
	getReq = getReq.WithContext(context.WithValue(getReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserB,
		OrganizationID: tenantIsolationOrgB,
		Role:           "member",
	}))
	getRec := httptest.NewRecorder()
	journal.ServeJournalEntry(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("tenant B direct read cross-tenant status = %d body = %s", getRec.Code, getRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/journal_entries", nil)
	listReq = listReq.WithContext(context.WithValue(listReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserB,
		OrganizationID: tenantIsolationOrgB,
		Role:           "member",
	}))
	listRec := httptest.NewRecorder()
	journal.ServeJournalEntries(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("tenant B list status = %d body = %s", listRec.Code, listRec.Body.String())
	}
	var blockedEntries []JournalPayload
	if err := json.Unmarshal(listRec.Body.Bytes(), &blockedEntries); err != nil {
		t.Fatalf("decode tenant B journal list: %v", err)
	}
	if len(blockedEntries) != 0 {
		t.Fatalf("tenant B can read entries from another tenant: %+v", blockedEntries)
	}

	ownerListReq := httptest.NewRequest(http.MethodGet, "/api/v1/journal_entries", nil)
	ownerListReq = ownerListReq.WithContext(context.WithValue(ownerListReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgA,
		Role:           "member",
	}))
	ownerListRec := httptest.NewRecorder()
	journal.ServeJournalEntries(ownerListRec, ownerListReq)
	if ownerListRec.Code != http.StatusOK {
		t.Fatalf("tenant A list status = %d body = %s", ownerListRec.Code, ownerListRec.Body.String())
	}
	var ownerEntries []JournalPayload
	if err := json.Unmarshal(ownerListRec.Body.Bytes(), &ownerEntries); err != nil {
		t.Fatalf("decode tenant A journal list: %v", err)
	}
	if len(ownerEntries) != 1 || ownerEntries[0].ID != created.ID {
		t.Fatalf("tenant A list expected one matching entry, got %#v", ownerEntries)
	}
	assertCrossTenantWriteBlocked(t, ctx, db, tenantIsolationOrgA, tenantIsolationOrgB, tenantIsolationUserB)
}

func TestRoomHandlersHonorTenantIsolation(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantIsolationFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantIsolationFixtures(cleanupCtx, t, db)
	})

	roomState := &tenantIsolationStateStore{}
	roomHandler := &RoomHandler{
		DB:           db,
		StateManager: roomState,
	}
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/create", strings.NewReader(`{"title":"Tenant Isolation Room"}`))
	createReq = createReq.WithContext(context.WithValue(createReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgA,
		Role:           "member",
	}))
	createRec := httptest.NewRecorder()
	roomHandler.CreateRoomHandler(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("tenant A room create status = %d body = %s", createRec.Code, createRec.Body.String())
	}
	var created RoomResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode room create response: %v", err)
	}

	blockedActiveReq := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/active", nil)
	blockedActiveReq = blockedActiveReq.WithContext(context.WithValue(blockedActiveReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserB,
		OrganizationID: tenantIsolationOrgB,
		Role:           "member",
	}))
	blockedActiveRec := httptest.NewRecorder()
	roomHandler.ActiveRoomsHandler(blockedActiveRec, blockedActiveReq)
	if blockedActiveRec.Code != http.StatusOK {
		t.Fatalf("tenant B active rooms status = %d body = %s", blockedActiveRec.Code, blockedActiveRec.Body.String())
	}
	var blockedRooms []RoomResponse
	if err := json.Unmarshal(blockedActiveRec.Body.Bytes(), &blockedRooms); err != nil {
		t.Fatalf("decode tenant B active rooms: %v", err)
	}
	if len(blockedRooms) != 0 {
		t.Fatalf("tenant B can see room from another tenant: %#v", blockedRooms)
	}

	ownerActiveReq := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/active", nil)
	ownerActiveReq = ownerActiveReq.WithContext(context.WithValue(ownerActiveReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgA,
		Role:           "member",
	}))
	ownerActiveRec := httptest.NewRecorder()
	roomHandler.ActiveRoomsHandler(ownerActiveRec, ownerActiveReq)
	if ownerActiveRec.Code != http.StatusOK {
		t.Fatalf("tenant A active rooms status = %d body = %s", ownerActiveRec.Code, ownerActiveRec.Body.String())
	}
	var ownerRooms []RoomResponse
	if err := json.Unmarshal(ownerActiveRec.Body.Bytes(), &ownerRooms); err != nil {
		t.Fatalf("decode tenant A active rooms: %v", err)
	}
	if len(ownerRooms) != 1 || ownerRooms[0].ID != created.ID {
		t.Fatalf("tenant A active rooms expected one matching room, got %#v", ownerRooms)
	}

	blockedStateReq := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/state/"+created.ID, nil)
	blockedStateReq = blockedStateReq.WithContext(context.WithValue(blockedStateReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserB,
		OrganizationID: tenantIsolationOrgB,
		Role:           "member",
	}))
	blockedStateRec := httptest.NewRecorder()
	roomHandler.RoomStateHandler(blockedStateRec, blockedStateReq)
	if blockedStateRec.Code != http.StatusForbidden {
		t.Fatalf("tenant B room state status = %d body = %s", blockedStateRec.Code, blockedStateRec.Body.String())
	}

	ownerStateReq := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/state/"+created.ID, nil)
	ownerStateReq = ownerStateReq.WithContext(context.WithValue(ownerStateReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgA,
		Role:           "member",
	}))
	ownerStateRec := httptest.NewRecorder()
	roomHandler.RoomStateHandler(ownerStateRec, ownerStateReq)
	if ownerStateRec.Code != http.StatusOK {
		t.Fatalf("tenant A room state status = %d body = %s", ownerStateRec.Code, ownerStateRec.Body.String())
	}
}

func TestSocketStreamIsTenantScoped(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantIsolationFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantIsolationFixtures(cleanupCtx, t, db)
	})

	var roomID string
	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgA, func(ctx context.Context, tx pgx.Tx) {
		if err := tx.QueryRow(
			ctx,
			`INSERT INTO live_rooms (organization_id, host_user_id, title, meeting_provider, meeting_metadata)
			 VALUES ($1, $2, $3, 'offline', '{"mode":"offline"}'::jsonb)
			 RETURNING id`,
			tenantIsolationOrgA,
			tenantIsolationUserA,
			"Tenant Stream Room",
		).Scan(&roomID); err != nil {
			t.Fatalf("seed tenant A room: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO room_participants (organization_id, room_id, user_id) VALUES ($1, $2, $3)`, tenantIsolationOrgA, roomID, tenantIsolationUserA); err != nil {
			t.Fatalf("seed tenant A room participant: %v", err)
		}
	})

	store := &fakeRoomEventStore{}
	socket := &SocketConnection{
		DB:           db,
		StateManager: store,
		Hub:          NewRoomHub(),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.URL.Query().Get("tenant")
		user := r.URL.Query().Get("user")
		var claims *auth.TokenClaims
		switch tenant {
		case "tenant-a":
			claims = &auth.TokenClaims{UserID: user, OrganizationID: tenantIsolationOrgA, Role: "member"}
		case "tenant-b":
			claims = &auth.TokenClaims{UserID: user, OrganizationID: tenantIsolationOrgB, Role: "member"}
		default:
			claims = &auth.TokenClaims{UserID: user, OrganizationID: "unknown", Role: "member"}
		}
		socket.HandleLiveRoom(w, r.WithContext(context.WithValue(r.Context(), auth.ContextKeyUser, claims)))
	}))
	defer server.Close()

	wsForTenantA := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/" + roomID + "?tenant=tenant-a&client=a"
	tenantAConn, _, err := websocket.DefaultDialer.Dial(wsForTenantA, nil)
	if err != nil {
		t.Fatalf("tenant A socket dial should succeed: %v", err)
	}
	if err := tenantAConn.Close(); err != nil {
		t.Fatalf("close tenant A socket: %v", err)
	}

	wsForTenantB := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/" + roomID + "?tenant=tenant-b&client=b"
	tenantBConn, response, err := websocket.DefaultDialer.Dial(wsForTenantB, nil)
	if err == nil {
		_ = tenantBConn.Close()
		t.Fatal("cross-tenant socket dial expected to fail")
	}
	if response != nil && response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-tenant socket status = %d", response.StatusCode)
	}

	if got := store.appendCount(); got != 0 {
		t.Fatalf("tenant B event append count = %d, want 0", got)
	}
}

type tenantIsolationStateStore struct{}

func (tenantIsolationStateStore) SetRoomActiveState(context.Context, string, bool) error { return nil }

func (tenantIsolationStateStore) GetLatestRoomEvent(_ context.Context, roomID string) (string, error) {
	return `{"type":"state_sync","room_id":"` + roomID + `"}`, nil
}

func assertCrossTenantWriteBlocked(t *testing.T, ctx context.Context, db *pgxpool.Pool, ownerOrg string, foreignOrg string, foreignUser string) {
	t.Helper()
	withTenantIsolationContext(ctx, t, db, foreignOrg, func(ctx context.Context, tx pgx.Tx) {
		var countBefore int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM journal_entries WHERE organization_id = $1`, ownerOrg).Scan(&countBefore); err != nil {
			t.Fatalf("check owner tenant journal baseline: %v", err)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO journal_entries (organization_id, user_id, ciphertext, iv, salt_id, salt_version)
			VALUES ($1, $2, 'cross-tenant-payload', 'cross-tenant-iv', 'cross-tenant-salt', 1)`,
			ownerOrg,
			foreignUser,
		)
		if err == nil {
			t.Fatalf("cross-tenant write unexpectedly succeeded while tenant context was %s", foreignOrg)
		}
		var countAfter int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM journal_entries WHERE organization_id = $1`, ownerOrg).Scan(&countAfter); err != nil {
			t.Fatalf("check owner tenant journal after write attempt: %v", err)
		}
		if countAfter != countBefore {
			t.Fatalf("cross-tenant write changed owner data row count: before=%d after=%d", countBefore, countAfter)
		}
	})
}
