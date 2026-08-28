package ports

import (
	"context"
	"encoding/json"
	"errors"
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
	"scriptureforge/internal/domain/observability"
	"scriptureforge/internal/domain/room"
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
		if os.Getenv("REQUIRE_DATABASE_URL") == "true" {
			t.Fatal("DATABASE_URL is required when REQUIRE_DATABASE_URL=true for tenant isolation Postgres/RLS proof")
		}
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
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire tenant isolation RLS test role setup connection: %v", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tenant isolation RLS test role setup: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(774411)`); err != nil {
		t.Fatalf("lock tenant isolation RLS test role setup: %v", err)
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
		t.Fatalf("ensure tenant isolation RLS test role: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tenant isolation RLS test role setup: %v", err)
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
	cleanupTenantIsolationFixtures(ctx, t, db)

	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgA, func(ctx context.Context, tx pgx.Tx) {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'Tenant Isolation A')`, tenantIsolationOrgA)
		if err != nil {
			t.Fatalf("seed tenant A org: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'tenant-isolation-a@example.test', 'hash', 'member')`, tenantIsolationUserA, tenantIsolationOrgA); err != nil {
			t.Fatalf("seed tenant A user: %v", err)
		}
	})
	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgB, func(ctx context.Context, tx pgx.Tx) {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'Tenant Isolation B')`, tenantIsolationOrgB)
		if err != nil {
			t.Fatalf("seed tenant B org: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'tenant-isolation-b@example.test', 'hash', 'member')`, tenantIsolationUserB, tenantIsolationOrgB); err != nil {
			t.Fatalf("seed tenant B user: %v", err)
		}
	})
}

func cleanupTenantIsolationFixtures(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	for _, orgID := range []string{tenantIsolationOrgA, tenantIsolationOrgB} {
		withTenantIsolationContext(ctx, t, db, orgID, func(ctx context.Context, tx pgx.Tx) {
			_, _ = tx.Exec(ctx, `DELETE FROM citation_trails WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM ai_request_logs WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM room_participants WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM live_rooms WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM journal_entries WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM scripture_texts WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM users WHERE organization_id = $1`, orgID)
			_, _ = tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)
		})
	}
}

func TestJournalHandlersHonorTenantIsolation(t *testing.T) {
	t.Setenv("JOURNAL_SALT_SECRET", "tenant-journal-salt-secret-0123456789")
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
	observer := observability.NewObserver(observability.Options{})
	ownerClaims := &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgA,
		Role:           "member",
	}
	bootstrapReq := httptest.NewRequest(http.MethodGet, "/api/v1/journal/bootstrap", nil)
	bootstrapReq = bootstrapReq.WithContext(context.WithValue(bootstrapReq.Context(), auth.ContextKeyUser, ownerClaims))
	bootstrapRec := httptest.NewRecorder()
	journal.ServeJournalBootstrap(bootstrapRec, bootstrapReq)
	if bootstrapRec.Code != http.StatusOK {
		t.Fatalf("tenant A journal bootstrap status = %d body = %s", bootstrapRec.Code, bootstrapRec.Body.String())
	}
	var bootstrap JournalBootstrapResponse
	if err := json.Unmarshal(bootstrapRec.Body.Bytes(), &bootstrap); err != nil {
		t.Fatalf("decode tenant A journal bootstrap: %v", err)
	}
	createPayload, err := json.Marshal(JournalPayload{
		Ciphertext:  "dGVuYW50LWEtc2VhbGVkLXBheWxvYWQ=",
		IV:          "AQIDBAUGBwgJCgsM",
		SaltID:      bootstrap.SaltID,
		SaltVersion: bootstrap.SaltVersion,
	})
	if err != nil {
		t.Fatalf("encode tenant A journal payload: %v", err)
	}
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/journal_entries", strings.NewReader(string(createPayload)))
	createReq = createReq.WithContext(context.WithValue(createReq.Context(), auth.ContextKeyUser, ownerClaims))
	createReq = createReq.WithContext(observability.WithObserver(createReq.Context(), observer))
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
	getReq = getReq.WithContext(observability.WithObserver(getReq.Context(), observer))
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
	listReq = listReq.WithContext(observability.WithObserver(listReq.Context(), observer))
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
	ownerListReq = ownerListReq.WithContext(observability.WithObserver(ownerListReq.Context(), observer))
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
	metrics := observer.Snapshot()
	for _, expected := range []string{
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="journal_create",status="success"} 1`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="journal_read",status="not_found"} 1`,
		`scriptureforge_dependency_operations_total{dependency="postgres",operation="journal_list",status="success"} 2`,
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("journal tenant/RLS dependency metrics missing %s:\n%s", expected, metrics)
		}
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
	meetingAdapter := &testMeetingAdapter{details: &room.MeetingDetails{
		ID:       "123456789",
		JoinURL:  "https://zoom.us/j/123456789",
		StartURL: "https://zoom.us/s/host-secret",
	}}
	roomHandler := &RoomHandler{
		DB:              db,
		StateManager:    roomState,
		MeetingAdapter:  meetingAdapter,
		MeetingProvider: "zoom",
	}
	overrideReq := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/create", strings.NewReader(`{"title":"Tenant Override Room","organization_id":"`+tenantIsolationOrgB+`","user_id":"`+tenantIsolationUserB+`"}`))
	overrideReq = overrideReq.WithContext(context.WithValue(overrideReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgA,
		Role:           "member",
	}))
	overrideRec := httptest.NewRecorder()
	roomHandler.CreateRoomHandler(overrideRec, overrideReq)
	if overrideRec.Code != http.StatusBadRequest {
		t.Fatalf("tenant override room create status = %d body = %s, want 400", overrideRec.Code, overrideRec.Body.String())
	}

	mismatchedClaimReq := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/create", strings.NewReader(`{"title":"Mismatched Tenant Claim Room"}`))
	mismatchedClaimReq = mismatchedClaimReq.WithContext(context.WithValue(mismatchedClaimReq.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgB,
		Role:           "member",
	}))
	mismatchedClaimRec := httptest.NewRecorder()
	roomHandler.CreateRoomHandler(mismatchedClaimRec, mismatchedClaimReq)
	if mismatchedClaimRec.Code == http.StatusCreated {
		t.Fatal("mismatched tenant/user room create unexpectedly succeeded")
	}
	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgB, func(ctx context.Context, tx pgx.Tx) {
		var roomCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM live_rooms WHERE organization_id = $1 AND title = 'Mismatched Tenant Claim Room'`, tenantIsolationOrgB).Scan(&roomCount); err != nil {
			t.Fatalf("query mismatched tenant/user room create result: %v", err)
		}
		if roomCount != 0 {
			t.Fatalf("mismatched tenant/user room create persisted %d rooms, want 0", roomCount)
		}
		var participantCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM room_participants WHERE organization_id = $1 AND user_id = $2`, tenantIsolationOrgB, tenantIsolationUserA).Scan(&participantCount); err != nil {
			t.Fatalf("query mismatched tenant/user room participant result: %v", err)
		}
		if participantCount != 0 {
			t.Fatalf("mismatched tenant/user room create persisted %d participants, want 0", participantCount)
		}
	})

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
	if created.MeetingProvider != "zoom" || created.MeetingID != "123456789" || created.JoinURL != "https://zoom.us/j/123456789" {
		t.Fatalf("room meeting mapping = %#v, want persisted Zoom identity and join URL", created)
	}
	if meetingAdapter.createdConfig.Topic != "Tenant Isolation Room" || meetingAdapter.createdConfig.HostID != tenantIsolationUserA || meetingAdapter.createdConfig.Duration != 60 {
		t.Fatalf("meeting adapter config = %#v, want tenant room config", meetingAdapter.createdConfig)
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
	if ownerRooms[0].MeetingProvider != "zoom" || ownerRooms[0].MeetingID != "123456789" || ownerRooms[0].JoinURL != "https://zoom.us/j/123456789" {
		t.Fatalf("active room meeting mapping = %#v, want persisted Zoom identity and join URL", ownerRooms[0])
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

func TestCreateRoomFailsClosedAndDeactivatesRoomWhenRedisStateInitializationFails(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantIsolationFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantIsolationFixtures(cleanupCtx, t, db)
	})

	roomHandler := &RoomHandler{
		DB:           db,
		StateManager: &tenantIsolationStateStore{setActiveErr: errors.New("redis unavailable")},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/create", strings.NewReader(`{"title":"Redis State Failure Room"}`))
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         tenantIsolationUserA,
		OrganizationID: tenantIsolationOrgA,
		Role:           "member",
	}))
	recorder := httptest.NewRecorder()
	roomHandler.CreateRoomHandler(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("Redis state failure status = %d body = %s, want 503", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "redis unavailable") {
		t.Fatalf("Redis state failure leaked dependency detail: %s", recorder.Body.String())
	}

	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgA, func(ctx context.Context, tx pgx.Tx) {
		var roomCount int
		var active bool
		if err := tx.QueryRow(ctx, `SELECT COUNT(*), COALESCE(BOOL_OR(is_active), FALSE) FROM live_rooms WHERE organization_id = $1 AND title = 'Redis State Failure Room'`, tenantIsolationOrgA).Scan(&roomCount, &active); err != nil {
			t.Fatalf("query compensated room: %v", err)
		}
		if roomCount != 1 || active {
			t.Fatalf("compensated room count=%d active=%t, want count=1 active=false", roomCount, active)
		}
	})
}

func TestZoomWebhookRoomMappingRLSBinding(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantIsolationFixtures(ctx, t, db)
	const (
		roomID    = "21212121-2121-4212-8212-212121212121"
		meetingID = "zoom-rls-binding-meeting"
	)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantIsolationFixtures(cleanupCtx, t, db)
	})

	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgA, func(ctx context.Context, tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `INSERT INTO live_rooms (id, organization_id, host_user_id, title, meeting_external_id) VALUES ($1, $2, $3, 'Zoom RLS Binding Room', $4)`, roomID, tenantIsolationOrgA, tenantIsolationUserA, meetingID); err != nil {
			t.Fatalf("seed Zoom mapping room: %v", err)
		}
	})

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Zoom mapping RLS transaction: %v", err)
	}
	defer tx.Rollback(ctx)
	var isSuperuser bool
	if err := tx.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuperuser); err != nil {
		t.Fatalf("check Zoom mapping RLS role: %v", err)
	}
	if isSuperuser {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+tenantIsolationRLSRole); err != nil {
			t.Fatalf("set Zoom mapping RLS role: %v", err)
		}
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_org_id', '00000000-0000-4000-8000-000000000000', true)`); err != nil {
		t.Fatalf("set Zoom mapping sentinel tenant context: %v", err)
	}

	var visibleWithoutVerification int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM live_rooms WHERE meeting_external_id = $1`, meetingID).Scan(&visibleWithoutVerification); err != nil {
		t.Fatalf("query Zoom mapping without verified context: %v", err)
	}
	if visibleWithoutVerification != 0 {
		t.Fatalf("zoom webhook mapping without verified context visible rows=%d, want 0", visibleWithoutVerification)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.webhook_lookup_verified', 'true', true), set_config('app.webhook_lookup_meeting_id', $1, true)`, meetingID); err != nil {
		t.Fatalf("set Zoom webhook mapping context: %v", err)
	}
	var mappedRoomID string
	if err := tx.QueryRow(ctx, `SELECT id FROM live_rooms WHERE meeting_external_id = $1`, meetingID).Scan(&mappedRoomID); err != nil {
		t.Fatalf("query Zoom mapping with verified context: %v", err)
	}
	if mappedRoomID != roomID {
		t.Fatalf("zoom webhook mapping verified exact meeting room=%s, want %s", mappedRoomID, roomID)
	}
}

func TestSocketStreamIsTenantScoped(t *testing.T) {
	t.Setenv("ALLOWED_WS_ORIGINS", "")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "")

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

	wsForTenantA := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/" + roomID + "?tenant=tenant-a&user=" + tenantIsolationUserA + "&client=a"
	tenantAConn, _, err := websocket.DefaultDialer.Dial(wsForTenantA, nil)
	if err != nil {
		t.Fatalf("tenant A socket dial should succeed: %v", err)
	}
	if err := tenantAConn.Close(); err != nil {
		t.Fatalf("close tenant A socket: %v", err)
	}

	wsForTenantB := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/rooms/stream/" + roomID + "?tenant=tenant-b&user=" + tenantIsolationUserB + "&client=b"
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

func TestAuthRefreshLogoutHonorTenantIsolation(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedTenantIsolationFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantIsolationFixtures(cleanupCtx, t, db)
	})

	refreshToken := createTenantScopedRefreshToken(ctx, t, db, tenantIsolationOrgA, tenantIsolationUserA)
	if refreshToken == "" {
		t.Fatal("tenant A refresh token should be generated")
	}

	handler := &AuthHandler{DB: db}

	crossRefresh := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+refreshToken+`","organization_id":"`+tenantIsolationOrgB+`"}`))
	crossRefreshRec := httptest.NewRecorder()
	handler.RefreshHandler(crossRefreshRec, crossRefresh)
	if crossRefreshRec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant refresh status = %d body = %s", crossRefreshRec.Code, crossRefreshRec.Body.String())
	}

	withTenantIsolationContext(ctx, t, db, tenantIsolationOrgB, func(ctx context.Context, tx pgx.Tx) {
		var crossTenantTokenCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = $1`, hashToken(refreshToken)).Scan(&crossTenantTokenCount); err != nil {
			t.Fatalf("query cross-tenant refresh token visibility: %v", err)
		}
		if crossTenantTokenCount != 0 {
			t.Fatalf("cross-tenant token visibility leaked token count=%d", crossTenantTokenCount)
		}
	})

	sameTenantRefresh := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+refreshToken+`","organization_id":"`+tenantIsolationOrgA+`"}`))
	sameTenantRefreshRec := httptest.NewRecorder()
	handler.RefreshHandler(sameTenantRefreshRec, sameTenantRefresh)
	if sameTenantRefreshRec.Code != http.StatusOK {
		t.Fatalf("same-tenant refresh status = %d body = %s", sameTenantRefreshRec.Code, sameTenantRefreshRec.Body.String())
	}
	var refreshed AuthResponse
	if err := json.Unmarshal(sameTenantRefreshRec.Body.Bytes(), &refreshed); err != nil {
		t.Fatalf("decode same-tenant refresh response: %v", err)
	}
	if refreshed.UserID != tenantIsolationUserA || refreshed.OrganizationID != tenantIsolationOrgA {
		t.Fatalf("same-tenant refresh response unexpected identity: %+v", refreshed)
	}
	if refreshed.RefreshToken == "" || refreshed.Token == "" {
		t.Fatalf("same-tenant refresh response missing tokens: %+v", refreshed)
	}

	tenantALogoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(`{"refresh_token":"`+refreshed.RefreshToken+`","organization_id":"`+tenantIsolationOrgA+`"}`))
	tenantALogoutRec := httptest.NewRecorder()
	handler.LogoutHandler(tenantALogoutRec, tenantALogoutReq)
	if tenantALogoutRec.Code != http.StatusNoContent {
		t.Fatalf("tenant A logout status = %d body = %s", tenantALogoutRec.Code, tenantALogoutRec.Body.String())
	}

	assertRefreshTokenRevocation(ctx, t, db, tenantIsolationOrgA, refreshed.RefreshToken, true)

	crossLogout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(`{"refresh_token":"`+refreshed.RefreshToken+`","organization_id":"`+tenantIsolationOrgB+`"}`))
	crossLogoutRec := httptest.NewRecorder()
	handler.LogoutHandler(crossLogoutRec, crossLogout)
	if crossLogoutRec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant logout status = %d body = %s", crossLogoutRec.Code, crossLogoutRec.Body.String())
	}
}

type tenantIsolationStateStore struct {
	setActiveErr error
}

func (s tenantIsolationStateStore) SetRoomActiveState(context.Context, string, bool) error {
	return s.setActiveErr
}

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
		if _, err := tx.Exec(ctx, `SAVEPOINT cross_tenant_write_attempt`); err != nil {
			t.Fatalf("create cross-tenant write savepoint: %v", err)
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
		if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT cross_tenant_write_attempt`); rollbackErr != nil {
			t.Fatalf("rollback expected cross-tenant write denial: %v", rollbackErr)
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

func createTenantScopedRefreshToken(ctx context.Context, t *testing.T, db *pgxpool.Pool, orgID, userID string) string {
	t.Helper()
	var token string
	withTenantIsolationContext(ctx, t, db, orgID, func(ctx context.Context, tx pgx.Tx) {
		var err error
		token, err = storeRefreshToken(ctx, tx, userID, orgID, nil, false)
		if err != nil {
			t.Fatalf("create refresh token for tenant %s user %s: %v", orgID, userID, err)
		}
	})
	return token
}

func assertRefreshTokenRevocation(ctx context.Context, t *testing.T, db *pgxpool.Pool, orgID, token string, revoked bool) {
	t.Helper()
	withTenantIsolationContext(ctx, t, db, orgID, func(ctx context.Context, tx pgx.Tx) {
		var count int
		var query string
		if revoked {
			query = `SELECT COUNT(*) FROM refresh_tokens WHERE organization_id = $1 AND token_hash = $2 AND revoked_at IS NOT NULL`
		} else {
			query = `SELECT COUNT(*) FROM refresh_tokens WHERE organization_id = $1 AND token_hash = $2 AND revoked_at IS NULL`
		}
		if err := tx.QueryRow(ctx, query, orgID, hashToken(token)).Scan(&count); err != nil {
			t.Fatalf("query refresh token revocation state for tenant %s: %v", orgID, err)
		}
		if count != 1 {
			t.Fatalf("refresh token revocation state for tenant %s token revoked=%v expected 1 row, got %d", orgID, revoked, count)
		}
	})
}
