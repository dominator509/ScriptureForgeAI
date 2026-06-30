package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	tenantScriptureA = "55555555-5555-4555-8555-555555555555"
	tenantScriptureB = "66666666-6666-4666-8666-666666666666"
	tenantRefreshA   = "77777777-7777-4777-8777-777777777777"
	tenantRefreshB   = "88888888-8888-4888-8888-888888888888"
	tenantJournalA   = "99999999-9999-4999-8999-999999999999"
	tenantJournalB   = "12121212-1212-4121-8121-121212121212"
	tenantAILogA     = "13131313-1313-4131-8131-131313131313"
	tenantAILogB     = "14141414-1414-4141-8141-141414141414"
	tenantCitationA  = "15151515-1515-4151-8151-151515151515"
	tenantCitationB  = "16161616-1616-4161-8161-161616161616"
	tenantWriteProbe = "17171717-1717-4171-8171-171717171717"
	tenantWriteUser  = "18181818-1818-4181-8181-181818181818"
	tenantWriteRoom  = "19191919-1919-4191-8191-191919191919"
	tenantWriteAI    = "20202020-2020-4202-8202-202020202020"
)

func TestTenantRLSCoversAllTenantTables(t *testing.T) {
	db := openTenantIsolationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	seedTenantFixtures(ctx, t, db)
	seedTableRLSFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupTenantFixtures(cleanupCtx, t, db)
	})

	assertVisibleCounts := func(orgID string, expected map[string]int) {
		t.Helper()
		setTenantForTest(ctx, t, db, orgID, func(ctx context.Context, tx pgx.Tx) {
			for table, want := range expected {
				var got int
				if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM `+table).Scan(&got); err != nil {
					t.Fatalf("count visible rows for %s as %s: %v", table, orgID, err)
				}
				if got != want {
					t.Fatalf("visible rows for %s as %s = %d, want %d", table, orgID, got, want)
				}
			}
		})
	}

	assertVisibleCounts(tenantOrgA, map[string]int{
		"organizations":     1,
		"users":             2,
		"scripture_texts":   1,
		"refresh_tokens":    1,
		"journal_entries":   1,
		"live_rooms":        1,
		"room_participants": 1,
		"ai_request_logs":   1,
		"citation_trails":   1,
	})
	assertVisibleCounts(tenantOrgB, map[string]int{
		"organizations":     1,
		"users":             1,
		"scripture_texts":   1,
		"refresh_tokens":    1,
		"journal_entries":   1,
		"live_rooms":        1,
		"room_participants": 1,
		"ai_request_logs":   1,
		"citation_trails":   1,
	})
	assertTenantScopedRowVisibility(ctx, t, db, tenantOrgA, []tenantTableVisibilityProbe{
		{table: "organizations", predicate: "id = $1", ownID: tenantOrgA, blockedID: tenantOrgB},
		{table: "users", predicate: "id = $1", ownID: tenantUserA, blockedID: tenantUserB},
		{table: "scripture_texts", predicate: "id = $1", ownID: tenantScriptureA, blockedID: tenantScriptureB},
		{table: "refresh_tokens", predicate: "id = $1", ownID: tenantRefreshA, blockedID: tenantRefreshB},
		{table: "journal_entries", predicate: "id = $1", ownID: tenantJournalA, blockedID: tenantJournalB},
		{table: "live_rooms", predicate: "id = $1", ownID: tenantRoomA, blockedID: tenantRoomB},
		{table: "room_participants", predicate: "room_id = $1", ownID: tenantRoomA, blockedID: tenantRoomB},
		{table: "ai_request_logs", predicate: "id = $1", ownID: tenantAILogA, blockedID: tenantAILogB},
		{table: "citation_trails", predicate: "id = $1", ownID: tenantCitationA, blockedID: tenantCitationB},
	})
	assertTenantScopedRowVisibility(ctx, t, db, tenantOrgB, []tenantTableVisibilityProbe{
		{table: "organizations", predicate: "id = $1", ownID: tenantOrgB, blockedID: tenantOrgA},
		{table: "users", predicate: "id = $1", ownID: tenantUserB, blockedID: tenantUserA},
		{table: "scripture_texts", predicate: "id = $1", ownID: tenantScriptureB, blockedID: tenantScriptureA},
		{table: "refresh_tokens", predicate: "id = $1", ownID: tenantRefreshB, blockedID: tenantRefreshA},
		{table: "journal_entries", predicate: "id = $1", ownID: tenantJournalB, blockedID: tenantJournalA},
		{table: "live_rooms", predicate: "id = $1", ownID: tenantRoomB, blockedID: tenantRoomA},
		{table: "room_participants", predicate: "room_id = $1", ownID: tenantRoomB, blockedID: tenantRoomA},
		{table: "ai_request_logs", predicate: "id = $1", ownID: tenantAILogB, blockedID: tenantAILogA},
		{table: "citation_trails", predicate: "id = $1", ownID: tenantCitationB, blockedID: tenantCitationA},
	})
	assertSameTenantWritesPassAllTables(ctx, t, db)

	setTenantForTest(ctx, t, db, tenantOrgA, func(ctx context.Context, tx pgx.Tx) {
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO organizations (id, name) VALUES ($1, 'Cross Tenant Org')`, tenantWriteProbe)
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'cross-user@example.test', 'hash', 'member')`, tenantWriteProbe, tenantOrgB)
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO scripture_texts (id, organization_id, book, chapter, verse, content) VALUES ($1, $2, 'Genesis', 1, 3, 'Cross tenant')`, tenantWriteProbe, tenantOrgB)
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO refresh_tokens (id, organization_id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, 'cross-token-hash', now() + interval '1 hour')`, tenantWriteProbe, tenantOrgB, tenantUserB)
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO journal_entries (id, organization_id, user_id, ciphertext, iv, salt_id) VALUES ($1, $2, $3, 'cipher', 'iv', 'salt')`, tenantWriteProbe, tenantOrgB, tenantUserB)
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO live_rooms (id, organization_id, host_user_id, title) VALUES ($1, $2, $3, 'Cross Room')`, tenantWriteProbe, tenantOrgB, tenantUserB)
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO room_participants (organization_id, room_id, user_id) VALUES ($1, $2, $3)`, tenantOrgB, tenantRoomB, tenantUserB)
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO ai_request_logs (id, organization_id, user_id, prompt, status) VALUES ($1, $2, $3, 'cross prompt', 'failed')`, tenantWriteProbe, tenantOrgB, tenantUserB)
		requireRLSWriteDenied(t, ctx, tx, `INSERT INTO citation_trails (id, organization_id, ai_request_log_id, citation, verified) VALUES ($1, $2, $3, '[Cross 1:1]', false)`, tenantWriteProbe, tenantOrgB, tenantAILogB)
		requireRLSMutationHidden(t, ctx, tx, "organizations", "cross-tenant update hidden", `UPDATE organizations SET name = 'mutated by tenant A' WHERE id = $1`, tenantOrgB)
		requireRLSMutationHidden(t, ctx, tx, "users", "cross-tenant update hidden", `UPDATE users SET email = 'mutated-user@example.test' WHERE id = $1`, tenantUserB)
		requireRLSMutationHidden(t, ctx, tx, "scripture_texts", "cross-tenant update hidden", `UPDATE scripture_texts SET content = 'mutated scripture' WHERE id = $1`, tenantScriptureB)
		requireRLSMutationHidden(t, ctx, tx, "refresh_tokens", "cross-tenant update hidden", `UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1`, tenantRefreshB)
		requireRLSMutationHidden(t, ctx, tx, "journal_entries", "cross-tenant update hidden", `UPDATE journal_entries SET ciphertext = 'mutated cipher' WHERE id = $1`, tenantJournalB)
		requireRLSMutationHidden(t, ctx, tx, "live_rooms", "cross-tenant update hidden", `UPDATE live_rooms SET title = 'mutated room' WHERE id = $1`, tenantRoomB)
		requireRLSMutationHidden(t, ctx, tx, "room_participants", "cross-tenant update hidden", `UPDATE room_participants SET joined_at = now() WHERE room_id = $1 AND user_id = $2`, tenantRoomB, tenantUserB)
		requireRLSMutationHidden(t, ctx, tx, "ai_request_logs", "cross-tenant update hidden", `UPDATE ai_request_logs SET status = 'failed' WHERE id = $1`, tenantAILogB)
		requireRLSMutationHidden(t, ctx, tx, "citation_trails", "cross-tenant update hidden", `UPDATE citation_trails SET verified = false WHERE id = $1`, tenantCitationB)
		requireRLSMutationHidden(t, ctx, tx, "citation_trails", "cross-tenant delete hidden", `DELETE FROM citation_trails WHERE id = $1`, tenantCitationB)
		requireRLSMutationHidden(t, ctx, tx, "ai_request_logs", "cross-tenant delete hidden", `DELETE FROM ai_request_logs WHERE id = $1`, tenantAILogB)
		requireRLSMutationHidden(t, ctx, tx, "room_participants", "cross-tenant delete hidden", `DELETE FROM room_participants WHERE room_id = $1 AND user_id = $2`, tenantRoomB, tenantUserB)
		requireRLSMutationHidden(t, ctx, tx, "live_rooms", "cross-tenant delete hidden", `DELETE FROM live_rooms WHERE id = $1`, tenantRoomB)
		requireRLSMutationHidden(t, ctx, tx, "journal_entries", "cross-tenant delete hidden", `DELETE FROM journal_entries WHERE id = $1`, tenantJournalB)
		requireRLSMutationHidden(t, ctx, tx, "refresh_tokens", "cross-tenant delete hidden", `DELETE FROM refresh_tokens WHERE id = $1`, tenantRefreshB)
		requireRLSMutationHidden(t, ctx, tx, "scripture_texts", "cross-tenant delete hidden", `DELETE FROM scripture_texts WHERE id = $1`, tenantScriptureB)
		requireRLSMutationHidden(t, ctx, tx, "users", "cross-tenant delete hidden", `DELETE FROM users WHERE id = $1`, tenantUserB)
		requireRLSMutationHidden(t, ctx, tx, "organizations", "cross-tenant delete hidden", `DELETE FROM organizations WHERE id = $1`, tenantOrgB)
	})
}

func assertSameTenantWritesPassAllTables(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	setTenantForTest(ctx, t, db, tenantWriteProbe, func(ctx context.Context, tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `SAVEPOINT rls_same_tenant_write_probe`); err != nil {
			t.Fatalf("create same-tenant write savepoint: %v", err)
		}
		mustExecTenant(t, ctx, tx, `INSERT INTO organizations (id, name) VALUES ($1, 'Tenant Write Probe')`, tenantWriteProbe)
		mustExecTenant(t, ctx, tx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'same-write@example.test', 'hash', 'member')`, tenantWriteUser, tenantWriteProbe)
		mustExecTenant(t, ctx, tx, `INSERT INTO scripture_texts (organization_id, book, chapter, verse, content) VALUES ($1, 'Genesis', 1, 2, 'Same tenant scripture')`, tenantWriteProbe)
		mustExecTenant(t, ctx, tx, `INSERT INTO refresh_tokens (organization_id, user_id, token_hash, expires_at) VALUES ($1, $2, 'same-tenant-token-hash', now() + interval '1 hour')`, tenantWriteProbe, tenantWriteUser)
		mustExecTenant(t, ctx, tx, `INSERT INTO journal_entries (organization_id, user_id, ciphertext, iv, salt_id) VALUES ($1, $2, 'same-cipher', 'same-iv', 'same:salt:v1')`, tenantWriteProbe, tenantWriteUser)
		mustExecTenant(t, ctx, tx, `INSERT INTO live_rooms (id, organization_id, host_user_id, title) VALUES ($1, $2, $3, 'Same Tenant Room')`, tenantWriteRoom, tenantWriteProbe, tenantWriteUser)
		mustExecTenant(t, ctx, tx, `INSERT INTO room_participants (organization_id, room_id, user_id) VALUES ($1, $2, $3)`, tenantWriteProbe, tenantWriteRoom, tenantWriteUser)
		mustExecTenant(t, ctx, tx, `INSERT INTO ai_request_logs (id, organization_id, user_id, prompt, status) VALUES ($1, $2, $3, 'same prompt', 'succeeded')`, tenantWriteAI, tenantWriteProbe, tenantWriteUser)
		mustExecTenant(t, ctx, tx, `INSERT INTO citation_trails (organization_id, ai_request_log_id, citation, verified) VALUES ($1, $2, '[Genesis 1:2]', true)`, tenantWriteProbe, tenantWriteAI)
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT rls_same_tenant_write_probe`); err != nil {
			t.Fatalf("rollback same-tenant write savepoint: %v", err)
		}
		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT rls_same_tenant_write_probe`); err != nil {
			t.Fatalf("release same-tenant write savepoint: %v", err)
		}
	})
}

type tenantTableVisibilityProbe struct {
	table     string
	predicate string
	ownID     string
	blockedID string
}

func assertTenantScopedRowVisibility(ctx context.Context, t *testing.T, db *pgxpool.Pool, orgID string, probes []tenantTableVisibilityProbe) {
	t.Helper()
	setTenantForTest(ctx, t, db, orgID, func(ctx context.Context, tx pgx.Tx) {
		for _, probe := range probes {
			assertTenantRowCount(t, ctx, tx, probe.table, probe.predicate, probe.ownID, 1, "same-tenant read visible")
			assertTenantRowCount(t, ctx, tx, probe.table, probe.predicate, probe.blockedID, 0, "cross-tenant read hidden")
		}
	})
}

func assertTenantRowCount(t *testing.T, ctx context.Context, tx pgx.Tx, table, predicate, id string, want int, label string) {
	t.Helper()
	var got int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM `+table+` WHERE `+predicate, id).Scan(&got); err != nil {
		t.Fatalf("%s query failed for %s id %s: %v", label, table, id, err)
	}
	if got != want {
		t.Fatalf("%s for %s id %s = %d, want %d", label, table, id, got, want)
	}
}

func seedTableRLSFixtures(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	setTenantForTest(ctx, t, db, tenantOrgA, func(ctx context.Context, tx pgx.Tx) {
		mustExecTenant(t, ctx, tx, `INSERT INTO scripture_texts (id, organization_id, book, chapter, verse, content) VALUES ($1, $2, 'Genesis', 1, 1, 'Tenant A scripture')`, tenantScriptureA, tenantOrgA)
		mustExecTenant(t, ctx, tx, `INSERT INTO refresh_tokens (id, organization_id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, 'tenant-a-token-hash', now() + interval '1 hour')`, tenantRefreshA, tenantOrgA, tenantUserA)
		mustExecTenant(t, ctx, tx, `INSERT INTO journal_entries (id, organization_id, user_id, ciphertext, iv, salt_id) VALUES ($1, $2, $3, 'cipher-a', 'iv-a', 'journal:a:v1')`, tenantJournalA, tenantOrgA, tenantUserA)
		mustExecTenant(t, ctx, tx, `INSERT INTO ai_request_logs (id, organization_id, user_id, prompt, status) VALUES ($1, $2, $3, 'tenant A prompt', 'succeeded')`, tenantAILogA, tenantOrgA, tenantUserA)
		mustExecTenant(t, ctx, tx, `INSERT INTO citation_trails (id, organization_id, ai_request_log_id, citation, verified) VALUES ($1, $2, $3, '[Genesis 1:1]', true)`, tenantCitationA, tenantOrgA, tenantAILogA)
	})
	setTenantForTest(ctx, t, db, tenantOrgB, func(ctx context.Context, tx pgx.Tx) {
		mustExecTenant(t, ctx, tx, `INSERT INTO scripture_texts (id, organization_id, book, chapter, verse, content) VALUES ($1, $2, 'John', 1, 1, 'Tenant B scripture')`, tenantScriptureB, tenantOrgB)
		mustExecTenant(t, ctx, tx, `INSERT INTO refresh_tokens (id, organization_id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, 'tenant-b-token-hash', now() + interval '1 hour')`, tenantRefreshB, tenantOrgB, tenantUserB)
		mustExecTenant(t, ctx, tx, `INSERT INTO journal_entries (id, organization_id, user_id, ciphertext, iv, salt_id) VALUES ($1, $2, $3, 'cipher-b', 'iv-b', 'journal:b:v1')`, tenantJournalB, tenantOrgB, tenantUserB)
		mustExecTenant(t, ctx, tx, `INSERT INTO ai_request_logs (id, organization_id, user_id, prompt, status) VALUES ($1, $2, $3, 'tenant B prompt', 'succeeded')`, tenantAILogB, tenantOrgB, tenantUserB)
		mustExecTenant(t, ctx, tx, `INSERT INTO citation_trails (id, organization_id, ai_request_log_id, citation, verified) VALUES ($1, $2, $3, '[John 1:1]', true)`, tenantCitationB, tenantOrgB, tenantAILogB)
	})
}

func requireRLSWriteDenied(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SAVEPOINT rls_write_probe`); err != nil {
		t.Fatalf("create RLS write savepoint: %v", err)
	}
	_, err := tx.Exec(ctx, sql, args...)
	if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT rls_write_probe`); rollbackErr != nil {
		t.Fatalf("rollback RLS write savepoint: %v", rollbackErr)
	}
	if _, releaseErr := tx.Exec(ctx, `RELEASE SAVEPOINT rls_write_probe`); releaseErr != nil {
		t.Fatalf("release RLS write savepoint: %v", releaseErr)
	}
	if err == nil {
		t.Fatalf("cross-tenant write unexpectedly succeeded: %s", sql)
	} else if !strings.Contains(err.Error(), "row-level security") && !strings.Contains(err.Error(), "violates foreign key constraint") {
		t.Fatalf("cross-tenant write failed for unexpected reason: %v", err)
	}
}

func requireRLSMutationHidden(t *testing.T, ctx context.Context, tx pgx.Tx, table, label, sql string, args ...any) {
	t.Helper()
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		t.Fatalf("%s for %s failed unexpectedly: %v", label, table, err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("%s for %s affected %d rows, want 0", label, table, tag.RowsAffected())
	}
}
