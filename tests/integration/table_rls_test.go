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
	})
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
