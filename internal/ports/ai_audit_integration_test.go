package ports

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/domain/auth"
)

const (
	aiAuditOrgA    = "77777777-7777-4777-8777-777777777777"
	aiAuditOrgB    = "88888888-8888-4888-8888-888888888888"
	aiAuditUserA   = "99999999-9999-4999-8999-999999999999"
	aiAuditUserB   = "12121212-1212-4121-8121-121212121212"
	aiAuditRLSRole = "scriptureforge_rls_test"
)

func openAIAuditDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" || strings.Contains(databaseURL, "${") {
		t.Skip("DATABASE_URL is required for AI audit-log Postgres/RLS proof")
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
	ensureAIAuditRLSRole(ctx, t, db)
	t.Cleanup(db.Close)
	return db
}

func ensureAIAuditRLSRole(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	var isSuperuser bool
	if err := db.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuperuser); err != nil {
		t.Fatalf("check current user role: %v", err)
	}
	if !isSuperuser {
		return
	}
	if _, err := db.Exec(ctx, `SELECT pg_advisory_lock(774411)`); err != nil {
		t.Fatalf("lock AI audit RLS test role setup: %v", err)
	}
	defer func() {
		if _, err := db.Exec(ctx, `SELECT pg_advisory_unlock(774411)`); err != nil {
			t.Fatalf("unlock AI audit RLS test role setup: %v", err)
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
		t.Fatalf("ensure AI audit RLS test role: %v", err)
	}
}

func withAIAuditTenant(ctx context.Context, t *testing.T, db *pgxpool.Pool, orgID string, fn func(context.Context, pgx.Tx)) {
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
			t.Fatalf("set local AI audit RLS test role: %v", err)
		}
	}
	fn(ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tenant transaction %s: %v", orgID, err)
	}
}

func cleanupAIAuditFixtures(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	for _, orgID := range []string{aiAuditOrgA, aiAuditOrgB} {
		withAIAuditTenant(ctx, t, db, orgID, func(ctx context.Context, tx pgx.Tx) {
			if _, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID); err != nil {
				t.Fatalf("cleanup AI audit tenant %s: %v", orgID, err)
			}
		})
	}
}

func seedAIAuditFixtures(ctx context.Context, t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	cleanupAIAuditFixtures(ctx, t, db)
	withAIAuditTenant(ctx, t, db, aiAuditOrgA, func(ctx context.Context, tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'AI Audit Tenant A')`, aiAuditOrgA); err != nil {
			t.Fatalf("seed AI audit org A: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'ai-audit-a@example.test', 'hash', 'member')`, aiAuditUserA, aiAuditOrgA); err != nil {
			t.Fatalf("seed AI audit user A: %v", err)
		}
	})
	withAIAuditTenant(ctx, t, db, aiAuditOrgB, func(ctx context.Context, tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, 'AI Audit Tenant B')`, aiAuditOrgB); err != nil {
			t.Fatalf("seed AI audit org B: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($1, $2, 'ai-audit-b@example.test', 'hash', 'member')`, aiAuditUserB, aiAuditOrgB); err != nil {
			t.Fatalf("seed AI audit user B: %v", err)
		}
	})
}

func TestAIRequestLogPersistsCitationsAndHonorsTenantRLS(t *testing.T) {
	db := openAIAuditDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedAIAuditFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupAIAuditFixtures(cleanupCtx, t, db)
	})

	handler := &AIHandler{DB: db}
	request := httptest.NewRequest("POST", "/api/v1/ai/generate/study", strings.NewReader(`{}`))
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         aiAuditUserA,
		OrganizationID: aiAuditOrgA,
		Role:           "member",
	}))

	handler.writeAIRequestLog(request, &auth.TokenClaims{UserID: aiAuditUserA, OrganizationID: aiAuditOrgA, Role: "member"}, "creation", "succeeded", "", "Study [Genesis 1:1] and [John 1:1]")
	handler.writeAIRequestLog(request, &auth.TokenClaims{UserID: aiAuditUserA, OrganizationID: aiAuditOrgA, Role: "member"}, "bad citation", "failed", "verification failed: hallucinated citation", "")

	withAIAuditTenant(ctx, t, db, aiAuditOrgA, func(ctx context.Context, tx pgx.Tx) {
		var successCount, failureCount, citationCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE organization_id = $1 AND user_id = $2 AND status = 'succeeded'`, aiAuditOrgA, aiAuditUserA).Scan(&successCount); err != nil {
			t.Fatalf("query AI success logs: %v", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE organization_id = $1 AND user_id = $2 AND status = 'failed' AND error_message LIKE '%hallucinated citation%'`, aiAuditOrgA, aiAuditUserA).Scan(&failureCount); err != nil {
			t.Fatalf("query AI failure logs: %v", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM citation_trails WHERE organization_id = $1 AND citation IN ('[Genesis 1:1]', '[John 1:1]') AND verified = TRUE`, aiAuditOrgA).Scan(&citationCount); err != nil {
			t.Fatalf("query AI citation trails: %v", err)
		}
		if successCount != 1 || failureCount != 1 || citationCount != 2 {
			t.Fatalf("AI audit counts success=%d failure=%d citations=%d, want 1/1/2", successCount, failureCount, citationCount)
		}
	})

	withAIAuditTenant(ctx, t, db, aiAuditOrgB, func(ctx context.Context, tx pgx.Tx) {
		var visibleLogs, visibleCitations int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs`).Scan(&visibleLogs); err != nil {
			t.Fatalf("query cross-tenant AI logs: %v", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM citation_trails`).Scan(&visibleCitations); err != nil {
			t.Fatalf("query cross-tenant citation trails: %v", err)
		}
		if visibleLogs != 0 || visibleCitations != 0 {
			t.Fatalf("cross-tenant AI audit visibility logs=%d citations=%d, want 0/0", visibleLogs, visibleCitations)
		}
	})
}
