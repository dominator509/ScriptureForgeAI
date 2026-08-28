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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/adapters/llm"
	"scriptureforge/internal/domain/ai"
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
		if os.Getenv("REQUIRE_DATABASE_URL") == "true" {
			t.Fatal("DATABASE_URL is required when REQUIRE_DATABASE_URL=true for AI audit-log Postgres/RLS proof")
		}
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
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire AI audit RLS test role setup connection: %v", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin AI audit RLS test role setup: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(774411)`); err != nil {
		t.Fatalf("lock AI audit RLS test role setup: %v", err)
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
		t.Fatalf("ensure AI audit RLS test role: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit AI audit RLS test role setup: %v", err)
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
		var successCount, failureCount, citationCount, rawPromptCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE organization_id = $1 AND user_id = $2 AND status = 'succeeded'`, aiAuditOrgA, aiAuditUserA).Scan(&successCount); err != nil {
			t.Fatalf("query AI success logs: %v", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE organization_id = $1 AND user_id = $2 AND status = 'failed' AND error_message LIKE '%hallucinated citation%'`, aiAuditOrgA, aiAuditUserA).Scan(&failureCount); err != nil {
			t.Fatalf("query AI failure logs: %v", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM citation_trails WHERE organization_id = $1 AND citation IN ('[Genesis 1:1]', '[John 1:1]') AND verified = TRUE`, aiAuditOrgA).Scan(&citationCount); err != nil {
			t.Fatalf("query AI citation trails: %v", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE prompt <> '[redacted]' OR prompt_length <= 0`).Scan(&rawPromptCount); err != nil {
			t.Fatalf("query redacted AI prompts: %v", err)
		}
		if successCount != 1 || failureCount != 1 || citationCount != 2 || rawPromptCount != 0 {
			t.Fatalf("AI audit counts success=%d failure=%d citations=%d, want 1/1/2; raw_or_unmeasured=%d", successCount, failureCount, citationCount, rawPromptCount)
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

func TestGenerateCurriculumHandlerPersistsAuditRowsWithTenantRLS(t *testing.T) {
	db := openAIAuditDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedAIAuditFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupAIAuditFixtures(cleanupCtx, t, db)
	})

	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": "Creation study grounded in [Genesis 1:1]."}},
			},
		})
	}))
	defer llmServer.Close()

	handler := &AIHandler{
		DB:              db,
		RAGEngine:       ai.NewRAGEngine(fakeAIVectorDB{}),
		Verifier:        ai.NewResponseVerificationSubsystem(),
		LLMClient:       &llm.LLMClient{APIKey: "test-key", Endpoint: llmServer.URL, Model: "test-model", HTTPClient: llmServer.Client(), MaxRetries: 0, AllowedProviderHosts: []string{"127.0.0.1"}},
		MapReduceWorker: ai.NewMapReduceWorker(4000),
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/ai/generate/study", strings.NewReader(`{"topic":"creation"}`))
	request = request.WithContext(context.WithValue(request.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         aiAuditUserA,
		OrganizationID: aiAuditOrgA,
		Role:           "member",
	}))
	recorder := httptest.NewRecorder()

	handler.GenerateCurriculumHandler(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("AI generation status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "[Genesis 1:1]") {
		t.Fatalf("AI generation response did not include verified citation: %s", recorder.Body.String())
	}

	withAIAuditTenant(ctx, t, db, aiAuditOrgA, func(ctx context.Context, tx pgx.Tx) {
		var logCount, citationCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE organization_id = $1 AND user_id = $2 AND prompt = '[redacted]' AND prompt_length > 0 AND status = 'succeeded'`, aiAuditOrgA, aiAuditUserA).Scan(&logCount); err != nil {
			t.Fatalf("query handler AI audit logs: %v", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM citation_trails WHERE organization_id = $1 AND citation = '[Genesis 1:1]' AND verified = TRUE`, aiAuditOrgA).Scan(&citationCount); err != nil {
			t.Fatalf("query handler AI citation trails: %v", err)
		}
		if logCount != 1 || citationCount != 1 {
			t.Fatalf("handler AI audit counts logs=%d citations=%d, want 1/1", logCount, citationCount)
		}
	})

	withAIAuditTenant(ctx, t, db, aiAuditOrgB, func(ctx context.Context, tx pgx.Tx) {
		var visibleLogs, visibleCitations int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE prompt = '[redacted]'`).Scan(&visibleLogs); err != nil {
			t.Fatalf("query cross-tenant handler AI logs: %v", err)
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM citation_trails WHERE citation = '[Genesis 1:1]'`).Scan(&visibleCitations); err != nil {
			t.Fatalf("query cross-tenant handler AI citations: %v", err)
		}
		if visibleLogs != 0 || visibleCitations != 0 {
			t.Fatalf("cross-tenant handler AI audit visibility logs=%d citations=%d, want 0/0", visibleLogs, visibleCitations)
		}
	})
}

func TestGenerateCurriculumHandlerTenantIsolationForCrossTenantReadsAndWrites(t *testing.T) {
	db := openAIAuditDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedAIAuditFixtures(ctx, t, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupAIAuditFixtures(cleanupCtx, t, db)
	})

	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": "Tenant-aware study anchored in [Genesis 1:1]."}},
			},
		})
	}))
	defer llmServer.Close()

	handler := &AIHandler{
		DB:              db,
		RAGEngine:       ai.NewRAGEngine(fakeAIVectorDB{}),
		Verifier:        ai.NewResponseVerificationSubsystem(),
		LLMClient:       &llm.LLMClient{APIKey: "test-key", Endpoint: llmServer.URL, Model: "test-model", HTTPClient: llmServer.Client(), MaxRetries: 0, AllowedProviderHosts: []string{"127.0.0.1"}},
		MapReduceWorker: ai.NewMapReduceWorker(4000),
	}

	requestOrgA := httptest.NewRequest(http.MethodPost, "/api/v1/ai/generate/study", strings.NewReader(`{"topic":"genesis"}`))
	requestOrgA = requestOrgA.WithContext(context.WithValue(requestOrgA.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         aiAuditUserA,
		OrganizationID: aiAuditOrgA,
		Role:           "member",
	}))
	recOrgA := httptest.NewRecorder()
	handler.GenerateCurriculumHandler(recOrgA, requestOrgA)
	if recOrgA.Code != http.StatusOK {
		t.Fatalf("tenant A AI generation status = %d body = %s", recOrgA.Code, recOrgA.Body.String())
	}

	requestOrgARepeat := httptest.NewRequest(http.MethodPost, "/api/v1/ai/generate/study", strings.NewReader(`{"topic":"genesis"}`))
	requestOrgARepeat = requestOrgARepeat.WithContext(context.WithValue(requestOrgARepeat.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         aiAuditUserA,
		OrganizationID: aiAuditOrgA,
		Role:           "member",
	}))
	recOrgARepeat := httptest.NewRecorder()
	handler.GenerateCurriculumHandler(recOrgARepeat, requestOrgARepeat)
	if recOrgARepeat.Code != http.StatusOK {
		t.Fatalf("tenant A second AI generation status = %d body = %s", recOrgARepeat.Code, recOrgARepeat.Body.String())
	}

	requestOrgB := httptest.NewRequest(http.MethodPost, "/api/v1/ai/generate/study", strings.NewReader(`{"topic":"john"}`))
	requestOrgB = requestOrgB.WithContext(context.WithValue(requestOrgB.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         aiAuditUserB,
		OrganizationID: aiAuditOrgB,
		Role:           "member",
	}))
	recOrgB := httptest.NewRecorder()
	handler.GenerateCurriculumHandler(recOrgB, requestOrgB)
	if recOrgB.Code != http.StatusOK {
		t.Fatalf("tenant B AI generation status = %d body = %s", recOrgB.Code, recOrgB.Body.String())
	}

	withAIAuditTenant(ctx, t, db, aiAuditOrgA, func(ctx context.Context, tx pgx.Tx) {
		var orgARequestCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE organization_id = $1 AND user_id = $2`, aiAuditOrgA, aiAuditUserA).Scan(&orgARequestCount); err != nil {
			t.Fatalf("count tenant A AI requests: %v", err)
		}
		var orgACitationCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM citation_trails WHERE organization_id = $1`, aiAuditOrgA).Scan(&orgACitationCount); err != nil {
			t.Fatalf("count tenant A citation trails: %v", err)
		}
		if orgARequestCount != 2 {
			t.Fatalf("tenant A AI request count = %d, want 2", orgARequestCount)
		}
		if orgACitationCount != 2 {
			t.Fatalf("tenant A citation count = %d, want one citation trail per successful generation (2)", orgACitationCount)
		}
	})

	withAIAuditTenant(ctx, t, db, aiAuditOrgB, func(ctx context.Context, tx pgx.Tx) {
		var orgBRequestCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE organization_id = $1 AND user_id = $2`, aiAuditOrgB, aiAuditUserB).Scan(&orgBRequestCount); err != nil {
			t.Fatalf("count tenant B AI requests: %v", err)
		}
		var orgBCitationCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM citation_trails WHERE organization_id = $1`, aiAuditOrgB).Scan(&orgBCitationCount); err != nil {
			t.Fatalf("count tenant B citation trails: %v", err)
		}
		if orgBRequestCount != 1 {
			t.Fatalf("tenant B AI request count = %d, want 1", orgBRequestCount)
		}
		if orgBCitationCount != 1 {
			t.Fatalf("tenant B citation count = %d, want 1", orgBCitationCount)
		}
	})

	withAIAuditTenant(ctx, t, db, aiAuditOrgA, func(ctx context.Context, tx pgx.Tx) {
		var crossTenantView int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE user_id = $1`, aiAuditUserB).Scan(&crossTenantView); err != nil {
			t.Fatalf("cross-tenant AI read check for tenant A: %v", err)
		}
		if crossTenantView != 0 {
			t.Fatalf("tenant A can read tenant B AI request logs: %d", crossTenantView)
		}
	})
	withAIAuditTenant(ctx, t, db, aiAuditOrgB, func(ctx context.Context, tx pgx.Tx) {
		var crossTenantView int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM ai_request_logs WHERE user_id = $1`, aiAuditUserA).Scan(&crossTenantView); err != nil {
			t.Fatalf("cross-tenant AI read check for tenant B: %v", err)
		}
		if crossTenantView != 0 {
			t.Fatalf("tenant B can read tenant A AI request logs: %d", crossTenantView)
		}
	})
}

type fakeAIVectorDB struct{}

func (fakeAIVectorDB) Search(context.Context, string, string, int) ([]ai.SearchResult, error) {
	return []ai.SearchResult{{
		Book:            "Genesis",
		Chapter:         1,
		Verse:           1,
		TextContent:     "In the beginning God created the heavens and the earth.",
		SimilarityScore: 0.99,
	}}, nil
}
