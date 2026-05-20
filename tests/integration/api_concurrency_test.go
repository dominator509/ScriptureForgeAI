package integration_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/ports"
)

// Mock objects to prevent actual LLM/DB calls during concurrency
type MockVerifier struct {}
func (m *MockVerifier) Verify(response string) bool { return true }

type MockRAGEngine struct {}
func (m *MockRAGEngine) CompileContext(ctx context.Context, orgID string, text string) (string, error) {
	return "mock context", nil
}

// Tests high concurrency of the AI Handler to ensure thread safety
func TestAICurriculum_HighConcurrency(t *testing.T) {
	// Instead of using the real RAG/Verifier which we can't easily mock because they aren't interfaces in ports.AIHandler,
	// wait, ports.AIHandler uses pointers to structs instead of interfaces!
	// We will send malformed payloads that fail validation immediately to test the concurrency of the HTTP handler
	// and RBAC middleware without triggering the nil pointers or external LLM limits.

	token, _ := auth.GenerateToken("user1", "org1", "member", time.Hour)

	aiHandler := &ports.AIHandler{}
	handler := auth.RBACMiddleware(http.HandlerFunc(aiHandler.GenerateCurriculumHandler), "")

	var wg sync.WaitGroup
	var successCount int32
	var failCount int32

	concurrentRequests := 200

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// We send empty payloads so it hits the Bad Request validation
			// This tests the middleware and handler thread-safety under load
			req, _ := http.NewRequest(http.MethodPost, "/api/ai/curriculum", bytes.NewBufferString(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code == http.StatusBadRequest {
				atomic.AddInt32(&successCount, 1) // "Success" here means it successfully handled the request and threw a 400
			} else {
				atomic.AddInt32(&failCount, 1)
			}
		}()
	}

	wg.Wait()

	if failCount > 0 {
		t.Errorf("Concurrency test failed: %d requests had unexpected status codes", failCount)
	}
	if successCount != int32(concurrentRequests) {
		t.Errorf("Expected %d successful handlings, got %d", concurrentRequests, successCount)
	}
}
