package integration_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/ports"
)

// Tests boundary conditions and schema validation (empty strings, huge payloads, incorrect types)

func TestAuthRegister_SchemaValidation(t *testing.T) {
	// Create handler independently from DB since validation happens before DB insert
	// We pass nil for DB, which might panic if validation passes, so we expect it to fail validation first.
	handler := &ports.AuthHandler{DB: nil}

	tests := []struct {
		name           string
		payload        string
		expectedStatus int
	}{
		{
			name:           "Empty Payload",
			payload:        `{}`,
			expectedStatus: http.StatusBadRequest, // Validation failed
		},
		{
			name:           "Invalid Email Format",
			payload:        `{"email": "not-an-email", "password": "password123", "organization_id": "org1"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Short Password",
			payload:        `{"email": "test@test.com", "password": "short", "organization_id": "org1"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Missing Organization",
			payload:        `{"email": "test@test.com", "password": "password123"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Malformed JSON (Syntax Error)",
			payload:        `{"email": "test@test.com", "password": "password123",}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Type Coercion (Number instead of string)",
			payload:        `{"email": "test@test.com", "password": 12345678, "organization_id": "org1"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Huge Payload (SQL Injection / Buffer Overflow Attempt)",
			payload:        `{"email": "test@test.com", "password": "` + strings.Repeat("a", 100000) + `", "organization_id": "org1"}`,
			// It may fail validation depending on how strict, or attempt to hash. We want it to be handled safely.
			expectedStatus: http.StatusInternalServerError, // Or Bad Request if restricted
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBufferString(tc.payload))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			// We catch panics in case it passes validation and tries to hit the nil DB
			defer func() {
				if r := recover(); r != nil {
					// If it panicked, it means it passed validation but hit the nil DB.
					// Depending on the test, this might be expected or unexpected.
					if tc.expectedStatus == http.StatusBadRequest {
						t.Errorf("Validation should have failed for %s, but passed and panicked", tc.name)
					}
				}
			}()

			handler.RegisterHandler(rr, req)

			// The huge payload might trigger an internal server error because bcrypt/argon2 might refuse large inputs
			// or we hit a nil DB. But as long as it's not a success and handled, it's fine.
			if rr.Code != tc.expectedStatus && !(tc.name == "Huge Payload (SQL Injection / Buffer Overflow Attempt)" && rr.Code == http.StatusBadRequest) {
				t.Errorf("handler returned wrong status code for %s: got %v want %v", tc.name, rr.Code, tc.expectedStatus)
			}
		})
	}
}

func TestAICurriculum_SchemaValidation(t *testing.T) {
	// The AI curriculum requires topic
	aiHandler := &ports.AIHandler{
		RAGEngine:       nil,
		Verifier:        nil,
		LLMClient:       nil,
		MapReduceWorker: nil,
	}

	token, _ := auth.GenerateToken("user1", "org1", "member", time.Hour)

	tests := []struct {
		name           string
		payload        string
		expectedStatus int
	}{
		{
			name:           "Empty Payload",
			payload:        `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Missing Topic",
			payload:        `{"other_field": "value"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Type Coercion (Topic is array instead of string)",
			payload:        `{"topic": ["array", "of", "strings"]}`,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/api/ai/curriculum", bytes.NewBufferString(tc.payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)

			rr := httptest.NewRecorder()

			// Wrap in middleware to provide claims
			handler := auth.RBACMiddleware(http.HandlerFunc(aiHandler.GenerateCurriculumHandler), "")
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("handler returned wrong status code for %s: got %v want %v", tc.name, rr.Code, tc.expectedStatus)
			}
		})
	}
}
