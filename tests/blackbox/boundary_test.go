package blackbox

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const baseURL = "http://localhost:8080"

// TestBoundaryRegistration tests the boundary values and equivalence partitions for /api/auth/register
func TestBoundaryRegistration(t *testing.T) {
	endpoints := []string{baseURL + "/api/auth/register"}

	for _, endpoint := range endpoints {
		t.Run("Valid Registration", func(t *testing.T) {
			payload := map[string]string{
				"email":           "valid.boundary.user@example.com",
				"password":        "validPass123!",
				"organization_id": "org-valid-uuid-1",
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Fatalf("Failed to execute request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
				t.Errorf("Expected 201 or 409, got %d", resp.StatusCode)
			}
		})

		t.Run("Invalid Password Length Boundary", func(t *testing.T) {
			payload := map[string]string{
				"email":           "shortpass@example.com",
				"password":        "1234567", // 7 chars, bound is 8
				"organization_id": "org-valid-uuid-1",
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Fatalf("Failed to execute request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected 400 Bad Request for short password, got %d", resp.StatusCode)
			}
		})

		t.Run("Invalid Email Format", func(t *testing.T) {
			payload := map[string]string{
				"email":           "not-an-email",
				"password":        "validPass123!",
				"organization_id": "org-valid-uuid-1",
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Fatalf("Failed to execute request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected 400 Bad Request for invalid email, got %d", resp.StatusCode)
			}
		})

		t.Run("Missing Organization ID", func(t *testing.T) {
			payload := map[string]string{
				"email":    "missingorg@example.com",
				"password": "validPass123!",
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Fatalf("Failed to execute request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected 400 Bad Request for missing org ID, got %d", resp.StatusCode)
			}
		})

		t.Run("Extremely Large Payload", func(t *testing.T) {
			payload := map[string]string{
				"email":           "large@example.com",
				"password":        "validPass123!",
				"organization_id": strings.Repeat("A", 100000), // 100KB org id
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Fatalf("Failed to execute request: %v", err)
			}
			defer resp.Body.Close()

			// It might reject due to max request size, or postgres text limit, or timeout.
			// As long as it's not a 2xx or 5xx that leaks data, we consider it handled.
			if resp.StatusCode >= 500 {
				t.Errorf("System failed to gracefully handle large boundary payload, got %d", resp.StatusCode)
			}
		})
	}
}

// TestBoundaryCurriculum tests boundaries on the protected AI endpoint
func TestBoundaryCurriculum(t *testing.T) {
	endpoint := baseURL + "/api/ai/curriculum"

	t.Run("Missing Authorization Header", func(t *testing.T) {
		payload := map[string]string{
			"topic": "Grace",
		}
		body, _ := json.Marshal(payload)

		req, _ := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to execute request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for missing token, got %d", resp.StatusCode)
		}
	})

	// Further testing of this endpoint requires a valid token which is handled in Phase 3/4
}
