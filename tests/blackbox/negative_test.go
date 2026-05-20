package blackbox

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNegativeAndInformationLeakage(t *testing.T) {
	// 1. Malformed JSON
	t.Run("Malformed JSON payload", func(t *testing.T) {
		malformedJSON := `{"email": "test@example.com", "password": "pass",`

		resp, err := http.Post(baseURL+"/api/auth/register", "application/json", bytes.NewBufferString(malformedJSON))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for malformed JSON, got %d", resp.StatusCode)
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)

		// Assert no internal leakage
		if strings.Contains(bodyStr, "unexpected end of JSON input") || strings.Contains(bodyStr, "go/src/encoding/json") {
			t.Errorf("Information Leakage: Internal stack trace or specific parse error exposed: %s", bodyStr)
		}
	})

	// 2. Mismatched Content-Types
	t.Run("Mismatched Content-Type", func(t *testing.T) {
		validJSON := `{"email": "valid@example.com", "password": "validPass123!", "organization_id": "org1"}`

		resp, err := http.Post(baseURL+"/api/auth/register", "text/plain", bytes.NewBufferString(validJSON))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// System might parse it anyway or reject it.
		// As long as it doesn't 500 and leak the parser state.
		if resp.StatusCode >= 500 {
			t.Errorf("System crashed on mismatched Content-Type. Expected gracefull error, got %d", resp.StatusCode)
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)

		if strings.Contains(bodyStr, "panic:") || strings.Contains(bodyStr, "sql:") {
			t.Errorf("Information Leakage on Content-Type mismatch: %s", bodyStr)
		}
	})

	// 3. Webhook Invalid Signature
	t.Run("Zoom Webhook Invalid Signature Leakage", func(t *testing.T) {
		payload := `{"event": "meeting.started", "payload": {}}`

		req, _ := http.NewRequest("POST", baseURL+"/api/webhooks/zoom", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-zm-signature", "v0=invalidhashvalue")
		req.Header.Set("x-zm-request-timestamp", "1234567890")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for invalid signature, got %d", resp.StatusCode)
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)

		// Assert no hmac internal errors leaked
		if strings.Contains(bodyStr, "hmac") || strings.Contains(bodyStr, "sha256") {
			t.Errorf("Information Leakage: Crypto implementation details exposed: %s", bodyStr)
		}
	})

	// 4. Mathematical/Database limit bounds forcing SQL error leakage
	t.Run("Database SQL Injection / String overflow Leakage test", func(t *testing.T) {
		payload := `{"email": "test@example.com' OR '1'='1", "password": "pass", "organization_id": "org1"}`

		resp, err := http.Post(baseURL+"/api/auth/register", "application/json", bytes.NewBufferString(payload))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)

		// Assert no internal database specifics leaked
		if strings.Contains(bodyStr, "pq: ") || strings.Contains(bodyStr, "syntax error at or near") || strings.Contains(bodyStr, "PostgreSQL") {
			t.Errorf("CRITICAL Information Leakage: SQL backend details exposed: %s", bodyStr)
		}
	})
}
