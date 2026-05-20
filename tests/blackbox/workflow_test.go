package blackbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

func TestStateTransitionWorkflow(t *testing.T) {
	// 1. Register a new user
	registerPayload := map[string]string{
		"email":           "workflow.user@example.com",
		"password":        "workflowPass123!",
		"organization_id": "org-workflow-1",
	}
	regBody, _ := json.Marshal(registerPayload)

	respReg, err := http.Post(baseURL+"/api/auth/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("Failed to execute registration request: %v", err)
	}
	defer respReg.Body.Close()

	if respReg.StatusCode != http.StatusCreated && respReg.StatusCode != http.StatusConflict {
		t.Fatalf("Registration failed with status %d", respReg.StatusCode)
	}

	// 2. Login to get token
	loginPayload := map[string]string{
		"email":    "workflow.user@example.com",
		"password": "workflowPass123!",
	}
	loginBody, _ := json.Marshal(loginPayload)

	respLogin, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("Failed to execute login request: %v", err)
	}
	defer respLogin.Body.Close()

	if respLogin.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for login, got %d", respLogin.StatusCode)
	}

	var loginResponse map[string]string
	if err := json.NewDecoder(respLogin.Body).Decode(&loginResponse); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}

	token, ok := loginResponse["token"]
	if !ok || token == "" {
		t.Fatalf("Login response did not contain a valid token")
	}

	// 3. Emulate Access to Protected Resource using the extracted token
	curriculumPayload := map[string]string{
		"topic": "Faith",
	}
	currBody, _ := json.Marshal(curriculumPayload)

	req, _ := http.NewRequest("POST", baseURL+"/api/ai/curriculum", bytes.NewBuffer(currBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	respCurr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to execute curriculum request: %v", err)
	}
	defer respCurr.Body.Close()

	// The Rust gRPC server is mocked with socat. It will likely fail to respond meaningfully to the Go server.
	// The Go server should handle this gracefully (500 internal error, but standard format, no panic).
	// The key is that it passes the 401 Authorization check.
	if respCurr.StatusCode == http.StatusUnauthorized {
		t.Errorf("Expected authorized state transition to persist, but got 401 Unauthorized")
	}

	// Check if the response follows the standard PlatformException contract if it fails
	if respCurr.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(respCurr.Body)
		var errResp map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			t.Errorf("Failed to parse error response: %s", string(bodyBytes))
		}

		if _, ok := errResp["category"]; !ok {
			t.Errorf("Error response missing required 'category' field: %v", errResp)
		}
	}
}
