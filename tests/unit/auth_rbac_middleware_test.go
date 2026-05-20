package unit

import (
	"os"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"scriptureforge/internal/domain/auth"
)


func TestRBACMiddleware(t *testing.T) {
	os.Setenv("JWT_SECRET_KEY", "test-secret")
	defer os.Clearenv()
	// Create a dummy handler that returns 200 OK
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap dummy handler with RBAC middleware requiring "admin" role
	middleware := auth.RBACMiddleware(dummyHandler, "admin")

	// Generate a valid admin token
	adminToken, err := auth.GenerateToken("admin-123", "org-456", "admin", time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate admin token: %v", err)
	}

	// Generate a valid user token (lacks "admin" role)
	userToken, err := auth.GenerateToken("user-123", "org-456", "user", time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate user token: %v", err)
	}

	t.Run("MissingToken", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for missing token, got %v", rr.Code)
		}
	})

	t.Run("ValidAdminToken", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for valid admin token, got %v", rr.Code)
		}
	})

	t.Run("ValidUserTokenLackingRole", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for valid user token lacking required role, got %v", rr.Code)
		}
	})

	t.Run("ValidAdminTokenViaTicket", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/?ticket="+adminToken, nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for valid admin token via ticket, got %v", rr.Code)
		}
	})
}
