package unit

import (
	"os"
	"testing"
	"time"

	"scriptureforge/internal/domain/auth"
)

// TestArgon2idHashing validates the memory-safe string hashing modules
func TestArgon2idHashing(t *testing.T) {
	password := "SecurePass123!"

	hash, err := auth.HashPassword(password, auth.DefaultHashConfig)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	match, err := auth.VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}

	if !match {
		t.Errorf("Expected password to match hash")
	}

	// Test incorrect password
	match, err = auth.VerifyPassword("WrongPass!", hash)
	if err != nil {
		t.Fatalf("Failed to verify wrong password: %v", err)
	}

	if match {
		t.Errorf("Expected wrong password to fail verification")
	}
}

// TestJWTValidation validates the JWT creation and parsing components
func TestJWTValidation(t *testing.T) {
	os.Setenv("JWT_SECRET_KEY", "test-secret")
	defer os.Clearenv()
	userID := "user-123"



	orgID := "org-456"
	role := "admin"

	// Create valid token
	token, err := auth.GenerateToken(userID, orgID, role, time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate token
	claims, err := auth.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.UserID != userID || claims.OrganizationID != orgID || claims.Role != role {
		t.Errorf("Token claims do not match requested values")
	}

	// Create expired token
	expiredToken, _ := auth.GenerateToken(userID, orgID, role, -time.Hour)
	_, err = auth.ValidateToken(expiredToken)

	if err == nil {
		t.Errorf("Expected expired token to fail validation")
	}

	// Check typed error mapping
	if pe, ok := err.(*auth.PlatformException); !ok || pe.Category != auth.AuthenticationFault {
		t.Errorf("Expected PlatformException with AuthenticationFault category")
	}
}
