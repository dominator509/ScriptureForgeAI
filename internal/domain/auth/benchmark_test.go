package auth

import (
	"os"
	"testing"
	"time"
)

func BenchmarkArgon2idHashing(b *testing.B) {
	password := "SecurePassword123!"
	config := DefaultHashConfig

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HashPassword(password, config)
		if err != nil {
			b.Fatalf("Hashing failed: %v", err)
		}
	}
}

func BenchmarkArgon2idVerification(b *testing.B) {
	password := "SecurePassword123!"
	config := DefaultHashConfig
	hash, err := HashPassword(password, config)
	if err != nil {
		b.Fatalf("Setup failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := VerifyPassword(password, hash)
		if err != nil || !valid {
			b.Fatalf("Verification failed or returned invalid")
		}
	}
}

func BenchmarkJWTGeneration(b *testing.B) {
	os.Setenv("GO_ENV", "testing")
	defer os.Unsetenv("GO_ENV")
	os.Setenv("JWT_SECRET_KEY", "super-secret-key-for-benchmarking")
	defer os.Unsetenv("JWT_SECRET_KEY")

	userID := "user-123"
	orgID := "org-456"
	role := "admin"
	duration := time.Hour * 24

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateToken(userID, orgID, role, duration)
		if err != nil {
			b.Fatalf("Token generation failed: %v", err)
		}
	}
}

func BenchmarkJWTValidation(b *testing.B) {
	os.Setenv("GO_ENV", "testing")
	defer os.Unsetenv("GO_ENV")
	os.Setenv("JWT_SECRET_KEY", "super-secret-key-for-benchmarking")
	defer os.Unsetenv("JWT_SECRET_KEY")

	userID := "user-123"
	orgID := "org-456"
	role := "admin"
	duration := time.Hour * 24

	token, err := GenerateToken(userID, orgID, role, duration)
	if err != nil {
		b.Fatalf("Setup failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ValidateToken(token)
		if err != nil {
			b.Fatalf("Token validation failed: %v", err)
		}
	}
}
