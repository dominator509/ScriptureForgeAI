package auth

import (
	"os"
	"testing"
)

func TestGetSecretKey(t *testing.T) {
	t.Run("ValidSecretKey", func(t *testing.T) {
		expectedSecret := "secure-dummy-test-key-12345"
		t.Setenv("JWT_SECRET_KEY", expectedSecret)

		key, err := getSecretKey()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if string(key) != expectedSecret {
			t.Fatalf("expected %s, got %s", expectedSecret, string(key))
		}
	})

	t.Run("MissingSecretKey", func(t *testing.T) {
		os.Unsetenv("JWT_SECRET_KEY")

		key, err := getSecretKey()
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if key != nil {
			t.Fatalf("expected nil key, got %v", key)
		}
	})
}
