package auth

import (
	"strings"
	"testing"
	"time"
)

func TestValidateSecretStrength(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		wantError string
	}{
		{name: "missing", secret: "", wantError: "missing"},
		{name: "whitespace", secret: "   ", wantError: "missing"},
		{name: "weak", secret: "too-short", wantError: "at least 32 bytes"},
		{name: "valid", secret: "01234567890123456789012345678901"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSecretStrength("JWT_SECRET_KEY", test.secret)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("ValidateSecretStrength returned error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ValidateSecretStrength error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestGenerateTokenRejectsWeakJWTSecret(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "weak")
	if token, err := GenerateToken("user-123", "org-456", "member", time.Minute); err == nil || token != "" {
		t.Fatalf("GenerateToken = token=%q error=%v, want typed weak-key rejection", token, err)
	} else if platformErr, ok := err.(*PlatformException); !ok || platformErr.Category != AuthenticationFault || platformErr.Code != 500 {
		t.Fatalf("GenerateToken error = %#v, want authentication configuration fault", err)
	}
}
