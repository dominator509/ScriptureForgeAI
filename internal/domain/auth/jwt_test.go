package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestGenerateMFAEnrollmentTokenIsPurposeBound(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "mfa-enrollment-token-test-secret-0123456789")
	token, err := GenerateMFAEnrollmentToken("user-mfa", "org-mfa", "admin", 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateMFAEnrollmentToken returned error: %v", err)
	}
	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if !claims.MFAEnrollmentOnly || claims.UserID != "user-mfa" || claims.OrganizationID != "org-mfa" || claims.Role != "admin" {
		t.Fatalf("enrollment claims = %#v, want purpose-bound admin claims", claims)
	}
	if claims.ExpiresAt == nil || time.Until(claims.ExpiresAt.Time) > 10*time.Minute || time.Until(claims.ExpiresAt.Time) <= 9*time.Minute {
		t.Fatalf("enrollment expiration = %v, want roughly ten minutes", claims.ExpiresAt)
	}

	normalToken, err := GenerateToken("user-mfa", "org-mfa", "admin", time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}
	normalClaims, err := ValidateToken(normalToken)
	if err != nil {
		t.Fatalf("ValidateToken normal token returned error: %v", err)
	}
	if normalClaims.MFAEnrollmentOnly {
		t.Fatal("normal access token unexpectedly carried MFA enrollment-only purpose")
	}
}

func TestValidateTokenRejectsUnexpectedAlgorithmIssuerAndIdentity(t *testing.T) {
	secret := "jwt-validation-contract-secret-0123456789"
	t.Setenv("JWT_SECRET_KEY", secret)

	tests := []struct {
		name   string
		method jwt.SigningMethod
		claims TokenClaims
	}{
		{
			name:   "unexpected hmac algorithm",
			method: jwt.SigningMethodHS512,
			claims: TokenClaims{UserID: "user-1", OrganizationID: "org-1", Role: "member", RegisteredClaims: jwt.RegisteredClaims{Issuer: tokenIssuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}},
		},
		{
			name:   "unexpected issuer",
			method: jwt.SigningMethodHS256,
			claims: TokenClaims{UserID: "user-1", OrganizationID: "org-1", Role: "member", RegisteredClaims: jwt.RegisteredClaims{Issuer: "other-service", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}},
		},
		{
			name:   "missing identity claim",
			method: jwt.SigningMethodHS256,
			claims: TokenClaims{UserID: "", OrganizationID: "org-1", Role: "member", RegisteredClaims: jwt.RegisteredClaims{Issuer: tokenIssuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}},
		},
		{
			name:   "missing expiration claim",
			method: jwt.SigningMethodHS256,
			claims: TokenClaims{UserID: "user-1", OrganizationID: "org-1", Role: "member", RegisteredClaims: jwt.RegisteredClaims{Issuer: tokenIssuer}},
		},
		{
			name:   "missing issued-at claim",
			method: jwt.SigningMethodHS256,
			claims: TokenClaims{UserID: "user-1", OrganizationID: "org-1", Role: "member", RegisteredClaims: jwt.RegisteredClaims{Issuer: tokenIssuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := jwt.NewWithClaims(test.method, test.claims).SignedString([]byte(secret))
			if err != nil {
				t.Fatalf("sign token: %v", err)
			}
			if _, err := ValidateToken(token); err == nil {
				t.Fatal("ValidateToken accepted an invalid JWT contract")
			}
		})
	}
}
