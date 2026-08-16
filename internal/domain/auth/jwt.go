package auth

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	MinimumSecretBytes = 32
	tokenIssuer        = "scriptureforge-platform"
)

// ValidateSecretStrength keeps runtime-injected signing and derivation secrets
// out of the weak-key path while preserving the original secret bytes.
func ValidateSecretStrength(name, secret string) error {
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("%s environment variable is missing", name)
	}
	if len([]byte(secret)) < MinimumSecretBytes {
		return fmt.Errorf("%s must be at least %d bytes", name, MinimumSecretBytes)
	}
	return nil
}

// Define custom PlatformException types to adhere to structural requirements
type ErrorCategory string

const (
	AuthenticationFault ErrorCategory = "AUTHENTICATION_FAULT"
	AuthorizationFault  ErrorCategory = "AUTHORIZATION_FAULT"
)

type PlatformException struct {
	Category ErrorCategory `json:"category"`
	Message  string        `json:"message"`
	Code     int           `json:"code"`
	TraceID  string        `json:"trace_id"`
}

func (e *PlatformException) Error() string {
	return e.Message
}

// TokenClaims represents the payload embedded in the JWT
type TokenClaims struct {
	UserID         string `json:"user_id"`
	OrganizationID string `json:"org_id"`
	Role           string `json:"role"`
	jwt.RegisteredClaims
}

// getSecretKey loads the key securely from the environment, defaulting to an error if not set
func getSecretKey() ([]byte, error) {
	secret := os.Getenv("JWT_SECRET_KEY")
	if err := ValidateSecretStrength("JWT_SECRET_KEY", secret); err != nil {
		return nil, err
	}
	return []byte(secret), nil
}

// GenerateToken creates a signed JWT for the authenticated user
func GenerateToken(userID, orgID, role string, duration time.Duration) (string, error) {
	secretKey, err := getSecretKey()
	if err != nil {
		return "", &PlatformException{
			Category: AuthenticationFault,
			Message:  "server configuration error",
			Code:     500,
		}
	}

	claims := TokenClaims{
		UserID:         userID,
		OrganizationID: orgID,
		Role:           role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    tokenIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", &PlatformException{
			Category: AuthenticationFault,
			Message:  fmt.Sprintf("failed to sign token: %v", err),
			Code:     500,
		}
	}
	return signedToken, nil
}

// ValidateToken parses and verifies the JWT signature and claims
func ValidateToken(tokenString string) (*TokenClaims, error) {
	secretKey, err := getSecretKey()
	if err != nil {
		return nil, &PlatformException{
			Category: AuthenticationFault,
			Message:  "server configuration error",
			Code:     500,
		}
	}

	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Accept only the algorithm used by our issuer. Accepting any HMAC
		// variant weakens the protocol contract even when the signing secret is
		// shared correctly.
		if token.Method == nil || token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	}, jwt.WithIssuer(tokenIssuer))

	if err != nil {
		return nil, &PlatformException{
			Category: AuthenticationFault,
			Message:  "invalid token signature or expiration",
			Code:     401,
		}
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		if strings.TrimSpace(claims.UserID) == "" ||
			strings.TrimSpace(claims.OrganizationID) == "" ||
			strings.TrimSpace(claims.Role) == "" {
			return nil, &PlatformException{
				Category: AuthenticationFault,
				Message:  "invalid token identity claims",
				Code:     401,
			}
		}
		return claims, nil
	}

	return nil, &PlatformException{
		Category: AuthenticationFault,
		Message:  "invalid token structure",
		Code:     401,
	}
}
