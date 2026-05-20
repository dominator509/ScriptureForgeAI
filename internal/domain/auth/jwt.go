package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
	if secret == "" {
		// In tests this might be empty, but in prod it MUST be set. We'll fallback to a dummy only for tests
		if os.Getenv("GO_ENV") == "testing" {
			return []byte("test-secret"), nil
		}
		return nil, fmt.Errorf("JWT_SECRET_KEY environment variable is missing")
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
			Issuer:    "scriptureforge-platform",
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
		// Validate the alg is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, &PlatformException{
			Category: AuthenticationFault,
			Message:  "invalid token signature or expiration",
			Code:     401,
		}
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, &PlatformException{
		Category: AuthenticationFault,
		Message:  "invalid token structure",
		Code:     401,
	}
}
