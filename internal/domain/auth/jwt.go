package auth

import (
	"errors"
	"os"
)

func getSecretKey() ([]byte, error) {
	secret := os.Getenv("JWT_SECRET_KEY")
	if secret == "" {
		return nil, errors.New("JWT_SECRET_KEY environment variable is missing")
	}
	return []byte(secret), nil
}
