package auth

import crypto_utils "scriptureforge/pkg/crypto_utils"

// HashConfig remains available from the auth package for compatibility with
// existing handlers while the shared implementation lives in crypto_utils.
type HashConfig = crypto_utils.HashConfig

// DefaultHashConfig preserves the existing auth call-site contract.
var DefaultHashConfig = crypto_utils.DefaultHashConfig

// GenerateSalt delegates to the shared server-side crypto boundary.
func GenerateSalt(length int) ([]byte, error) {
	return crypto_utils.GenerateSalt(length)
}

// HashPassword delegates to the shared Argon2id implementation.
func HashPassword(password string, config *HashConfig) (string, error) {
	return crypto_utils.HashPassword(password, config)
}

// VerifyPassword delegates to the bounded Argon2id parser and verifier.
func VerifyPassword(password, encodedHash string) (bool, error) {
	return crypto_utils.VerifyPassword(password, encodedHash)
}
