// Package crypto_utils contains shared server-side cryptographic primitives.
package crypto_utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultSaltLength = 16
	minSaltLength     = 1
	minHashSaltLength = 16
	maxSaltLength     = 1024
	minKeyLength      = 16
	maxKeyLength      = 64
	maxMemoryKiB      = 256 * 1024
	maxTime           = 4
	maxThreads        = 16
)

// HashConfig specifies the Argon2id work factors used for password hashing.
type HashConfig struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

// DefaultHashConfig is the production baseline used by the authentication API.
var DefaultHashConfig = &HashConfig{
	Time:    1,
	Memory:  64 * 1024,
	Threads: 4,
	KeyLen:  32,
}

// GenerateSalt returns cryptographically secure random salt material.
func GenerateSalt(length int) ([]byte, error) {
	if length < minSaltLength || length > maxSaltLength {
		return nil, fmt.Errorf("salt length must be between %d and %d bytes", minSaltLength, maxSaltLength)
	}

	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		clearBytes(salt)
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	return salt, nil
}

// HashPassword generates an Argon2id hash for the supplied password.
func HashPassword(password string, config *HashConfig) (string, error) {
	if err := validateHashConfig(config); err != nil {
		return "", err
	}

	salt, err := GenerateSalt(DefaultSaltLength)
	if err != nil {
		return "", err
	}
	defer clearBytes(salt)

	passwordBytes := []byte(password)
	defer clearBytes(passwordBytes)
	hash := argon2.IDKey(passwordBytes, salt, config.Time, config.Memory, config.Threads, config.KeyLen)
	defer clearBytes(hash)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, config.Memory, config.Time, config.Threads, b64Salt, b64Hash), nil
}

// VerifyPassword checks a password against an encoded Argon2id hash. Stored
// parameters are bounded before Argon2 work begins to prevent hash-row DoS.
func VerifyPassword(password, encodedHash string) (bool, error) {
	version, memory, timeCost, threads, salt, expected, err := parseEncodedHash(encodedHash)
	if err != nil {
		return false, err
	}
	defer clearBytes(salt)
	defer clearBytes(expected)

	if version != argon2.Version {
		return false, errors.New("incompatible argon2 version")
	}
	if memory < 8 || threads == 0 || memory < uint32(threads)*8 || memory > maxMemoryKiB || timeCost == 0 || timeCost > maxTime || threads > maxThreads {
		return false, errors.New("argon2 parameters exceed verification limits")
	}

	passwordBytes := []byte(password)
	defer clearBytes(passwordBytes)
	actual := argon2.IDKey(passwordBytes, salt, timeCost, memory, threads, uint32(len(expected)))
	defer clearBytes(actual)
	return subtle.ConstantTimeCompare(expected, actual) == 1, nil
}

func validateHashConfig(config *HashConfig) error {
	if config == nil {
		return errors.New("argon2 hash config is required")
	}
	if config.Time == 0 || config.Time > maxTime {
		return fmt.Errorf("argon2 time must be between 1 and %d", maxTime)
	}
	if config.Memory < 8 || config.Memory > maxMemoryKiB {
		return fmt.Errorf("argon2 memory must be between 8 and %d KiB", maxMemoryKiB)
	}
	if config.Threads == 0 || config.Threads > maxThreads {
		return fmt.Errorf("argon2 threads must be between 1 and %d", maxThreads)
	}
	if config.Memory < uint32(config.Threads)*8 {
		return errors.New("argon2 memory is too small for the configured parallelism")
	}
	if config.KeyLen < minKeyLength || config.KeyLen > maxKeyLength {
		return fmt.Errorf("argon2 key length must be between %d and %d bytes", minKeyLength, maxKeyLength)
	}
	return nil
}

func parseEncodedHash(encodedHash string) (uint32, uint32, uint32, uint8, []byte, []byte, error) {
	if len(encodedHash) > 512 {
		return 0, 0, 0, 0, nil, nil, errors.New("encoded hash is too large")
	}
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return 0, 0, 0, 0, nil, nil, errors.New("invalid hash format")
	}

	version, err := parseUintField(parts[2], "v", 32)
	if err != nil {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("invalid argon2 version: %w", err)
	}
	memory, timeCost, threadValue, err := parseArgon2Params(parts[3])
	if err != nil {
		return 0, 0, 0, 0, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minHashSaltLength || len(salt) > maxSaltLength {
		return 0, 0, 0, 0, nil, nil, errors.New("invalid argon2 salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < minKeyLength || len(expected) > maxKeyLength {
		clearBytes(salt)
		return 0, 0, 0, 0, nil, nil, errors.New("invalid argon2 hash")
	}
	return uint32(version), memory, timeCost, uint8(threadValue), salt, expected, nil
}

func parseArgon2Params(params string) (uint32, uint32, uint64, error) {
	fields := strings.Split(params, ",")
	if len(fields) != 3 {
		return 0, 0, 0, errors.New("invalid argon2 parameters")
	}
	seen := make(map[string]struct{}, len(fields))
	var memory, timeCost, threads uint64
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			return 0, 0, 0, errors.New("invalid argon2 parameter field")
		}
		name := parts[0]
		if _, exists := seen[name]; exists {
			return 0, 0, 0, errors.New("duplicate argon2 parameter")
		}
		seen[name] = struct{}{}
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return 0, 0, 0, errors.New("invalid argon2 parameter value")
		}
		switch name {
		case "m":
			memory = value
		case "t":
			timeCost = value
		case "p":
			threads = value
		default:
			return 0, 0, 0, errors.New("unknown argon2 parameter")
		}
	}
	if len(seen) != 3 {
		return 0, 0, 0, errors.New("missing argon2 parameter")
	}
	if memory > ^uint64(0)>>32 || timeCost > ^uint64(0)>>32 || threads > ^uint64(0)>>8 {
		return 0, 0, 0, errors.New("argon2 parameter is out of range")
	}
	return uint32(memory), uint32(timeCost), threads, nil
}

func parseUintField(field, name string, bitSize int) (uint64, error) {
	if !strings.HasPrefix(field, name+"=") {
		return 0, errors.New("missing field")
	}
	value := strings.TrimPrefix(field, name+"=")
	if value == "" {
		return 0, errors.New("empty value")
	}
	return strconv.ParseUint(value, 10, bitSize)
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
