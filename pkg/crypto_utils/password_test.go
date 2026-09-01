package crypto_utils

import (
	"strings"
	"testing"
)

func TestHashPasswordRoundTripUsesUniqueSalt(t *testing.T) {
	first, err := HashPassword("correct horse battery staple", DefaultHashConfig)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	second, err := HashPassword("correct horse battery staple", DefaultHashConfig)
	if err != nil {
		t.Fatalf("HashPassword() second error = %v", err)
	}
	if first == second {
		t.Fatal("HashPassword() reused salt")
	}

	for _, encoded := range []string{first, second} {
		match, err := VerifyPassword("correct horse battery staple", encoded)
		if err != nil || !match {
			t.Fatalf("VerifyPassword() = match=%v error=%v, want match", match, err)
		}
		match, err = VerifyPassword("wrong password", encoded)
		if err != nil || match {
			t.Fatalf("VerifyPassword(wrong) = match=%v error=%v, want mismatch", match, err)
		}
	}
}

func TestHashPasswordRejectsInvalidConfig(t *testing.T) {
	invalid := []*HashConfig{
		nil,
		{Time: 0, Memory: 64 * 1024, Threads: 4, KeyLen: 32},
		{Time: 1, Memory: 64 * 1024, Threads: 0, KeyLen: 32},
		{Time: 1, Memory: 64 * 1024, Threads: 4, KeyLen: 8},
		{Time: 1, Memory: maxMemoryKiB + 1, Threads: 4, KeyLen: 32},
	}
	for _, config := range invalid {
		if hash, err := HashPassword("password", config); err == nil || hash != "" {
			t.Fatalf("HashPassword(%#v) = hash=%q error=%v, want configuration failure", config, hash, err)
		}
	}
}

func TestVerifyPasswordRejectsMalformedAndOverBudgetHashes(t *testing.T) {
	valid, err := HashPassword("password", DefaultHashConfig)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	malformed := []string{
		valid + "$extra",
		strings.Replace(valid, "$argon2id$", "$argon2i$", 1),
		strings.Replace(valid, "m=65536,t=1,p=4", "m=65536,t=1,p=4,p=4", 1),
		strings.Replace(valid, "m=65536,t=1,p=4", "m=999999,t=1,p=4", 1),
		strings.Replace(valid, "m=65536,t=1,p=4", "m=65536,t=1,x=4", 1),
	}
	for _, encoded := range malformed {
		if match, err := VerifyPassword("password", encoded); err == nil || match {
			t.Fatalf("VerifyPassword(%q) = match=%v error=%v, want rejection", encoded, match, err)
		}
	}
}

func TestGenerateSaltRejectsUnsafeLengths(t *testing.T) {
	for _, length := range []int{0, maxSaltLength + 1} {
		if salt, err := GenerateSalt(length); err == nil || salt != nil {
			t.Fatalf("GenerateSalt(%d) = salt=%v error=%v, want rejection", length, salt, err)
		}
	}
	salt, err := GenerateSalt(8)
	if err != nil || len(salt) != 8 {
		t.Fatalf("GenerateSalt(8) = len=%d error=%v", len(salt), err)
	}
}
