package security

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPasswordArgon2id(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("Correct-Horse-Battery-Staple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("expected argon2id prefix, got %q", hash)
	}
	if !CheckPassword(hash, "Correct-Horse-Battery-Staple") {
		t.Fatal("expected password to verify")
	}
	if CheckPassword(hash, "wrong-password") {
		t.Fatal("expected wrong password to fail")
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	t.Parallel()
	hash1, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	hash2, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash1 == hash2 {
		t.Fatal("expected unique salts to produce different hashes")
	}
}

func TestCheckPasswordEmpty(t *testing.T) {
	t.Parallel()
	if _, err := HashPassword(""); err == nil {
		t.Fatal("expected error for empty password")
	}
	if CheckPassword("not-a-valid-hash", "anything") {
		t.Fatal("expected invalid hash to fail verification")
	}
}

func TestCheckPasswordLegacyBcrypt(t *testing.T) {
	t.Parallel()
	legacyBytes, err := bcrypt.GenerateFromPassword([]byte("legacy-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}
	legacy := string(legacyBytes)
	if !CheckPassword(legacy, "legacy-password") {
		t.Fatal("expected legacy bcrypt hash to verify during migration")
	}
	if CheckPassword(legacy, "not-the-password") {
		t.Fatal("expected wrong password against legacy hash to fail")
	}
}
