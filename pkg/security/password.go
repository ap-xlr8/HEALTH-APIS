package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	argon2idTime    uint32 = 1
	argon2idMemory  uint32 = 64 * 1024
	argon2idThreads uint8  = 4
	argon2idKeyLen  uint32 = 32
	argon2idSaltLen        = 16
)

// HashPassword generates an Argon2id hash with random salt.
// Stored format: $argon2id$v=19$m=65536,t=1,p=4$<base64 salt>$<base64 hash>
func HashPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("password must not be empty")
	}
	salt := make([]byte, argon2idSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argon2idTime, argon2idMemory, argon2idThreads, argon2idKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2idMemory,
		argon2idTime,
		argon2idThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// CheckPassword verifies a password against an Argon2id hash.
// Legacy bcrypt hashes ($2a$/$2b$/$2y$) are still verified to allow
// in-place migration, but new hashes are always Argon2id.
func CheckPassword(hash, password string) bool {
	if strings.HasPrefix(hash, "$argon2id$") {
		parsed, err := parseArgon2idHash(hash)
		if err != nil {
			return false
		}
		computed := argon2.IDKey([]byte(password), parsed.salt, parsed.time, parsed.memory, parsed.threads, uint32(len(parsed.hash)))
		return subtle.ConstantTimeCompare(computed, parsed.hash) == 1
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

type argon2idParams struct {
	time    uint32
	memory  uint32
	threads uint8
	salt    []byte
	hash    []byte
}

func parseArgon2idHash(encoded string) (*argon2idParams, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=65536,t=1,p=4", salt, hash]
	if len(parts) != 6 {
		return nil, errors.New("invalid argon2id hash format")
	}
	if parts[1] != "argon2id" {
		return nil, errors.New("unsupported hash algorithm")
	}
	params := &argon2idParams{}
	if _, err := fmt.Sscanf(parts[2], "v=%d", new(int)); err != nil {
		return nil, errors.New("invalid argon2id version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads); err != nil {
		return nil, errors.New("invalid argon2id parameters")
	}
	var err error
	if params.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, errors.New("invalid argon2id salt")
	}
	if params.hash, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return nil, errors.New("invalid argon2id hash")
	}
	return params, nil
}
