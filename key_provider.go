package encryptfs

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// PasswordKeyProvider implements KeyProvider using password-based key derivation
type PasswordKeyProvider struct {
	password     []byte
	useArgon2id  bool
	pbkdf2Params PBKDF2Params
	argon2Params Argon2idParams
}

// NewPasswordKeyProviderPBKDF2 creates a new password-based key provider using PBKDF2
func NewPasswordKeyProviderPBKDF2(password []byte, params PBKDF2Params) *PasswordKeyProvider {
	// Set defaults
	if params.Iterations == 0 {
		params.Iterations = 100000
	}
	if params.SaltSize == 0 {
		params.SaltSize = 32
	}
	if params.KeySize == 0 {
		params.KeySize = 32
	}

	return &PasswordKeyProvider{
		password:     password,
		useArgon2id:  false,
		pbkdf2Params: params,
	}
}

// NewPasswordKeyProvider creates a new password-based key provider using Argon2id (recommended)
func NewPasswordKeyProvider(password []byte, params Argon2idParams) *PasswordKeyProvider {
	// Set defaults
	if params.Memory == 0 {
		params.Memory = 64 * 1024 // 64 MB
	}
	if params.Iterations == 0 {
		params.Iterations = 3
	}
	if params.Parallelism == 0 {
		params.Parallelism = 4
	}
	if params.SaltSize == 0 {
		params.SaltSize = 32
	}
	if params.KeySize == 0 {
		params.KeySize = 32
	}

	return &PasswordKeyProvider{
		password:     password,
		useArgon2id:  true,
		argon2Params: params,
	}
}

// DeriveKey derives an encryption key from the password and salt
func (p *PasswordKeyProvider) DeriveKey(salt []byte) ([]byte, error) {
	if len(p.password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	if p.useArgon2id {
		// Use Argon2id
		key := argon2.IDKey(
			p.password,
			salt,
			p.argon2Params.Iterations,
			p.argon2Params.Memory,
			p.argon2Params.Parallelism,
			uint32(p.argon2Params.KeySize),
		)
		return key, nil
	}

	// Use PBKDF2
	var hashFunc func() hash.Hash
	switch p.pbkdf2Params.HashFunc {
	case SHA256:
		hashFunc = sha256.New
	case SHA512:
		hashFunc = sha512.New
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", p.pbkdf2Params.HashFunc)
	}

	key := pbkdf2.Key(
		p.password,
		salt,
		p.pbkdf2Params.Iterations,
		p.pbkdf2Params.KeySize,
		hashFunc,
	)
	return key, nil
}

// GenerateSalt generates a new random salt
func (p *PasswordKeyProvider) GenerateSalt() ([]byte, error) {
	var saltSize int
	if p.useArgon2id {
		saltSize = p.argon2Params.SaltSize
	} else {
		saltSize = p.pbkdf2Params.SaltSize
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// EnvKeyProvider implements KeyProvider using an environment variable
type EnvKeyProvider struct {
	envVar   string
	saltSize int
}

// NewEnvKeyProvider creates a new environment variable key provider
func NewEnvKeyProvider(envVar string) *EnvKeyProvider {
	return &EnvKeyProvider{
		envVar:   envVar,
		saltSize: 32,
	}
}

// DeriveKey returns the key from the environment variable
// For env-based keys, the salt is ignored as the key is pre-derived
func (e *EnvKeyProvider) DeriveKey(salt []byte) ([]byte, error) {
	keyHex := os.Getenv(e.envVar)
	if keyHex == "" {
		return nil, fmt.Errorf("environment variable %s not set", e.envVar)
	}

	// For simplicity, we expect the key to be provided as raw bytes
	// In production, you might want to use hex or base64 encoding
	key := []byte(keyHex)

	if len(key) != 32 {
		return nil, fmt.Errorf("key from environment variable must be 32 bytes, got %d", len(key))
	}

	return key, nil
}

// GenerateSalt generates a new random salt
func (e *EnvKeyProvider) GenerateSalt() ([]byte, error) {
	salt := make([]byte, e.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
