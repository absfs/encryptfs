package encryptfs

import (
	"errors"
	"hash"
)

// CipherSuite represents the encryption algorithm to use
type CipherSuite uint8

const (
	// CipherAuto automatically selects the best cipher based on hardware capabilities
	CipherAuto CipherSuite = iota
	// CipherAES256GCM uses AES-256 with Galois/Counter Mode
	CipherAES256GCM
	// CipherChaCha20Poly1305 uses ChaCha20 stream cipher with Poly1305 MAC
	CipherChaCha20Poly1305
)

// String returns the string representation of the cipher suite
func (c CipherSuite) String() string {
	switch c {
	case CipherAuto:
		return "auto"
	case CipherAES256GCM:
		return "aes-256-gcm"
	case CipherChaCha20Poly1305:
		return "chacha20-poly1305"
	default:
		return "unknown"
	}
}

// FilenameEncryption represents the filename encryption mode
type FilenameEncryption uint8

const (
	// FilenameEncryptionNone does not encrypt filenames
	FilenameEncryptionNone FilenameEncryption = iota
	// FilenameEncryptionDeterministic uses SIV mode for deterministic encryption
	FilenameEncryptionDeterministic
	// FilenameEncryptionRandom uses random encryption with metadata database
	FilenameEncryptionRandom
)

// HashFunc represents hash function types for PBKDF2
type HashFunc uint8

const (
	// SHA256 hash function
	SHA256 HashFunc = iota
	// SHA512 hash function
	SHA512
)

// PBKDF2Params contains parameters for PBKDF2 key derivation
type PBKDF2Params struct {
	Iterations int      // Number of iterations (minimum 100,000 recommended)
	HashFunc   HashFunc // Hash function to use
	SaltSize   int      // Salt size in bytes (default 32)
	KeySize    int      // Derived key size in bytes (default 32 for AES-256)
}

// Argon2idParams contains parameters for Argon2id key derivation
type Argon2idParams struct {
	Memory      uint32 // Memory in KiB (e.g., 64*1024 for 64MB)
	Iterations  uint32 // Number of iterations (time parameter)
	Parallelism uint8  // Degree of parallelism
	SaltSize    int    // Salt size in bytes (default 32)
	KeySize     int    // Derived key size in bytes (default 32 for AES-256)
}

// Config contains configuration for the encrypted filesystem
type Config struct {
	// Cipher suite to use for encryption
	Cipher CipherSuite

	// KeyProvider supplies encryption keys
	KeyProvider KeyProvider

	// FilenameEncryption mode (Phase 3 feature)
	FilenameEncryption FilenameEncryption

	// PreserveExtensions keeps file extensions visible when using filename encryption
	PreserveExtensions bool

	// MetadataPath is the path to store metadata for random filename encryption
	MetadataPath string

	// ChunkSize for streaming encryption (Phase 4 feature)
	ChunkSize int

	// EnableSeek allows seeking within encrypted files (Phase 4 feature)
	EnableSeek bool
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config cannot be nil")
	}
	if c.KeyProvider == nil {
		return errors.New("key provider cannot be nil")
	}
	if c.Cipher != CipherAES256GCM && c.Cipher != CipherChaCha20Poly1305 && c.Cipher != CipherAuto {
		return errors.New("unsupported cipher suite")
	}
	return nil
}

// KeyProvider is an interface for providing encryption keys
type KeyProvider interface {
	// DeriveKey derives an encryption key from the given salt
	DeriveKey(salt []byte) ([]byte, error)

	// GenerateSalt generates a new random salt
	GenerateSalt() ([]byte, error)
}

// HashFuncToHash converts HashFunc to hash.Hash
func HashFuncToHash(hf HashFunc) func() hash.Hash {
	switch hf {
	case SHA256:
		return func() hash.Hash {
			// Import crypto/sha256
			return nil // Will be implemented
		}
	case SHA512:
		return func() hash.Hash {
			// Import crypto/sha512
			return nil // Will be implemented
		}
	default:
		return func() hash.Hash {
			return nil
		}
	}
}

// Common errors
var (
	ErrInvalidKey        = errors.New("invalid encryption key")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrAuthFailed        = errors.New("authentication failed - data may be corrupted or tampered")
	ErrInvalidHeader     = errors.New("invalid file header")
	ErrUnsupportedVersion = errors.New("unsupported file format version")
	ErrUnsupportedCipher = errors.New("unsupported cipher suite")
)
