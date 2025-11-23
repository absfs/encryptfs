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

// Validate checks if the Argon2id parameters are valid
func (p *Argon2idParams) Validate() error {
	if p.Memory < 8*1024 {
		return errors.New("argon2id memory must be at least 8 MiB (8192 KiB)")
	}
	if p.Memory > 4*1024*1024 {
		return errors.New("argon2id memory must not exceed 4 GiB (4194304 KiB)")
	}
	if p.Iterations < 1 {
		return errors.New("argon2id iterations must be at least 1")
	}
	if p.Iterations > 100 {
		return errors.New("argon2id iterations must not exceed 100")
	}
	if p.Parallelism < 1 {
		return errors.New("argon2id parallelism must be at least 1")
	}
	if p.Parallelism > 255 {
		return errors.New("argon2id parallelism must not exceed 255")
	}
	if p.SaltSize < 16 {
		return errors.New("argon2id salt size must be at least 16 bytes")
	}
	if p.SaltSize > 128 {
		return errors.New("argon2id salt size must not exceed 128 bytes")
	}
	if p.KeySize < 16 {
		return errors.New("argon2id key size must be at least 16 bytes")
	}
	if p.KeySize > 64 {
		return errors.New("argon2id key size must not exceed 64 bytes")
	}
	return nil
}

// Validate checks if the PBKDF2 parameters are valid
func (p *PBKDF2Params) Validate() error {
	if p.Iterations < 100000 {
		return errors.New("pbkdf2 iterations must be at least 100,000 for security")
	}
	if p.Iterations > 10000000 {
		return errors.New("pbkdf2 iterations must not exceed 10,000,000")
	}
	if p.HashFunc != SHA256 && p.HashFunc != SHA512 {
		return errors.New("pbkdf2 hash function must be SHA256 or SHA512")
	}
	if p.SaltSize < 16 {
		return errors.New("pbkdf2 salt size must be at least 16 bytes")
	}
	if p.SaltSize > 128 {
		return errors.New("pbkdf2 salt size must not exceed 128 bytes")
	}
	if p.KeySize < 16 {
		return errors.New("pbkdf2 key size must be at least 16 bytes")
	}
	if p.KeySize > 64 {
		return errors.New("pbkdf2 key size must not exceed 64 bytes")
	}
	return nil
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

	// Parallel controls parallel chunk processing (Phase 5 feature)
	Parallel ParallelConfig
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config cannot be nil")
	}

	// Validate KeyProvider
	if c.KeyProvider == nil {
		return errors.New("key provider cannot be nil")
	}

	// Validate CipherSuite
	if c.Cipher != CipherAES256GCM && c.Cipher != CipherChaCha20Poly1305 && c.Cipher != CipherAuto {
		return errors.New("unsupported cipher suite")
	}

	// Validate FilenameEncryption
	if c.FilenameEncryption != FilenameEncryptionNone &&
		c.FilenameEncryption != FilenameEncryptionDeterministic &&
		c.FilenameEncryption != FilenameEncryptionRandom {
		return errors.New("unsupported filename encryption mode")
	}

	// Validate MetadataPath for random filename encryption
	if c.FilenameEncryption == FilenameEncryptionRandom && c.MetadataPath == "" {
		return errors.New("metadata path must be set when using random filename encryption")
	}

	// Validate ChunkSize
	if c.ChunkSize < 0 {
		return errors.New("chunk size cannot be negative")
	}
	if c.ChunkSize > 0 {
		// ChunkSize must be between 4KB and 16MB
		const minChunkSize = 4 * 1024      // 4KB
		const maxChunkSize = 16 * 1024 * 1024 // 16MB

		if c.ChunkSize < minChunkSize {
			return errors.New("chunk size must be at least 4 KiB when chunked mode is enabled")
		}
		if c.ChunkSize > maxChunkSize {
			return errors.New("chunk size must not exceed 16 MiB")
		}

		// Warn if not a power of 2 (not an error, but suboptimal)
		// Check if power of 2: n & (n-1) == 0
		if c.ChunkSize&(c.ChunkSize-1) != 0 {
			// Not a power of 2 - this is allowed but not recommended
			// Could log a warning here if we had a logger
		}
	}

	// Validate ParallelConfig
	if c.Parallel.Enabled {
		if c.Parallel.MaxWorkers < 0 {
			return errors.New("parallel max workers cannot be negative")
		}
		if c.Parallel.MaxWorkers > 1024 {
			return errors.New("parallel max workers must not exceed 1024")
		}
		if c.Parallel.MinChunksForParallel < 1 {
			return errors.New("parallel min chunks threshold must be at least 1")
		}
		if c.Parallel.MinChunksForParallel > 1000 {
			return errors.New("parallel min chunks threshold must not exceed 1000")
		}

		// Parallel processing requires chunked mode
		if c.ChunkSize == 0 {
			return errors.New("parallel processing requires chunked mode (ChunkSize > 0)")
		}
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
