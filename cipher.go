package encryptfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherEngine provides AEAD encryption/decryption
type CipherEngine interface {
	// Encrypt encrypts plaintext with the given nonce
	Encrypt(nonce, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext with the given nonce
	Decrypt(nonce, ciphertext []byte) ([]byte, error)

	// NonceSize returns the size of nonces in bytes
	NonceSize() int

	// Overhead returns the authentication tag size
	Overhead() int
}

// AESGCMEngine implements CipherEngine using AES-256-GCM
type AESGCMEngine struct {
	aead cipher.AEAD
}

// NewAESGCMEngine creates a new AES-256-GCM cipher engine
func NewAESGCMEngine(key []byte) (*AESGCMEngine, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires a 32-byte key, got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &AESGCMEngine{aead: aead}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
func (e *AESGCMEngine) Encrypt(nonce, plaintext []byte) ([]byte, error) {
	if len(nonce) != e.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", e.NonceSize(), len(nonce))
	}

	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (e *AESGCMEngine) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != e.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", e.NonceSize(), len(nonce))
	}

	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}

	return plaintext, nil
}

// NonceSize returns the nonce size for AES-GCM (12 bytes)
func (e *AESGCMEngine) NonceSize() int {
	return e.aead.NonceSize()
}

// Overhead returns the authentication tag size (16 bytes)
func (e *AESGCMEngine) Overhead() int {
	return e.aead.Overhead()
}

// ChaCha20Poly1305Engine implements CipherEngine using ChaCha20-Poly1305
type ChaCha20Poly1305Engine struct {
	aead cipher.AEAD
}

// NewChaCha20Poly1305Engine creates a new ChaCha20-Poly1305 cipher engine
func NewChaCha20Poly1305Engine(key []byte) (*ChaCha20Poly1305Engine, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("ChaCha20-Poly1305 requires a %d-byte key, got %d bytes",
			chacha20poly1305.KeySize, len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	return &ChaCha20Poly1305Engine{aead: aead}, nil
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305
func (e *ChaCha20Poly1305Engine) Encrypt(nonce, plaintext []byte) ([]byte, error) {
	if len(nonce) != e.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", e.NonceSize(), len(nonce))
	}

	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305
func (e *ChaCha20Poly1305Engine) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != e.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", e.NonceSize(), len(nonce))
	}

	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}

	return plaintext, nil
}

// NonceSize returns the nonce size for ChaCha20-Poly1305 (12 bytes)
func (e *ChaCha20Poly1305Engine) NonceSize() int {
	return e.aead.NonceSize()
}

// Overhead returns the authentication tag size (16 bytes)
func (e *ChaCha20Poly1305Engine) Overhead() int {
	return e.aead.Overhead()
}

// NewCipherEngine creates a new cipher engine based on the cipher suite
func NewCipherEngine(cipher CipherSuite, key []byte) (CipherEngine, error) {
	switch cipher {
	case CipherAES256GCM:
		return NewAESGCMEngine(key)
	case CipherChaCha20Poly1305:
		return NewChaCha20Poly1305Engine(key)
	case CipherAuto:
		// Auto-select based on hardware capabilities
		// For now, default to AES-256-GCM
		// In the future, we could check for AES-NI support
		return NewAESGCMEngine(key)
	default:
		return nil, ErrUnsupportedCipher
	}
}

// GenerateNonce generates a random nonce for the given cipher
func GenerateNonce(cipher CipherSuite) ([]byte, error) {
	var nonceSize int

	switch cipher {
	case CipherAES256GCM:
		nonceSize = 12 // GCM standard nonce size
	case CipherChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSize
	case CipherAuto:
		nonceSize = 12 // Default to GCM size
	default:
		return nil, ErrUnsupportedCipher
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return nonce, nil
}
