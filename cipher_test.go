package encryptfs

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAESGCMEngine(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	engine, err := NewAESGCMEngine(key)
	if err != nil {
		t.Fatalf("NewAESGCMEngine failed: %v", err)
	}

	// Test NonceSize
	if engine.NonceSize() != 12 {
		t.Errorf("NonceSize: got %d, want 12", engine.NonceSize())
	}

	// Test Overhead
	if engine.Overhead() != 16 {
		t.Errorf("Overhead: got %d, want 16", engine.Overhead())
	}

	// Test Encrypt/Decrypt
	nonce := make([]byte, engine.NonceSize())
	rand.Read(nonce)

	plaintext := []byte("Hello, AES-GCM!")

	ciphertext, err := engine.Encrypt(nonce, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := engine.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCMEngine_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Should be 32

	_, err := NewAESGCMEngine(key)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestAESGCMEngine_InvalidNonceSize(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	engine, _ := NewAESGCMEngine(key)

	// Wrong nonce size for encrypt
	_, err := engine.Encrypt([]byte("short"), []byte("plaintext"))
	if err == nil {
		t.Error("Expected error for invalid nonce size in Encrypt")
	}

	// Wrong nonce size for decrypt
	_, err = engine.Decrypt([]byte("short"), []byte("ciphertext"))
	if err == nil {
		t.Error("Expected error for invalid nonce size in Decrypt")
	}
}

func TestChaCha20Poly1305Engine(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	engine, err := NewChaCha20Poly1305Engine(key)
	if err != nil {
		t.Fatalf("NewChaCha20Poly1305Engine failed: %v", err)
	}

	// Test NonceSize
	if engine.NonceSize() != 12 {
		t.Errorf("NonceSize: got %d, want 12", engine.NonceSize())
	}

	// Test Overhead
	if engine.Overhead() != 16 {
		t.Errorf("Overhead: got %d, want 16", engine.Overhead())
	}

	// Test Encrypt/Decrypt
	nonce := make([]byte, engine.NonceSize())
	rand.Read(nonce)

	plaintext := []byte("Hello, ChaCha20-Poly1305!")

	ciphertext, err := engine.Encrypt(nonce, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := engine.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestChaCha20Poly1305Engine_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Should be 32

	_, err := NewChaCha20Poly1305Engine(key)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestChaCha20Poly1305Engine_InvalidNonceSize(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	engine, _ := NewChaCha20Poly1305Engine(key)

	// Wrong nonce size for encrypt
	_, err := engine.Encrypt([]byte("short"), []byte("plaintext"))
	if err == nil {
		t.Error("Expected error for invalid nonce size in Encrypt")
	}

	// Wrong nonce size for decrypt
	_, err = engine.Decrypt([]byte("short"), []byte("ciphertext"))
	if err == nil {
		t.Error("Expected error for invalid nonce size in Decrypt")
	}
}

func TestChaCha20Poly1305Engine_AuthFailed(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	engine, _ := NewChaCha20Poly1305Engine(key)

	nonce := make([]byte, engine.NonceSize())
	rand.Read(nonce)

	// Try to decrypt garbage
	_, err := engine.Decrypt(nonce, []byte("invalid ciphertext with auth tag"))
	if err != ErrAuthFailed {
		t.Errorf("Expected ErrAuthFailed, got %v", err)
	}
}

func TestNewCipherEngine(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tests := []struct {
		cipher    CipherSuite
		expectErr bool
	}{
		{CipherAES256GCM, false},
		{CipherChaCha20Poly1305, false},
		{CipherAuto, false},
		{99, true}, // Invalid cipher
	}

	for _, tt := range tests {
		engine, err := NewCipherEngine(tt.cipher, key)
		if tt.expectErr && err == nil {
			t.Errorf("Cipher %d: expected error", tt.cipher)
		}
		if !tt.expectErr && err != nil {
			t.Errorf("Cipher %d: unexpected error: %v", tt.cipher, err)
		}
		if !tt.expectErr && engine == nil {
			t.Errorf("Cipher %d: engine is nil", tt.cipher)
		}
	}
}

func TestGenerateNonce(t *testing.T) {
	tests := []struct {
		cipher    CipherSuite
		expectLen int
		expectErr bool
	}{
		{CipherAES256GCM, 12, false},
		{CipherChaCha20Poly1305, 12, false},
		{CipherAuto, 12, false},
		{99, 0, true}, // Invalid cipher
	}

	for _, tt := range tests {
		nonce, err := GenerateNonce(tt.cipher)
		if tt.expectErr {
			if err == nil {
				t.Errorf("Cipher %d: expected error", tt.cipher)
			}
			continue
		}
		if err != nil {
			t.Errorf("Cipher %d: unexpected error: %v", tt.cipher, err)
			continue
		}
		if len(nonce) != tt.expectLen {
			t.Errorf("Cipher %d: nonce length %d, want %d", tt.cipher, len(nonce), tt.expectLen)
		}
	}
}

func TestAESGCMEngine_AuthFailed(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	engine, _ := NewAESGCMEngine(key)

	nonce := make([]byte, engine.NonceSize())
	rand.Read(nonce)

	// Try to decrypt garbage
	_, err := engine.Decrypt(nonce, []byte("invalid ciphertext"))
	if err != ErrAuthFailed {
		t.Errorf("Expected ErrAuthFailed, got %v", err)
	}
}
