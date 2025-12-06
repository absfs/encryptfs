package encryptfs

import (
	"bytes"
	"os"
	"testing"
)

func TestPasswordKeyProvider_Argon2id(t *testing.T) {
	provider := NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	// Generate salt
	salt, err := provider.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt) == 0 {
		t.Error("Salt is empty")
	}

	// Derive key
	key, err := provider.DeriveKey(salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Key length: got %d, want 32", len(key))
	}

	// Derive key again with same salt - should be the same
	key2, err := provider.DeriveKey(salt)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Error("Same salt should produce same key")
	}
}

func TestPasswordKeyProvider_Argon2id_Defaults(t *testing.T) {
	// Test with zero params (should use defaults)
	provider := NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{})

	salt, err := provider.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	key, err := provider.DeriveKey(salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Key length: got %d, want 32", len(key))
	}
}

func TestPasswordKeyProvider_PBKDF2(t *testing.T) {
	provider := NewPasswordKeyProviderPBKDF2([]byte("test-password"), PBKDF2Params{
		Iterations: 10000,
		HashFunc:   SHA256,
	})

	// Generate salt
	salt, err := provider.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	// Derive key
	key, err := provider.DeriveKey(salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Key length: got %d, want 32", len(key))
	}
}

func TestPasswordKeyProvider_PBKDF2_SHA512(t *testing.T) {
	provider := NewPasswordKeyProviderPBKDF2([]byte("test-password"), PBKDF2Params{
		Iterations: 10000,
		HashFunc:   SHA512,
	})

	salt, _ := provider.GenerateSalt()
	key, err := provider.DeriveKey(salt)
	if err != nil {
		t.Fatalf("DeriveKey with SHA512 failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Key length: got %d, want 32", len(key))
	}
}

func TestPasswordKeyProvider_PBKDF2_Defaults(t *testing.T) {
	// Test with zero params (should use defaults)
	provider := NewPasswordKeyProviderPBKDF2([]byte("test-password"), PBKDF2Params{})

	salt, _ := provider.GenerateSalt()
	key, err := provider.DeriveKey(salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Key length: got %d, want 32", len(key))
	}
}

func TestPasswordKeyProvider_EmptyPassword(t *testing.T) {
	provider := NewPasswordKeyProvider([]byte{}, Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	salt, _ := provider.GenerateSalt()

	_, err := provider.DeriveKey(salt)
	if err == nil {
		t.Error("Expected error for empty password")
	}
}

func TestPasswordKeyProvider_EmptySalt(t *testing.T) {
	provider := NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	_, err := provider.DeriveKey([]byte{})
	if err == nil {
		t.Error("Expected error for empty salt")
	}
}

func TestPasswordKeyProvider_DifferentSaltsProduceDifferentKeys(t *testing.T) {
	provider := NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	salt1, _ := provider.GenerateSalt()
	salt2, _ := provider.GenerateSalt()

	key1, _ := provider.DeriveKey(salt1)
	key2, _ := provider.DeriveKey(salt2)

	if bytes.Equal(key1, key2) {
		t.Error("Different salts should produce different keys")
	}
}

func TestPasswordKeyProvider_DifferentPasswordsProduceDifferentKeys(t *testing.T) {
	provider1 := NewPasswordKeyProvider([]byte("password1"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	provider2 := NewPasswordKeyProvider([]byte("password2"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	salt, _ := provider1.GenerateSalt()

	key1, _ := provider1.DeriveKey(salt)
	key2, _ := provider2.DeriveKey(salt)

	if bytes.Equal(key1, key2) {
		t.Error("Different passwords should produce different keys")
	}
}

func TestEnvKeyProvider(t *testing.T) {
	// Set up environment variable with 32-byte key
	key := "12345678901234567890123456789012"
	os.Setenv("TEST_ENCRYPT_KEY", key)
	defer os.Unsetenv("TEST_ENCRYPT_KEY")

	provider := NewEnvKeyProvider("TEST_ENCRYPT_KEY")

	// GenerateSalt
	salt, err := provider.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt) != 32 {
		t.Errorf("Salt length: got %d, want 32", len(salt))
	}

	// DeriveKey
	derivedKey, err := provider.DeriveKey(salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if string(derivedKey) != key {
		t.Errorf("DeriveKey returned %q, want %q", string(derivedKey), key)
	}
}

func TestEnvKeyProvider_NotSet(t *testing.T) {
	os.Unsetenv("NONEXISTENT_KEY")

	provider := NewEnvKeyProvider("NONEXISTENT_KEY")

	salt, _ := provider.GenerateSalt()
	_, err := provider.DeriveKey(salt)
	if err == nil {
		t.Error("Expected error for unset environment variable")
	}
}

func TestEnvKeyProvider_WrongSize(t *testing.T) {
	os.Setenv("TEST_BAD_KEY", "too-short")
	defer os.Unsetenv("TEST_BAD_KEY")

	provider := NewEnvKeyProvider("TEST_BAD_KEY")

	salt, _ := provider.GenerateSalt()
	_, err := provider.DeriveKey(salt)
	if err == nil {
		t.Error("Expected error for wrong key size")
	}
}

func TestPasswordKeyProvider_PBKDF2_UnsupportedHash(t *testing.T) {
	// Create provider with unsupported hash function
	provider := &PasswordKeyProvider{
		password:    []byte("test-password"),
		useArgon2id: false,
		pbkdf2Params: PBKDF2Params{
			Iterations: 10000,
			HashFunc:   99, // Invalid hash function
			SaltSize:   32,
			KeySize:    32,
		},
	}

	salt := make([]byte, 32)
	_, err := provider.DeriveKey(salt)
	if err == nil {
		t.Error("Expected error for unsupported hash function")
	}
}
