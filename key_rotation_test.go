package encryptfs

import (
	"bytes"
	"io"
	"testing"
)

func TestMultiKeyProvider(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	// Create file with original key
	originalKey := NewPasswordKeyProvider([]byte("original-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	config1 := &Config{
		Cipher:      CipherAES256GCM,
		KeyProvider: originalKey,
	}

	fs1, err := New(base, config1)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	testData := []byte("Secret data encrypted with original key")

	// Write with original key
	file, err := fs1.Create("/test.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	file.Write(testData)
	file.Close()

	// Create multi-key provider with old and new keys
	newKey := NewPasswordKeyProvider([]byte("new-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	multiKey, err := NewMultiKeyProvider(newKey, originalKey)
	if err != nil {
		t.Fatalf("failed to create multi-key provider: %v", err)
	}

	config2 := &Config{
		Cipher:      CipherAES256GCM,
		KeyProvider: multiKey,
	}

	fs2, err := New(base, config2)
	if err != nil {
		t.Fatalf("failed to create EncryptFS with multi-key: %v", err)
	}

	// Should be able to read file encrypted with old key
	file, err = fs2.Open("/test.txt")
	if err != nil {
		t.Fatalf("failed to open file with multi-key: %v", err)
	}

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	file.Close()

	if !bytes.Equal(readData, testData) {
		t.Fatalf("data mismatch when reading with multi-key provider")
	}
}

func TestReEncrypt(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	// Create file with original key
	originalKey := NewPasswordKeyProvider([]byte("original-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	config := &Config{
		Cipher:      CipherAES256GCM,
		KeyProvider: originalKey,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	testData := []byte("Data to be re-encrypted")

	// Write with original key
	file, err := fs.Create("/reencrypt.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	file.Write(testData)
	file.Close()

	// Re-encrypt with new key
	newKey := NewPasswordKeyProvider([]byte("new-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	opts := KeyRotationOptions{
		NewKeyProvider: newKey,
		Verbose:        false,
	}

	if err := fs.ReEncrypt("/reencrypt.txt", opts); err != nil {
		t.Fatalf("failed to re-encrypt: %v", err)
	}

	// Old key should no longer work
	file, err = fs.Open("/reencrypt.txt")
	if err == nil {
		file.Close()
		t.Fatal("old key should not be able to decrypt re-encrypted file")
	}

	// New key should work
	newConfig := &Config{
		Cipher:      CipherAES256GCM,
		KeyProvider: newKey,
	}

	newFS, err := New(base, newConfig)
	if err != nil {
		t.Fatalf("failed to create new EncryptFS: %v", err)
	}

	file, err = newFS.Open("/reencrypt.txt")
	if err != nil {
		t.Fatalf("failed to open with new key: %v", err)
	}

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read with new key: %v", err)
	}
	file.Close()

	if !bytes.Equal(readData, testData) {
		t.Fatalf("data mismatch after re-encryption")
	}
}

func TestMigrateCipher(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	keyProvider := NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	// Create file with AES-256-GCM
	config1 := &Config{
		Cipher:      CipherAES256GCM,
		KeyProvider: keyProvider,
	}

	fs1, err := New(base, config1)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	testData := []byte("Data encrypted with AES")

	file, err := fs1.Create("/migrate.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	file.Write(testData)
	file.Close()

	// Migrate to ChaCha20-Poly1305
	opts := KeyRotationOptions{
		NewKeyProvider: keyProvider, // Same key, different cipher
		NewCipher:      CipherChaCha20Poly1305,
	}

	if err := fs1.ReEncrypt("/migrate.txt", opts); err != nil {
		t.Fatalf("failed to migrate cipher: %v", err)
	}

	// Read with ChaCha20 config
	config2 := &Config{
		Cipher:      CipherChaCha20Poly1305,
		KeyProvider: keyProvider,
	}

	fs2, err := New(base, config2)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	file, err = fs2.Open("/migrate.txt")
	if err != nil {
		t.Fatalf("failed to open migrated file: %v", err)
	}

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read migrated file: %v", err)
	}
	file.Close()

	if !bytes.Equal(readData, testData) {
		t.Fatalf("data mismatch after cipher migration")
	}
}

func TestVerifyEncryption(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	// Create valid encrypted file
	file, err := fs.Create("/valid.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	file.Write([]byte("valid data"))
	file.Close()

	// Verify should succeed
	if err := fs.VerifyEncryption("/valid.txt"); err != nil {
		t.Fatalf("verification failed for valid file: %v", err)
	}

	// Create file with wrong key
	wrongConfig := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("wrong-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
	}

	wrongFS, err := New(base, wrongConfig)
	if err != nil {
		t.Fatalf("failed to create wrong EncryptFS: %v", err)
	}

	// Verify should fail with wrong key
	if err := wrongFS.VerifyEncryption("/valid.txt"); err == nil {
		t.Fatal("verification should fail with wrong key")
	}
}

func TestDryRun(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	originalKey := NewPasswordKeyProvider([]byte("original"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	config := &Config{
		Cipher:      CipherAES256GCM,
		KeyProvider: originalKey,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	// Create file
	file, err := fs.Create("/dryrun.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	file.Write([]byte("test data"))
	file.Close()

	// Dry run re-encryption
	newKey := NewPasswordKeyProvider([]byte("new-key"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	opts := KeyRotationOptions{
		NewKeyProvider: newKey,
		DryRun:         true,
	}

	if err := fs.ReEncrypt("/dryrun.txt", opts); err != nil {
		t.Fatalf("dry run failed: %v", err)
	}

	// File should still be readable with original key
	file, err = fs.Open("/dryrun.txt")
	if err != nil {
		t.Fatalf("failed to open after dry run: %v", err)
	}
	file.Close()

	// File should not be readable with new key (dry run didn't change it)
	newConfig := &Config{
		Cipher:      CipherAES256GCM,
		KeyProvider: newKey,
	}

	newFS, err := New(base, newConfig)
	if err != nil {
		t.Fatalf("failed to create new EncryptFS: %v", err)
	}

	file, err = newFS.Open("/dryrun.txt")
	if err == nil {
		file.Close()
		t.Fatal("dry run should not have changed the encryption")
	}
}
