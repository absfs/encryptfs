package encryptfs

import (
	"fmt"
	"testing"
)

// mockPanicEngine is a mock engine that panics on Encrypt or Decrypt
type mockPanicEngine struct {
	panicOnEncrypt bool
	panicOnDecrypt bool
	panicMessage   string
}

func (m *mockPanicEngine) Encrypt(nonce, plaintext []byte) ([]byte, error) {
	if m.panicOnEncrypt {
		panic(m.panicMessage)
	}
	// Return dummy ciphertext
	return append(plaintext, []byte("encrypted")...), nil
}

func (m *mockPanicEngine) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	if m.panicOnDecrypt {
		panic(m.panicMessage)
	}
	// Return dummy plaintext
	if len(ciphertext) < 9 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return ciphertext[:len(ciphertext)-9], nil
}

func (m *mockPanicEngine) NonceSize() int {
	return 12 // AES-GCM standard nonce size
}

func (m *mockPanicEngine) Overhead() int {
	return 16 // AES-GCM authentication tag size
}

// TestParallelEncryptPanicRecovery tests that panics in encryption workers are recovered
func TestParallelEncryptPanicRecovery(t *testing.T) {
	// Create a chunked file with panic-inducing engine
	base, cleanup := setupTestFS(t)
	defer cleanup()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 64 * 1024,
		Parallel:  DefaultParallelConfig(),
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/test.bin")
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	cf, ok := file.(*ChunkedFile)
	if !ok {
		t.Fatal("Expected ChunkedFile")
	}

	// Replace engine with panic-inducing mock
	originalEngine := cf.engine
	cf.engine = &mockPanicEngine{
		panicOnEncrypt: true,
		panicMessage:   "test panic in encryption",
	}

	// Create jobs that will trigger panic
	jobs := []chunkJob{
		{index: 0, plaintext: []byte("test1"), nonce: make([]byte, 12)},
		{index: 1, plaintext: []byte("test2"), nonce: make([]byte, 12)},
		{index: 2, plaintext: []byte("test3"), nonce: make([]byte, 12)},
		{index: 3, plaintext: []byte("test4"), nonce: make([]byte, 12)},
		{index: 4, plaintext: []byte("test5"), nonce: make([]byte, 12)},
	}

	// This should recover from panic and return an error
	err = cf.parallelEncryptChunks(jobs)

	// Restore original engine
	cf.engine = originalEngine

	if err == nil {
		t.Fatal("Expected error from panic recovery, got nil")
	}

	// Check that error message contains panic information
	expectedSubstring := "panic in encryption worker"
	if len(err.Error()) < len(expectedSubstring) || err.Error()[:len(expectedSubstring)] != expectedSubstring {
		t.Errorf("Expected error message to start with %q, got %q", expectedSubstring, err.Error())
	}

	t.Logf("Successfully recovered from panic: %v", err)
}

// TestParallelDecryptPanicRecovery tests that panics in decryption workers are recovered
func TestParallelDecryptPanicRecovery(t *testing.T) {
	// Create a chunked file with panic-inducing engine
	base, cleanup := setupTestFS(t)
	defer cleanup()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 64 * 1024,
		Parallel:  DefaultParallelConfig(),
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/test.bin")
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	cf, ok := file.(*ChunkedFile)
	if !ok {
		t.Fatal("Expected ChunkedFile")
	}

	// Replace engine with panic-inducing mock
	originalEngine := cf.engine
	cf.engine = &mockPanicEngine{
		panicOnDecrypt: true,
		panicMessage:   "test panic in decryption",
	}

	// Create jobs that will trigger panic
	jobs := []chunkJob{
		{index: 0, ciphertext: []byte("test1encrypted"), nonce: make([]byte, 12)},
		{index: 1, ciphertext: []byte("test2encrypted"), nonce: make([]byte, 12)},
		{index: 2, ciphertext: []byte("test3encrypted"), nonce: make([]byte, 12)},
		{index: 3, ciphertext: []byte("test4encrypted"), nonce: make([]byte, 12)},
		{index: 4, ciphertext: []byte("test5encrypted"), nonce: make([]byte, 12)},
	}

	// This should recover from panic and return an error
	err = cf.parallelDecryptChunks(jobs)

	// Restore original engine
	cf.engine = originalEngine

	if err == nil {
		t.Fatal("Expected error from panic recovery, got nil")
	}

	// Check that error message contains panic information
	expectedSubstring := "panic in decryption worker"
	if len(err.Error()) < len(expectedSubstring) || err.Error()[:len(expectedSubstring)] != expectedSubstring {
		t.Errorf("Expected error message to start with %q, got %q", expectedSubstring, err.Error())
	}

	t.Logf("Successfully recovered from panic: %v", err)
}

// TestParallelEncryptNoPanic tests that normal operation doesn't trigger panic recovery
func TestParallelEncryptNoPanic(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 64 * 1024,
		Parallel:  DefaultParallelConfig(),
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/test.bin")
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	cf, ok := file.(*ChunkedFile)
	if !ok {
		t.Fatal("Expected ChunkedFile")
	}

	// Replace engine with non-panicking mock
	originalEngine := cf.engine
	cf.engine = &mockPanicEngine{
		panicOnEncrypt: false, // No panic
	}

	// Create jobs
	jobs := []chunkJob{
		{index: 0, plaintext: []byte("test1"), nonce: make([]byte, 12)},
		{index: 1, plaintext: []byte("test2"), nonce: make([]byte, 12)},
		{index: 2, plaintext: []byte("test3"), nonce: make([]byte, 12)},
		{index: 3, plaintext: []byte("test4"), nonce: make([]byte, 12)},
		{index: 4, plaintext: []byte("test5"), nonce: make([]byte, 12)},
	}

	// This should succeed without panic
	err = cf.parallelEncryptChunks(jobs)

	// Restore original engine
	cf.engine = originalEngine

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify all jobs were processed
	for i, job := range jobs {
		if job.ciphertext == nil {
			t.Errorf("Job %d was not processed", i)
		}
	}
}

// TestParallelDecryptNoPanic tests that normal operation doesn't trigger panic recovery
func TestParallelDecryptNoPanic(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 64 * 1024,
		Parallel:  DefaultParallelConfig(),
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/test.bin")
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	cf, ok := file.(*ChunkedFile)
	if !ok {
		t.Fatal("Expected ChunkedFile")
	}

	// Replace engine with non-panicking mock
	originalEngine := cf.engine
	cf.engine = &mockPanicEngine{
		panicOnDecrypt: false, // No panic
	}

	// Create jobs
	jobs := []chunkJob{
		{index: 0, ciphertext: []byte("test1encrypted"), nonce: make([]byte, 12)},
		{index: 1, ciphertext: []byte("test2encrypted"), nonce: make([]byte, 12)},
		{index: 2, ciphertext: []byte("test3encrypted"), nonce: make([]byte, 12)},
		{index: 3, ciphertext: []byte("test4encrypted"), nonce: make([]byte, 12)},
		{index: 4, ciphertext: []byte("test5encrypted"), nonce: make([]byte, 12)},
	}

	// This should succeed without panic
	err = cf.parallelDecryptChunks(jobs)

	// Restore original engine
	cf.engine = originalEngine

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify all jobs were processed
	for i, job := range jobs {
		if job.plaintext == nil {
			t.Errorf("Job %d was not processed", i)
		}
	}
}
