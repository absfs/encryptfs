package encryptfs

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSIVEngine_EncryptDecrypt(t *testing.T) {
	// Generate a 64-byte key for SIV
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	siv, err := NewSIVEngine(key)
	if err != nil {
		t.Fatalf("Failed to create SIV engine: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
		ad        [][]byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("Hello, World!"),
			ad:        nil,
		},
		{
			name:      "empty plaintext",
			plaintext: []byte(""),
			ad:        nil,
		},
		{
			name:      "with AD",
			plaintext: []byte("secret message"),
			ad:        [][]byte{[]byte("context1"), []byte("context2")},
		},
		{
			name:      "long plaintext",
			plaintext: bytes.Repeat([]byte("A"), 1000),
			ad:        nil,
		},
		{
			name:      "short plaintext",
			plaintext: []byte("x"),
			ad:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := siv.Encrypt(tt.plaintext, tt.ad...)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Verify ciphertext is longer than plaintext (includes SIV)
			if len(ciphertext) < len(tt.plaintext)+16 {
				t.Errorf("Ciphertext too short: got %d, want at least %d", len(ciphertext), len(tt.plaintext)+16)
			}

			// Decrypt
			decrypted, err := siv.Decrypt(ciphertext, tt.ad...)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify plaintext matches
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypted plaintext doesn't match:\ngot:  %q\nwant: %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestSIVEngine_Deterministic(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	siv, err := NewSIVEngine(key)
	if err != nil {
		t.Fatalf("Failed to create SIV engine: %v", err)
	}

	plaintext := []byte("deterministic test")

	// Encrypt the same plaintext twice
	ciphertext1, err := siv.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	ciphertext2, err := siv.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Verify ciphertexts are identical (deterministic)
	if !bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("SIV is not deterministic:\nfirst:  %x\nsecond: %x", ciphertext1, ciphertext2)
	}
}

func TestSIVEngine_ADMismatch(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	siv, err := NewSIVEngine(key)
	if err != nil {
		t.Fatalf("Failed to create SIV engine: %v", err)
	}

	plaintext := []byte("test message")
	ad1 := [][]byte{[]byte("context1")}
	ad2 := [][]byte{[]byte("context2")}

	// Encrypt with AD1
	ciphertext, err := siv.Encrypt(plaintext, ad1...)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with AD2 (should fail)
	_, err = siv.Decrypt(ciphertext, ad2...)
	if err == nil {
		t.Error("Decrypt should have failed with mismatched AD")
	}
	if err != ErrAuthFailed {
		t.Errorf("Expected ErrAuthFailed, got: %v", err)
	}

	// Decrypt with correct AD1 (should succeed)
	decrypted, err := siv.Decrypt(ciphertext, ad1...)
	if err != nil {
		t.Fatalf("Decrypt with correct AD failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted plaintext doesn't match")
	}
}

func TestSIVEngine_Tampering(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	siv, err := NewSIVEngine(key)
	if err != nil {
		t.Fatalf("Failed to create SIV engine: %v", err)
	}

	plaintext := []byte("important message")

	// Encrypt
	ciphertext, err := siv.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper with ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0x01 // Flip a bit

	// Try to decrypt tampered ciphertext (should fail)
	_, err = siv.Decrypt(tampered)
	if err == nil {
		t.Error("Decrypt should have failed with tampered ciphertext")
	}
	if err != ErrAuthFailed {
		t.Errorf("Expected ErrAuthFailed, got: %v", err)
	}
}

func TestSIVEngine_InvalidKey(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"too short", 32},
		{"too long", 96},
		{"empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := NewSIVEngine(key)
			if err == nil {
				t.Error("NewSIVEngine should have failed with invalid key size")
			}
		})
	}
}

func TestSIVEngine_ShortCiphertext(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	siv, err := NewSIVEngine(key)
	if err != nil {
		t.Fatalf("Failed to create SIV engine: %v", err)
	}

	// Try to decrypt ciphertext shorter than SIV (16 bytes)
	shortCiphertext := []byte("short")
	_, err = siv.Decrypt(shortCiphertext)
	if err == nil {
		t.Error("Decrypt should have failed with short ciphertext")
	}
}

func BenchmarkSIVEngine_Encrypt(b *testing.B) {
	key := make([]byte, 64)
	rand.Read(key)

	siv, _ := NewSIVEngine(key)

	sizes := []int{16, 64, 256, 1024, 4096}

	for _, size := range sizes {
		b.Run(string(rune(size))+"B", func(b *testing.B) {
			plaintext := make([]byte, size)
			rand.Read(plaintext)

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				siv.Encrypt(plaintext)
			}
		})
	}
}

func BenchmarkSIVEngine_Decrypt(b *testing.B) {
	key := make([]byte, 64)
	rand.Read(key)

	siv, _ := NewSIVEngine(key)

	sizes := []int{16, 64, 256, 1024, 4096}

	for _, size := range sizes {
		b.Run(string(rune(size))+"B", func(b *testing.B) {
			plaintext := make([]byte, size)
			rand.Read(plaintext)

			ciphertext, _ := siv.Encrypt(plaintext)

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				siv.Decrypt(ciphertext)
			}
		})
	}
}
