package encryptfs

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/absfs/memfs"
)

func TestDeterministicFilenameEncryptor(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := NewDeterministicFilenameEncryptor(key, false, "/")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple file", "test.txt"},
		{"no extension", "myfile"},
		{"long name", "very-long-filename-with-many-characters.doc"},
		{"special chars", "file_with-special.chars.txt"},
		{"unicode", "文件名.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := enc.EncryptFilename(tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptFilename failed: %v", err)
			}

			// Verify encrypted is different
			if encrypted == tt.plaintext {
				t.Error("Encrypted filename should be different from plaintext")
			}

			// Decrypt
			decrypted, err := enc.DecryptFilename(encrypted)
			if err != nil {
				t.Fatalf("DecryptFilename failed: %v", err)
			}

			// Verify round-trip
			if decrypted != tt.plaintext {
				t.Errorf("Round-trip failed:\ngot:  %q\nwant: %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestDeterministicFilenameEncryptor_Deterministic(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := NewDeterministicFilenameEncryptor(key, false, "/")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "deterministic.txt"

	// Encrypt twice
	encrypted1, err := enc.EncryptFilename(plaintext)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := enc.EncryptFilename(plaintext)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Verify deterministic
	if encrypted1 != encrypted2 {
		t.Errorf("Encryption is not deterministic:\nfirst:  %q\nsecond: %q", encrypted1, encrypted2)
	}
}

func TestDeterministicFilenameEncryptor_PreserveExtensions(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := NewDeterministicFilenameEncryptor(key, true, "/")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		plaintext string
		extension string
	}{
		{"test.txt", ".txt"},
		{"myfile.pdf", ".pdf"},
		{"archive.tar.gz", ".gz"},
		{"noext", ""},
	}

	for _, tt := range tests {
		t.Run(tt.plaintext, func(t *testing.T) {
			encrypted, err := enc.EncryptFilename(tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptFilename failed: %v", err)
			}

			// Check extension preservation
			if tt.extension != "" {
				if !strings.HasSuffix(encrypted, tt.extension) {
					t.Errorf("Extension not preserved:\ngot:  %q\nwant suffix: %q", encrypted, tt.extension)
				}
			}

			// Verify round-trip
			decrypted, err := enc.DecryptFilename(encrypted)
			if err != nil {
				t.Fatalf("DecryptFilename failed: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("Round-trip failed:\ngot:  %q\nwant: %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestDeterministicFilenameEncryptor_Paths(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := NewDeterministicFilenameEncryptor(key, false, "/")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"simple path", "/home/user/file.txt"},
		{"nested path", "/a/b/c/d/e.txt"},
		{"root file", "/file.txt"},
		{"relative path", "dir/file.txt"},
		{"current dir", "."},
		{"parent dir", ".."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt path
			encrypted, err := enc.EncryptPath(tt.path)
			if err != nil {
				t.Fatalf("EncryptPath failed: %v", err)
			}

			// Special cases should remain unchanged
			if tt.path == "." || tt.path == ".." {
				if encrypted != tt.path {
					t.Errorf("Special path should remain unchanged: %q -> %q", tt.path, encrypted)
				}
				return
			}

			// Verify structure is preserved (same number of components)
			plainParts := strings.Split(tt.path, "/")
			encryptedParts := strings.Split(encrypted, "/")
			if len(plainParts) != len(encryptedParts) {
				t.Errorf("Path structure not preserved:\noriginal: %d parts\nencrypted: %d parts", len(plainParts), len(encryptedParts))
			}

			// Decrypt path
			decrypted, err := enc.DecryptPath(encrypted)
			if err != nil {
				t.Fatalf("DecryptPath failed: %v", err)
			}

			// Verify round-trip
			if decrypted != tt.path {
				t.Errorf("Round-trip failed:\ngot:  %q\nwant: %q", decrypted, tt.path)
			}
		})
	}
}

func TestRandomFilenameEncryptor(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	metadata := NewFilenameMetadata()
	enc, err := NewRandomFilenameEncryptor(key, metadata, "/")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "test.txt"

	// Encrypt
	encrypted, err := enc.EncryptFilename(plaintext)
	if err != nil {
		t.Fatalf("EncryptFilename failed: %v", err)
	}

	// Verify encrypted is different
	if encrypted == plaintext {
		t.Error("Encrypted filename should be different from plaintext")
	}

	// Decrypt
	decrypted, err := enc.DecryptFilename(encrypted)
	if err != nil {
		t.Fatalf("DecryptFilename failed: %v", err)
	}

	// Verify round-trip
	if decrypted != plaintext {
		t.Errorf("Round-trip failed:\ngot:  %q\nwant: %q", decrypted, plaintext)
	}
}

func TestRandomFilenameEncryptor_Consistency(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	metadata := NewFilenameMetadata()
	enc, err := NewRandomFilenameEncryptor(key, metadata, "/")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "consistent.txt"

	// Encrypt twice - should get same result (uses metadata)
	encrypted1, err := enc.EncryptFilename(plaintext)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := enc.EncryptFilename(plaintext)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Should be consistent due to metadata lookup
	if encrypted1 != encrypted2 {
		t.Errorf("Random encryption should be consistent with metadata:\nfirst:  %q\nsecond: %q", encrypted1, encrypted2)
	}
}

func TestFilenameMetadata_SaveLoad(t *testing.T) {
	fs, _ := memfs.NewFS()
	metadataPath := "/.metadata.json"

	// Create metadata with some mappings
	metadata := NewFilenameMetadata()
	metadata.Add("encrypted1", "plain1.txt")
	metadata.Add("encrypted2", "plain2.txt")

	// Save
	if err := metadata.Save(fs, metadataPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load into new metadata
	loaded := NewFilenameMetadata()
	if err := loaded.Load(fs, metadataPath); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify mappings
	if plain, ok := loaded.Get("encrypted1"); !ok || plain != "plain1.txt" {
		t.Errorf("Mapping 1 not loaded correctly: got %q, want %q", plain, "plain1.txt")
	}

	if plain, ok := loaded.Get("encrypted2"); !ok || plain != "plain2.txt" {
		t.Errorf("Mapping 2 not loaded correctly: got %q, want %q", plain, "plain2.txt")
	}

	// Verify reverse mappings
	if enc, ok := loaded.GetReverse("plain1.txt"); !ok || enc != "encrypted1" {
		t.Errorf("Reverse mapping 1 not loaded correctly: got %q, want %q", enc, "encrypted1")
	}
}

func TestNoOpFilenameEncryptor(t *testing.T) {
	enc := &noOpFilenameEncryptor{}

	tests := []string{
		"test.txt",
		"/path/to/file.txt",
		".",
		"..",
	}

	for _, plaintext := range tests {
		t.Run(plaintext, func(t *testing.T) {
			encrypted, err := enc.EncryptFilename(plaintext)
			if err != nil {
				t.Fatalf("EncryptFilename failed: %v", err)
			}

			if encrypted != plaintext {
				t.Errorf("NoOp should not change filename: got %q, want %q", encrypted, plaintext)
			}

			decrypted, err := enc.DecryptFilename(encrypted)
			if err != nil {
				t.Fatalf("DecryptFilename failed: %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("NoOp should not change filename: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestNewFilenameEncryptor(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	fs, _ := memfs.NewFS()

	tests := []struct {
		name           string
		encryptionMode FilenameEncryption
		expectType     string
	}{
		{"none", FilenameEncryptionNone, "noOp"},
		{"deterministic", FilenameEncryptionDeterministic, "deterministic"},
		{"random", FilenameEncryptionRandom, "random"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Cipher:             CipherAES256GCM,
				FilenameEncryption: tt.encryptionMode,
				PreserveExtensions: false,
				MetadataPath:       "/.metadata.json",
			}

			enc, err := NewFilenameEncryptor(config, key, fs)
			if err != nil {
				t.Fatalf("NewFilenameEncryptor failed: %v", err)
			}

			if enc == nil {
				t.Fatal("Encryptor should not be nil")
			}

			// Test basic operation
			plaintext := "test.txt"
			encrypted, err := enc.EncryptFilename(plaintext)
			if err != nil {
				t.Fatalf("EncryptFilename failed: %v", err)
			}

			decrypted, err := enc.DecryptFilename(encrypted)
			if err != nil {
				t.Fatalf("DecryptFilename failed: %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func BenchmarkDeterministicFilenameEncryptor(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, _ := NewDeterministicFilenameEncryptor(key, false, "/")
	plaintext := "benchmark-file.txt"

	b.Run("Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.EncryptFilename(plaintext)
		}
	})

	encrypted, _ := enc.EncryptFilename(plaintext)

	b.Run("Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.DecryptFilename(encrypted)
		}
	})
}

func BenchmarkRandomFilenameEncryptor(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	metadata := NewFilenameMetadata()
	enc, _ := NewRandomFilenameEncryptor(key, metadata, "/")
	plaintext := "benchmark-file.txt"

	b.Run("Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.EncryptFilename(plaintext)
		}
	})

	encrypted, _ := enc.EncryptFilename(plaintext)

	b.Run("Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.DecryptFilename(encrypted)
		}
	})
}
