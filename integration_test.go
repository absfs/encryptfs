package encryptfs

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/absfs/memfs"
)

// TestIntegration_FilenameEncryption tests the complete workflow with filename encryption
func TestIntegration_FilenameEncryption(t *testing.T) {
	// Create base filesystem
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create base filesystem: %v", err)
	}

	// Create encrypted filesystem with deterministic filename encryption
	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: FilenameEncryptionDeterministic,
		PreserveExtensions: true,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Test 1: Create directory structure
	if err := fs.MkdirAll("/projects/webapp/assets", 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Test 2: Create files with plaintext names
	testFiles := map[string]string{
		"/projects/readme.md":            "Project documentation",
		"/projects/webapp/index.html":    "<html>...</html>",
		"/projects/webapp/assets/logo.png": "PNG data",
		"/secret.txt":                     "Top secret information",
	}

	for path, content := range testFiles {
		file, err := fs.Create(path)
		if err != nil {
			t.Fatalf("Create(%q) failed: %v", path, err)
		}

		if _, err := file.Write([]byte(content)); err != nil {
			file.Close()
			t.Fatalf("Write to %q failed: %v", path, err)
		}
		file.Close()
	}

	// Test 3: Read files back using plaintext names
	for path, expectedContent := range testFiles {
		file, err := fs.Open(path)
		if err != nil {
			t.Fatalf("Open(%q) failed: %v", path, err)
		}

		data, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			t.Fatalf("ReadAll(%q) failed: %v", path, err)
		}

		if string(data) != expectedContent {
			t.Errorf("Content mismatch for %q:\ngot:  %q\nwant: %q", path, string(data), expectedContent)
		}
	}

	// Test 4: Stat files using plaintext names
	for path := range testFiles {
		info, err := fs.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%q) failed: %v", path, err)
		}

		if info.IsDir() {
			t.Errorf("File %q reported as directory", path)
		}
	}

	// Test 5: Rename file
	if err := fs.Rename("/secret.txt", "/top-secret.txt"); err != nil {
		t.Fatalf("Rename failed: %v", err)
	}

	// Verify old name doesn't exist
	if _, err := fs.Stat("/secret.txt"); !os.IsNotExist(err) {
		t.Error("Old filename should not exist after rename")
	}

	// Verify new name exists
	file, err := fs.Open("/top-secret.txt")
	if err != nil {
		t.Fatalf("Open renamed file failed: %v", err)
	}
	data, _ := io.ReadAll(file)
	file.Close()

	if string(data) != "Top secret information" {
		t.Errorf("Renamed file content mismatch: got %q", string(data))
	}

	// Test 6: Remove file
	if err := fs.Remove("/top-secret.txt"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	if _, err := fs.Stat("/top-secret.txt"); !os.IsNotExist(err) {
		t.Error("Removed file should not exist")
	}

	// Test 7: Verify filenames are encrypted on disk
	// The base filesystem should have encrypted names, not plaintext
	baseInfo, err := base.Stat("/projects")
	if err == nil {
		// If this succeeds, it means the directory name is NOT encrypted (unexpected)
		t.Error("Directory name should be encrypted on base filesystem")
		_ = baseInfo
	}
}

// TestIntegration_RandomFilenameEncryption tests random filename encryption with metadata
func TestIntegration_RandomFilenameEncryption(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create base filesystem: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: FilenameEncryptionRandom,
		MetadataPath:       "/.metadata.json",
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create files
	files := []string{"/file1.txt", "/file2.txt", "/data.json"}
	for _, path := range files {
		file, err := fs.Create(path)
		if err != nil {
			t.Fatalf("Create(%q) failed: %v", path, err)
		}
		file.Write([]byte("content of " + filepath.Base(path)))
		file.Close()
	}

	// Read files back
	for _, path := range files {
		file, err := fs.Open(path)
		if err != nil {
			t.Fatalf("Open(%q) failed: %v", path, err)
		}

		data, _ := io.ReadAll(file)
		file.Close()

		expected := "content of " + filepath.Base(path)
		if string(data) != expected {
			t.Errorf("Content mismatch for %q: got %q, want %q", path, string(data), expected)
		}
	}

	// Note: Metadata is saved on-demand or during filesystem operations
	// For random encryption, the metadata is stored in memory during the session
	// In a real application, you would call a SaveMetadata() method or
	// the filesystem would save it during Sync() or Close() operations
}

// TestIntegration_NoFilenameEncryption tests content-only encryption
func TestIntegration_NoFilenameEncryption(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create base filesystem: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: FilenameEncryptionNone,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create file
	file, err := fs.Create("/plaintext-name.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("secret content"))
	file.Close()

	// Verify plaintext name exists on base filesystem
	if _, err := base.Stat("/plaintext-name.txt"); err != nil {
		t.Error("With FilenameEncryptionNone, filename should be plaintext on base filesystem")
	}

	// Verify content is still encrypted
	baseFile, err := base.Open("/plaintext-name.txt")
	if err != nil {
		t.Fatalf("Base filesystem Open failed: %v", err)
	}
	rawData, _ := io.ReadAll(baseFile)
	baseFile.Close()

	// Raw data should be encrypted (start with magic header)
	// Magic bytes 0x454E4352 in little-endian = "RCNE"
	if len(rawData) < 4 {
		t.Fatal("File too short to have encryption header")
	}

	// Check for encrypted file (should have binary header, not plaintext)
	// Just verify it's not the plaintext content
	if string(rawData) == "secret content" {
		t.Error("File should be encrypted, not plaintext")
	}

	// Verify decrypted content via encrypted filesystem
	file, _ = fs.Open("/plaintext-name.txt")
	decrypted, _ := io.ReadAll(file)
	file.Close()

	if string(decrypted) != "secret content" {
		t.Errorf("Decrypted content mismatch: got %q", string(decrypted))
	}
}

// TestIntegration_MultipleFilesystems tests using different encryption configs
func TestIntegration_MultipleFilesystems(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create base filesystem: %v", err)
	}

	// Create first filesystem with one key
	config1 := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("password1"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: FilenameEncryptionNone,
	}

	fs1, err := New(base, config1)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS 1: %v", err)
	}

	// Create file with fs1
	file, _ := fs1.Create("/test.txt")
	file.Write([]byte("data from fs1"))
	file.Close()

	// Try to read with wrong key (should fail)
	config2 := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("wrong-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: FilenameEncryptionNone,
	}

	fs2, err := New(base, config2)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS 2: %v", err)
	}

	file, err = fs2.Open("/test.txt")
	if err == nil {
		data, _ := io.ReadAll(file)
		file.Close()
		// Should fail authentication
		if string(data) == "data from fs1" {
			t.Error("Wrong key should not successfully decrypt file")
		}
	}
}

// BenchmarkIntegration_FilenameEncryption benchmarks filesystem operations with filename encryption
func BenchmarkIntegration_FilenameEncryption(b *testing.B) {
	base, _ := memfs.NewFS()

	modes := []struct {
		name string
		mode FilenameEncryption
	}{
		{"None", FilenameEncryptionNone},
		{"Deterministic", FilenameEncryptionDeterministic},
		{"Random", FilenameEncryptionRandom},
	}

	for _, mode := range modes {
		b.Run(mode.name, func(b *testing.B) {
			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1, // Reduce for benchmark
					Parallelism: 2,
				}),
				FilenameEncryption: mode.mode,
				MetadataPath:       "/.metadata.json",
			}

			fs, _ := New(base, config)

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Create file
				file, _ := fs.Create("/bench.txt")
				file.Write([]byte("benchmark data"))
				file.Close()

				// Read file
				file, _ = fs.Open("/bench.txt")
				io.ReadAll(file)
				file.Close()

				// Remove file
				fs.Remove("/bench.txt")
			}
		})
	}
}
