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

// Additional integration tests for coverage

func TestIntegration_ChunkedFile_SeekRead(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024, // 4KB chunks
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create file with sequential data spanning multiple chunks
	testData := make([]byte, 20*1024) // 20KB = 5 chunks
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	file, _ := fs.Create("/seek-test.bin")
	file.Write(testData)
	file.Close()

	// Open and test seek operations
	file, _ = fs.Open("/seek-test.bin")
	defer file.Close()

	// Seek to middle of chunk 2
	pos, _ := file.Seek(5000, io.SeekStart)
	if pos != 5000 {
		t.Errorf("Seek got %d, want 5000", pos)
	}

	// Read some data
	buf := make([]byte, 100)
	n, _ := file.Read(buf)
	if n != 100 {
		t.Errorf("Read got %d bytes, want 100", n)
	}

	// Verify data is correct
	for i := 0; i < 100; i++ {
		expected := byte((5000 + i) % 256)
		if buf[i] != expected {
			t.Errorf("Data mismatch at %d: got %d, want %d", i, buf[i], expected)
			break
		}
	}
}

func TestIntegration_FileReadAt_BeyondEOF(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

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
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/eof.txt")
	file.Write([]byte("short"))
	file.Close()

	file, _ = fs.Open("/eof.txt")
	defer file.Close()

	// ReadAt beyond EOF
	buf := make([]byte, 10)
	_, err = file.ReadAt(buf, 100)
	if err != io.EOF {
		t.Errorf("Expected EOF, got %v", err)
	}
}

func TestIntegration_FileWriteAt_Extend(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

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
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/extend.txt")
	file.Write([]byte("start"))

	// WriteAt beyond current size
	file.WriteAt([]byte("END"), 10)
	file.Close()

	// Verify
	file, _ = fs.Open("/extend.txt")
	defer file.Close()

	data, _ := io.ReadAll(file)
	if len(data) != 13 { // "start" + zeros + "END"
		t.Errorf("Expected 13 bytes, got %d", len(data))
	}
}

func TestIntegration_File_Truncate_Extend(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

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
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/truncate.txt")
	file.Write([]byte("short"))

	// Extend via truncate
	file.Truncate(20)
	file.Close()

	// Verify
	file, _ = fs.Open("/truncate.txt")
	defer file.Close()

	data, _ := io.ReadAll(file)
	if len(data) != 20 {
		t.Errorf("Expected 20 bytes, got %d", len(data))
	}
}

func TestIntegration_File_Truncate_Shrink(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

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
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/truncate.txt")
	file.Write([]byte("0123456789"))

	// Shrink via truncate
	file.Truncate(5)
	file.Close()

	// Verify
	file, _ = fs.Open("/truncate.txt")
	defer file.Close()

	data, _ := io.ReadAll(file)
	if string(data) != "01234" {
		t.Errorf("Expected '01234', got %q", string(data))
	}
}

func TestIntegration_File_Truncate_Negative(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

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
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/truncate-neg.txt")
	file.Write([]byte("test"))

	// Negative truncate should error
	err = file.Truncate(-1)
	if err == nil {
		t.Error("Expected error for negative truncate")
	}
	file.Close()
}

func TestIntegration_File_WriteAt_Negative(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

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
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/writeat-neg.txt")

	// Negative offset should error
	_, err = file.WriteAt([]byte("test"), -1)
	if err == nil {
		t.Error("Expected error for negative WriteAt offset")
	}
	file.Close()
}

func TestIntegration_File_ReadAt_Negative(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

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
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/readat-neg.txt")
	file.Write([]byte("test"))
	file.Close()

	file, _ = fs.Open("/readat-neg.txt")

	// Negative offset should error
	_, err = file.ReadAt(make([]byte, 10), -1)
	if err == nil {
		t.Error("Expected error for negative ReadAt offset")
	}
	file.Close()
}

func TestIntegration_File_Seek_Invalid(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

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
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/seek.txt")
	file.Write([]byte("test"))
	file.Close()

	file, _ = fs.Open("/seek.txt")

	// Invalid whence
	_, err = file.Seek(0, 99)
	if err == nil {
		t.Error("Expected error for invalid whence")
	}

	// Negative position
	_, err = file.Seek(-100, io.SeekStart)
	if err == nil {
		t.Error("Expected error for negative seek")
	}

	file.Close()
}

func TestIntegration_PBKDF2Provider(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	// Use PBKDF2 with SHA512
	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProviderPBKDF2([]byte("test-password"), PBKDF2Params{
			Iterations: 1000, // Low for testing
			HashFunc:   SHA512,
		}),
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/pbkdf2.txt")
	file.Write([]byte("PBKDF2 test"))
	file.Close()

	file, _ = fs.Open("/pbkdf2.txt")
	data, _ := io.ReadAll(file)
	file.Close()

	if string(data) != "PBKDF2 test" {
		t.Errorf("Got %q", string(data))
	}
}

func TestIntegration_ChaCha20Poly1305(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherChaCha20Poly1305,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, _ := fs.Create("/chacha.txt")
	file.Write([]byte("ChaCha20-Poly1305 test"))
	file.Close()

	file, _ = fs.Open("/chacha.txt")
	data, _ := io.ReadAll(file)
	file.Close()

	if string(data) != "ChaCha20-Poly1305 test" {
		t.Errorf("Got %q", string(data))
	}
}
