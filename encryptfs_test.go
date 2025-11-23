package encryptfs

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/absfs/absfs"
)

// memFS is a simple in-memory filesystem for testing
// We'll use the osfs package and a temporary directory instead
func setupTestFS(t *testing.T) (absfs.FileSystem, func()) {
	t.Helper()

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "encryptfs-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Import osfs for the base filesystem
	// For now, we'll create a simple wrapper around os package
	base := &osTestFS{root: tmpDir}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return base, cleanup
}

// osTestFS is a minimal filesystem implementation for testing
type osTestFS struct {
	root string
	cwd  string
}

func (fs *osTestFS) OpenFile(name string, flag int, perm os.FileMode) (absfs.File, error) {
	path := filepath.Join(fs.root, name)
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, flag, perm)
}

func (fs *osTestFS) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(filepath.Join(fs.root, name), perm)
}

func (fs *osTestFS) MkdirAll(name string, perm os.FileMode) error {
	return os.MkdirAll(filepath.Join(fs.root, name), perm)
}

func (fs *osTestFS) Remove(name string) error {
	return os.Remove(filepath.Join(fs.root, name))
}

func (fs *osTestFS) RemoveAll(path string) error {
	return os.RemoveAll(filepath.Join(fs.root, path))
}

func (fs *osTestFS) Rename(oldpath, newpath string) error {
	return os.Rename(filepath.Join(fs.root, oldpath), filepath.Join(fs.root, newpath))
}

func (fs *osTestFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(filepath.Join(fs.root, name))
}

func (fs *osTestFS) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(filepath.Join(fs.root, name), mode)
}

func (fs *osTestFS) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(filepath.Join(fs.root, name), atime, mtime)
}

func (fs *osTestFS) Chown(name string, uid, gid int) error {
	return os.Chown(filepath.Join(fs.root, name), uid, gid)
}

func (fs *osTestFS) Separator() uint8 {
	return os.PathSeparator
}

func (fs *osTestFS) ListSeparator() uint8 {
	return os.PathListSeparator
}

func (fs *osTestFS) Chdir(dir string) error {
	fs.cwd = dir
	return nil
}

func (fs *osTestFS) Getwd() (string, error) {
	if fs.cwd == "" {
		return "/", nil
	}
	return fs.cwd, nil
}

func (fs *osTestFS) TempDir() string {
	return os.TempDir()
}

func (fs *osTestFS) Open(name string) (absfs.File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

func (fs *osTestFS) Create(name string) (absfs.File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (fs *osTestFS) Truncate(name string, size int64) error {
	return os.Truncate(filepath.Join(fs.root, name), size)
}

func TestNewEncryptFS(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1, // Low for testing speed
			Parallelism: 2,
		}),
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	if fs == nil {
		t.Fatal("EncryptFS is nil")
	}
}

func TestEncryptFS_WriteAndRead(t *testing.T) {
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

	// Test data
	testData := []byte("Hello, World! This is a test of the encryption system.")

	// Write data
	file, err := fs.Create("/test.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	n, err := file.Write(testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if n != len(testData) {
		t.Fatalf("wrote %d bytes, expected %d", n, len(testData))
	}

	if err := file.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	// Read data back
	file, err = fs.Open("/test.txt")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	if !bytes.Equal(readData, testData) {
		t.Fatalf("data mismatch:\ngot:  %q\nwant: %q", readData, testData)
	}
}

func TestEncryptFS_MultipleWrites(t *testing.T) {
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

	// Write data in multiple writes
	file, err := fs.Create("/multi.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	writes := [][]byte{
		[]byte("First line\n"),
		[]byte("Second line\n"),
		[]byte("Third line\n"),
	}

	for _, data := range writes {
		if _, err := file.Write(data); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
	}

	if err := file.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	// Read all data back
	file, err = fs.Open("/multi.txt")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	file.Close()

	expected := bytes.Join(writes, nil)
	if !bytes.Equal(readData, expected) {
		t.Fatalf("data mismatch:\ngot:  %q\nwant: %q", readData, expected)
	}
}

func TestEncryptFS_ChaCha20(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

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
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	testData := []byte("Testing ChaCha20-Poly1305 cipher")

	// Write
	file, err := fs.Create("/chacha.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	if _, err := file.Write(testData); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	file.Close()

	// Read
	file, err = fs.Open("/chacha.txt")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	file.Close()

	if !bytes.Equal(readData, testData) {
		t.Fatalf("data mismatch")
	}
}

func TestEncryptFS_Seek(t *testing.T) {
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

	testData := []byte("0123456789ABCDEF")

	// Write
	file, err := fs.Create("/seek.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	file.Write(testData)
	file.Close()

	// Read with seeking
	file, err = fs.Open("/seek.txt")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer file.Close()

	// Seek to middle
	pos, err := file.Seek(5, io.SeekStart)
	if err != nil {
		t.Fatalf("failed to seek: %v", err)
	}

	if pos != 5 {
		t.Fatalf("seek position: got %d, want 5", pos)
	}

	// Read from position 5
	buf := make([]byte, 5)
	n, err := file.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if n != 5 {
		t.Fatalf("read %d bytes, want 5", n)
	}

	expected := testData[5:10]
	if !bytes.Equal(buf, expected) {
		t.Fatalf("read data mismatch: got %q, want %q", buf, expected)
	}
}

func TestEncryptFS_WrongPassword(t *testing.T) {
	base, cleanup := setupTestFS(t)
	defer cleanup()

	// Write with one password
	config1 := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("correct-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
	}

	fs1, err := New(base, config1)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	file, err := fs1.Create("/secret.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	file.Write([]byte("secret data"))
	file.Close()

	// Try to read with wrong password
	config2 := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("wrong-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
	}

	fs2, err := New(base, config2)
	if err != nil {
		t.Fatalf("failed to create EncryptFS: %v", err)
	}

	file, err = fs2.Open("/secret.txt")
	if err == nil {
		file.Close()
		t.Fatal("expected error when opening file with wrong password")
	}

	// Should get authentication error
	if err != ErrAuthFailed && err.Error() != "failed to load encrypted file: failed to decrypt: authentication failed - data may be corrupted or tampered" {
		t.Logf("got error: %v", err)
	}
}
