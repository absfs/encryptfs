package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/absfs/absfs"
	"github.com/absfs/encryptfs"
)

// simpleFS is a minimal filesystem implementation for the example
type simpleFS struct {
	root string
}

func (fs *simpleFS) OpenFile(name string, flag int, perm os.FileMode) (absfs.File, error) {
	path := filepath.Join(fs.root, name)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, flag, perm)
}

func (fs *simpleFS) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(filepath.Join(fs.root, name), perm)
}

func (fs *simpleFS) MkdirAll(name string, perm os.FileMode) error {
	return os.MkdirAll(filepath.Join(fs.root, name), perm)
}

func (fs *simpleFS) Remove(name string) error {
	return os.Remove(filepath.Join(fs.root, name))
}

func (fs *simpleFS) RemoveAll(path string) error {
	return os.RemoveAll(filepath.Join(fs.root, path))
}

func (fs *simpleFS) Rename(oldpath, newpath string) error {
	return os.Rename(filepath.Join(fs.root, oldpath), filepath.Join(fs.root, newpath))
}

func (fs *simpleFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(filepath.Join(fs.root, name))
}

func (fs *simpleFS) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(filepath.Join(fs.root, name), mode)
}

func (fs *simpleFS) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(filepath.Join(fs.root, name), atime, mtime)
}

func (fs *simpleFS) Chown(name string, uid, gid int) error {
	return os.Chown(filepath.Join(fs.root, name), uid, gid)
}

func (fs *simpleFS) Separator() uint8 {
	return os.PathSeparator
}

func (fs *simpleFS) ListSeparator() uint8 {
	return os.PathListSeparator
}

func (fs *simpleFS) Chdir(dir string) error {
	return nil
}

func (fs *simpleFS) Getwd() (string, error) {
	return "/", nil
}

func (fs *simpleFS) TempDir() string {
	return os.TempDir()
}

func (fs *simpleFS) Open(name string) (absfs.File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

func (fs *simpleFS) Create(name string) (absfs.File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (fs *simpleFS) Truncate(name string, size int64) error {
	return os.Truncate(filepath.Join(fs.root, name), size)
}

func main() {
	// Create a temporary directory for the example
	tmpDir, err := os.MkdirTemp("", "encryptfs-example-*")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Printf("Using temporary directory: %s\n\n", tmpDir)

	// Create base filesystem
	base := &simpleFS{root: tmpDir}

	// Example 1: AES-256-GCM with Argon2id key derivation
	fmt.Println("=== Example 1: AES-256-GCM with Argon2id ===")

	config := &encryptfs.Config{
		Cipher: encryptfs.CipherAES256GCM,
		KeyProvider: encryptfs.NewPasswordKeyProvider(
			[]byte("my-secure-password"),
			encryptfs.Argon2idParams{
				Memory:      64 * 1024, // 64 MB
				Iterations:  3,
				Parallelism: 4,
			},
		),
	}

	fs, err := encryptfs.New(base, config)
	if err != nil {
		log.Fatalf("Failed to create encrypted filesystem: %v", err)
	}

	// Write encrypted data
	file, err := fs.Create("/secret.txt")
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}

	secretData := "This is my secret message that will be encrypted!"
	n, err := file.Write([]byte(secretData))
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}
	fmt.Printf("Wrote %d bytes (plaintext)\n", n)

	if err := file.Close(); err != nil {
		log.Fatalf("Failed to close: %v", err)
	}

	// Check the actual file size on disk (includes header + ciphertext + tag)
	info, err := os.Stat(filepath.Join(tmpDir, "secret.txt"))
	if err != nil {
		log.Fatalf("Failed to stat: %v", err)
	}
	fmt.Printf("File size on disk: %d bytes (includes header + overhead)\n", info.Size())

	// Read the encrypted data back
	file, err = fs.Open("/secret.txt")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	readData, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Failed to read: %v", err)
	}

	file.Close()

	fmt.Printf("Read back: %q\n", string(readData))
	fmt.Printf("Data matches: %v\n\n", string(readData) == secretData)

	// Example 2: ChaCha20-Poly1305
	fmt.Println("=== Example 2: ChaCha20-Poly1305 ===")

	config2 := &encryptfs.Config{
		Cipher: encryptfs.CipherChaCha20Poly1305,
		KeyProvider: encryptfs.NewPasswordKeyProvider(
			[]byte("another-password"),
			encryptfs.Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 4,
			},
		),
	}

	fs2, err := encryptfs.New(base, config2)
	if err != nil {
		log.Fatalf("Failed to create encrypted filesystem: %v", err)
	}

	file, err = fs2.Create("/chacha-secret.txt")
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}

	file.Write([]byte("This is encrypted with ChaCha20-Poly1305!"))
	file.Close()

	file, err = fs2.Open("/chacha-secret.txt")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	readData, _ = io.ReadAll(file)
	file.Close()

	fmt.Printf("Read back: %q\n\n", string(readData))

	// Example 3: Demonstrate wrong password fails
	fmt.Println("=== Example 3: Wrong password ===")

	wrongConfig := &encryptfs.Config{
		Cipher: encryptfs.CipherAES256GCM,
		KeyProvider: encryptfs.NewPasswordKeyProvider(
			[]byte("wrong-password"),
			encryptfs.Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 4,
			},
		),
	}

	fsWrong, err := encryptfs.New(base, wrongConfig)
	if err != nil {
		log.Fatalf("Failed to create encrypted filesystem: %v", err)
	}

	file, err = fsWrong.Open("/secret.txt")
	if err != nil {
		fmt.Printf("✓ Expected error with wrong password: %v\n", err)
	} else {
		file.Close()
		fmt.Println("ERROR: Should have failed with wrong password!")
	}

	fmt.Println("\n=== Example completed successfully ===")
}
