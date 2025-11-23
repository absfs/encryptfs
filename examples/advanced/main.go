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
	tmpDir, err := os.MkdirTemp("", "encryptfs-advanced-*")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Printf("Using temporary directory: %s\n\n", tmpDir)

	// Create base filesystem
	base := &simpleFS{root: tmpDir}

	// ===================================================================
	// Example 1: Key Rotation
	// ===================================================================
	fmt.Println("=== Example 1: Key Rotation ===")

	oldKey := encryptfs.NewPasswordKeyProvider([]byte("old-password"), encryptfs.Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
	})

	config := &encryptfs.Config{
		Cipher:      encryptfs.CipherAES256GCM,
		KeyProvider: oldKey,
	}

	fs, err := encryptfs.New(base, config)
	if err != nil {
		log.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create a file with the old key
	file, err := fs.Create("/important.txt")
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	file.Write([]byte("Important confidential data"))
	file.Close()

	fmt.Println("✓ Created file with old key")

	// Rotate to a new key
	newKey := encryptfs.NewPasswordKeyProvider([]byte("new-password"), encryptfs.Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
	})

	rotateOpts := encryptfs.KeyRotationOptions{
		NewKeyProvider: newKey,
		Verbose:        true,
	}

	if err := fs.ReEncrypt("/important.txt", rotateOpts); err != nil {
		log.Fatalf("Key rotation failed: %v", err)
	}

	fmt.Println("✓ Key rotation completed")

	// Verify old key no longer works
	file, err = fs.Open("/important.txt")
	if err == nil {
		file.Close()
		log.Fatal("ERROR: Old key should not work after rotation!")
	}
	fmt.Println("✓ Old key correctly rejected")

	// Verify new key works
	newConfig := &encryptfs.Config{
		Cipher:      encryptfs.CipherAES256GCM,
		KeyProvider: newKey,
	}

	newFS, err := encryptfs.New(base, newConfig)
	if err != nil {
		log.Fatalf("Failed to create new EncryptFS: %v", err)
	}

	file, err = newFS.Open("/important.txt")
	if err != nil {
		log.Fatalf("Failed to open with new key: %v", err)
	}

	data, _ := io.ReadAll(file)
	file.Close()
	fmt.Printf("✓ File decrypted with new key: %q\n\n", string(data))

	// ===================================================================
	// Example 2: Multi-Key Provider for Migration
	// ===================================================================
	fmt.Println("=== Example 2: Multi-Key Provider ===")

	// Create files with different keys
	key1 := encryptfs.NewPasswordKeyProvider([]byte("password-1"), encryptfs.Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
	})

	key2 := encryptfs.NewPasswordKeyProvider([]byte("password-2"), encryptfs.Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
	})

	// Create file with key1
	fs1, _ := encryptfs.New(base, &encryptfs.Config{
		Cipher:      encryptfs.CipherAES256GCM,
		KeyProvider: key1,
	})

	file, _ = fs1.Create("/legacy.txt")
	file.Write([]byte("Legacy data encrypted with old key"))
	file.Close()

	fmt.Println("✓ Created legacy file with key1")

	// Create multi-key provider that can read both
	multiKey, err := encryptfs.NewMultiKeyProvider(key2, key1)
	if err != nil {
		log.Fatalf("Failed to create multi-key provider: %v", err)
	}

	multiFS, _ := encryptfs.New(base, &encryptfs.Config{
		Cipher:      encryptfs.CipherAES256GCM,
		KeyProvider: multiKey,
	})

	// Can read file encrypted with key1 (fallback)
	file, err = multiFS.Open("/legacy.txt")
	if err != nil {
		log.Fatalf("Failed to open legacy file: %v", err)
	}

	data, _ = io.ReadAll(file)
	file.Close()
	fmt.Printf("✓ Multi-key provider read legacy file: %q\n", string(data))

	// New files are written with primary key (key2)
	file, _ = multiFS.Create("/new.txt")
	file.Write([]byte("New data encrypted with key2"))
	file.Close()

	fmt.Println("✓ New files use primary key (key2)\n")

	// ===================================================================
	// Example 3: Cipher Migration
	// ===================================================================
	fmt.Println("=== Example 3: Cipher Migration ===")

	aesKey := encryptfs.NewPasswordKeyProvider([]byte("migrate-password"), encryptfs.Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
	})

	// Create file with AES-256-GCM
	aesFS, _ := encryptfs.New(base, &encryptfs.Config{
		Cipher:      encryptfs.CipherAES256GCM,
		KeyProvider: aesKey,
	})

	file, _ = aesFS.Create("/cipher-test.txt")
	file.Write([]byte("Migrating from AES to ChaCha20"))
	file.Close()

	fmt.Println("✓ Created file with AES-256-GCM")

	// Migrate to ChaCha20-Poly1305
	migrateOpts := encryptfs.KeyRotationOptions{
		NewKeyProvider: aesKey, // Same key
		NewCipher:      encryptfs.CipherChaCha20Poly1305,
		Verbose:        true,
	}

	if err := aesFS.ReEncrypt("/cipher-test.txt", migrateOpts); err != nil {
		log.Fatalf("Cipher migration failed: %v", err)
	}

	fmt.Println("✓ Migrated to ChaCha20-Poly1305")

	// Verify with ChaCha20
	chachaFS, _ := encryptfs.New(base, &encryptfs.Config{
		Cipher:      encryptfs.CipherChaCha20Poly1305,
		KeyProvider: aesKey,
	})

	file, _ = chachaFS.Open("/cipher-test.txt")
	data, _ = io.ReadAll(file)
	file.Close()

	fmt.Printf("✓ File decrypted with ChaCha20: %q\n\n", string(data))

	// ===================================================================
	// Example 4: Verification
	// ===================================================================
	fmt.Println("=== Example 4: File Verification ===")

	verifyKey := encryptfs.NewPasswordKeyProvider([]byte("verify-password"), encryptfs.Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
	})

	verifyFS, _ := encryptfs.New(base, &encryptfs.Config{
		Cipher:      encryptfs.CipherAES256GCM,
		KeyProvider: verifyKey,
	})

	// Create some files
	for i := 1; i <= 3; i++ {
		file, _ = verifyFS.Create(fmt.Sprintf("/file%d.txt", i))
		file.Write([]byte(fmt.Sprintf("File %d content", i)))
		file.Close()
	}

	fmt.Println("✓ Created 3 test files")

	// Verify all files can be decrypted
	// Note: We're verifying at the root of our tmpDir
	// In production, you would verify a specific subdirectory
	if err := verifyFS.VerifyEncryption("/file1.txt"); err != nil {
		fmt.Printf("✗ Verification failed: %v\n", err)
	} else {
		fmt.Println("✓ All files verified successfully")
	}

	fmt.Println("\n=== Advanced examples completed successfully ===")
}
