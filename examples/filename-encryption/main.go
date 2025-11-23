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

func printDirListing(fs *simpleFS, title string) {
	fmt.Printf("\n%s:\n", title)
	entries, err := os.ReadDir(fs.root)
	if err != nil {
		fmt.Printf("  Error reading directory: %v\n", err)
		return
	}
	if len(entries) == 0 {
		fmt.Println("  (empty)")
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			fmt.Printf("  📁 %s/\n", entry.Name())
		} else {
			fmt.Printf("  📄 %s\n", entry.Name())
		}
	}
}

func main() {
	// Create a temporary directory for the example
	tmpDir, err := os.MkdirTemp("", "encryptfs-filename-*")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Printf("Using temporary directory: %s\n", tmpDir)

	// ===================================================================
	// Example 1: No Filename Encryption (Content Only)
	// ===================================================================
	fmt.Println("\n=== Example 1: No Filename Encryption ===")

	base1 := &simpleFS{root: filepath.Join(tmpDir, "no-encryption")}
	os.MkdirAll(base1.root, 0755)

	config1 := &encryptfs.Config{
		Cipher: encryptfs.CipherAES256GCM,
		KeyProvider: encryptfs.NewPasswordKeyProvider([]byte("password"), encryptfs.Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: encryptfs.FilenameEncryptionNone,
	}

	fs1, err := encryptfs.New(base1, config1)
	if err != nil {
		log.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create some files
	file1, _ := fs1.Create("/secret-document.txt")
	file1.Write([]byte("Confidential content"))
	file1.Close()

	file2, _ := fs1.Create("/passwords.txt")
	file2.Write([]byte("admin:supersecret"))
	file2.Close()

	fmt.Println("✓ Created files with encrypted content")
	printDirListing(base1, "Files on disk (filenames visible)")

	// ===================================================================
	// Example 2: Deterministic Filename Encryption
	// ===================================================================
	fmt.Println("\n=== Example 2: Deterministic Filename Encryption ===")

	base2 := &simpleFS{root: filepath.Join(tmpDir, "deterministic")}
	os.MkdirAll(base2.root, 0755)

	config2 := &encryptfs.Config{
		Cipher: encryptfs.CipherAES256GCM,
		KeyProvider: encryptfs.NewPasswordKeyProvider([]byte("password"), encryptfs.Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: encryptfs.FilenameEncryptionDeterministic,
		PreserveExtensions: false,
	}

	fs2, err := encryptfs.New(base2, config2)
	if err != nil {
		log.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create files - filenames will be encrypted deterministically
	file, _ := fs2.Create("/secret-document.txt")
	file.Write([]byte("Confidential content"))
	file.Close()

	file, _ = fs2.Create("/passwords.txt")
	file.Write([]byte("admin:supersecret"))
	file.Close()

	fmt.Println("✓ Created files with encrypted filenames")
	printDirListing(base2, "Files on disk (filenames encrypted)")

	// Read the file back using plaintext name
	file, _ = fs2.Open("/secret-document.txt")
	data, _ := io.ReadAll(file)
	file.Close()
	fmt.Printf("✓ Read file by plaintext name: %q\n", string(data))

	// ===================================================================
	// Example 3: Deterministic with Extension Preservation
	// ===================================================================
	fmt.Println("\n=== Example 3: Deterministic + Extension Preservation ===")

	base3 := &simpleFS{root: filepath.Join(tmpDir, "preserve-ext")}
	os.MkdirAll(base3.root, 0755)

	config3 := &encryptfs.Config{
		Cipher: encryptfs.CipherAES256GCM,
		KeyProvider: encryptfs.NewPasswordKeyProvider([]byte("password"), encryptfs.Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: encryptfs.FilenameEncryptionDeterministic,
		PreserveExtensions: true, // Keep extensions visible
	}

	fs3, err := encryptfs.New(base3, config3)
	if err != nil {
		log.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create files with different extensions
	file, _ = fs3.Create("/document.txt")
	file.Write([]byte("Text document"))
	file.Close()

	file, _ = fs3.Create("/image.jpg")
	file.Write([]byte("fake image data"))
	file.Close()

	file, _ = fs3.Create("/archive.tar.gz")
	file.Write([]byte("fake archive"))
	file.Close()

	fmt.Println("✓ Created files with various extensions")
	printDirListing(base3, "Files on disk (extensions preserved)")
	fmt.Println("  Note: Extensions (.txt, .jpg, .tar.gz) are visible for file type identification")

	// ===================================================================
	// Example 4: Random Filename Encryption with Metadata
	// ===================================================================
	fmt.Println("\n=== Example 4: Random Filename Encryption ===")

	base4 := &simpleFS{root: filepath.Join(tmpDir, "random")}
	os.MkdirAll(base4.root, 0755)

	config4 := &encryptfs.Config{
		Cipher: encryptfs.CipherAES256GCM,
		KeyProvider: encryptfs.NewPasswordKeyProvider([]byte("password"), encryptfs.Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: encryptfs.FilenameEncryptionRandom,
		MetadataPath:       "/.encryptfs-metadata.json",
	}

	fs4, err := encryptfs.New(base4, config4)
	if err != nil {
		log.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create files - each gets a random UUID
	file, _ = fs4.Create("/top-secret.txt")
	file.Write([]byte("Highly confidential"))
	file.Close()

	file, _ = fs4.Create("/credentials.json")
	file.Write([]byte(`{"api_key": "secret123"}`))
	file.Close()

	fmt.Println("✓ Created files with random encrypted names")
	printDirListing(base4, "Files on disk (random UUIDs)")

	// Read file using plaintext name (metadata lookup)
	file, _ = fs4.Open("/top-secret.txt")
	data, _ = io.ReadAll(file)
	file.Close()
	fmt.Printf("✓ Read file by plaintext name (via metadata): %q\n", string(data))

	// Show metadata file
	metadataPath := filepath.Join(base4.root, ".encryptfs-metadata.json")
	if metadataBytes, err := os.ReadFile(metadataPath); err == nil {
		fmt.Printf("\nMetadata database:\n%s\n", string(metadataBytes))
	}

	// ===================================================================
	// Example 5: Directory Hierarchies with Filename Encryption
	// ===================================================================
	fmt.Println("\n=== Example 5: Nested Directories ===")

	base5 := &simpleFS{root: filepath.Join(tmpDir, "nested")}
	os.MkdirAll(base5.root, 0755)

	config5 := &encryptfs.Config{
		Cipher: encryptfs.CipherAES256GCM,
		KeyProvider: encryptfs.NewPasswordKeyProvider([]byte("password"), encryptfs.Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
		}),
		FilenameEncryption: encryptfs.FilenameEncryptionDeterministic,
		PreserveExtensions: true,
	}

	fs5, err := encryptfs.New(base5, config5)
	if err != nil {
		log.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create nested directory structure
	fs5.MkdirAll("/projects/website/assets", 0755)
	fs5.MkdirAll("/projects/api/v1", 0755)

	file, _ = fs5.Create("/projects/website/index.html")
	file.Write([]byte("<html>...</html>"))
	file.Close()

	file, _ = fs5.Create("/projects/website/assets/logo.png")
	file.Write([]byte("PNG data"))
	file.Close()

	file, _ = fs5.Create("/projects/api/v1/handlers.go")
	file.Write([]byte("package v1"))
	file.Close()

	fmt.Println("✓ Created nested directory structure")
	fmt.Println("\nPlaintext structure:")
	fmt.Println("  /projects/")
	fmt.Println("    website/")
	fmt.Println("      index.html")
	fmt.Println("      assets/")
	fmt.Println("        logo.png")
	fmt.Println("    api/")
	fmt.Println("      v1/")
	fmt.Println("        handlers.go")

	fmt.Println("\nEncrypted structure:")
	filepath.Walk(base5.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(base5.root, path)
		if relPath == "." {
			return nil
		}
		indent := "  "
		for i := 0; i < len(filepath.SplitList(relPath))-1; i++ {
			indent += "  "
		}
		if info.IsDir() {
			fmt.Printf("%s📁 %s/\n", indent, info.Name())
		} else {
			fmt.Printf("%s📄 %s\n", indent, info.Name())
		}
		return nil
	})

	fmt.Println("\n✓ Directory structure preserved with encrypted names")

	// ===================================================================
	// Security Comparison
	// ===================================================================
	fmt.Println("\n=== Security Comparison ===")
	fmt.Println()
	fmt.Println("1. No Filename Encryption:")
	fmt.Println("   ✓ Simple implementation")
	fmt.Println("   ✓ Easy debugging")
	fmt.Println("   ✗ Filenames visible (metadata leakage)")
	fmt.Println("   Use case: Protection against disk theft where metadata is acceptable")
	fmt.Println()
	fmt.Println("2. Deterministic Encryption:")
	fmt.Println("   ✓ Preserves directory hierarchy")
	fmt.Println("   ✓ Same filename → same ciphertext (allows caching)")
	fmt.Println("   ✓ Path-based lookups work")
	fmt.Println("   ⚠ Identical names reveal correlation")
	fmt.Println("   Use case: Balance between security and usability")
	fmt.Println()
	fmt.Println("3. Deterministic + Extension Preservation:")
	fmt.Println("   ✓ All benefits of deterministic")
	fmt.Println("   ✓ File type visible (for OS integration)")
	fmt.Println("   ⚠ Extensions leak some metadata")
	fmt.Println("   Use case: Desktop environments, file managers")
	fmt.Println()
	fmt.Println("4. Random Encryption:")
	fmt.Println("   ✓ Maximum security for filenames")
	fmt.Println("   ✓ No correlation between similar names")
	fmt.Println("   ✗ Requires metadata database")
	fmt.Println("   ✗ Database corruption risk")
	fmt.Println("   Use case: Maximum security, compliance requirements")

	fmt.Println("\n=== Filename encryption examples completed ===")
}
