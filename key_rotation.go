package encryptfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// MultiKeyProvider tries multiple key providers in order for decryption
// This is useful during key rotation/migration
type MultiKeyProvider struct {
	providers []KeyProvider
	primary   KeyProvider // Primary provider for new encryptions
}

// NewMultiKeyProvider creates a new multi-key provider
// The first provider is used for new encryptions, others for decryption fallback
func NewMultiKeyProvider(providers ...KeyProvider) (*MultiKeyProvider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("at least one key provider required")
	}

	return &MultiKeyProvider{
		providers: providers,
		primary:   providers[0],
	}, nil
}

// DeriveKey uses the primary provider
func (m *MultiKeyProvider) DeriveKey(salt []byte) ([]byte, error) {
	return m.primary.DeriveKey(salt)
}

// GenerateSalt uses the primary provider
func (m *MultiKeyProvider) GenerateSalt() ([]byte, error) {
	return m.primary.GenerateSalt()
}

// TryDeriveKey attempts to derive a key using each provider in order
// Returns the first successful key derivation
func (m *MultiKeyProvider) TryDeriveKey(salt []byte) ([]byte, error) {
	var lastErr error
	for _, provider := range m.providers {
		key, err := provider.DeriveKey(salt)
		if err != nil {
			lastErr = err
			continue
		}
		// Successfully derived key
		return key, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all key providers failed: %w", lastErr)
	}
	return nil, fmt.Errorf("no key providers available")
}

// KeyRotationOptions contains options for key rotation operations
type KeyRotationOptions struct {
	// NewKeyProvider is the key provider to use for re-encryption
	NewKeyProvider KeyProvider

	// Cipher suite to use (if different from original)
	NewCipher CipherSuite

	// PreserveTimestamps keeps original file modification times
	PreserveTimestamps bool

	// Verbose enables progress output
	Verbose bool

	// DryRun simulates the operation without making changes
	DryRun bool
}

// ReEncrypt re-encrypts a file with a new key provider
func (e *EncryptFS) ReEncrypt(name string, opts KeyRotationOptions) error {
	// Read the current file
	file, err := e.Open(name)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	// Read all content (decrypted)
	content, err := io.ReadAll(file)
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to read file: %w", err)
	}
	file.Close()

	// Get original file info
	var origModTime os.FileMode
	if opts.PreserveTimestamps {
		info, err := e.Stat(name)
		if err != nil {
			return fmt.Errorf("failed to stat file: %w", err)
		}
		origModTime = info.Mode()
	}

	if opts.DryRun {
		if opts.Verbose {
			fmt.Printf("[DRY RUN] Would re-encrypt %s (%d bytes)\n", name, len(content))
		}
		return nil
	}

	// Create a new EncryptFS with the new key provider
	cipher := opts.NewCipher
	if cipher == 0 {
		cipher = e.cipher // Use existing cipher if not specified
	}

	newConfig := &Config{
		Cipher:      cipher,
		KeyProvider: opts.NewKeyProvider,
	}

	newFS, err := New(e.base, newConfig)
	if err != nil {
		return fmt.Errorf("failed to create new encrypted filesystem: %w", err)
	}

	// Write with new encryption
	newFile, err := newFS.Create(name)
	if err != nil {
		return fmt.Errorf("failed to create new file: %w", err)
	}

	_, err = newFile.Write(content)
	if err != nil {
		newFile.Close()
		return fmt.Errorf("failed to write re-encrypted content: %w", err)
	}

	if err := newFile.Close(); err != nil {
		return fmt.Errorf("failed to close new file: %w", err)
	}

	// Restore permissions if requested
	if opts.PreserveTimestamps {
		if err := e.Chmod(name, origModTime); err != nil {
			return fmt.Errorf("failed to restore permissions: %w", err)
		}
	}

	if opts.Verbose {
		fmt.Printf("Re-encrypted %s (%d bytes)\n", name, len(content))
	}

	return nil
}

// RotateAllKeys re-encrypts all files in a directory tree with a new key
func (e *EncryptFS) RotateAllKeys(root string, opts KeyRotationOptions) error {
	var filesRotated int
	var errors []error

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			errors = append(errors, fmt.Errorf("walk error for %s: %w", path, err))
			return nil // Continue walking
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Try to re-encrypt the file
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to get relative path for %s: %w", path, err))
			return nil
		}

		if err := e.ReEncrypt("/"+relPath, opts); err != nil {
			errors = append(errors, fmt.Errorf("failed to re-encrypt %s: %w", relPath, err))
			return nil
		}

		filesRotated++
		return nil
	})

	if err != nil {
		return fmt.Errorf("walk failed: %w", err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("key rotation completed with %d errors (rotated %d files)", len(errors), filesRotated)
	}

	if opts.Verbose {
		fmt.Printf("Successfully rotated keys for %d files\n", filesRotated)
	}

	return nil
}

// MigrateToNewCipher migrates all files from one cipher suite to another
func (e *EncryptFS) MigrateToNewCipher(root string, newCipher CipherSuite, opts KeyRotationOptions) error {
	opts.NewCipher = newCipher
	return e.RotateAllKeys(root, opts)
}

// EncryptedFileWalker is a function type for walking encrypted files
type EncryptedFileWalker func(path string, info os.FileInfo, err error) error

// WalkEncrypted walks a directory tree of encrypted files
func (e *EncryptFS) WalkEncrypted(root string, walkFn EncryptedFileWalker) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		return walkFn(path, info, err)
	})
}

// VerifyEncryption verifies that a file can be decrypted successfully
func (e *EncryptFS) VerifyEncryption(name string) error {
	file, err := e.Open(name)
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}
	defer file.Close()

	// Try to read the entire file
	_, err = io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	return nil
}

// VerifyAllEncryption verifies all files in a directory can be decrypted
func (e *EncryptFS) VerifyAllEncryption(root string) ([]string, error) {
	var failed []string

	err := e.WalkEncrypted(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		if err := e.VerifyEncryption("/" + relPath); err != nil {
			failed = append(failed, relPath)
		}

		return nil
	})

	if err != nil {
		return failed, fmt.Errorf("verification walk failed: %w", err)
	}

	if len(failed) > 0 {
		return failed, fmt.Errorf("%d files failed verification", len(failed))
	}

	return nil, nil
}
