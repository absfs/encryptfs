package encryptfs

import (
	"fmt"
	"io"
	"os"

	"github.com/absfs/absfs"
)

// encryptedFile wraps a base file and provides transparent encryption/decryption
type encryptedFile struct {
	base      absfs.File
	fs        *EncryptFS
	header    *FileHeader
	engine    CipherEngine
	flags     int
	plaintext []byte // Cached decrypted content for read operations
	dirty     bool   // True if plaintext has been modified
	offset    int64  // Current read/write offset in plaintext
}

// newEncryptedFile creates a new encrypted file wrapper
func newEncryptedFile(base absfs.File, fs *EncryptFS, flags int) (*encryptedFile, error) {
	ef := &encryptedFile{
		base:  base,
		fs:    fs,
		flags: flags,
	}

	// Check if file is being opened for reading or if it already exists
	info, err := base.Stat()
	if err != nil {
		return nil, err
	}

	// If file exists and has content, try to read the header and decrypt
	if info.Size() > 0 {
		if err := ef.loadFile(); err != nil {
			return nil, fmt.Errorf("failed to load encrypted file: %w", err)
		}
	} else {
		// New file - initialize with new header
		if err := ef.initNewFile(); err != nil {
			return nil, fmt.Errorf("failed to initialize new file: %w", err)
		}
	}

	return ef, nil
}

// initNewFile initializes a new encrypted file
func (f *encryptedFile) initNewFile() error {
	// Generate salt
	salt, err := f.fs.keyProvider.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate nonce
	nonce, err := GenerateNonce(f.fs.cipher)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create header
	f.header = NewFileHeader(f.fs.cipher, salt, nonce)

	// Derive key
	key, err := f.fs.keyProvider.DeriveKey(salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create cipher engine
	f.engine, err = NewCipherEngine(f.fs.cipher, key)
	if err != nil {
		return fmt.Errorf("failed to create cipher engine: %w", err)
	}

	// Initialize empty plaintext
	f.plaintext = []byte{}
	f.dirty = true

	return nil
}

// loadFile loads and decrypts an existing file
func (f *encryptedFile) loadFile() error {
	// Seek to beginning
	if _, err := f.base.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	// Read header
	f.header = &FileHeader{}
	if _, err := f.header.ReadFrom(f.base); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Validate header
	if err := f.header.Validate(); err != nil {
		return err
	}

	// Read ciphertext (do this before key derivation to avoid multiple reads)
	ciphertext, err := io.ReadAll(f.base)
	if err != nil {
		return fmt.Errorf("failed to read ciphertext: %w", err)
	}

	// Try to decrypt with the key provider(s)
	// Check if we have a MultiKeyProvider for fallback support
	if multiProvider, ok := f.fs.keyProvider.(*MultiKeyProvider); ok {
		// Try each provider in order
		var lastErr error
		for _, provider := range multiProvider.providers {
			key, err := provider.DeriveKey(f.header.Salt)
			if err != nil {
				lastErr = err
				continue
			}

			// Create cipher engine
			engine, err := NewCipherEngine(f.header.Cipher, key)
			if err != nil {
				lastErr = err
				continue
			}

			// Try to decrypt
			if len(ciphertext) > 0 {
				plaintext, err := engine.Decrypt(f.header.Nonce, ciphertext)
				if err != nil {
					lastErr = err
					continue
				}
				// Success!
				f.engine = engine
				f.plaintext = plaintext
				f.dirty = false
				f.offset = 0
				return nil
			} else {
				f.engine = engine
				f.plaintext = []byte{}
				f.dirty = false
				f.offset = 0
				return nil
			}
		}

		// All providers failed
		if lastErr != nil {
			return fmt.Errorf("all key providers failed to decrypt: %w", lastErr)
		}
		return fmt.Errorf("no key providers could decrypt the file")
	}

	// Single key provider - standard path
	key, err := f.fs.keyProvider.DeriveKey(f.header.Salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create cipher engine
	f.engine, err = NewCipherEngine(f.header.Cipher, key)
	if err != nil {
		return fmt.Errorf("failed to create cipher engine: %w", err)
	}

	// Decrypt if there's any ciphertext
	if len(ciphertext) > 0 {
		f.plaintext, err = f.engine.Decrypt(f.header.Nonce, ciphertext)
		if err != nil {
			return fmt.Errorf("failed to decrypt: %w", err)
		}
	} else {
		f.plaintext = []byte{}
	}

	f.dirty = false
	f.offset = 0

	return nil
}

// flush writes any pending changes to the underlying file
func (f *encryptedFile) flush() error {
	if !f.dirty {
		return nil
	}

	// Encrypt plaintext
	ciphertext, err := f.engine.Encrypt(f.header.Nonce, f.plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Seek to beginning of base file
	if _, err := f.base.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	// Write header
	if _, err := f.header.WriteTo(f.base); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write ciphertext
	if _, err := f.base.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	// Truncate any extra data
	currentPos, err := f.base.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get position: %w", err)
	}

	if err := f.base.Truncate(currentPos); err != nil {
		return fmt.Errorf("failed to truncate: %w", err)
	}

	f.dirty = false

	return nil
}

// Name returns the name of the file
func (f *encryptedFile) Name() string {
	return f.base.Name()
}

// Read reads from the decrypted content
func (f *encryptedFile) Read(p []byte) (n int, err error) {
	if f.offset >= int64(len(f.plaintext)) {
		return 0, io.EOF
	}

	n = copy(p, f.plaintext[f.offset:])
	f.offset += int64(n)

	if n < len(p) {
		err = io.EOF
	}

	return n, err
}

// Write writes to the plaintext buffer (will be encrypted on Close/Sync)
func (f *encryptedFile) Write(p []byte) (n int, err error) {
	// Extend plaintext if needed
	newSize := f.offset + int64(len(p))
	if newSize > int64(len(f.plaintext)) {
		newPlaintext := make([]byte, newSize)
		copy(newPlaintext, f.plaintext)
		f.plaintext = newPlaintext
	}

	n = copy(f.plaintext[f.offset:], p)
	f.offset += int64(n)
	f.dirty = true

	return n, nil
}

// WriteString writes a string to the file
func (f *encryptedFile) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}

// Seek sets the offset for the next Read or Write
func (f *encryptedFile) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64

	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = f.offset + offset
	case io.SeekEnd:
		newOffset = int64(len(f.plaintext)) + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}

	if newOffset < 0 {
		return 0, fmt.Errorf("negative position")
	}

	f.offset = newOffset
	return f.offset, nil
}

// Close flushes any pending writes and closes the file
func (f *encryptedFile) Close() error {
	if err := f.flush(); err != nil {
		f.base.Close()
		return err
	}

	return f.base.Close()
}

// Sync flushes any pending writes to stable storage
func (f *encryptedFile) Sync() error {
	if err := f.flush(); err != nil {
		return err
	}

	return f.base.Sync()
}

// Stat returns file information
func (f *encryptedFile) Stat() (os.FileInfo, error) {
	info, err := f.base.Stat()
	if err != nil {
		return nil, err
	}

	return newEncryptedFileInfo(info, f.fs.cipher), nil
}

// Readdir reads directory entries
func (f *encryptedFile) Readdir(n int) ([]os.FileInfo, error) {
	return f.base.Readdir(n)
}

// Readdirnames reads directory entry names
func (f *encryptedFile) Readdirnames(n int) ([]string, error) {
	return f.base.Readdirnames(n)
}

// ReadAt reads from a specific offset in the decrypted content
func (f *encryptedFile) ReadAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}

	if off >= int64(len(f.plaintext)) {
		return 0, io.EOF
	}

	n = copy(b, f.plaintext[off:])
	if n < len(b) {
		err = io.EOF
	}

	return n, err
}

// WriteAt writes to a specific offset in the plaintext
func (f *encryptedFile) WriteAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}

	// Extend plaintext if needed
	newSize := off + int64(len(b))
	if newSize > int64(len(f.plaintext)) {
		newPlaintext := make([]byte, newSize)
		copy(newPlaintext, f.plaintext)
		f.plaintext = newPlaintext
	}

	n = copy(f.plaintext[off:], b)
	f.dirty = true

	return n, nil
}

// Truncate changes the size of the file
func (f *encryptedFile) Truncate(size int64) error {
	if size < 0 {
		return fmt.Errorf("negative size")
	}

	if size > int64(len(f.plaintext)) {
		// Extend with zeros
		newPlaintext := make([]byte, size)
		copy(newPlaintext, f.plaintext)
		f.plaintext = newPlaintext
	} else {
		// Truncate
		f.plaintext = f.plaintext[:size]
	}

	f.dirty = true

	return nil
}
