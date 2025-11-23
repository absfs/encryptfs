package encryptfs

import (
	"fmt"
	"os"
	"time"

	"github.com/absfs/absfs"
)

// EncryptFS implements absfs.FileSystem with transparent encryption
type EncryptFS struct {
	base              absfs.FileSystem
	config            *Config
	keyProvider       KeyProvider
	cipher            CipherSuite
	filenameEncryptor FilenameEncryptor
	masterKey         []byte
}

// New creates a new encrypted filesystem wrapping the base filesystem
func New(base absfs.FileSystem, config *Config) (*EncryptFS, error) {
	if base == nil {
		return nil, fmt.Errorf("base filesystem cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Determine the actual cipher to use
	cipher := config.Cipher
	if cipher == CipherAuto {
		// Auto-select AES-256-GCM (in future, detect AES-NI support)
		cipher = CipherAES256GCM
	}

	// Derive master key for filename encryption
	salt, err := config.KeyProvider.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	masterKey, err := config.KeyProvider.DeriveKey(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Create filename encryptor
	filenameEncryptor, err := NewFilenameEncryptor(config, masterKey, base)
	if err != nil {
		return nil, fmt.Errorf("failed to create filename encryptor: %w", err)
	}

	return &EncryptFS{
		base:              base,
		config:            config,
		keyProvider:       config.KeyProvider,
		cipher:            cipher,
		filenameEncryptor: filenameEncryptor,
		masterKey:         masterKey,
	}, nil
}

// translatePath translates a plaintext path to its encrypted form
func (e *EncryptFS) translatePath(plaintext string) (string, error) {
	return e.filenameEncryptor.EncryptPath(plaintext)
}

// untranslatePath translates an encrypted path back to plaintext
func (e *EncryptFS) untranslatePath(ciphertext string) (string, error) {
	return e.filenameEncryptor.DecryptPath(ciphertext)
}

// Separator returns the path separator for the underlying filesystem
func (e *EncryptFS) Separator() uint8 {
	return e.base.Separator()
}

// ListSeparator returns the list separator for the underlying filesystem
func (e *EncryptFS) ListSeparator() uint8 {
	return e.base.ListSeparator()
}

// Chdir changes the current working directory
func (e *EncryptFS) Chdir(dir string) error {
	encryptedPath, err := e.translatePath(dir)
	if err != nil {
		return err
	}
	return e.base.Chdir(encryptedPath)
}

// Getwd returns the current working directory
func (e *EncryptFS) Getwd() (string, error) {
	encryptedPath, err := e.base.Getwd()
	if err != nil {
		return "", err
	}
	return e.untranslatePath(encryptedPath)
}

// TempDir returns the temporary directory path
func (e *EncryptFS) TempDir() string {
	return e.base.TempDir()
}

// Open opens a file for reading with transparent decryption
func (e *EncryptFS) Open(name string) (absfs.File, error) {
	return e.OpenFile(name, os.O_RDONLY, 0)
}

// Create creates or truncates a file for writing with transparent encryption
func (e *EncryptFS) Create(name string) (absfs.File, error) {
	return e.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

// OpenFile opens a file with the specified flags and permissions
func (e *EncryptFS) OpenFile(name string, flag int, perm os.FileMode) (absfs.File, error) {
	// Translate path to encrypted form
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return nil, err
	}

	baseFile, err := e.base.OpenFile(encryptedPath, flag, perm)
	if err != nil {
		return nil, err
	}

	// Check if chunking is enabled
	useChunking := e.config.ChunkSize > 0

	if useChunking {
		// Use chunked file for better performance with large files
		chunkSize := uint32(e.config.ChunkSize)
		if chunkSize == 0 {
			chunkSize = DefaultChunkSize
		}

		chunkFile, err := newChunkedFile(baseFile, e, chunkSize, flag)
		if err != nil {
			baseFile.Close()
			return nil, err
		}
		return chunkFile, nil
	}

	// Use traditional single-chunk encryption
	encFile, err := newEncryptedFile(baseFile, e, flag)
	if err != nil {
		baseFile.Close()
		return nil, err
	}

	return encFile, nil
}

// Mkdir creates a directory
func (e *EncryptFS) Mkdir(name string, perm os.FileMode) error {
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return err
	}
	return e.base.Mkdir(encryptedPath, perm)
}

// MkdirAll creates a directory and all necessary parent directories
func (e *EncryptFS) MkdirAll(name string, perm os.FileMode) error {
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return err
	}
	return e.base.MkdirAll(encryptedPath, perm)
}

// Remove removes a file or empty directory
func (e *EncryptFS) Remove(name string) error {
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return err
	}
	return e.base.Remove(encryptedPath)
}

// RemoveAll removes a path and any children it contains
func (e *EncryptFS) RemoveAll(path string) error {
	encryptedPath, err := e.translatePath(path)
	if err != nil {
		return err
	}
	return e.base.RemoveAll(encryptedPath)
}

// Rename renames (moves) a file
func (e *EncryptFS) Rename(oldpath, newpath string) error {
	encryptedOld, err := e.translatePath(oldpath)
	if err != nil {
		return err
	}
	encryptedNew, err := e.translatePath(newpath)
	if err != nil {
		return err
	}
	return e.base.Rename(encryptedOld, encryptedNew)
}

// Stat returns file information
func (e *EncryptFS) Stat(name string) (os.FileInfo, error) {
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return nil, err
	}

	info, err := e.base.Stat(encryptedPath)
	if err != nil {
		return nil, err
	}

	// For encrypted files, we need to adjust the size to exclude the header
	// and overhead. This is done by the encryptedFileInfo wrapper.
	if !info.IsDir() {
		return newEncryptedFileInfo(info, e.cipher), nil
	}

	return info, nil
}

// Chmod changes the mode of a file
func (e *EncryptFS) Chmod(name string, mode os.FileMode) error {
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return err
	}
	return e.base.Chmod(encryptedPath, mode)
}

// Chtimes changes the access and modification times of a file
func (e *EncryptFS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return err
	}
	return e.base.Chtimes(encryptedPath, atime, mtime)
}

// Chown changes the owner and group of a file
func (e *EncryptFS) Chown(name string, uid, gid int) error {
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return err
	}
	return e.base.Chown(encryptedPath, uid, gid)
}

// Truncate truncates a file to a specified size
func (e *EncryptFS) Truncate(name string, size int64) error {
	encryptedPath, err := e.translatePath(name)
	if err != nil {
		return err
	}
	// For encrypted files, we need to account for the header and overhead
	// For now, we'll implement basic truncation
	return e.base.Truncate(encryptedPath, size)
}

// encryptedFileInfo wraps os.FileInfo to adjust size for encrypted files
type encryptedFileInfo struct {
	os.FileInfo
	cipher CipherSuite
}

// newEncryptedFileInfo creates a new encryptedFileInfo
func newEncryptedFileInfo(info os.FileInfo, cipher CipherSuite) *encryptedFileInfo {
	return &encryptedFileInfo{
		FileInfo: info,
		cipher:   cipher,
	}
}

// Size returns the decrypted size of the file
func (e *encryptedFileInfo) Size() int64 {
	// Actual size on disk includes:
	// - Header (variable size)
	// - Ciphertext (plaintext + overhead)
	// For simplicity in this initial implementation, we return the actual size
	// In a full implementation, we would calculate the actual plaintext size
	return e.FileInfo.Size()
}
