package encryptfs

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/absfs/absfs"
	"github.com/google/uuid"
)

// FilenameEncryptor handles encryption and decryption of filenames
type FilenameEncryptor interface {
	// EncryptFilename encrypts a filename
	EncryptFilename(plaintext string) (string, error)

	// DecryptFilename decrypts a filename
	DecryptFilename(ciphertext string) (string, error)

	// EncryptPath encrypts a full path (including directory separators)
	EncryptPath(plaintext string) (string, error)

	// DecryptPath decrypts a full path
	DecryptPath(ciphertext string) (string, error)
}

// noOpFilenameEncryptor passes through filenames without encryption
type noOpFilenameEncryptor struct{}

func (n *noOpFilenameEncryptor) EncryptFilename(plaintext string) (string, error) {
	return plaintext, nil
}

func (n *noOpFilenameEncryptor) DecryptFilename(ciphertext string) (string, error) {
	return ciphertext, nil
}

func (n *noOpFilenameEncryptor) EncryptPath(plaintext string) (string, error) {
	return plaintext, nil
}

func (n *noOpFilenameEncryptor) DecryptPath(ciphertext string) (string, error) {
	return ciphertext, nil
}

// deterministicFilenameEncryptor uses SIV mode for deterministic filename encryption
type deterministicFilenameEncryptor struct {
	siv               *SIVEngine
	preserveExtensions bool
	separator         string
}

// NewDeterministicFilenameEncryptor creates a new deterministic filename encryptor
func NewDeterministicFilenameEncryptor(key []byte, preserveExtensions bool, separator string) (*deterministicFilenameEncryptor, error) {
	// Derive a 64-byte key for SIV from the 32-byte master key
	sivKey := make([]byte, 64)

	// Use HKDF or similar to derive the SIV key
	// For simplicity, we'll duplicate and XOR for now
	// In production, use proper key derivation
	copy(sivKey[:32], key)
	copy(sivKey[32:], key)

	// XOR second half with a constant to differentiate
	for i := 0; i < 32; i++ {
		sivKey[32+i] ^= 0xAA
	}

	siv, err := NewSIVEngine(sivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SIV engine: %w", err)
	}

	return &deterministicFilenameEncryptor{
		siv:               siv,
		preserveExtensions: preserveExtensions,
		separator:         separator,
	}, nil
}

func (d *deterministicFilenameEncryptor) EncryptFilename(plaintext string) (string, error) {
	if plaintext == "" || plaintext == "." || plaintext == ".." {
		return plaintext, nil
	}

	var base, ext string
	if d.preserveExtensions {
		ext = filepath.Ext(plaintext)
		base = strings.TrimSuffix(plaintext, ext)
	} else {
		base = plaintext
	}

	// Encrypt the base name using SIV
	ciphertext, err := d.siv.Encrypt([]byte(base))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt filename: %w", err)
	}

	// Encode as URL-safe base64
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(ciphertext)

	// Reattach extension if preserved
	if d.preserveExtensions && ext != "" {
		return encoded + ext, nil
	}

	return encoded, nil
}

func (d *deterministicFilenameEncryptor) DecryptFilename(ciphertext string) (string, error) {
	if ciphertext == "" || ciphertext == "." || ciphertext == ".." {
		return ciphertext, nil
	}

	var encoded, ext string
	if d.preserveExtensions {
		ext = filepath.Ext(ciphertext)
		encoded = strings.TrimSuffix(ciphertext, ext)
	} else {
		encoded = ciphertext
	}

	// Decode from base64
	data, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode filename: %w", err)
	}

	// Decrypt using SIV
	plaintext, err := d.siv.Decrypt(data)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt filename: %w", err)
	}

	// Reattach extension if it was preserved
	if d.preserveExtensions && ext != "" {
		return string(plaintext) + ext, nil
	}

	return string(plaintext), nil
}

func (d *deterministicFilenameEncryptor) EncryptPath(plaintext string) (string, error) {
	if plaintext == "" || plaintext == "." {
		return plaintext, nil
	}

	// Split path into components
	parts := strings.Split(plaintext, d.separator)

	// Encrypt each component
	for i, part := range parts {
		if part != "" && part != "." && part != ".." {
			encrypted, err := d.EncryptFilename(part)
			if err != nil {
				return "", err
			}
			parts[i] = encrypted
		}
	}

	return strings.Join(parts, d.separator), nil
}

func (d *deterministicFilenameEncryptor) DecryptPath(ciphertext string) (string, error) {
	if ciphertext == "" || ciphertext == "." {
		return ciphertext, nil
	}

	// Split path into components
	parts := strings.Split(ciphertext, d.separator)

	// Decrypt each component
	for i, part := range parts {
		if part != "" && part != "." && part != ".." {
			decrypted, err := d.DecryptFilename(part)
			if err != nil {
				return "", err
			}
			parts[i] = decrypted
		}
	}

	return strings.Join(parts, d.separator), nil
}

// randomFilenameEncryptor uses random UUIDs with a metadata database
type randomFilenameEncryptor struct {
	siv          *SIVEngine
	metadata     *FilenameMetadata
	separator    string
	mu           sync.RWMutex
}

// FilenameMetadata stores mappings between encrypted and plaintext filenames
type FilenameMetadata struct {
	// Map from encrypted path to plaintext path
	Mappings map[string]string `json:"mappings"`
	// Map from plaintext path to encrypted path (reverse lookup)
	Reverse  map[string]string `json:"reverse"`
	mu       sync.RWMutex
}

// NewFilenameMetadata creates a new metadata store
func NewFilenameMetadata() *FilenameMetadata {
	return &FilenameMetadata{
		Mappings: make(map[string]string),
		Reverse:  make(map[string]string),
	}
}

// Load loads metadata from a file
func (m *FilenameMetadata) Load(fs absfs.FileSystem, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, err := fs.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, start fresh
			return nil
		}
		return fmt.Errorf("failed to open metadata file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(m); err != nil {
		return fmt.Errorf("failed to decode metadata: %w", err)
	}

	// Rebuild reverse map
	m.Reverse = make(map[string]string)
	for encrypted, plaintext := range m.Mappings {
		m.Reverse[plaintext] = encrypted
	}

	return nil
}

// Save saves metadata to a file
func (m *FilenameMetadata) Save(fs absfs.FileSystem, path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	file, err := fs.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create metadata file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(m); err != nil {
		return fmt.Errorf("failed to encode metadata: %w", err)
	}

	return nil
}

// Add adds a mapping
func (m *FilenameMetadata) Add(encrypted, plaintext string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Mappings[encrypted] = plaintext
	m.Reverse[plaintext] = encrypted
}

// Get retrieves a plaintext filename from an encrypted one
func (m *FilenameMetadata) Get(encrypted string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plaintext, ok := m.Mappings[encrypted]
	return plaintext, ok
}

// GetReverse retrieves an encrypted filename from a plaintext one
func (m *FilenameMetadata) GetReverse(plaintext string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	encrypted, ok := m.Reverse[plaintext]
	return encrypted, ok
}

// NewRandomFilenameEncryptor creates a new random filename encryptor
func NewRandomFilenameEncryptor(key []byte, metadata *FilenameMetadata, separator string) (*randomFilenameEncryptor, error) {
	// Derive a 64-byte key for SIV
	sivKey := make([]byte, 64)
	copy(sivKey[:32], key)
	copy(sivKey[32:], key)
	for i := 0; i < 32; i++ {
		sivKey[32+i] ^= 0xBB
	}

	siv, err := NewSIVEngine(sivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SIV engine: %w", err)
	}

	return &randomFilenameEncryptor{
		siv:       siv,
		metadata:  metadata,
		separator: separator,
	}, nil
}

func (r *randomFilenameEncryptor) EncryptFilename(plaintext string) (string, error) {
	if plaintext == "" || plaintext == "." || plaintext == ".." {
		return plaintext, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we already have a mapping
	if encrypted, ok := r.metadata.GetReverse(plaintext); ok {
		return encrypted, nil
	}

	// Generate a random UUID for the encrypted filename
	id := uuid.New()
	encrypted := id.String()

	// Store the mapping
	r.metadata.Add(encrypted, plaintext)

	return encrypted, nil
}

func (r *randomFilenameEncryptor) DecryptFilename(ciphertext string) (string, error) {
	if ciphertext == "" || ciphertext == "." || ciphertext == ".." {
		return ciphertext, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Look up the mapping
	plaintext, ok := r.metadata.Get(ciphertext)
	if !ok {
		return "", fmt.Errorf("no mapping found for encrypted filename: %s", ciphertext)
	}

	return plaintext, nil
}

func (r *randomFilenameEncryptor) EncryptPath(plaintext string) (string, error) {
	if plaintext == "" || plaintext == "." {
		return plaintext, nil
	}

	parts := strings.Split(plaintext, r.separator)

	for i, part := range parts {
		if part != "" && part != "." && part != ".." {
			encrypted, err := r.EncryptFilename(part)
			if err != nil {
				return "", err
			}
			parts[i] = encrypted
		}
	}

	return strings.Join(parts, r.separator), nil
}

func (r *randomFilenameEncryptor) DecryptPath(ciphertext string) (string, error) {
	if ciphertext == "" || ciphertext == "." {
		return ciphertext, nil
	}

	parts := strings.Split(ciphertext, r.separator)

	for i, part := range parts {
		if part != "" && part != "." && part != ".." {
			decrypted, err := r.DecryptFilename(part)
			if err != nil {
				return "", err
			}
			parts[i] = decrypted
		}
	}

	return strings.Join(parts, r.separator), nil
}

// NewFilenameEncryptor creates a filename encryptor based on the configuration
func NewFilenameEncryptor(config *Config, key []byte, fs absfs.FileSystem) (FilenameEncryptor, error) {
	separator := string([]byte{fs.Separator()})

	switch config.FilenameEncryption {
	case FilenameEncryptionNone:
		return &noOpFilenameEncryptor{}, nil

	case FilenameEncryptionDeterministic:
		return NewDeterministicFilenameEncryptor(key, config.PreserveExtensions, separator)

	case FilenameEncryptionRandom:
		metadata := NewFilenameMetadata()

		// Load existing metadata if path is specified
		if config.MetadataPath != "" {
			if err := metadata.Load(fs, config.MetadataPath); err != nil {
				// If load fails, we'll start fresh
				// In production, might want to handle this differently
			}
		}

		return NewRandomFilenameEncryptor(key, metadata, separator)

	default:
		return &noOpFilenameEncryptor{}, nil
	}
}

// deriveFilenameKey derives a separate key for filename encryption
func deriveFilenameKey(masterKey []byte) ([]byte, error) {
	// Use a simple derivation - in production use HKDF
	key := make([]byte, 32)

	// Read from crypto/rand using masterKey as context
	// For now, we'll just XOR with a constant
	copy(key, masterKey)
	for i := 0; i < 32; i++ {
		key[i] ^= byte(i)
	}

	// Better approach: use HKDF
	// This is placeholder for proper key derivation
	randBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		return nil, err
	}

	for i := 0; i < 32; i++ {
		key[i] ^= randBytes[i]
	}

	return key, nil
}
