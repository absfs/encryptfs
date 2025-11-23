package encryptfs

import (
	"errors"
	"fmt"
)

// Error types represent different categories of errors

// ValidationError represents a configuration or parameter validation error
type ValidationError struct {
	Field   string // The field or parameter that failed validation
	Value   any    // The invalid value
	Message string // Human-readable error message
	Err     error  // Underlying error, if any
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error: %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// EncryptionError represents an encryption or decryption failure
type EncryptionError struct {
	Operation string // "encrypt" or "decrypt"
	Path      string // File path, if applicable
	ChunkIdx  uint32 // Chunk index, if applicable
	Message   string // Human-readable error message
	Err       error  // Underlying error
}

func (e *EncryptionError) Error() string {
	if e.Path != "" && e.ChunkIdx > 0 {
		return fmt.Sprintf("%s error: %s (chunk %d): %s", e.Operation, e.Path, e.ChunkIdx, e.Message)
	} else if e.Path != "" {
		return fmt.Sprintf("%s error: %s: %s", e.Operation, e.Path, e.Message)
	}
	return fmt.Sprintf("%s error: %s", e.Operation, e.Message)
}

func (e *EncryptionError) Unwrap() error {
	return e.Err
}

// IOError represents a file system I/O error
type IOError struct {
	Operation string // "read", "write", "seek", "open", "close", etc.
	Path      string // File path
	Offset    int64  // File offset, if applicable
	Message   string // Human-readable error message
	Err       error  // Underlying error
}

func (e *IOError) Error() string {
	if e.Path != "" && e.Offset >= 0 {
		return fmt.Sprintf("io error: %s %s at offset %d: %s", e.Operation, e.Path, e.Offset, e.Message)
	} else if e.Path != "" {
		return fmt.Sprintf("io error: %s %s: %s", e.Operation, e.Path, e.Message)
	}
	return fmt.Sprintf("io error: %s: %s", e.Operation, e.Message)
}

func (e *IOError) Unwrap() error {
	return e.Err
}

// CorruptionError represents a data corruption or integrity check failure
type CorruptionError struct {
	Path     string // File path
	ChunkIdx uint32 // Chunk index, if applicable
	Message  string // Human-readable error message
	Err      error  // Underlying error
}

func (e *CorruptionError) Error() string {
	if e.ChunkIdx > 0 {
		return fmt.Sprintf("corruption error: %s (chunk %d): %s", e.Path, e.ChunkIdx, e.Message)
	} else if e.Path != "" {
		return fmt.Sprintf("corruption error: %s: %s", e.Path, e.Message)
	}
	return fmt.Sprintf("corruption error: %s", e.Message)
}

func (e *CorruptionError) Unwrap() error {
	return e.Err
}

// AuthenticationError represents an authentication or authorization failure
type AuthenticationError struct {
	Path    string // File path
	Message string // Human-readable error message
	Err     error  // Underlying error
}

func (e *AuthenticationError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("authentication error: %s: %s", e.Path, e.Message)
	}
	return fmt.Sprintf("authentication error: %s", e.Message)
}

func (e *AuthenticationError) Unwrap() error {
	return e.Err
}

// Common sentinel errors (kept for backward compatibility)
var (
	ErrInvalidKey         = errors.New("invalid encryption key")
	ErrInvalidCiphertext  = errors.New("invalid ciphertext")
	ErrAuthFailed         = errors.New("authentication failed - data may be corrupted or tampered")
	ErrInvalidHeader      = errors.New("invalid file header")
	ErrUnsupportedVersion = errors.New("unsupported file format version")
	ErrUnsupportedCipher  = errors.New("unsupported cipher suite")
	ErrNilConfig          = errors.New("config cannot be nil")
	ErrNilKeyProvider     = errors.New("key provider cannot be nil")
	ErrNilBuffer          = errors.New("buffer cannot be nil")
	ErrInvalidOffset      = errors.New("invalid file offset")
	ErrInvalidSize        = errors.New("invalid size parameter")
	ErrNegativeOffset     = errors.New("negative offset not allowed")
)

// Helper functions for creating structured errors

// NewValidationError creates a new validation error
func NewValidationError(field string, value any, message string) error {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}

// NewEncryptionError creates a new encryption error
func NewEncryptionError(operation, path string, err error) error {
	return &EncryptionError{
		Operation: operation,
		Path:      path,
		Message:   err.Error(),
		Err:       err,
	}
}

// NewIOError creates a new I/O error
func NewIOError(operation, path string, err error) error {
	return &IOError{
		Operation: operation,
		Path:      path,
		Offset:    -1,
		Message:   err.Error(),
		Err:       err,
	}
}

// NewCorruptionError creates a new corruption error
func NewCorruptionError(path string, message string) error {
	return &CorruptionError{
		Path:    path,
		Message: message,
	}
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(path string, err error) error {
	return &AuthenticationError{
		Path:    path,
		Message: err.Error(),
		Err:     err,
	}
}

// Error checking helpers

// IsValidationError checks if an error is a validation error
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

// IsEncryptionError checks if an error is an encryption error
func IsEncryptionError(err error) bool {
	var ee *EncryptionError
	return errors.As(err, &ee)
}

// IsIOError checks if an error is an I/O error
func IsIOError(err error) bool {
	var ie *IOError
	return errors.As(err, &ie)
}

// IsCorruptionError checks if an error is a corruption error
func IsCorruptionError(err error) bool {
	var ce *CorruptionError
	return errors.As(err, &ce)
}

// IsAuthenticationError checks if an error is an authentication error
func IsAuthenticationError(err error) bool {
	var ae *AuthenticationError
	return errors.As(err, &ae)
}
