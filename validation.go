package encryptfs

import (
	"fmt"
)

// Input validation helpers for defensive programming

// ValidateBuffer checks if a buffer is valid (non-nil and has expected size)
func ValidateBuffer(buf []byte, name string, minSize int) error {
	if buf == nil {
		return &ValidationError{
			Field:   name,
			Message: "buffer cannot be nil",
		}
	}
	if minSize > 0 && len(buf) < minSize {
		return &ValidationError{
			Field:   name,
			Value:   len(buf),
			Message: fmt.Sprintf("buffer too small: got %d bytes, need at least %d bytes", len(buf), minSize),
		}
	}
	return nil
}

// ValidateOffset checks if a file offset is valid
func ValidateOffset(offset int64, name string) error {
	if offset < 0 {
		return &ValidationError{
			Field:   name,
			Value:   offset,
			Message: "offset cannot be negative",
		}
	}
	return nil
}

// ValidateSize checks if a size parameter is valid
func ValidateSize(size int, name string, minSize, maxSize int) error {
	if size < 0 {
		return &ValidationError{
			Field:   name,
			Value:   size,
			Message: "size cannot be negative",
		}
	}
	if minSize >= 0 && size < minSize {
		return &ValidationError{
			Field:   name,
			Value:   size,
			Message: fmt.Sprintf("size too small: got %d, minimum is %d", size, minSize),
		}
	}
	if maxSize > 0 && size > maxSize {
		return &ValidationError{
			Field:   name,
			Value:   size,
			Message: fmt.Sprintf("size too large: got %d, maximum is %d", size, maxSize),
		}
	}
	return nil
}

// ValidateNonce checks if a nonce has the correct size for a cipher
func ValidateNonce(nonce []byte, cipher CipherSuite) error {
	if nonce == nil {
		return &ValidationError{
			Field:   "nonce",
			Message: "nonce cannot be nil",
		}
	}

	var expectedSize int
	switch cipher {
	case CipherAES256GCM:
		expectedSize = 12 // AES-GCM standard nonce size
	case CipherChaCha20Poly1305:
		expectedSize = 12 // ChaCha20-Poly1305 nonce size
	default:
		return &ValidationError{
			Field:   "cipher",
			Value:   cipher,
			Message: "unsupported cipher suite for nonce validation",
		}
	}

	if len(nonce) != expectedSize {
		return &ValidationError{
			Field:   "nonce",
			Value:   len(nonce),
			Message: fmt.Sprintf("invalid nonce size: got %d bytes, expected %d bytes for %s", len(nonce), expectedSize, cipher.String()),
		}
	}

	return nil
}

// ValidateKey checks if a key has the correct size
func ValidateKey(key []byte, expectedSize int) error {
	if key == nil {
		return &ValidationError{
			Field:   "key",
			Message: "key cannot be nil",
		}
	}

	if len(key) != expectedSize {
		return &ValidationError{
			Field:   "key",
			Value:   len(key),
			Message: fmt.Sprintf("invalid key size: got %d bytes, expected %d bytes", len(key), expectedSize),
		}
	}

	return nil
}

// ValidateChunkIndex checks if a chunk index is within valid bounds
func ValidateChunkIndex(index, maxIndex uint32, context string) error {
	if index > maxIndex {
		return &ValidationError{
			Field:   "chunk_index",
			Value:   index,
			Message: fmt.Sprintf("%s: chunk index %d exceeds maximum %d", context, index, maxIndex),
		}
	}
	return nil
}

// ValidateFilePath checks if a file path is valid (not empty)
func ValidateFilePath(path string) error {
	if path == "" {
		return &ValidationError{
			Field:   "path",
			Message: "file path cannot be empty",
		}
	}
	return nil
}

// ValidateReadWrite checks common preconditions for read/write operations
func ValidateReadWrite(buf []byte, position int64) error {
	if buf == nil {
		return ErrNilBuffer
	}
	if position < 0 {
		return ErrNegativeOffset
	}
	return nil
}
