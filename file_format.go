package encryptfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MagicBytes identifies encrypted files (ASCII: "ENCR")
	MagicBytes = uint32(0x454E4352)

	// CurrentVersion is the current file format version
	CurrentVersion = uint8(1)

	// HeaderSize is the fixed size of the file header (without salt and nonce)
	// 4 bytes (magic) + 1 byte (version) + 1 byte (cipher) + 2 bytes (salt size) = 8 bytes
	MinHeaderSize = 8
)

// FileHeader represents the header of an encrypted file
type FileHeader struct {
	Magic      uint32      // Magic bytes to identify encrypted files
	Version    uint8       // File format version
	Cipher     CipherSuite // Cipher suite used for encryption
	SaltSize   uint16      // Size of the salt in bytes
	Salt       []byte      // Salt for key derivation
	NonceSize  uint16      // Size of the nonce in bytes
	Nonce      []byte      // Nonce/IV for encryption
}

// NewFileHeader creates a new file header with the given parameters
func NewFileHeader(cipher CipherSuite, salt, nonce []byte) *FileHeader {
	return &FileHeader{
		Magic:     MagicBytes,
		Version:   CurrentVersion,
		Cipher:    cipher,
		SaltSize:  uint16(len(salt)),
		Salt:      salt,
		NonceSize: uint16(len(nonce)),
		Nonce:     nonce,
	}
}

// Size returns the total size of the header in bytes
func (h *FileHeader) Size() int {
	return MinHeaderSize + len(h.Salt) + 2 + len(h.Nonce)
}

// WriteTo writes the header to the given writer
func (h *FileHeader) WriteTo(w io.Writer) (int64, error) {
	buf := new(bytes.Buffer)

	// Write fixed-size fields
	if err := binary.Write(buf, binary.LittleEndian, h.Magic); err != nil {
		return 0, fmt.Errorf("failed to write magic bytes: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.Version); err != nil {
		return 0, fmt.Errorf("failed to write version: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.Cipher); err != nil {
		return 0, fmt.Errorf("failed to write cipher: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.SaltSize); err != nil {
		return 0, fmt.Errorf("failed to write salt size: %w", err)
	}

	// Write salt
	if _, err := buf.Write(h.Salt); err != nil {
		return 0, fmt.Errorf("failed to write salt: %w", err)
	}

	// Write nonce size
	if err := binary.Write(buf, binary.LittleEndian, h.NonceSize); err != nil {
		return 0, fmt.Errorf("failed to write nonce size: %w", err)
	}

	// Write nonce
	if _, err := buf.Write(h.Nonce); err != nil {
		return 0, fmt.Errorf("failed to write nonce: %w", err)
	}

	// Write to actual writer
	n, err := w.Write(buf.Bytes())
	return int64(n), err
}

// ReadFrom reads the header from the given reader
func (h *FileHeader) ReadFrom(r io.Reader) (int64, error) {
	var totalRead int64

	// Read magic bytes
	if err := binary.Read(r, binary.LittleEndian, &h.Magic); err != nil {
		return totalRead, fmt.Errorf("failed to read magic bytes: %w", err)
	}
	totalRead += 4

	if h.Magic != MagicBytes {
		return totalRead, ErrInvalidHeader
	}

	// Read version
	if err := binary.Read(r, binary.LittleEndian, &h.Version); err != nil {
		return totalRead, fmt.Errorf("failed to read version: %w", err)
	}
	totalRead += 1

	if h.Version > CurrentVersion {
		return totalRead, ErrUnsupportedVersion
	}

	// Read cipher
	if err := binary.Read(r, binary.LittleEndian, &h.Cipher); err != nil {
		return totalRead, fmt.Errorf("failed to read cipher: %w", err)
	}
	totalRead += 1

	// Read salt size
	if err := binary.Read(r, binary.LittleEndian, &h.SaltSize); err != nil {
		return totalRead, fmt.Errorf("failed to read salt size: %w", err)
	}
	totalRead += 2

	// Read salt
	h.Salt = make([]byte, h.SaltSize)
	n, err := io.ReadFull(r, h.Salt)
	totalRead += int64(n)
	if err != nil {
		return totalRead, fmt.Errorf("failed to read salt: %w", err)
	}

	// Read nonce size
	if err := binary.Read(r, binary.LittleEndian, &h.NonceSize); err != nil {
		return totalRead, fmt.Errorf("failed to read nonce size: %w", err)
	}
	totalRead += 2

	// Read nonce
	h.Nonce = make([]byte, h.NonceSize)
	n, err = io.ReadFull(r, h.Nonce)
	totalRead += int64(n)
	if err != nil {
		return totalRead, fmt.Errorf("failed to read nonce: %w", err)
	}

	return totalRead, nil
}

// Validate checks if the header is valid
func (h *FileHeader) Validate() error {
	if h.Magic != MagicBytes {
		return ErrInvalidHeader
	}
	if h.Version > CurrentVersion {
		return ErrUnsupportedVersion
	}
	if h.Cipher != CipherAES256GCM && h.Cipher != CipherChaCha20Poly1305 {
		return ErrUnsupportedCipher
	}
	if len(h.Salt) == 0 {
		return fmt.Errorf("salt cannot be empty")
	}
	if len(h.Nonce) == 0 {
		return fmt.Errorf("nonce cannot be empty")
	}
	return nil
}
