package encryptfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// ChunkedFileFormat defines the structure for chunk-based encrypted files
//
// File Layout:
// ┌─────────────────────────────────────┐
// │ Main Header                         │ <- FileHeader (magic, version, cipher, salt, nonce)
// ├─────────────────────────────────────┤
// │ Chunk Index Header                  │ <- ChunkIndexHeader
// │ - Chunk size (uint32)               │
// │ - Chunk count (uint32)              │
// │ - Index offset table ([]uint64)     │
// ├─────────────────────────────────────┤
// │ Chunk 0                             │
// │ ├─ Chunk Header                     │
// │ │  - Plaintext size (uint32)        │
// │ │  - Nonce (12 bytes for GCM)       │
// │ └─ Ciphertext + Auth Tag            │
// ├─────────────────────────────────────┤
// │ Chunk 1                             │
// │ └─ ...                              │
// └─────────────────────────────────────┘

const (
	// DefaultChunkSize is the default chunk size (64 KB)
	DefaultChunkSize = 64 * 1024

	// MinChunkSize is the minimum allowed chunk size (64 bytes, for testing)
	MinChunkSize = 64

	// MaxChunkSize is the maximum allowed chunk size (16 MB)
	MaxChunkSize = 16 * 1024 * 1024

	// ChunkIndexReservedSize is the reserved space for chunk index (enough for ~1700 chunks)
	// This prevents the index from overwriting chunk data as it grows
	// Size calculation: 8 (header) + 1700 * 12 (offset + size per chunk) = 20,408 bytes
	ChunkIndexReservedSize = 20 * 1024 // 20 KB
)

// ChunkIndexHeader contains metadata about all chunks in the file
type ChunkIndexHeader struct {
	ChunkSize      uint32   // Size of each plaintext chunk (constant for file)
	ChunkCount     uint32   // Total number of chunks
	ChunkOffsets   []uint64 // Byte offset of each chunk from start of file
	PlaintextSizes []uint32 // Plaintext size of each chunk (may be < ChunkSize for last chunk)
}

// NewChunkIndexHeader creates a new chunk index header
func NewChunkIndexHeader(chunkSize uint32) *ChunkIndexHeader {
	return &ChunkIndexHeader{
		ChunkSize:      chunkSize,
		ChunkCount:     0,
		ChunkOffsets:   make([]uint64, 0),
		PlaintextSizes: make([]uint32, 0),
	}
}

// Size returns the total size of the chunk index header in bytes (including reserved space)
func (h *ChunkIndexHeader) Size() int64 {
	// Always return the reserved size to ensure consistent file layout
	return ChunkIndexReservedSize
}

// ActualSize returns the actual size of the data (without padding)
func (h *ChunkIndexHeader) ActualSize() int64 {
	// 4 (chunk size) + 4 (count) + count*8 (offsets) + count*4 (sizes)
	return int64(8 + len(h.ChunkOffsets)*8 + len(h.PlaintextSizes)*4)
}

// WriteTo writes the chunk index header to a writer
func (h *ChunkIndexHeader) WriteTo(w io.Writer) (int64, error) {
	buf := new(bytes.Buffer)

	// Write chunk size
	if err := binary.Write(buf, binary.LittleEndian, h.ChunkSize); err != nil {
		return 0, fmt.Errorf("failed to write chunk size: %w", err)
	}

	// Write chunk count
	if err := binary.Write(buf, binary.LittleEndian, h.ChunkCount); err != nil {
		return 0, fmt.Errorf("failed to write chunk count: %w", err)
	}

	// Write all chunk offsets
	for _, offset := range h.ChunkOffsets {
		if err := binary.Write(buf, binary.LittleEndian, offset); err != nil {
			return 0, fmt.Errorf("failed to write chunk offset: %w", err)
		}
	}

	// Write all plaintext sizes
	for _, size := range h.PlaintextSizes {
		if err := binary.Write(buf, binary.LittleEndian, size); err != nil {
			return 0, fmt.Errorf("failed to write plaintext size: %w", err)
		}
	}

	// Write padding to fill reserved space
	actualSize := buf.Len()
	paddingSize := int(ChunkIndexReservedSize) - actualSize
	if paddingSize > 0 {
		padding := make([]byte, paddingSize)
		buf.Write(padding)
	}

	n, err := w.Write(buf.Bytes())
	return int64(n), err
}

// ReadFrom reads the chunk index header from a reader
func (h *ChunkIndexHeader) ReadFrom(r io.Reader) (int64, error) {
	var totalRead int64

	// Read chunk size
	if err := binary.Read(r, binary.LittleEndian, &h.ChunkSize); err != nil {
		return totalRead, fmt.Errorf("failed to read chunk size: %w", err)
	}
	totalRead += 4

	// Read chunk count
	if err := binary.Read(r, binary.LittleEndian, &h.ChunkCount); err != nil {
		return totalRead, fmt.Errorf("failed to read chunk count: %w", err)
	}
	totalRead += 4

	// Read chunk offsets
	h.ChunkOffsets = make([]uint64, h.ChunkCount)
	for i := uint32(0); i < h.ChunkCount; i++ {
		if err := binary.Read(r, binary.LittleEndian, &h.ChunkOffsets[i]); err != nil {
			return totalRead, fmt.Errorf("failed to read chunk offset %d: %w", i, err)
		}
		totalRead += 8
	}

	// Read plaintext sizes
	h.PlaintextSizes = make([]uint32, h.ChunkCount)
	for i := uint32(0); i < h.ChunkCount; i++ {
		if err := binary.Read(r, binary.LittleEndian, &h.PlaintextSizes[i]); err != nil {
			return totalRead, fmt.Errorf("failed to read plaintext size %d: %w", i, err)
		}
		totalRead += 4
	}

	// Skip padding to reach the end of reserved space
	paddingSize := ChunkIndexReservedSize - totalRead
	if paddingSize > 0 {
		padding := make([]byte, paddingSize)
		n, err := io.ReadFull(r, padding)
		totalRead += int64(n)
		if err != nil {
			return totalRead, fmt.Errorf("failed to skip padding: %w", err)
		}
	}

	return totalRead, nil
}

// AddChunk adds a new chunk to the index
func (h *ChunkIndexHeader) AddChunk(offset uint64, plaintextSize uint32) {
	h.ChunkOffsets = append(h.ChunkOffsets, offset)
	h.PlaintextSizes = append(h.PlaintextSizes, plaintextSize)
	h.ChunkCount++
}

// GetChunkInfo returns the offset and plaintext size for a given chunk index
func (h *ChunkIndexHeader) GetChunkInfo(chunkIdx uint32) (offset uint64, plaintextSize uint32, err error) {
	if chunkIdx >= h.ChunkCount {
		return 0, 0, fmt.Errorf("chunk index %d out of range (count: %d)", chunkIdx, h.ChunkCount)
	}
	return h.ChunkOffsets[chunkIdx], h.PlaintextSizes[chunkIdx], nil
}

// TotalPlaintextSize returns the total size of all plaintext data
func (h *ChunkIndexHeader) TotalPlaintextSize() int64 {
	var total int64
	for _, size := range h.PlaintextSizes {
		total += int64(size)
	}
	return total
}

// FindChunkForOffset finds which chunk contains the given plaintext offset
// Returns: chunk index, offset within chunk, error
func (h *ChunkIndexHeader) FindChunkForOffset(offset int64) (uint32, int64, error) {
	if offset < 0 {
		return 0, 0, fmt.Errorf("negative offset: %d", offset)
	}

	var currentOffset int64
	for i := uint32(0); i < h.ChunkCount; i++ {
		chunkSize := int64(h.PlaintextSizes[i])
		if offset < currentOffset+chunkSize {
			// Found the chunk
			return i, offset - currentOffset, nil
		}
		currentOffset += chunkSize
	}

	// Offset is beyond EOF
	if offset == currentOffset {
		// Exactly at EOF
		return h.ChunkCount, 0, nil
	}

	return 0, 0, fmt.Errorf("offset %d beyond file size %d", offset, currentOffset)
}

// EncryptedChunkHeader contains metadata for a single encrypted chunk
type EncryptedChunkHeader struct {
	PlaintextSize uint32 // Size of plaintext data in this chunk
	Nonce         []byte // Nonce for this chunk's encryption
}

// NewEncryptedChunkHeader creates a new chunk header
func NewEncryptedChunkHeader(plaintextSize uint32, nonce []byte) *EncryptedChunkHeader {
	return &EncryptedChunkHeader{
		PlaintextSize: plaintextSize,
		Nonce:         nonce,
	}
}

// Size returns the size of the chunk header in bytes
func (h *EncryptedChunkHeader) Size() int {
	return 4 + len(h.Nonce)
}

// WriteTo writes the chunk header to a writer
func (h *EncryptedChunkHeader) WriteTo(w io.Writer) (int64, error) {
	buf := new(bytes.Buffer)

	// Write plaintext size
	if err := binary.Write(buf, binary.LittleEndian, h.PlaintextSize); err != nil {
		return 0, fmt.Errorf("failed to write plaintext size: %w", err)
	}

	// Write nonce
	if _, err := buf.Write(h.Nonce); err != nil {
		return 0, fmt.Errorf("failed to write nonce: %w", err)
	}

	n, err := w.Write(buf.Bytes())
	return int64(n), err
}

// ReadFrom reads the chunk header from a reader
func (h *EncryptedChunkHeader) ReadFrom(r io.Reader, nonceSize int) (int64, error) {
	var totalRead int64

	// Read plaintext size
	if err := binary.Read(r, binary.LittleEndian, &h.PlaintextSize); err != nil {
		return totalRead, fmt.Errorf("failed to read plaintext size: %w", err)
	}
	totalRead += 4

	// Read nonce
	h.Nonce = make([]byte, nonceSize)
	n, err := io.ReadFull(r, h.Nonce)
	totalRead += int64(n)
	if err != nil {
		return totalRead, fmt.Errorf("failed to read nonce: %w", err)
	}

	return totalRead, nil
}

// ValidateChunkSize validates that a chunk size is within acceptable bounds
func ValidateChunkSize(size uint32) error {
	if size < MinChunkSize {
		return fmt.Errorf("chunk size %d below minimum %d", size, MinChunkSize)
	}
	if size > MaxChunkSize {
		return fmt.Errorf("chunk size %d above maximum %d", size, MaxChunkSize)
	}
	return nil
}

// CalculateChunkCount calculates how many chunks are needed for a given data size
func CalculateChunkCount(dataSize int64, chunkSize uint32) uint32 {
	if dataSize == 0 {
		return 0
	}
	chunks := (dataSize + int64(chunkSize) - 1) / int64(chunkSize)
	return uint32(chunks)
}

// CalculateCiphertextSize calculates the ciphertext size for a plaintext chunk
// including the chunk header and authentication tag
func CalculateCiphertextSize(plaintextSize uint32, nonceSize, tagSize int) int {
	headerSize := 4 + nonceSize // PlaintextSize (4 bytes) + Nonce
	return headerSize + int(plaintextSize) + tagSize
}
