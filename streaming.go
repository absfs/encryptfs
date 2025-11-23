package encryptfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/absfs/absfs"
)

// StreamingConfig controls streaming encryption behavior
type StreamingConfig struct {
	ChunkSize  int  // Size of each encrypted chunk (default: 64KB)
	EnableSeek bool // Allow seeking within encrypted files
}

// DefaultStreamingConfig returns sensible defaults for streaming
func DefaultStreamingConfig() StreamingConfig {
	return StreamingConfig{
		ChunkSize:  64 * 1024, // 64 KB chunks
		EnableSeek: true,
	}
}

// ChunkHeader represents metadata for an encrypted chunk
type ChunkHeader struct {
	ChunkSize     uint32 // Size of the plaintext chunk
	CiphertextSize uint32 // Size of the encrypted chunk (including tag)
	Nonce         []byte // Nonce for this chunk
}

// streamingFile wraps a file for chunked streaming encryption/decryption
type streamingFile struct {
	base          absfs.File
	fs            *EncryptFS
	fileHeader    *FileHeader
	engine        CipherEngine
	streamConfig  StreamingConfig
	chunks        []ChunkHeader
	currentChunk  int
	chunkData     []byte // Current chunk plaintext
	chunkOffset   int64  // Offset within current chunk
	globalOffset  int64  // Global offset in the virtual plaintext
	fileSize      int64  // Total plaintext size
	dirty         bool   // True if current chunk has been modified
	flags         int
	headerSize    int64 // Size of the main file header
	chunksStartPos int64 // Position where chunks start
}

// newStreamingFile creates a new streaming encrypted file
func newStreamingFile(base absfs.File, fs *EncryptFS, config StreamingConfig, flags int) (*streamingFile, error) {
	sf := &streamingFile{
		base:         base,
		fs:           fs,
		streamConfig: config,
		flags:        flags,
	}

	// Check if file exists and has content
	info, err := base.Stat()
	if err != nil {
		return nil, err
	}

	if info.Size() > 0 {
		if err := sf.loadStreamingFile(); err != nil {
			return nil, fmt.Errorf("failed to load streaming file: %w", err)
		}
	} else {
		if err := sf.initStreamingFile(); err != nil {
			return nil, fmt.Errorf("failed to initialize streaming file: %w", err)
		}
	}

	return sf, nil
}

// initStreamingFile initializes a new streaming encrypted file
func (sf *streamingFile) initStreamingFile() error {
	// Generate salt and nonce for file header
	salt, err := sf.fs.keyProvider.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	nonce, err := GenerateNonce(sf.fs.cipher)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	sf.fileHeader = NewFileHeader(sf.fs.cipher, salt, nonce)

	// Derive key
	key, err := sf.fs.keyProvider.DeriveKey(salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create cipher engine
	sf.engine, err = NewCipherEngine(sf.fs.cipher, key)
	if err != nil {
		return fmt.Errorf("failed to create cipher engine: %w", err)
	}

	sf.chunks = []ChunkHeader{}
	sf.chunkData = make([]byte, 0, sf.streamConfig.ChunkSize)
	sf.headerSize = int64(sf.fileHeader.Size())
	sf.chunksStartPos = sf.headerSize
	sf.dirty = true

	return nil
}

// loadStreamingFile loads an existing streaming encrypted file
func (sf *streamingFile) loadStreamingFile() error {
	// Read file header
	if _, err := sf.base.Seek(0, io.SeekStart); err != nil {
		return err
	}

	sf.fileHeader = &FileHeader{}
	n, err := sf.fileHeader.ReadFrom(sf.base)
	if err != nil {
		return fmt.Errorf("failed to read file header: %w", err)
	}
	sf.headerSize = n

	if err := sf.fileHeader.Validate(); err != nil {
		return err
	}

	// Derive key
	key, err := sf.fs.keyProvider.DeriveKey(sf.fileHeader.Salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create cipher engine
	sf.engine, err = NewCipherEngine(sf.fileHeader.Cipher, key)
	if err != nil {
		return fmt.Errorf("failed to create cipher engine: %w", err)
	}

	// Read chunk metadata (stored after file header)
	sf.chunksStartPos = sf.headerSize

	// For now, treat the file as a single chunk (backward compatible)
	// In a full implementation, we would read chunk headers
	ciphertextSize, err := sf.base.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	ciphertextSize -= sf.headerSize

	if ciphertextSize > 0 {
		sf.chunks = []ChunkHeader{{
			ChunkSize:      uint32(ciphertextSize) - uint32(sf.engine.Overhead()),
			CiphertextSize: uint32(ciphertextSize),
			Nonce:          sf.fileHeader.Nonce,
		}}
		sf.fileSize = int64(sf.chunks[0].ChunkSize)
	}

	return nil
}

// Read reads from the current position
func (sf *streamingFile) Read(p []byte) (n int, err error) {
	if sf.globalOffset >= sf.fileSize {
		return 0, io.EOF
	}

	// Load current chunk if needed
	if sf.chunkData == nil || len(sf.chunkData) == 0 {
		if err := sf.loadChunk(sf.currentChunk); err != nil {
			return 0, err
		}
	}

	// Read from current chunk
	n = copy(p, sf.chunkData[sf.chunkOffset:])
	sf.chunkOffset += int64(n)
	sf.globalOffset += int64(n)

	// Check if we need to load next chunk
	if sf.chunkOffset >= int64(len(sf.chunkData)) && sf.currentChunk+1 < len(sf.chunks) {
		sf.currentChunk++
		sf.chunkOffset = 0
		sf.chunkData = nil
	}

	if n < len(p) && sf.globalOffset < sf.fileSize {
		// Recursively read more
		n2, err2 := sf.Read(p[n:])
		n += n2
		if err2 != nil && err2 != io.EOF {
			return n, err2
		}
	}

	if sf.globalOffset >= sf.fileSize && n > 0 {
		err = io.EOF
	}

	return n, err
}

// loadChunk loads and decrypts a specific chunk
func (sf *streamingFile) loadChunk(chunkIdx int) error {
	if chunkIdx >= len(sf.chunks) {
		return io.EOF
	}

	chunk := sf.chunks[chunkIdx]

	// Calculate chunk position in file
	var chunkPos int64 = sf.chunksStartPos
	for i := 0; i < chunkIdx; i++ {
		chunkPos += int64(sf.chunks[i].CiphertextSize)
	}

	// Seek to chunk position
	if _, err := sf.base.Seek(chunkPos, io.SeekStart); err != nil {
		return err
	}

	// Read ciphertext
	ciphertext := make([]byte, chunk.CiphertextSize)
	if _, err := io.ReadFull(sf.base, ciphertext); err != nil {
		return fmt.Errorf("failed to read chunk ciphertext: %w", err)
	}

	// Decrypt
	plaintext, err := sf.engine.Decrypt(chunk.Nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt chunk: %w", err)
	}

	sf.chunkData = plaintext
	sf.chunkOffset = 0

	return nil
}

// Write writes data (will be chunked and encrypted on flush/close)
func (sf *streamingFile) Write(p []byte) (n int, err error) {
	// For simplicity, buffer writes until close
	// In a full implementation, we'd write complete chunks immediately
	sf.chunkData = append(sf.chunkData, p...)
	sf.globalOffset += int64(len(p))
	sf.dirty = true
	return len(p), nil
}

// Flush writes any pending chunks
func (sf *streamingFile) Flush() error {
	if !sf.dirty || len(sf.chunkData) == 0 {
		return nil
	}

	// Seek to beginning
	if _, err := sf.base.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// Write file header
	if _, err := sf.fileHeader.WriteTo(sf.base); err != nil {
		return err
	}

	// Encrypt and write data
	ciphertext, err := sf.engine.Encrypt(sf.fileHeader.Nonce, sf.chunkData)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	if _, err := sf.base.Write(ciphertext); err != nil {
		return err
	}

	// Truncate
	pos, err := sf.base.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	if err := sf.base.Truncate(pos); err != nil {
		return err
	}

	sf.fileSize = int64(len(sf.chunkData))
	sf.dirty = false

	return nil
}

// Close flushes and closes the file
func (sf *streamingFile) Close() error {
	if err := sf.Flush(); err != nil {
		sf.base.Close()
		return err
	}
	return sf.base.Close()
}

// Seek sets the offset for the next read/write
func (sf *streamingFile) Seek(offset int64, whence int) (int64, error) {
	if !sf.streamConfig.EnableSeek {
		return 0, fmt.Errorf("seeking disabled")
	}

	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = sf.globalOffset + offset
	case io.SeekEnd:
		newOffset = sf.fileSize + offset
	default:
		return 0, fmt.Errorf("invalid whence")
	}

	if newOffset < 0 {
		return 0, fmt.Errorf("negative position")
	}

	// Find which chunk contains this offset
	// For now with single chunk, just update offset
	sf.globalOffset = newOffset
	sf.chunkOffset = newOffset

	return newOffset, nil
}

// Stub methods to satisfy absfs.File interface
func (sf *streamingFile) Name() string                               { return sf.base.Name() }
func (sf *streamingFile) WriteString(s string) (int, error)          { return sf.Write([]byte(s)) }
func (sf *streamingFile) Sync() error                                { return sf.Flush() }
func (sf *streamingFile) Stat() (os.FileInfo, error)                 { return sf.base.Stat() }
func (sf *streamingFile) Readdir(n int) ([]os.FileInfo, error)       { return sf.base.Readdir(n) }
func (sf *streamingFile) Readdirnames(n int) ([]string, error)       { return sf.base.Readdirnames(n) }
func (sf *streamingFile) Truncate(size int64) error {
	// Simplified truncate
	if size < 0 {
		return fmt.Errorf("negative size")
	}
	sf.chunkData = sf.chunkData[:min(len(sf.chunkData), int(size))]
	sf.dirty = true
	return nil
}

func (sf *streamingFile) ReadAt(b []byte, off int64) (n int, err error) {
	// Simplified ReadAt
	oldOffset := sf.globalOffset
	if _, err := sf.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n, err = sf.Read(b)
	sf.globalOffset = oldOffset
	return n, err
}

func (sf *streamingFile) WriteAt(b []byte, off int64) (n int, err error) {
	// Simplified WriteAt
	oldOffset := sf.globalOffset
	if _, err := sf.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n, err = sf.Write(b)
	sf.globalOffset = oldOffset
	return n, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// writeChunkHeader writes chunk metadata (for future use)
func writeChunkHeader(w io.Writer, ch *ChunkHeader) error {
	if err := binary.Write(w, binary.LittleEndian, ch.ChunkSize); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, ch.CiphertextSize); err != nil {
		return err
	}
	nonceSize := uint16(len(ch.Nonce))
	if err := binary.Write(w, binary.LittleEndian, nonceSize); err != nil {
		return err
	}
	if _, err := w.Write(ch.Nonce); err != nil {
		return err
	}
	return nil
}

// readChunkHeader reads chunk metadata (for future use)
func readChunkHeader(r io.Reader) (*ChunkHeader, error) {
	ch := &ChunkHeader{}
	if err := binary.Read(r, binary.LittleEndian, &ch.ChunkSize); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ch.CiphertextSize); err != nil {
		return nil, err
	}
	var nonceSize uint16
	if err := binary.Read(r, binary.LittleEndian, &nonceSize); err != nil {
		return nil, err
	}
	ch.Nonce = make([]byte, nonceSize)
	if _, err := io.ReadFull(r, ch.Nonce); err != nil {
		return nil, err
	}
	return ch, nil
}
