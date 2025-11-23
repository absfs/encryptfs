package encryptfs

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/absfs/absfs"
)

// ChunkedFile implements a chunked encrypted file with efficient seeking
type ChunkedFile struct {
	base       absfs.File
	fs         *EncryptFS
	fileHeader *FileHeader
	chunkIndex *ChunkIndexHeader
	engine     CipherEngine
	chunkSize  uint32
	flags      int

	// Current state
	position int64 // Current read/write position in plaintext
	dirty    bool  // Whether we have uncommitted changes

	// Chunk cache
	cache      *chunkCache
	currentIdx uint32      // Index of currently loaded chunk
	currentBuf []byte      // Currently loaded chunk plaintext
	chunkDirty bool        // Whether current chunk has been modified
	mu         sync.RWMutex // Protects concurrent access
}

// newChunkedFile creates a new chunked encrypted file
func newChunkedFile(base absfs.File, fs *EncryptFS, chunkSize uint32, flags int) (*ChunkedFile, error) {
	if err := ValidateChunkSize(chunkSize); err != nil {
		return nil, err
	}

	cf := &ChunkedFile{
		base:       base,
		fs:         fs,
		chunkSize:  chunkSize,
		flags:      flags,
		cache:      newChunkCache(16), // Cache up to 16 chunks
		currentIdx: 0,
		position:   0,
	}

	// Check if file exists and has content
	info, err := base.Stat()
	if err != nil {
		return nil, err
	}

	if info.Size() > 0 {
		// Load existing chunked file
		if err := cf.loadChunkedFile(); err != nil {
			return nil, fmt.Errorf("failed to load chunked file: %w", err)
		}
	} else {
		// Initialize new chunked file
		if err := cf.initChunkedFile(); err != nil {
			return nil, fmt.Errorf("failed to initialize chunked file: %w", err)
		}
	}

	return cf, nil
}

// initChunkedFile initializes a new chunked encrypted file
func (cf *ChunkedFile) initChunkedFile() error {
	// Generate salt
	salt, err := cf.fs.keyProvider.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key
	key, err := cf.fs.keyProvider.DeriveKey(salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create cipher engine
	cf.engine, err = NewCipherEngine(cf.fs.cipher, key)
	if err != nil {
		return fmt.Errorf("failed to create cipher engine: %w", err)
	}

	// Generate nonce for file header (not used for chunk encryption)
	nonce, err := GenerateNonce(cf.fs.cipher)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create file header
	cf.fileHeader = NewFileHeader(cf.fs.cipher, salt, nonce)

	// Create empty chunk index
	cf.chunkIndex = NewChunkIndexHeader(cf.chunkSize)

	// Write headers to file
	if err := cf.writeHeaders(); err != nil {
		return fmt.Errorf("failed to write headers: %w", err)
	}

	return nil
}

// loadChunkedFile loads an existing chunked encrypted file
func (cf *ChunkedFile) loadChunkedFile() error {
	// Seek to start
	if _, err := cf.base.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	// Read file header
	cf.fileHeader = &FileHeader{}
	if _, err := cf.fileHeader.ReadFrom(cf.base); err != nil {
		return fmt.Errorf("failed to read file header: %w", err)
	}

	// Validate header
	if err := cf.fileHeader.Validate(); err != nil {
		return fmt.Errorf("invalid file header: %w", err)
	}

	// Derive key
	key, err := cf.fs.keyProvider.DeriveKey(cf.fileHeader.Salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create cipher engine
	cf.engine, err = NewCipherEngine(cf.fileHeader.Cipher, key)
	if err != nil {
		return fmt.Errorf("failed to create cipher engine: %w", err)
	}

	// Read chunk index
	cf.chunkIndex = &ChunkIndexHeader{}
	if _, err := cf.chunkIndex.ReadFrom(cf.base); err != nil {
		return fmt.Errorf("failed to read chunk index: %w", err)
	}

	return nil
}

// writeHeaders writes file header and chunk index to the beginning of the file
func (cf *ChunkedFile) writeHeaders() error {
	// Seek to start
	if _, err := cf.base.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// Write file header
	if _, err := cf.fileHeader.WriteTo(cf.base); err != nil {
		return fmt.Errorf("failed to write file header: %w", err)
	}

	// Write chunk index
	if _, err := cf.chunkIndex.WriteTo(cf.base); err != nil {
		return fmt.Errorf("failed to write chunk index: %w", err)
	}

	return nil
}

// Read reads up to len(p) bytes from the chunked file
func (cf *ChunkedFile) Read(p []byte) (int, error) {
	// Input validation
	if p == nil {
		return 0, ErrNilBuffer
	}

	cf.mu.Lock()
	defer cf.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	totalRead := 0
	fileSize := cf.chunkIndex.TotalPlaintextSize()

	for totalRead < len(p) {
		// Check if we're at EOF
		if cf.position >= fileSize {
			if totalRead == 0 {
				return 0, io.EOF
			}
			return totalRead, nil
		}

		// Find which chunk we're in
		chunkIdx, offsetInChunk, err := cf.chunkIndex.FindChunkForOffset(cf.position)
		if err != nil {
			return totalRead, err
		}

		// Load the chunk if not already loaded
		if err := cf.ensureChunkLoaded(chunkIdx); err != nil {
			return totalRead, err
		}

		// Read from current chunk
		available := len(cf.currentBuf) - int(offsetInChunk)
		toRead := len(p) - totalRead
		if toRead > available {
			toRead = available
		}

		copy(p[totalRead:], cf.currentBuf[offsetInChunk:offsetInChunk+int64(toRead)])
		totalRead += toRead
		cf.position += int64(toRead)
	}

	return totalRead, nil
}

// Write writes len(p) bytes to the chunked file
func (cf *ChunkedFile) Write(p []byte) (int, error) {
	// Input validation
	if p == nil {
		return 0, ErrNilBuffer
	}

	cf.mu.Lock()
	defer cf.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	totalWritten := 0

	for totalWritten < len(p) {
		// Find which chunk we're in (or need to create)
		chunkIdx, offsetInChunk, err := cf.findOrCreateChunkForWrite(cf.position)
		if err != nil {
			return totalWritten, err
		}

		// Load the chunk
		if err := cf.ensureChunkLoaded(chunkIdx); err != nil {
			return totalWritten, err
		}

		// Expand buffer if needed
		neededSize := int(offsetInChunk) + (len(p) - totalWritten)
		if neededSize > len(cf.currentBuf) {
			if neededSize > int(cf.chunkSize) {
				neededSize = int(cf.chunkSize)
			}
			newBuf := make([]byte, neededSize)
			copy(newBuf, cf.currentBuf)
			cf.currentBuf = newBuf
		}

		// Write to current chunk
		available := int(cf.chunkSize) - int(offsetInChunk)
		toWrite := len(p) - totalWritten
		if toWrite > available {
			toWrite = available
		}

		copy(cf.currentBuf[offsetInChunk:], p[totalWritten:totalWritten+toWrite])
		totalWritten += toWrite
		cf.position += int64(toWrite)
		cf.chunkDirty = true
		cf.dirty = true
	}

	return totalWritten, nil
}

// ensureChunkLoaded loads a chunk into memory if not already loaded
func (cf *ChunkedFile) ensureChunkLoaded(chunkIdx uint32) error {
	// If already loaded, return
	if chunkIdx == cf.currentIdx && cf.currentBuf != nil {
		return nil
	}

	// Flush current chunk if dirty
	if cf.chunkDirty && cf.currentBuf != nil {
		if err := cf.flushCurrentChunk(); err != nil {
			return err
		}
	}

	// Handle new chunk creation (chunk doesn't exist yet)
	if chunkIdx >= cf.chunkIndex.ChunkCount {
		cf.currentBuf = make([]byte, 0, cf.chunkSize)
		cf.currentIdx = chunkIdx
		cf.chunkDirty = false
		return nil
	}

	// Check cache
	if data, ok := cf.cache.Get(chunkIdx); ok {
		cf.currentBuf = data
		cf.currentIdx = chunkIdx
		cf.chunkDirty = false
		return nil
	}

	// Load chunk from disk
	data, err := cf.readChunk(chunkIdx)
	if err != nil {
		return err
	}

	cf.currentBuf = data
	cf.currentIdx = chunkIdx
	cf.chunkDirty = false
	cf.cache.Put(chunkIdx, data)

	return nil
}

// readChunk reads and decrypts a single chunk
func (cf *ChunkedFile) readChunk(chunkIdx uint32) ([]byte, error) {
	// Get chunk info
	offset, plaintextSize, err := cf.chunkIndex.GetChunkInfo(chunkIdx)
	if err != nil {
		return nil, err
	}

	// Seek to chunk
	if _, err := cf.base.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to chunk: %w", err)
	}

	// Read chunk header
	chunkHeader := &EncryptedChunkHeader{}
	if _, err := chunkHeader.ReadFrom(cf.base, cf.engine.NonceSize()); err != nil {
		return nil, fmt.Errorf("failed to read chunk header: %w", err)
	}

	// Read ciphertext
	ciphertextSize := int(plaintextSize) + cf.engine.Overhead()
	ciphertext := make([]byte, ciphertextSize)
	if _, err := io.ReadFull(cf.base, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	// Decrypt
	plaintext, err := cf.engine.Decrypt(chunkHeader.Nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt chunk: %w", err)
	}

	return plaintext, nil
}

// flushCurrentChunk writes the current chunk to disk
func (cf *ChunkedFile) flushCurrentChunk() error {
	if !cf.chunkDirty || cf.currentBuf == nil {
		return nil
	}

	// Generate nonce
	nonce := make([]byte, cf.engine.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt chunk
	ciphertext, err := cf.engine.Encrypt(nonce, cf.currentBuf)
	if err != nil {
		return fmt.Errorf("failed to encrypt chunk: %w", err)
	}

	// Create chunk header
	chunkHeader := NewEncryptedChunkHeader(uint32(len(cf.currentBuf)), nonce)

	// Calculate where to write
	var offset int64
	if cf.currentIdx < cf.chunkIndex.ChunkCount {
		// Updating existing chunk
		offset = int64(cf.chunkIndex.ChunkOffsets[cf.currentIdx])
	} else {
		// Appending new chunk
		offset, err = cf.base.Seek(0, io.SeekEnd)
		if err != nil {
			return fmt.Errorf("failed to seek to end: %w", err)
		}
	}

	// Seek to position
	if _, err := cf.base.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	// Write chunk header
	if _, err := chunkHeader.WriteTo(cf.base); err != nil {
		return fmt.Errorf("failed to write chunk header: %w", err)
	}

	// Write ciphertext
	if _, err := cf.base.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	// Update chunk index
	if cf.currentIdx < cf.chunkIndex.ChunkCount {
		cf.chunkIndex.PlaintextSizes[cf.currentIdx] = uint32(len(cf.currentBuf))
	} else {
		cf.chunkIndex.AddChunk(uint64(offset), uint32(len(cf.currentBuf)))
	}

	cf.chunkDirty = false
	return nil
}

// findOrCreateChunkForWrite finds or creates a chunk for the given write position
func (cf *ChunkedFile) findOrCreateChunkForWrite(pos int64) (uint32, int64, error) {
	// Calculate which chunk this position falls into
	chunkIdx := uint32(pos / int64(cf.chunkSize))
	offsetInChunk := pos % int64(cf.chunkSize)

	return chunkIdx, offsetInChunk, nil
}

// Seek sets the offset for the next Read or Write
func (cf *ChunkedFile) Seek(offset int64, whence int) (int64, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	var newPos int64
	fileSize := cf.chunkIndex.TotalPlaintextSize()

	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = cf.position + offset
	case io.SeekEnd:
		newPos = fileSize + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}

	if newPos < 0 {
		return 0, fmt.Errorf("negative position: %d", newPos)
	}

	cf.position = newPos
	return newPos, nil
}

// Sync commits the current contents to stable storage
func (cf *ChunkedFile) Sync() error {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	// Flush current chunk if dirty
	if cf.chunkDirty {
		if err := cf.flushCurrentChunk(); err != nil {
			return err
		}
	}

	// Write updated headers
	if cf.dirty {
		if err := cf.writeHeaders(); err != nil {
			return err
		}
		cf.dirty = false
	}

	// Sync base file
	return cf.base.Sync()
}

// Close closes the chunked file
func (cf *ChunkedFile) Close() error {
	// Sync before closing
	if err := cf.Sync(); err != nil {
		return err
	}

	return cf.base.Close()
}

// Stat returns file info
func (cf *ChunkedFile) Stat() (os.FileInfo, error) {
	return cf.base.Stat()
}

// Name returns the name of the file
func (cf *ChunkedFile) Name() string {
	return cf.base.Name()
}

// ReadAt reads len(b) bytes from the File starting at byte offset off
func (cf *ChunkedFile) ReadAt(b []byte, off int64) (int, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	// Save current position
	oldPos := cf.position

	// Seek to offset
	cf.position = off

	// Read (use internal unlocked read)
	n, err := cf.readInternal(b)

	// Restore position
	cf.position = oldPos

	return n, err
}

// readInternal is an internal read that assumes lock is held
func (cf *ChunkedFile) readInternal(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	totalRead := 0
	fileSize := cf.chunkIndex.TotalPlaintextSize()

	for totalRead < len(p) {
		if cf.position >= fileSize {
			if totalRead == 0 {
				return 0, io.EOF
			}
			return totalRead, nil
		}

		chunkIdx, offsetInChunk, err := cf.chunkIndex.FindChunkForOffset(cf.position)
		if err != nil {
			return totalRead, err
		}

		if err := cf.ensureChunkLoaded(chunkIdx); err != nil {
			return totalRead, err
		}

		available := len(cf.currentBuf) - int(offsetInChunk)
		toRead := len(p) - totalRead
		if toRead > available {
			toRead = available
		}

		copy(p[totalRead:], cf.currentBuf[offsetInChunk:offsetInChunk+int64(toRead)])
		totalRead += toRead
		cf.position += int64(toRead)
	}

	return totalRead, nil
}

// WriteAt writes len(b) bytes to the File starting at byte offset off
func (cf *ChunkedFile) WriteAt(b []byte, off int64) (int, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	// Save current position
	oldPos := cf.position

	// Seek to offset
	cf.position = off

	// Write (use internal unlocked write)
	n, err := cf.writeInternal(b)

	// Restore position
	cf.position = oldPos

	return n, err
}

// writeInternal is an internal write that assumes lock is held
func (cf *ChunkedFile) writeInternal(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	totalWritten := 0

	for totalWritten < len(p) {
		chunkIdx, offsetInChunk, err := cf.findOrCreateChunkForWrite(cf.position)
		if err != nil {
			return totalWritten, err
		}

		if err := cf.ensureChunkLoaded(chunkIdx); err != nil {
			return totalWritten, err
		}

		neededSize := int(offsetInChunk) + (len(p) - totalWritten)
		if neededSize > len(cf.currentBuf) {
			if neededSize > int(cf.chunkSize) {
				neededSize = int(cf.chunkSize)
			}
			newBuf := make([]byte, neededSize)
			copy(newBuf, cf.currentBuf)
			cf.currentBuf = newBuf
		}

		available := int(cf.chunkSize) - int(offsetInChunk)
		toWrite := len(p) - totalWritten
		if toWrite > available {
			toWrite = available
		}

		copy(cf.currentBuf[offsetInChunk:], p[totalWritten:totalWritten+toWrite])
		totalWritten += toWrite
		cf.position += int64(toWrite)
		cf.chunkDirty = true
		cf.dirty = true
	}

	return totalWritten, nil
}

// WriteString writes the contents of string s
func (cf *ChunkedFile) WriteString(s string) (int, error) {
	return cf.Write([]byte(s))
}

// Truncate changes the size of the file
func (cf *ChunkedFile) Truncate(size int64) error {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	// For now, simple implementation
	// A complete implementation would handle shrinking/growing chunks properly
	return fmt.Errorf("Truncate not yet fully implemented for chunked files")
}

// Readdirnames reads directory names (not applicable for files)
func (cf *ChunkedFile) Readdirnames(n int) ([]string, error) {
	return nil, fmt.Errorf("not a directory")
}

// Readdir reads directory entries (not applicable for files)
func (cf *ChunkedFile) Readdir(n int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("not a directory")
}

// WriteBulk writes data using parallel chunk encryption (experimental)
// This method is optimized for large sequential writes
func (cf *ChunkedFile) WriteBulk(p []byte) (int, error) {
	// Input validation
	if p == nil {
		return 0, ErrNilBuffer
	}

	cf.mu.Lock()
	defer cf.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	// Check if parallel processing is enabled and worthwhile
	if !cf.fs.config.Parallel.Enabled || len(p) < int(cf.chunkSize)*4 {
		// Fall back to sequential write
		return cf.writeInternal(p)
	}

	// Calculate how many chunks we'll write
	startChunkIdx := uint32(cf.position / int64(cf.chunkSize))
	endPos := cf.position + int64(len(p))
	endChunkIdx := uint32((endPos + int64(cf.chunkSize) - 1) / int64(cf.chunkSize))
	numChunks := endChunkIdx - startChunkIdx

	// If not enough chunks for parallel, use sequential
	minChunks := uint32(cf.fs.config.Parallel.MinChunksForParallel)
	if minChunks == 0 {
		minChunks = 4
	}
	if numChunks < minChunks {
		return cf.writeInternal(p)
	}

	// Prepare chunks for parallel encryption
	jobs := make([]chunkJob, 0, numChunks)
	offset := 0

	for chunkIdx := startChunkIdx; chunkIdx < endChunkIdx && offset < len(p); chunkIdx++ {
		offsetInChunk := cf.position % int64(cf.chunkSize)
		if chunkIdx > startChunkIdx {
			offsetInChunk = 0
		}

		// Calculate how much to write to this chunk
		available := int64(cf.chunkSize) - offsetInChunk
		toWrite := int64(len(p)) - int64(offset)
		if toWrite > available {
			toWrite = available
		}

		// Prepare chunk data
		chunkData := make([]byte, cf.chunkSize)
		copy(chunkData[offsetInChunk:], p[offset:offset+int(toWrite)])

		// Generate nonce
		nonce := make([]byte, cf.engine.NonceSize())
		rand.Read(nonce)

		jobs = append(jobs, chunkJob{
			index:     chunkIdx,
			plaintext: chunkData[:offsetInChunk+toWrite],
			nonce:     nonce,
		})

		offset += int(toWrite)
		cf.position += toWrite
	}

	// Encrypt chunks in parallel
	if err := cf.parallelEncryptChunks(jobs); err != nil {
		return 0, err
	}

	// Write encrypted chunks to disk
	for _, job := range jobs {
		chunkHeader := NewEncryptedChunkHeader(uint32(len(job.plaintext)), job.nonce)

		// Calculate write offset
		var writeOffset int64
		if job.index < cf.chunkIndex.ChunkCount {
			writeOffset = int64(cf.chunkIndex.ChunkOffsets[job.index])
		} else {
			writeOffset, _ = cf.base.Seek(0, io.SeekEnd)
		}

		// Write chunk
		cf.base.Seek(writeOffset, io.SeekStart)
		chunkHeader.WriteTo(cf.base)
		cf.base.Write(job.ciphertext)

		// Update index
		if job.index < cf.chunkIndex.ChunkCount {
			cf.chunkIndex.PlaintextSizes[job.index] = uint32(len(job.plaintext))
		} else {
			cf.chunkIndex.AddChunk(uint64(writeOffset), uint32(len(job.plaintext)))
		}
	}

	cf.dirty = true
	return len(p), nil
}

// ReadBulk reads data using parallel chunk decryption (experimental)
// This method is optimized for large sequential reads
func (cf *ChunkedFile) ReadBulk(p []byte) (int, error) {
	// Input validation
	if p == nil {
		return 0, ErrNilBuffer
	}

	cf.mu.Lock()
	defer cf.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	fileSize := cf.chunkIndex.TotalPlaintextSize()
	if cf.position >= fileSize {
		return 0, io.EOF
	}

	// Check if parallel processing is enabled and worthwhile
	if !cf.fs.config.Parallel.Enabled || len(p) < int(cf.chunkSize)*4 {
		// Fall back to sequential read
		return cf.readInternal(p)
	}

	// Calculate chunks we need to read
	startChunkIdx, offsetInStart, _ := cf.chunkIndex.FindChunkForOffset(cf.position)
	endPos := cf.position + int64(len(p))
	if endPos > fileSize {
		endPos = fileSize
	}

	var endChunkIdx uint32
	if endPos == fileSize {
		endChunkIdx = cf.chunkIndex.ChunkCount
	} else {
		endChunkIdx, _, _ = cf.chunkIndex.FindChunkForOffset(endPos - 1)
		endChunkIdx++
	}

	numChunks := endChunkIdx - startChunkIdx

	// If not enough chunks for parallel, use sequential
	minChunks := uint32(cf.fs.config.Parallel.MinChunksForParallel)
	if minChunks == 0 {
		minChunks = 4
	}
	if numChunks < minChunks {
		return cf.readInternal(p)
	}

	// Load and decrypt chunks in parallel
	jobs := make([]chunkJob, numChunks)
	for i := uint32(0); i < numChunks; i++ {
		chunkIdx := startChunkIdx + i

		// Get chunk info
		offset, plaintextSize, _ := cf.chunkIndex.GetChunkInfo(chunkIdx)

		// Seek and read chunk header
		cf.base.Seek(int64(offset), io.SeekStart)
		header := &EncryptedChunkHeader{}
		header.ReadFrom(cf.base, cf.engine.NonceSize())

		// Read ciphertext
		ciphertextSize := int(plaintextSize) + cf.engine.Overhead()
		ciphertext := make([]byte, ciphertextSize)
		io.ReadFull(cf.base, ciphertext)

		jobs[i] = chunkJob{
			index:      chunkIdx,
			nonce:      header.Nonce,
			ciphertext: ciphertext,
		}
	}

	// Decrypt in parallel
	if err := cf.parallelDecryptChunks(jobs); err != nil {
		return 0, err
	}

	// Copy decrypted data to output buffer
	totalRead := 0
	for i, job := range jobs {
		var startOffset int64
		if i == 0 {
			startOffset = offsetInStart
		}

		toCopy := len(job.plaintext) - int(startOffset)
		remaining := len(p) - totalRead
		if toCopy > remaining {
			toCopy = remaining
		}

		copy(p[totalRead:], job.plaintext[startOffset:startOffset+int64(toCopy)])
		totalRead += toCopy

		if totalRead >= len(p) {
			break
		}
	}

	cf.position += int64(totalRead)
	return totalRead, nil
}

// chunkCache implements a simple LRU cache for chunks
type chunkCache struct {
	mu       sync.RWMutex
	capacity int
	cache    map[uint32][]byte
	lru      []uint32 // Simple LRU tracking
}

func newChunkCache(capacity int) *chunkCache {
	return &chunkCache{
		capacity: capacity,
		cache:    make(map[uint32][]byte),
		lru:      make([]uint32, 0, capacity),
	}
}

func (c *chunkCache) Get(key uint32) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, ok := c.cache[key]
	if !ok {
		return nil, false
	}

	// Make a copy to avoid data races
	result := make([]byte, len(data))
	copy(result, data)
	return result, true
}

func (c *chunkCache) Put(key uint32, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Make a copy
	stored := make([]byte, len(data))
	copy(stored, data)

	// Check if we need to evict
	if len(c.cache) >= c.capacity {
		// Evict oldest (first in LRU list)
		if len(c.lru) > 0 {
			oldest := c.lru[0]
			delete(c.cache, oldest)
			c.lru = c.lru[1:]
		}
	}

	c.cache[key] = stored
	c.lru = append(c.lru, key)
}
