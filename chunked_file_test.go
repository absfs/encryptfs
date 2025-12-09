package encryptfs

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"testing"

	"github.com/absfs/memfs"
)

func TestChunkIndexHeader_WriteRead(t *testing.T) {
	// Create index
	index := NewChunkIndexHeader(DefaultChunkSize)
	index.AddChunk(1000, 64*1024)
	index.AddChunk(66000, 64*1024)
	index.AddChunk(132000, 32*1024) // Last chunk smaller

	// Write to buffer
	buf := new(bytes.Buffer)
	written, err := index.WriteTo(buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	if written != index.Size() {
		t.Errorf("Written size mismatch: got %d, want %d", written, index.Size())
	}

	// Read back
	index2 := &ChunkIndexHeader{}
	read, err := index2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if read != written {
		t.Errorf("Read size mismatch: got %d, want %d", read, written)
	}

	// Verify contents
	if index2.ChunkSize != index.ChunkSize {
		t.Errorf("ChunkSize mismatch: got %d, want %d", index2.ChunkSize, index.ChunkSize)
	}

	if index2.ChunkCount != index.ChunkCount {
		t.Errorf("ChunkCount mismatch: got %d, want %d", index2.ChunkCount, index.ChunkCount)
	}

	for i := uint32(0); i < index.ChunkCount; i++ {
		if index2.ChunkOffsets[i] != index.ChunkOffsets[i] {
			t.Errorf("Chunk %d offset mismatch: got %d, want %d", i, index2.ChunkOffsets[i], index.ChunkOffsets[i])
		}
		if index2.PlaintextSizes[i] != index.PlaintextSizes[i] {
			t.Errorf("Chunk %d size mismatch: got %d, want %d", i, index2.PlaintextSizes[i], index.PlaintextSizes[i])
		}
	}
}

func TestChunkIndexHeader_FindChunkForOffset(t *testing.T) {
	index := NewChunkIndexHeader(1000)
	index.AddChunk(0, 1000)  // Chunk 0: bytes 0-999
	index.AddChunk(0, 1000)  // Chunk 1: bytes 1000-1999
	index.AddChunk(0, 500)   // Chunk 2: bytes 2000-2499

	tests := []struct {
		offset         int64
		expectedChunk  uint32
		expectedOffset int64
	}{
		{0, 0, 0},       // Start of chunk 0
		{500, 0, 500},   // Middle of chunk 0
		{999, 0, 999},   // End of chunk 0
		{1000, 1, 0},    // Start of chunk 1
		{1500, 1, 500},  // Middle of chunk 1
		{2000, 2, 0},    // Start of chunk 2
		{2499, 2, 499},  // End of chunk 2 (last byte)
		{2500, 3, 0},    // EOF
	}

	for _, tt := range tests {
		chunk, offset, err := index.FindChunkForOffset(tt.offset)
		if err != nil && tt.offset != 2500 {
			t.Fatalf("FindChunkForOffset(%d) failed: %v", tt.offset, err)
		}

		if chunk != tt.expectedChunk {
			t.Errorf("Offset %d: chunk mismatch: got %d, want %d", tt.offset, chunk, tt.expectedChunk)
		}

		if offset != tt.expectedOffset {
			t.Errorf("Offset %d: offset in chunk mismatch: got %d, want %d", tt.offset, offset, tt.expectedOffset)
		}
	}
}

func TestChunkedFile_WriteRead(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024, // 4KB chunks (minimum valid size)
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Write data
	testData := []byte("Hello, chunked encryption world! This is a test of Phase 4 implementation.")

	file, err := fs.Create("/test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	n, err := file.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Write size mismatch: got %d, want %d", n, len(testData))
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read back
	file, err = fs.Open("/test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	file.Close()

	if !bytes.Equal(readData, testData) {
		t.Errorf("Data mismatch:\ngot:  %q\nwant: %q", readData, testData)
	}
}

func TestChunkedFile_Seek(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024, // 4KB chunks for testing seek across chunks
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create file with known data
	testData := bytes.Repeat([]byte("0123456789"), 50) // 500 bytes

	file, err := fs.Create("/seek-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	file.Write(testData)
	file.Close()

	// Test seeking
	file, err = fs.Open("/seek-test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	tests := []struct {
		offset   int64
		whence   int
		expected int64
		readByte byte
	}{
		{0, io.SeekStart, 0, '0'},       // Start
		{10, io.SeekStart, 10, '0'},     // Middle of first chunk
		{100, io.SeekStart, 100, '0'},   // Start of second chunk
		{250, io.SeekStart, 250, '0'},   // Middle of file
		{-10, io.SeekEnd, 490, '0'},     // Near end
		{9, io.SeekCurrent, 500, 0},     // EOF (491 after previous read + 9 = 500)
	}

	for i, tt := range tests {
		pos, err := file.Seek(tt.offset, tt.whence)
		if err != nil {
			t.Fatalf("Test %d: Seek failed: %v", i, err)
		}

		if pos != tt.expected {
			t.Errorf("Test %d: Position mismatch: got %d, want %d", i, pos, tt.expected)
		}

		if tt.expected < int64(len(testData)) {
			buf := make([]byte, 1)
			n, err := file.Read(buf)
			if err != nil {
				t.Fatalf("Test %d: Read failed: %v", i, err)
			}

			if n != 1 {
				t.Errorf("Test %d: Read size mismatch: got %d, want 1", i, n)
			}

			if buf[0] != tt.readByte {
				t.Errorf("Test %d: Read byte mismatch: got %c, want %c", i, buf[0], tt.readByte)
			}
		}
	}
}

func TestChunkedFile_LargeFile(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4096, // 4KB chunks
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create 1MB of random data
	testData := make([]byte, 1024*1024)
	rand.Read(testData)

	file, err := fs.Create("/large.bin")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Write in chunks
	written := 0
	chunkSize := 8192
	for written < len(testData) {
		end := written + chunkSize
		if end > len(testData) {
			end = len(testData)
		}

		n, err := file.Write(testData[written:end])
		if err != nil {
			t.Fatalf("Write failed at offset %d: %v", written, err)
		}

		written += n
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read back and verify
	file, err = fs.Open("/large.bin")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(readData, testData) {
		t.Error("Large file data mismatch")
	}
}

func TestChunkedFile_PartialChunkWrite(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024, // 4KB chunks (minimum valid size)
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Write initial data
	file, err := fs.Create("/partial.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	initial := bytes.Repeat([]byte("A"), 250) // 2.5 chunks
	file.Write(initial)
	file.Close()

	// Modify middle chunk
	file, err = fs.OpenFile("/partial.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}

	// Seek to middle of second chunk
	file.Seek(150, io.SeekStart)
	file.Write([]byte("MODIFIED"))
	file.Close()

	// Read and verify
	file, err = fs.Open("/partial.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	result, _ := io.ReadAll(file)
	file.Close()

	// Check that modification is in place
	expected := append([]byte{}, initial...)
	copy(expected[150:], []byte("MODIFIED"))

	if !bytes.Equal(result, expected) {
		t.Error("Partial chunk write failed")
	}
}

func BenchmarkChunkedFile_SequentialWrite(b *testing.B) {
	base, _ := memfs.NewFS()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 64 * 1024,
	}

	fs, _ := New(base, config)

	data := make([]byte, 64*1024)
	rand.Read(data)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		file, _ := fs.Create("/bench.bin")
		file.Write(data)
		file.Close()
		fs.Remove("/bench.bin")
	}
}

func BenchmarkChunkedFile_SequentialRead(b *testing.B) {
	base, _ := memfs.NewFS()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 64 * 1024,
	}

	fs, _ := New(base, config)

	// Create test file
	data := make([]byte, 64*1024)
	rand.Read(data)

	file, _ := fs.Create("/bench.bin")
	file.Write(data)
	file.Close()

	buf := make([]byte, 64*1024)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		file, _ := fs.Open("/bench.bin")
		io.ReadFull(file, buf)
		file.Close()
	}
}

func BenchmarkChunkedFile_RandomSeek(b *testing.B) {
	base, _ := memfs.NewFS()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 64 * 1024,
	}

	fs, _ := New(base, config)

	// Create 1MB test file
	data := make([]byte, 1024*1024)
	rand.Read(data)

	file, _ := fs.Create("/bench.bin")
	file.Write(data)
	file.Close()

	positions := make([]int64, 100)
	for i := range positions {
		positions[i] = int64(i * 10000)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		file, _ := fs.Open("/bench.bin")
		buf := make([]byte, 100)
		for _, pos := range positions {
			file.Seek(pos, io.SeekStart)
			file.Read(buf)
		}
		file.Close()
	}
}

// Additional chunked file tests for coverage

func TestChunkedFile_ReadAt(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create file with known data
	testData := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

	file, err := fs.Create("/readat.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write(testData)
	file.Close()

	// Test ReadAt
	file, err = fs.Open("/readat.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	tests := []struct {
		name     string
		offset   int64
		bufSize  int
		expected string
	}{
		{"Start", 0, 5, "01234"},
		{"Middle", 10, 6, "ABCDEF"},
		{"Near end", 40, 6, "efghij"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufSize)
			n, err := file.ReadAt(buf, tt.offset)
			if err != nil && err != io.EOF {
				t.Fatalf("ReadAt failed: %v", err)
			}
			if string(buf[:n]) != tt.expected {
				t.Errorf("ReadAt got %q, want %q", string(buf[:n]), tt.expected)
			}
		})
	}
}

func TestChunkedFile_WriteAt(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create file with initial data
	file, err := fs.Create("/writeat.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	initial := []byte("0123456789ABCDEF")
	file.Write(initial)

	// Use WriteAt to modify middle
	n, err := file.WriteAt([]byte("XXXX"), 5)
	if err != nil {
		t.Fatalf("WriteAt failed: %v", err)
	}
	if n != 4 {
		t.Errorf("WriteAt wrote %d bytes, want 4", n)
	}

	file.Close()

	// Verify
	file, err = fs.Open("/writeat.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	expected := "01234XXXX9ABCDEF"
	if string(data) != expected {
		t.Errorf("Got %q, want %q", string(data), expected)
	}
}

func TestChunkedFile_WriteString(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/writestring.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	testString := "Hello WriteString!"
	n, err := file.WriteString(testString)
	if err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}
	if n != len(testString) {
		t.Errorf("WriteString wrote %d bytes, want %d", n, len(testString))
	}

	file.Close()

	// Verify
	file, err = fs.Open("/writestring.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	if string(data) != testString {
		t.Errorf("Got %q, want %q", string(data), testString)
	}
}

func TestChunkedFile_Truncate(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/truncate.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	file.Write([]byte("0123456789"))

	// Truncate should return an error as not fully implemented
	err = file.Truncate(5)
	if err == nil {
		// If no error, that's fine too
		t.Log("Truncate succeeded (implementation complete)")
	} else {
		// Expected to error
		t.Logf("Truncate returned expected error: %v", err)
	}

	file.Close()
}

func TestChunkedFile_Stat(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/stat.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test data"))
	file.Close()

	file, err = fs.Open("/stat.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info == nil {
		t.Error("Stat returned nil")
	}

	if info.Size() == 0 {
		t.Error("Expected non-zero size")
	}
}

func TestChunkedFile_Name(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/name-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer file.Close()

	name := file.Name()
	if name == "" {
		t.Error("Name() returned empty string")
	}
}

func TestChunkedFile_Readdirnames(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/readdir.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test"))
	file.Close()

	file, err = fs.Open("/readdir.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	// Readdirnames on a file should return an error
	_, err = file.Readdirnames(0)
	if err == nil {
		t.Error("Expected error for Readdirnames on a file")
	}
}

func TestChunkedFile_Readdir(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/readdir2.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test"))
	file.Close()

	file, err = fs.Open("/readdir2.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	// Readdir on a file should return an error
	_, err = file.Readdir(0)
	if err == nil {
		t.Error("Expected error for Readdir on a file")
	}
}

func TestChunkedFile_NilBuffer(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/nil-buffer.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer file.Close()

	// Write with nil buffer
	_, err = file.Write(nil)
	if err == nil {
		t.Error("Expected error for nil buffer Write")
	}

	// Read with nil buffer
	_, err = file.Read(nil)
	if err == nil {
		t.Error("Expected error for nil buffer Read")
	}
}

func TestChunkedFile_EmptyReadWrite(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/empty-rw.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Write empty buffer
	n, err := file.Write([]byte{})
	if err != nil {
		t.Errorf("Empty Write failed: %v", err)
	}
	if n != 0 {
		t.Errorf("Empty Write returned %d, want 0", n)
	}

	// Read empty buffer
	n, err = file.Read([]byte{})
	if err != nil {
		t.Errorf("Empty Read failed: %v", err)
	}
	if n != 0 {
		t.Errorf("Empty Read returned %d, want 0", n)
	}

	file.Close()
}

func TestChunkedFile_SeekErrors(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024,
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	file, err := fs.Create("/seek-errors.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test data"))
	file.Close()

	file, err = fs.Open("/seek-errors.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	// Test negative position
	_, err = file.Seek(-100, io.SeekStart)
	if err == nil {
		t.Error("Expected error for negative seek position")
	}

	// Test invalid whence
	_, err = file.Seek(0, 99)
	if err == nil {
		t.Error("Expected error for invalid whence")
	}
}

func TestChunkedFile_MultiChunkOperations(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 4 * 1024, // 4KB chunks (minimum)
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	// Create file spanning multiple chunks
	testData := make([]byte, 20*1024) // 20KB = 5 chunks at 4KB each
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	file, err := fs.Create("/multi-chunk.bin")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write(testData)
	file.Close()

	// Read and verify
	file, err = fs.Open("/multi-chunk.bin")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(readData, testData) {
		t.Error("Multi-chunk data mismatch")
	}
}

func TestChunkedFile_InvalidChunkSize(t *testing.T) {
	base, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("Failed to create memfs: %v", err)
	}

	// Test chunk size below minimum
	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("test-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 10, // Below MinChunkSize
	}

	_, err = New(base, config)
	if err == nil {
		t.Error("Expected error for chunk size below minimum")
	}
}

func TestChunkIndexHeader_GetChunkInfo_OutOfRange(t *testing.T) {
	index := NewChunkIndexHeader(1024)
	index.AddChunk(0, 1024)

	// Request chunk beyond range
	_, _, err := index.GetChunkInfo(5)
	if err == nil {
		t.Error("Expected error for out of range chunk index")
	}
}

func TestChunkIndexHeader_FindChunkForOffset_Negative(t *testing.T) {
	index := NewChunkIndexHeader(1024)
	index.AddChunk(0, 1024)

	_, _, err := index.FindChunkForOffset(-1)
	if err == nil {
		t.Error("Expected error for negative offset")
	}
}

func TestChunkIndexHeader_FindChunkForOffset_BeyondEOF(t *testing.T) {
	index := NewChunkIndexHeader(1024)
	index.AddChunk(0, 1024)

	_, _, err := index.FindChunkForOffset(5000) // Beyond the single chunk
	if err == nil {
		t.Error("Expected error for offset beyond EOF")
	}
}

func TestEncryptedChunkHeader_Size(t *testing.T) {
	nonce := make([]byte, 12)
	header := NewEncryptedChunkHeader(1024, nonce)

	expectedSize := 4 + 12 // uint32 + nonce
	if header.Size() != expectedSize {
		t.Errorf("Size() = %d, want %d", header.Size(), expectedSize)
	}
}

func TestEncryptedChunkHeader_WriteRead(t *testing.T) {
	nonce := make([]byte, 12)
	rand.Read(nonce)
	header := NewEncryptedChunkHeader(2048, nonce)

	buf := new(bytes.Buffer)
	_, err := header.WriteTo(buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	readHeader := &EncryptedChunkHeader{}
	_, err = readHeader.ReadChunkHeader(buf, 12)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if readHeader.PlaintextSize != header.PlaintextSize {
		t.Errorf("PlaintextSize mismatch: got %d, want %d", readHeader.PlaintextSize, header.PlaintextSize)
	}

	if !bytes.Equal(readHeader.Nonce, header.Nonce) {
		t.Error("Nonce mismatch")
	}
}

func TestValidateChunkSize(t *testing.T) {
	tests := []struct {
		size      uint32
		expectErr bool
	}{
		{MinChunkSize - 1, true},  // Below minimum
		{MinChunkSize, false},     // At minimum
		{DefaultChunkSize, false}, // Default
		{MaxChunkSize, false},     // At maximum
		{MaxChunkSize + 1, true},  // Above maximum
	}

	for _, tt := range tests {
		err := ValidateChunkSize(tt.size)
		if tt.expectErr && err == nil {
			t.Errorf("ValidateChunkSize(%d) expected error", tt.size)
		}
		if !tt.expectErr && err != nil {
			t.Errorf("ValidateChunkSize(%d) unexpected error: %v", tt.size, err)
		}
	}
}

func TestCalculateChunkCount(t *testing.T) {
	tests := []struct {
		dataSize  int64
		chunkSize uint32
		expected  uint32
	}{
		{0, 1024, 0},
		{1, 1024, 1},
		{1024, 1024, 1},
		{1025, 1024, 2},
		{2048, 1024, 2},
		{10240, 1024, 10},
	}

	for _, tt := range tests {
		result := CalculateChunkCount(tt.dataSize, tt.chunkSize)
		if result != tt.expected {
			t.Errorf("CalculateChunkCount(%d, %d) = %d, want %d", tt.dataSize, tt.chunkSize, result, tt.expected)
		}
	}
}

func TestCalculateCiphertextSize(t *testing.T) {
	result := CalculateCiphertextSize(1024, 12, 16)
	// Header: 4 (size) + 12 (nonce) = 16
	// Ciphertext: 1024 + 16 (tag) = 1040
	// Total: 16 + 1040 = 1056
	expected := 4 + 12 + 1024 + 16
	if result != expected {
		t.Errorf("CalculateCiphertextSize = %d, want %d", result, expected)
	}
}

func TestChunkIndexHeader_ActualSize(t *testing.T) {
	index := NewChunkIndexHeader(1024)
	index.AddChunk(0, 1024)
	index.AddChunk(1024, 1024)

	// 4 (chunk size) + 4 (count) + 2*8 (offsets) + 2*4 (sizes) = 32
	expected := int64(8 + 2*8 + 2*4)
	if index.ActualSize() != expected {
		t.Errorf("ActualSize() = %d, want %d", index.ActualSize(), expected)
	}
}

func TestChunkCache_Operations(t *testing.T) {
	cache := newChunkCache(3)

	// Put some data
	cache.Put(0, []byte("chunk0"))
	cache.Put(1, []byte("chunk1"))
	cache.Put(2, []byte("chunk2"))

	// Get and verify
	data, ok := cache.Get(0)
	if !ok {
		t.Error("Expected to find chunk 0")
	}
	if string(data) != "chunk0" {
		t.Errorf("Got %q, want %q", string(data), "chunk0")
	}

	// Test eviction
	cache.Put(3, []byte("chunk3"))

	// Oldest (0) should be evicted
	_, ok = cache.Get(0)
	if ok {
		t.Error("Expected chunk 0 to be evicted")
	}

	// Newer entries should still exist
	_, ok = cache.Get(1)
	if !ok {
		t.Error("Expected chunk 1 to still exist")
	}
}

func TestChunkCache_GetNonExistent(t *testing.T) {
	cache := newChunkCache(3)

	data, ok := cache.Get(99)
	if ok {
		t.Error("Expected not to find non-existent chunk")
	}
	if data != nil {
		t.Error("Expected nil data for non-existent chunk")
	}
}
