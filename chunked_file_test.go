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
		ChunkSize: 1024, // Small chunks for testing
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
		ChunkSize: 100, // Very small chunks for testing seek across chunks
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
		{10, io.SeekCurrent, 500, 0},    // EOF
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
		ChunkSize: 100,
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
