package encryptfs

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/absfs/memfs"
)

// createStreamingTestFS creates an EncryptFS configured for streaming mode (no chunking)
func createStreamingTestFS(t *testing.T) *EncryptFS {
	t.Helper()
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
		ChunkSize: 0, // Disable chunking to use streaming mode
	}

	fs, err := New(base, config)
	if err != nil {
		t.Fatalf("Failed to create EncryptFS: %v", err)
	}

	return fs
}

func TestStreamingConfig_Defaults(t *testing.T) {
	config := DefaultStreamingConfig()

	if config.ChunkSize != 64*1024 {
		t.Errorf("Expected default chunk size 64KB, got %d", config.ChunkSize)
	}

	if !config.EnableSeek {
		t.Error("Expected seeking to be enabled by default")
	}
}

func TestStreamingFile_NewFile(t *testing.T) {
	fs := createStreamingTestFS(t)

	// Create a new file
	file, err := fs.Create("/streaming-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	testData := []byte("Hello, streaming encryption!")

	n, err := file.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read it back
	file, err = fs.Open("/streaming-test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	readData, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(readData, testData) {
		t.Errorf("Data mismatch:\ngot:  %q\nwant: %q", readData, testData)
	}
}

func TestStreamingFile_EmptyFile(t *testing.T) {
	fs := createStreamingTestFS(t)

	// Create an empty file
	file, err := fs.Create("/empty.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read empty file
	file, err = fs.Open("/empty.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(data) != 0 {
		t.Errorf("Expected empty data, got %d bytes", len(data))
	}
}

func TestStreamingFile_WriteString(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/writestring.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	testString := "Testing WriteString method"
	n, err := file.WriteString(testString)
	if err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}

	if n != len(testString) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testString), n)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify
	file, err = fs.Open("/writestring.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	if string(data) != testString {
		t.Errorf("Data mismatch: got %q, want %q", string(data), testString)
	}
}

func TestStreamingFile_Sync(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/sync-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer file.Close()

	file.Write([]byte("test data"))

	// Sync should not error
	if err := file.Sync(); err != nil {
		t.Errorf("Sync failed: %v", err)
	}
}

func TestStreamingFile_Name(t *testing.T) {
	fs := createStreamingTestFS(t)

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

func TestStreamingFile_Stat(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/stat-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	file.Write([]byte("test data for stat"))
	file.Close()

	file, err = fs.Open("/stat-test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info == nil {
		t.Error("Stat returned nil info")
	}

	if info.Size() == 0 {
		t.Error("Expected non-zero file size")
	}
}

func TestStreamingFile_Seek(t *testing.T) {
	fs := createStreamingTestFS(t)

	// Create file with data
	file, err := fs.Create("/seek-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	testData := []byte("0123456789ABCDEFGHIJ")
	file.Write(testData)
	file.Close()

	// Open and seek
	file, err = fs.Open("/seek-test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	// Test SeekStart
	pos, err := file.Seek(5, io.SeekStart)
	if err != nil {
		t.Fatalf("Seek SeekStart failed: %v", err)
	}
	if pos != 5 {
		t.Errorf("Expected position 5, got %d", pos)
	}

	// Test SeekCurrent
	pos, err = file.Seek(3, io.SeekCurrent)
	if err != nil {
		t.Fatalf("Seek SeekCurrent failed: %v", err)
	}
	if pos != 8 {
		t.Errorf("Expected position 8, got %d", pos)
	}

	// Test SeekEnd
	pos, err = file.Seek(-5, io.SeekEnd)
	if err != nil {
		t.Fatalf("Seek SeekEnd failed: %v", err)
	}
	if pos != 15 {
		t.Errorf("Expected position 15, got %d", pos)
	}
}

func TestStreamingFile_SeekNegativePosition(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/seek-neg.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test"))
	file.Close()

	file, err = fs.Open("/seek-neg.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	// Attempt to seek to negative position
	_, err = file.Seek(-100, io.SeekStart)
	if err == nil {
		t.Error("Expected error for negative seek position")
	}
}

func TestStreamingFile_ReadAt(t *testing.T) {
	fs := createStreamingTestFS(t)

	// Create file with data
	file, err := fs.Create("/readat.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	testData := []byte("0123456789ABCDEFGHIJ")
	file.Write(testData)
	file.Close()

	// Open and use ReadAt
	file, err = fs.Open("/readat.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	buf := make([]byte, 5)
	n, err := file.ReadAt(buf, 10)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt failed: %v", err)
	}

	if n != 5 {
		t.Errorf("Expected to read 5 bytes, got %d", n)
	}

	expected := "ABCDE"
	if string(buf) != expected {
		t.Errorf("ReadAt data mismatch: got %q, want %q", string(buf), expected)
	}
}

func TestStreamingFile_WriteAt(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/writeat.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Write initial data
	testData := []byte("0123456789")
	file.Write(testData)

	// WriteAt to modify middle
	n, err := file.WriteAt([]byte("XXXXX"), 3)
	if err != nil {
		t.Fatalf("WriteAt failed: %v", err)
	}

	if n != 5 {
		t.Errorf("Expected to write 5 bytes, got %d", n)
	}

	file.Close()

	// Verify
	file, err = fs.Open("/writeat.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	expected := "012XXXXX89"
	if string(data) != expected {
		t.Errorf("WriteAt data mismatch: got %q, want %q", string(data), expected)
	}
}

func TestStreamingFile_Truncate(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/truncate.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Write data
	file.Write([]byte("0123456789ABCDEF"))

	// Truncate to smaller size
	err = file.Truncate(5)
	if err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}

	file.Close()

	// Verify
	file, err = fs.Open("/truncate.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	if len(data) != 5 {
		t.Errorf("Expected 5 bytes after truncate, got %d", len(data))
	}
}

func TestStreamingFile_TruncateNegative(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/truncate-neg.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer file.Close()

	file.Write([]byte("test"))

	// Truncate with negative size should error
	err = file.Truncate(-1)
	if err == nil {
		t.Error("Expected error for negative truncate size")
	}
}

func TestStreamingFile_LargeFile(t *testing.T) {
	fs := createStreamingTestFS(t)

	// Create 256KB of random data
	testData := make([]byte, 256*1024)
	rand.Read(testData)

	file, err := fs.Create("/large-streaming.bin")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	n, err := file.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read back and verify
	file, err = fs.Open("/large-streaming.bin")
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

func TestStreamingFile_MultipleWrites(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/multi-write.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Multiple writes
	file.Write([]byte("First "))
	file.Write([]byte("Second "))
	file.Write([]byte("Third"))

	file.Close()

	// Verify
	file, err = fs.Open("/multi-write.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	expected := "First Second Third"
	if string(data) != expected {
		t.Errorf("Data mismatch: got %q, want %q", string(data), expected)
	}
}

func TestStreamingFile_ReadAfterEOF(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/eof-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("short"))
	file.Close()

	file, err = fs.Open("/eof-test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	// Read all data
	data, _ := io.ReadAll(file)
	if string(data) != "short" {
		t.Errorf("Data mismatch: got %q", string(data))
	}

	// Try to read more - should get EOF
	buf := make([]byte, 10)
	n, err := file.Read(buf)
	if n != 0 || err != io.EOF {
		t.Errorf("Expected 0 bytes and EOF, got %d bytes and %v", n, err)
	}
}

func TestChunkHeader_WriteRead(t *testing.T) {
	// Test the chunk header serialization
	header := &ChunkHeader{
		ChunkSize:      1024,
		CiphertextSize: 1040,
		Nonce:          make([]byte, 12),
	}
	rand.Read(header.Nonce)

	buf := new(bytes.Buffer)
	err := writeChunkHeader(buf, header)
	if err != nil {
		t.Fatalf("writeChunkHeader failed: %v", err)
	}

	// Read back
	readHeader, err := readChunkHeader(buf)
	if err != nil {
		t.Fatalf("readChunkHeader failed: %v", err)
	}

	if readHeader.ChunkSize != header.ChunkSize {
		t.Errorf("ChunkSize mismatch: got %d, want %d", readHeader.ChunkSize, header.ChunkSize)
	}

	if readHeader.CiphertextSize != header.CiphertextSize {
		t.Errorf("CiphertextSize mismatch: got %d, want %d", readHeader.CiphertextSize, header.CiphertextSize)
	}

	if !bytes.Equal(readHeader.Nonce, header.Nonce) {
		t.Error("Nonce mismatch")
	}
}

func TestMinFunction(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 1, -1},
		{100, 100, 100},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestStreamingFile_Readdir(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/readdir-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test"))
	file.Close()

	file, err = fs.Open("/readdir-test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	// Readdir on a file should work (defers to base)
	_, err = file.Readdir(0)
	// Not an error if base supports it
	_ = err
}

func TestStreamingFile_Readdirnames(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/readdirnames-test.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test"))
	file.Close()

	file, err = fs.Open("/readdirnames-test.txt")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer file.Close()

	// Readdirnames on a file
	_, err = file.Readdirnames(0)
	_ = err
}

func TestStreamingFile_FlushEmptyFile(t *testing.T) {
	fs := createStreamingTestFS(t)

	file, err := fs.Create("/empty-flush.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Flush empty file should succeed
	err = file.Sync()
	if err != nil {
		t.Errorf("Sync on empty file failed: %v", err)
	}

	file.Close()
}
