package encryptfs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/absfs/absfs"
)

// Benchmark AES-256-GCM encryption throughput
func BenchmarkAESGCM_Encrypt(b *testing.B) {
	sizes := []int{
		1024,           // 1 KB
		64 * 1024,      // 64 KB
		1024 * 1024,    // 1 MB
		10 * 1024 * 1024, // 10 MB
	}

	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			benchmarkEncrypt(b, CipherAES256GCM, size)
		})
	}
}

// Benchmark ChaCha20-Poly1305 encryption throughput
func BenchmarkChaCha20_Encrypt(b *testing.B) {
	sizes := []int{
		1024,           // 1 KB
		64 * 1024,      // 64 KB
		1024 * 1024,    // 1 MB
		10 * 1024 * 1024, // 10 MB
	}

	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			benchmarkEncrypt(b, CipherChaCha20Poly1305, size)
		})
	}
}

func benchmarkEncrypt(b *testing.B, cipher CipherSuite, size int) {
	// Generate test data
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		b.Fatalf("failed to generate test data: %v", err)
	}

	// Create key
	key := make([]byte, 32)
	rand.Read(key)

	// Create cipher engine
	engine, err := NewCipherEngine(cipher, key)
	if err != nil {
		b.Fatalf("failed to create engine: %v", err)
	}

	// Generate nonce
	nonce, err := GenerateNonce(cipher)
	if err != nil {
		b.Fatalf("failed to generate nonce: %v", err)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := engine.Encrypt(nonce, data)
		if err != nil {
			b.Fatalf("encryption failed: %v", err)
		}
	}
}

// Benchmark decryption
func BenchmarkAESGCM_Decrypt(b *testing.B) {
	sizes := []int{
		1024,        // 1 KB
		64 * 1024,   // 64 KB
		1024 * 1024, // 1 MB
	}

	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			benchmarkDecrypt(b, CipherAES256GCM, size)
		})
	}
}

func benchmarkDecrypt(b *testing.B, cipher CipherSuite, size int) {
	// Generate and encrypt test data
	data := make([]byte, size)
	rand.Read(data)

	key := make([]byte, 32)
	rand.Read(key)

	engine, err := NewCipherEngine(cipher, key)
	if err != nil {
		b.Fatalf("failed to create engine: %v", err)
	}

	nonce, err := GenerateNonce(cipher)
	if err != nil {
		b.Fatalf("failed to generate nonce: %v", err)
	}

	ciphertext, err := engine.Encrypt(nonce, data)
	if err != nil {
		b.Fatalf("encryption failed: %v", err)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := engine.Decrypt(nonce, ciphertext)
		if err != nil {
			b.Fatalf("decryption failed: %v", err)
		}
	}
}

// Benchmark key derivation
func BenchmarkArgon2id_KeyDerivation(b *testing.B) {
	params := []Argon2idParams{
		{Memory: 32 * 1024, Iterations: 1, Parallelism: 2, SaltSize: 32, KeySize: 32},  // Fast
		{Memory: 64 * 1024, Iterations: 3, Parallelism: 4, SaltSize: 32, KeySize: 32},  // Balanced (default)
		{Memory: 256 * 1024, Iterations: 5, Parallelism: 4, SaltSize: 32, KeySize: 32}, // Secure
	}

	names := []string{"Fast", "Balanced", "Secure"}

	for i, param := range params {
		b.Run(names[i], func(b *testing.B) {
			provider := NewPasswordKeyProvider([]byte("test-password"), param)
			salt := make([]byte, 32)
			rand.Read(salt)

			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				_, err := provider.DeriveKey(salt)
				if err != nil {
					b.Fatalf("key derivation failed: %v", err)
				}
			}
		})
	}
}

// Benchmark full file write/read cycle
func BenchmarkFileWriteRead(b *testing.B) {
	sizes := []int{
		1024,      // 1 KB
		64 * 1024, // 64 KB
		1024 * 1024, // 1 MB
	}

	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			benchmarkFileWriteRead(b, size)
		})
	}
}

func benchmarkFileWriteRead(b *testing.B, size int) {
	base, cleanup := setupBenchFS(b)
	defer cleanup()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("bench-password"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1, // Fast for benchmarking
			Parallelism: 2,
		}),
	}

	fs, err := New(base, config)
	if err != nil {
		b.Fatalf("failed to create EncryptFS: %v", err)
	}

	data := make([]byte, size)
	rand.Read(data)

	b.SetBytes(int64(size * 2)) // Count both write and read
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Write
		file, err := fs.Create("/bench.dat")
		if err != nil {
			b.Fatalf("failed to create: %v", err)
		}

		if _, err := file.Write(data); err != nil {
			b.Fatalf("failed to write: %v", err)
		}

		if err := file.Close(); err != nil {
			b.Fatalf("failed to close: %v", err)
		}

		// Read
		file, err = fs.Open("/bench.dat")
		if err != nil {
			b.Fatalf("failed to open: %v", err)
		}

		readData, err := io.ReadAll(file)
		if err != nil {
			b.Fatalf("failed to read: %v", err)
		}

		file.Close()

		if !bytes.Equal(data, readData) {
			b.Fatal("data mismatch")
		}
	}
}

// Benchmark key rotation
func BenchmarkKeyRotation(b *testing.B) {
	// Create test file with original key
	data := make([]byte, 64*1024)
	rand.Read(data)

	oldKey := NewPasswordKeyProvider([]byte("old-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	newKey := NewPasswordKeyProvider([]byte("new-password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Set up new filesystem for each iteration
		base, cleanup := setupBenchFS(b)

		currentKey := oldKey
		if i%2 == 1 {
			currentKey = newKey
		}

		config := &Config{
			Cipher:      CipherAES256GCM,
			KeyProvider: currentKey,
		}

		fs, err := New(base, config)
		if err != nil {
			cleanup()
			b.Fatalf("failed to create EncryptFS: %v", err)
		}

		// Create test file
		file, err := fs.Create("/rotate.dat")
		if err != nil {
			cleanup()
			b.Fatalf("failed to create: %v", err)
		}
		file.Write(data)
		file.Close()

		nextKey := newKey
		if i%2 == 1 {
			nextKey = oldKey
		}

		opts := KeyRotationOptions{
			NewKeyProvider: nextKey,
		}

		b.StartTimer()
		if err := fs.ReEncrypt("/rotate.dat", opts); err != nil {
			cleanup()
			b.Fatalf("re-encryption failed: %v", err)
		}
		b.StopTimer()

		cleanup()
	}
}

func formatSize(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%dKB", size/1024)
	}
	return fmt.Sprintf("%dMB", size/(1024*1024))
}

// Helper for benchmarks
func setupBenchFS(tb testing.TB) (absfs.FileSystem, func()) {
	tb.Helper()

	tmpDir, err := os.MkdirTemp("", "encryptfs-bench-*")
	if err != nil {
		tb.Fatalf("failed to create temp dir: %v", err)
	}

	base := &osBenchFS{root: tmpDir}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return base, cleanup
}

// Benchmark-specific filesystem implementation
type osBenchFS struct {
	root string
}

func (fs *osBenchFS) OpenFile(name string, flag int, perm os.FileMode) (absfs.File, error) {
	path := filepath.Join(fs.root, name)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, flag, perm)
}

func (fs *osBenchFS) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(filepath.Join(fs.root, name), perm)
}

func (fs *osBenchFS) MkdirAll(name string, perm os.FileMode) error {
	return os.MkdirAll(filepath.Join(fs.root, name), perm)
}

func (fs *osBenchFS) Remove(name string) error {
	return os.Remove(filepath.Join(fs.root, name))
}

func (fs *osBenchFS) RemoveAll(path string) error {
	return os.RemoveAll(filepath.Join(fs.root, path))
}

func (fs *osBenchFS) Rename(oldpath, newpath string) error {
	return os.Rename(filepath.Join(fs.root, oldpath), filepath.Join(fs.root, newpath))
}

func (fs *osBenchFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(filepath.Join(fs.root, name))
}

func (fs *osBenchFS) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(filepath.Join(fs.root, name), mode)
}

func (fs *osBenchFS) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(filepath.Join(fs.root, name), atime, mtime)
}

func (fs *osBenchFS) Chown(name string, uid, gid int) error {
	return os.Chown(filepath.Join(fs.root, name), uid, gid)
}

func (fs *osBenchFS) Separator() uint8 {
	return os.PathSeparator
}

func (fs *osBenchFS) ListSeparator() uint8 {
	return os.PathListSeparator
}

func (fs *osBenchFS) Chdir(dir string) error {
	return nil
}

func (fs *osBenchFS) Getwd() (string, error) {
	return "/", nil
}

func (fs *osBenchFS) TempDir() string {
	return os.TempDir()
}

func (fs *osBenchFS) Open(name string) (absfs.File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

func (fs *osBenchFS) Create(name string) (absfs.File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (fs *osBenchFS) Truncate(name string, size int64) error {
	return os.Truncate(filepath.Join(fs.root, name), size)
}

// ====================================================================================
// Chunked vs Traditional Benchmarks
// ====================================================================================

// BenchmarkWriteTraditional benchmarks traditional (single-chunk) file writes
func BenchmarkWriteTraditional(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 0, // Traditional mode
			}
			fs, _ := New(base, config)

			data := make([]byte, size.size)
			rand.Read(data)

			b.SetBytes(int64(size.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Create("/bench.bin")
				file.Write(data)
				file.Close()
				fs.Remove("/bench.bin")
			}
		})
	}
}

// BenchmarkWriteChunked benchmarks chunked file writes
func BenchmarkWriteChunked(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 64 * 1024, // 64KB chunks
			}
			fs, _ := New(base, config)

			data := make([]byte, size.size)
			rand.Read(data)

			b.SetBytes(int64(size.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Create("/bench.bin")
				file.Write(data)
				file.Close()
				fs.Remove("/bench.bin")
			}
		})
	}
}

// BenchmarkReadTraditional benchmarks traditional (single-chunk) file reads
func BenchmarkReadTraditional(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 0, // Traditional mode
			}
			fs, _ := New(base, config)

			// Create test file
			data := make([]byte, size.size)
			rand.Read(data)
			file, _ := fs.Create("/bench.bin")
			file.Write(data)
			file.Close()

			buf := make([]byte, size.size)
			b.SetBytes(int64(size.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Open("/bench.bin")
				io.ReadFull(file, buf)
				file.Close()
			}
		})
	}
}

// BenchmarkReadChunked benchmarks chunked file reads
func BenchmarkReadChunked(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 64 * 1024, // 64KB chunks
			}
			fs, _ := New(base, config)

			// Create test file
			data := make([]byte, size.size)
			rand.Read(data)
			file, _ := fs.Create("/bench.bin")
			file.Write(data)
			file.Close()

			buf := make([]byte, size.size)
			b.SetBytes(int64(size.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Open("/bench.bin")
				io.ReadFull(file, buf)
				file.Close()
			}
		})
	}
}

// BenchmarkSeekTraditional benchmarks seeking in traditional files (requires full re-read)
func BenchmarkSeekTraditional(b *testing.B) {
	base, cleanup := setupBenchFS(b)
	defer cleanup()

	config := &Config{
		Cipher: CipherAES256GCM,
		KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
			Memory:      64 * 1024,
			Iterations:  1,
			Parallelism: 2,
		}),
		ChunkSize: 0, // Traditional mode
	}
	fs, _ := New(base, config)

	// Create 10MB test file
	data := make([]byte, 10*1024*1024)
	rand.Read(data)
	file, _ := fs.Create("/bench.bin")
	file.Write(data)
	file.Close()

	buf := make([]byte, 4096)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		file, _ := fs.Open("/bench.bin")
		// Try to seek and read (traditional mode may not support efficient seeking)
		file.Seek(5*1024*1024, io.SeekStart) // Seek to middle
		file.Read(buf)
		file.Close()
	}
}

// BenchmarkSeekChunked benchmarks random seeking in chunked files
func BenchmarkSeekChunked(b *testing.B) {
	base, cleanup := setupBenchFS(b)
	defer cleanup()

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

	// Create 10MB test file
	data := make([]byte, 10*1024*1024)
	rand.Read(data)
	file, _ := fs.Create("/bench.bin")
	file.Write(data)
	file.Close()

	// Prepare random seek positions
	positions := make([]int64, 100)
	for i := range positions {
		positions[i] = int64(i * 100000) // Every 100KB
	}

	buf := make([]byte, 4096)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		file, _ := fs.Open("/bench.bin")
		for _, pos := range positions {
			file.Seek(pos, io.SeekStart)
			file.Read(buf)
		}
		file.Close()
	}
}

// BenchmarkChunkSizes benchmarks different chunk sizes
func BenchmarkChunkSizes(b *testing.B) {
	chunkSizes := []struct {
		name string
		size int
	}{
		{"4KB", 4 * 1024},
		{"16KB", 16 * 1024},
		{"64KB", 64 * 1024},
		{"256KB", 256 * 1024},
		{"1MB", 1024 * 1024},
	}

	fileSize := 10 * 1024 * 1024 // 10MB file

	for _, cs := range chunkSizes {
		b.Run(cs.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: cs.size,
			}
			fs, _ := New(base, config)

			data := make([]byte, fileSize)
			rand.Read(data)

			b.SetBytes(int64(fileSize))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Create("/bench.bin")
				file.Write(data)
				file.Close()
				fs.Remove("/bench.bin")
			}
		})
	}
}

// ====================================================================================
// Parallel vs Sequential Benchmarks
// ====================================================================================

// BenchmarkWriteSequential benchmarks sequential chunked writes (no parallel)
func BenchmarkWriteSequential(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 64 * 1024, // 64KB chunks
				Parallel: ParallelConfig{
					Enabled: false, // Sequential
				},
			}
			fs, _ := New(base, config)

			data := make([]byte, size.size)
			rand.Read(data)

			b.SetBytes(int64(size.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Create("/bench.bin")
				file.Write(data)
				file.Close()
				fs.Remove("/bench.bin")
			}
		})
	}
}

// BenchmarkWriteParallel benchmarks parallel chunked writes
func BenchmarkWriteParallel(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 64 * 1024, // 64KB chunks
				Parallel:  DefaultParallelConfig(), // Parallel enabled
			}
			fs, _ := New(base, config)

			data := make([]byte, size.size)
			rand.Read(data)

			b.SetBytes(int64(size.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Create("/bench.bin")
				// Use WriteBulk for parallel writes
				if cf, ok := file.(*ChunkedFile); ok {
					cf.WriteBulk(data)
				} else {
					file.Write(data)
				}
				file.Close()
				fs.Remove("/bench.bin")
			}
		})
	}
}

// BenchmarkReadSequential benchmarks sequential chunked reads (no parallel)
func BenchmarkReadSequential(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 64 * 1024, // 64KB chunks
				Parallel: ParallelConfig{
					Enabled: false, // Sequential
				},
			}
			fs, _ := New(base, config)

			// Create test file
			data := make([]byte, size.size)
			rand.Read(data)
			file, _ := fs.Create("/bench.bin")
			file.Write(data)
			file.Close()

			buf := make([]byte, size.size)
			b.SetBytes(int64(size.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Open("/bench.bin")
				io.ReadFull(file, buf)
				file.Close()
			}
		})
	}
}

// BenchmarkReadParallel benchmarks parallel chunked reads
func BenchmarkReadParallel(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 64 * 1024, // 64KB chunks
				Parallel:  DefaultParallelConfig(), // Parallel enabled
			}
			fs, _ := New(base, config)

			// Create test file
			data := make([]byte, size.size)
			rand.Read(data)
			file, _ := fs.Create("/bench.bin")
			file.Write(data)
			file.Close()

			buf := make([]byte, size.size)
			b.SetBytes(int64(size.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Open("/bench.bin")
				// Use ReadBulk for parallel reads
				if cf, ok := file.(*ChunkedFile); ok {
					cf.ReadBulk(buf)
				} else {
					io.ReadFull(file, buf)
				}
				file.Close()
			}
		})
	}
}

// BenchmarkParallelWorkers benchmarks different worker counts
func BenchmarkParallelWorkers(b *testing.B) {
	workerCounts := []int{1, 2, 4, 8, 16}
	fileSize := 10 * 1024 * 1024 // 10MB

	for _, workers := range workerCounts {
		b.Run(fmt.Sprintf("%dworkers", workers), func(b *testing.B) {
			base, cleanup := setupBenchFS(b)
			defer cleanup()

			config := &Config{
				Cipher: CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("benchmark"), Argon2idParams{
					Memory:      64 * 1024,
					Iterations:  1,
					Parallelism: 2,
				}),
				ChunkSize: 64 * 1024,
				Parallel: ParallelConfig{
					Enabled:              true,
					MaxWorkers:           workers,
					MinChunksForParallel: 4,
				},
			}
			fs, _ := New(base, config)

			data := make([]byte, fileSize)
			rand.Read(data)

			b.SetBytes(int64(fileSize))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				file, _ := fs.Create("/bench.bin")
				if cf, ok := file.(*ChunkedFile); ok {
					cf.WriteBulk(data)
				} else {
					file.Write(data)
				}
				file.Close()
				fs.Remove("/bench.bin")
			}
		})
	}
}
