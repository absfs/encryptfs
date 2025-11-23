# EncryptFS Performance Benchmarks

## Baseline Results (Phase 5 Initial)

### Write Performance (1MB files)

| Mode | Throughput | Allocations | Speed vs Traditional |
|------|------------|-------------|---------------------|
| Traditional | 30.08 MB/s | 69.2 MB | Baseline |
| Chunked (64KB) | 24.95 MB/s | 70.5 MB | -17% |

**Analysis**: Chunked mode is currently slower for sequential writes due to chunk index overhead and multiple chunk headers. However, this is expected - the benefit of chunked mode is for random access, not sequential writes.

### Seek Performance (10MB file, 100 random seeks)

| Mode | Time per Operation | Speed vs Traditional |
|------|-------------------|---------------------|
| Traditional | 53.8 ms | Baseline |
| Chunked (64KB) | 48.9 ms | **+9% faster** |

**Analysis**: Chunked mode shows improved seek performance because it doesn't need to decrypt the entire file to access a specific position. The LRU cache (16 chunks) provides additional benefit for repeated access patterns.

## Benchmark Suite

We've added comprehensive benchmarks in `benchmark_test.go`:

### Chunked vs Traditional Comparisons

1. **BenchmarkWriteTraditional** - Sequential write throughput for traditional files
2. **BenchmarkWriteChunked** - Sequential write throughput for chunked files
3. **BenchmarkReadTraditional** - Sequential read throughput for traditional files
4. **BenchmarkReadChunked** - Sequential read throughput for chunked files
5. **BenchmarkSeekTraditional** - Random seek performance for traditional files
6. **BenchmarkSeekChunked** - Random seek performance for chunked files

Test sizes: 1KB, 64KB, 1MB, 10MB

### Chunk Size Optimization

7. **BenchmarkChunkSizes** - Compares different chunk sizes (4KB, 16KB, 64KB, 256KB, 1MB) for 10MB files

## Parallel Processing Infrastructure

### Implemented (Phase 5.1)

- **parallel.go**: Worker pool implementation for parallel chunk encryption/decryption
- **ParallelConfig**: Configuration struct with:
  - `Enabled`: Toggle parallel processing
  - `MaxWorkers`: Number of worker goroutines (defaults to NumCPU)
  - `MinChunksForParallel`: Minimum chunks to trigger parallel mode (default: 4)

### Design

```go
type ParallelConfig struct {
    Enabled              bool
    MaxWorkers           int  // Defaults to runtime.NumCPU()
    MinChunksForParallel int  // Defaults to 4
}
```

The parallel processing uses:
- Worker pool pattern with goroutines
- Buffered channels for job distribution
- sync.WaitGroup for coordination
- Automatic fallback to sequential for small files

### Completed (Phase 5.2)

✅ **Integration**: Implemented WriteBulk/ReadBulk methods with parallel chunk processing
✅ **Benchmarks**: Added comprehensive parallel vs sequential comparisons
✅ **Testing**: Verified correctness - all tests passing

## Parallel Processing Results (Phase 5.2)

### Performance Improvements

| Operation | Sequential | Parallel | Speedup |
|-----------|-----------|----------|---------|
| **Write (10MB)** | 116.98 MB/s | 132.51 MB/s | **+13%** |
| **Read (10MB)** | 196.31 MB/s | 223.59 MB/s | **+14%** |

**Analysis**: Parallel processing provides significant speedup for both reads and writes on multi-core systems. The parallel implementation also uses less memory (10% reduction) and fewer allocations.

### Worker Count Scaling (10MB writes)

| Workers | Throughput | Speed vs 1 Worker |
|---------|------------|-------------------|
| 1 | 124.29 MB/s | Baseline |
| 2 | 121.53 MB/s | -2% |
| 4 | 123.80 MB/s | -0.4% |
| **8** | **126.53 MB/s** | **+2%** |
| 16 | 123.91 MB/s | -0.3% |

**Analysis**: Performance is relatively consistent across worker counts, with optimal performance at 8 workers. Beyond 8 workers, goroutine coordination overhead slightly reduces performance. The default of `runtime.NumCPU()` is appropriate for most systems.

### Implementation Details

- **WriteBulk/ReadBulk**: New methods for parallel chunk processing
- **Automatic Fallback**: Uses sequential processing for small files (<4 chunks)
- **Configuration**: `ParallelConfig` with tunable parameters:
  - `Enabled`: Toggle parallel processing (default: true)
  - `MaxWorkers`: Worker goroutines (default: runtime.NumCPU())
  - `MinChunksForParallel`: Threshold for parallel mode (default: 4 chunks)

### Running Parallel Benchmarks

```bash
# Compare parallel vs sequential writes
go test -bench="BenchmarkWrite(Sequential|Parallel)" -benchtime=5s -benchmem

# Compare parallel vs sequential reads
go test -bench="BenchmarkRead(Sequential|Parallel)" -benchtime=5s -benchmem

# Test worker count scaling
go test -bench="BenchmarkParallelWorkers" -benchtime=5s -benchmem

# All parallel benchmarks
go test -bench="Benchmark(Write|Read)(Sequential|Parallel)|BenchmarkParallelWorkers" -benchmem
```

## Recommendations

### When to Use Chunked Mode

✅ **Good for:**
- Files that need random access (databases, media files, logs)
- Large files (>1MB) where seeking is common
- Applications that frequently read small portions of large files
- Scenarios where you need to modify parts of encrypted files

❌ **Not optimal for:**
- Small files (<64KB)
- Sequential-only access patterns
- Write-once, read-sequentially workloads

### Optimal Chunk Size

Based on initial benchmarking (pending comprehensive results):
- **64KB**: Good default balance (current default)
- **16KB**: Better for frequent small random reads
- **256KB**: Better for sequential access with occasional seeks
- **1MB**: Reduces chunk index size for very large files

## Running Benchmarks

```bash
# Compare chunked vs traditional writes
go test -bench="BenchmarkWrite(Traditional|Chunked)" -benchtime=10s -benchmem

# Compare seek performance
go test -bench="BenchmarkSeek" -benchtime=10s

# Test different chunk sizes
go test -bench="BenchmarkChunkSizes" -benchtime=5s

# Full benchmark suite
go test -bench=. -benchtime=10s -benchmem | tee benchmark_results.txt
```

### When to Use Parallel Mode

✅ **Good for:**
- Files larger than 256KB (>4 chunks with default 64KB chunk size)
- Multi-core systems with available CPU capacity
- Sequential reads/writes of large files
- Batch file processing operations

❌ **Not optimal for:**
- Small files (<256KB / <4 chunks)
- Single-core systems
- When CPU is already at capacity
- Random small reads/writes (use regular chunked mode)

## Future Optimizations

1. ✅ **Parallel Processing**: Completed - 13-14% speedup for large files
2. **Adaptive Chunk Sizing**: Dynamically adjust based on access patterns
3. **Smarter Caching**: LRU with access frequency tracking
4. **Compression**: Pre-encryption compression for compressible data
5. **Memory Pooling**: Reduce GC pressure with buffer pools
