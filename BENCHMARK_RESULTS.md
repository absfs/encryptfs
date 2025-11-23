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

### Next Steps (Phase 5.2)

- **Integration**: Wire parallel methods into chunked_file.go Write/Read operations
- **Benchmarks**: Add parallel vs sequential comparisons
- **Tuning**: Optimize worker count and chunk threshold
- **Testing**: Verify correctness with parallel operations

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

## Future Optimizations

1. **Parallel Processing**: Complete integration for multi-core speedup
2. **Adaptive Chunk Sizing**: Dynamically adjust based on access patterns
3. **Smarter Caching**: LRU with access frequency tracking
4. **Compression**: Pre-encryption compression for compressible data
5. **Memory Pooling**: Reduce GC pressure with buffer pools
