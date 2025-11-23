# encryptfs

A transparent encryption layer for the AbsFs filesystem abstraction, providing secure at-rest encryption with modern cryptographic primitives.

## Overview

`encryptfs` is a filesystem wrapper that provides transparent encryption and decryption of file contents and optionally filenames. It implements the `absfs.FileSystem` interface, allowing it to be layered on top of any AbsFs-compatible filesystem.

### Supported Cipher Suites

- **AES-256-GCM** - Advanced Encryption Standard with 256-bit keys and Galois/Counter Mode for authenticated encryption
- **ChaCha20-Poly1305** - Modern stream cipher with Poly1305 message authentication

Both cipher suites provide:
- Authenticated Encryption with Associated Data (AEAD)
- Protection against tampering and corruption
- 128-bit authentication tags
- Nonce/IV uniqueness guarantees

## Security Considerations

### Threat Model

**Protected Against:**
- Unauthorized access to encrypted files at rest
- Data tampering and corruption (authenticated encryption)
- Known-plaintext attacks (with proper key management)
- Offline brute-force attacks (with strong key derivation)

**Not Protected Against:**
- Memory dumps while files are decrypted in memory
- Side-channel attacks (timing, cache)
- Compromised systems with keyloggers or malware
- Physical access attacks on running systems
- Metadata leakage (file sizes, access patterns, unless filename encryption is enabled)

### Key Security Requirements

1. **Key Material Protection**
   - Keys must never be written to disk unencrypted
   - Use secure memory clearing after key derivation
   - Consider using OS keychain/keyring for key storage
   - Rotate keys periodically

2. **Nonce/IV Management**
   - Each encryption operation MUST use a unique nonce
   - Nonce reuse with the same key catastrophically breaks security
   - Implementation uses random nonces (96-bit for GCM, 192-bit for ChaCha20)

3. **Authentication**
   - Always verify authentication tags before decrypting
   - Reject any modified or corrupted ciphertext immediately
   - Never expose unauthenticated plaintext

## Implementation Phases

### Phase 1: Core Encryption Infrastructure

**File Format Design**
- Magic header for encrypted files
- Version field for future compatibility
- Cipher suite identifier
- Nonce/IV storage
- Authentication tag placement
- Optional metadata section (encrypted filename mappings)

**Cipher Implementation**
- AES-256-GCM encryption/decryption
- ChaCha20-Poly1305 encryption/decryption
- Secure nonce generation
- Key derivation integration
- AEAD interface abstraction

**Basic File Operations**
- Read encrypted files with transparent decryption
- Write files with transparent encryption
- Handle file headers and metadata
- Error handling and validation

### Phase 2: Key Management

**Key Derivation Functions**
- PBKDF2 with configurable iterations (minimum 100,000)
- Argon2id with memory-hard parameters
- Salt generation and storage
- Key caching with secure clearing

**Key Provider Interface**
- Pluggable key source abstraction
- Password-based key provider
- Environment variable key provider
- OS keychain/keyring integration
- Hardware security module (HSM) support preparation

**Key Rotation**
- Re-encryption support for key changes
- Bulk re-encryption utilities
- Multiple key support for migration

### Phase 3: Filename Encryption ✅

**Deterministic Filename Encryption**
- SIV mode (Synthetic IV) for deterministic encryption (RFC 5297)
- Preserves directory structure
- Allows path-based lookups
- Base64 URL-safe encoding for filesystem compatibility
- Same filename always encrypts to same ciphertext

**Random Filename Encryption**
- UUID-based encrypted filenames
- JSON metadata database for filename mappings
- Maximum security - no filename correlation
- Directory enumeration protection
- Persistent mapping storage

**Configuration Options**
- Three modes: None, Deterministic, Random
- Extension preservation option
- Configurable metadata path
- Transparent path translation

### Phase 4: Advanced Streaming Encryption ✅

**Chunk-Based Encryption** (Implemented)
- Multi-chunk file format with 64 KB default chunks
- Efficient random access without decrypting entire file
- LRU cache for 16 chunks minimizes disk I/O
- Independent nonce per chunk for security
- Thread-safe operations with mutex locks
- Read-modify-write support for partial updates
- Configurable chunk sizes: 64 bytes to 16 MB
- Automatic mode selection via Config.ChunkSize

**Usage Example**
```go
config := &encryptfs.Config{
    Cipher: encryptfs.CipherAES256GCM,
    KeyProvider: keyProvider,
    ChunkSize: 64 * 1024, // Enable chunked encryption
}
fs, _ := encryptfs.New(base, config)
```

**Future Advanced Features**

**Compression Integration** (Planned)
- Optional pre-encryption compression
- Cipher suite selection based on compressibility
- Compression detection

**Access Control** (Planned)
- Per-file key derivation
- Directory-based key hierarchies
- Multi-user support with key escrow

### Phase 5: Performance Optimization

**Hardware Acceleration**
- AES-NI instruction set usage
- ARM crypto extensions
- Hardware offload detection

**Caching Strategies**
- Decrypted block caching
- Key derivation caching
- Metadata caching

**Benchmarking**
- Throughput measurements
- Latency profiling
- Memory usage optimization

## API Design

### Basic Usage

```go
package main

import (
    "github.com/absfs/absfs"
    "github.com/absfs/encryptfs"
    "github.com/absfs/osfs"
)

func main() {
    // Create base filesystem
    base := osfs.New()

    // Create encrypted filesystem with password-based key
    config := &encryptfs.Config{
        Cipher: encryptfs.CipherAES256GCM,
        KeyProvider: encryptfs.NewPasswordKeyProvider(
            []byte("my-secure-password"),
            encryptfs.Argon2idParams{
                Memory:      64 * 1024, // 64 MB
                Iterations:  3,
                Parallelism: 4,
            },
        ),
    }

    fs, err := encryptfs.New(base, config)
    if err != nil {
        panic(err)
    }

    // Use like any absfs.FileSystem
    file, err := fs.Create("/secret.txt")
    if err != nil {
        panic(err)
    }

    // Writes are transparently encrypted
    _, err = file.WriteString("This will be encrypted on disk")
    file.Close()

    // Reads are transparently decrypted
    file, err = fs.Open("/secret.txt")
    if err != nil {
        panic(err)
    }
    defer file.Close()

    data, _ := io.ReadAll(file)
    fmt.Println(string(data)) // "This will be encrypted on disk"
}
```

### Key Management

```go
// PBKDF2 key derivation
keyProvider := encryptfs.NewPasswordKeyProvider(
    []byte("password"),
    encryptfs.PBKDF2Params{
        Iterations: 100000,
        HashFunc:   encryptfs.SHA256,
    },
)

// Argon2id key derivation (recommended)
keyProvider := encryptfs.NewPasswordKeyProvider(
    []byte("password"),
    encryptfs.Argon2idParams{
        Memory:      64 * 1024, // 64 MB
        Iterations:  3,
        Parallelism: 4,
        SaltSize:    32,
        KeySize:     32,
    },
)

// Environment variable key provider
keyProvider := encryptfs.NewEnvKeyProvider("ENCRYPTION_KEY")

// Custom key provider
type MyKeyProvider struct{}

func (p *MyKeyProvider) DeriveKey(salt []byte) ([]byte, error) {
    // Custom key derivation logic
    return key, nil
}

func (p *MyKeyProvider) GenerateSalt() ([]byte, error) {
    // Generate salt
    return salt, nil
}
```

### Cipher Selection

```go
// AES-256-GCM (default, hardware accelerated on most platforms)
config := &encryptfs.Config{
    Cipher: encryptfs.CipherAES256GCM,
}

// ChaCha20-Poly1305 (better for systems without AES-NI)
config := &encryptfs.Config{
    Cipher: encryptfs.CipherChaCha20Poly1305,
}

// Auto-select based on hardware capabilities
config := &encryptfs.Config{
    Cipher: encryptfs.CipherAuto,
}
```

### Filename Encryption

```go
// No filename encryption (only content encrypted)
config := &encryptfs.Config{
    FilenameEncryption: encryptfs.FilenameEncryptionNone,
}

// Deterministic filename encryption (SIV mode)
config := &encryptfs.Config{
    FilenameEncryption: encryptfs.FilenameEncryptionDeterministic,
    PreserveExtensions: true, // Keep .txt, .jpg, etc visible
}

// Random filename encryption with metadata database
config := &encryptfs.Config{
    FilenameEncryption: encryptfs.FilenameEncryptionRandom,
    MetadataPath:       "/.encryptfs-metadata",
}
```

### Streaming and Large Files

```go
// Chunk-based encryption for large files
config := &encryptfs.Config{
    ChunkSize: 64 * 1024, // 64 KB chunks
    EnableSeek: true,     // Allow seeking within encrypted files
}

// Use the filesystem normally - chunking is transparent
file, _ := fs.Create("/large-video.mp4")
io.Copy(file, videoReader) // Efficiently handles large streams
file.Close()

// Seeking works within encrypted files
file, _ = fs.Open("/large-video.mp4")
file.Seek(1024*1024, io.SeekStart) // Seek to 1MB offset
```

## Filename Encryption Options

### None (Content-Only Encryption)

**Pros:**
- Simple implementation
- Preserves directory structure
- Easy debugging and administration
- Compatible with all filesystems

**Cons:**
- Filenames are visible
- Metadata leakage (file count, sizes, names)
- Directory structure is exposed

**Use Case:** Protection against disk theft where metadata leakage is acceptable

### Deterministic Encryption (SIV Mode)

**Pros:**
- Preserves directory hierarchy
- Same filename always encrypts to same ciphertext
- Path-based lookups still work
- Reasonable security

**Cons:**
- Identical filenames in different directories reveal correlation
- Slightly weaker than random encryption
- Requires SIV-mode cipher

**Use Case:** Balance between security and usability, when directory structure should remain navigable

### Random Encryption

**Pros:**
- Maximum security for filenames
- No correlation between similar names
- Protects directory structure

**Cons:**
- Requires metadata database
- More complex implementation
- Database corruption risk
- Slower directory operations

**Use Case:** Maximum security scenarios, compliance requirements

## Performance Benchmarks

Target performance characteristics (will be measured and documented during implementation):

### Throughput

- **AES-256-GCM (with AES-NI):** >2 GB/s on modern CPUs
- **ChaCha20-Poly1305:** >1 GB/s on modern CPUs
- **Overhead:** <5% compared to unencrypted I/O for sequential access

### Latency

- **Small file (<4KB):** <100 microseconds overhead
- **Key derivation (Argon2id):** 50-200ms (tunable)
- **Chunk encryption (64KB):** <1ms

### Memory

- **Base overhead:** <10 MB
- **Per-file overhead:** <100 KB
- **Chunk buffer:** Configurable (default 64 KB)

## Compliance Notes

### FIPS 140-2 Compatibility

- Use `crypto/aes` from Go's FIPS-validated build
- AES-256-GCM is FIPS-approved
- ChaCha20-Poly1305 is NOT FIPS-approved (use AES for compliance)
- Key derivation should use PBKDF2 with SHA-256 for FIPS

### GDPR and Data Protection

- Encryption at rest satisfies many data protection requirements
- Key management is critical for compliance
- Consider "right to erasure" - secure key deletion ensures data is unrecoverable
- Document key lifecycle and retention policies

### Industry Standards

- **NIST SP 800-38D:** GCM mode specifications
- **NIST SP 800-175B:** Key derivation guidelines
- **RFC 7539:** ChaCha20-Poly1305 specification
- **RFC 5297:** SIV mode for deterministic encryption

## Key Derivation

### PBKDF2 (Password-Based Key Derivation Function 2)

```go
params := encryptfs.PBKDF2Params{
    Iterations: 100000,     // Minimum recommended
    HashFunc:   encryptfs.SHA256,
    SaltSize:   32,         // 256 bits
    KeySize:    32,         // 256 bits for AES-256
}
```

**Characteristics:**
- Widely supported and FIPS-approved
- Simple implementation
- CPU-intensive only (vulnerable to GPU attacks)
- Iterations should be tuned to ~100ms on target hardware

**Use Case:** FIPS compliance, compatibility with legacy systems

### Argon2id (Recommended)

```go
params := encryptfs.Argon2idParams{
    Memory:      64 * 1024,  // 64 MB
    Iterations:  3,          // Time parameter
    Parallelism: 4,          // CPU cores to use
    SaltSize:    32,         // 256 bits
    KeySize:     32,         // 256 bits
}
```

**Characteristics:**
- Memory-hard function (resistant to GPU/ASIC attacks)
- Winner of Password Hashing Competition
- Configurable memory, time, and parallelism
- Recommended for new implementations

**Use Case:** Modern systems with no FIPS requirement, maximum resistance to brute-force

### Key Derivation Best Practices

1. **Salt Management**
   - Use cryptographically random salts
   - Minimum 128 bits (16 bytes), recommend 256 bits
   - Store salt with encrypted data
   - Never reuse salts

2. **Parameter Tuning**
   - Target 100-500ms derivation time for interactive use
   - Higher iterations/memory for data-at-rest keys
   - Balance security vs. user experience

3. **Key Caching**
   - Cache derived keys in memory for session duration
   - Clear keys from memory when done
   - Consider time-limited caching
   - Never cache to disk

## Testing

Comprehensive test coverage will include:

- Unit tests for all encryption primitives
- Property-based testing for encryption/decryption round-trips
- Fuzzing for malformed ciphertext handling
- Integration tests with various base filesystems
- Performance benchmarks
- Security audits of key management
- Cross-platform compatibility tests

## Contributing

Contributions are welcome! Please ensure:

- All tests pass
- Code follows Go conventions
- Security-sensitive changes are well-documented
- Performance impacts are measured
- Cryptographic changes are reviewed carefully

## Security Disclosure

If you discover a security vulnerability, please email security@absfs.dev (DO NOT open a public issue).

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Uses Go's standard `crypto` package for cryptographic primitives
- Inspired by various encrypted filesystem implementations (EncFS, gocryptfs, CryFS)
- Part of the AbsFs filesystem abstraction project
