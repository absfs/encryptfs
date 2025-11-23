# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-23

### Added

#### Phase 3: Filename Encryption
- **AES-SIV Implementation** (`siv.go`)
  - RFC 5297 compliant Synthetic Initialization Vector mode
  - Deterministic authenticated encryption for filenames
  - Nonce-misuse resistant design
  - S2V algorithm with CMAC
  - CTR mode encryption
  - Comprehensive test suite with 6 test scenarios

- **Filename Encryption System** (`filename.go`)
  - Three encryption modes:
    - `FilenameEncryptionNone`: Content-only encryption (filenames plaintext)
    - `FilenameEncryptionDeterministic`: SIV-based deterministic encryption
    - `FilenameEncryptionRandom`: UUID-based with metadata database
  - Extension preservation option (`PreserveExtensions`)
  - Path translation with directory structure preservation
  - JSON-based metadata store for random mode
  - Forward and reverse filename mappings

- **EncryptFS Integration**
  - Added `FilenameEncryptor` to `EncryptFS` struct
  - Path translation in all filesystem methods:
    - File operations: Open, Create, OpenFile
    - Directory operations: Mkdir, MkdirAll, Remove, RemoveAll
    - Metadata operations: Stat, Chmod, Chtimes, Chown
    - Special operations: Rename, Truncate, Chdir, Getwd
  - Helper methods: `translatePath()` and `untranslatePath()`

- **Testing**
  - `siv_test.go`: 6 comprehensive test suites for SIV cipher
    - Encrypt/decrypt round-trips
    - Deterministic verification
    - Authentication failure detection
    - Tampering detection
    - Invalid key handling
    - Performance benchmarks
  - `filename_test.go`: 9 test suites for filename encryption
    - Deterministic mode tests
    - Random mode with metadata tests
    - Extension preservation tests
    - Path encryption tests
    - Metadata persistence tests
    - All encryption mode combinations
  - `integration_test.go`: 4 end-to-end integration tests
    - Complete filesystem workflows
    - Directory hierarchy handling
    - Multiple encryption modes
    - Cross-filesystem compatibility
  - Total test count: 30+ test cases
  - Test coverage: >60%

- **Examples**
  - `examples/filename-encryption/`: Comprehensive demonstration
    - No encryption comparison
    - Deterministic encryption walkthrough
    - Extension preservation examples
    - Random encryption with metadata
    - Nested directory structures
    - Security comparison analysis
    - Visual output showing encrypted vs plaintext names

- **Documentation**
  - Updated `FEATURES.md`:
    - Phase 3 marked as complete with detailed descriptions
    - Three filename encryption modes documented
    - Configuration options explained
    - Integration details provided
    - Updated statistics (30+ tests, >60% coverage)
    - Version bumped to v0.2.0
    - Expanded use cases
  - Updated `doc.go`:
    - Added filename encryption section
    - AES-SIV cipher suite documented
    - Three encryption modes with code examples
    - Updated security considerations
    - Metadata leakage protection noted
  - Updated `README.md`:
    - Phase 3 marked as complete
    - Deterministic and random encryption explained
    - Configuration examples added

### Changed
- Version bumped from v0.1.0 to v0.2.0
- Project status: Beta - API stabilizing
- Production readiness: Phase 3 now complete
- Enhanced metadata protection capabilities

### Security
- **RFC 5297 Compliant**: AES-SIV implementation follows security standards
- **Authenticated Encryption**: Filenames include authentication tags
- **Nonce-Misuse Resistant**: SIV mode protects against nonce reuse
- **Deterministic Security**: Same filename encrypts to same ciphertext (prevents correlation)
- **Maximum Privacy**: Random mode with UUIDs provides maximum filename security
- **Metadata Protection**: Significantly reduced metadata leakage with filename encryption

### Performance
- Deterministic filename encryption: Minimal overhead (~microseconds per filename)
- Random filename encryption: O(1) lookups with in-memory metadata
- SIV cipher benchmarks included for all data sizes (16B to 4KB)
- Integration benchmarks compare all three filename encryption modes

## [0.1.0] - 2025-11-23

### Added

#### Phase 1: Core Encryption Infrastructure
- AES-256-GCM cipher implementation
- ChaCha20-Poly1305 cipher implementation
- File format with magic header, version, and cipher identification
- Nonce/IV storage and generation
- Authentication tag verification
- Transparent encryption/decryption for file operations

#### Phase 2: Key Management
- PBKDF2 key derivation (FIPS-compliant)
- Argon2id key derivation (recommended)
- Password-based key provider
- Environment variable key provider
- Multi-key provider for migration scenarios
- Key rotation utilities
- Cipher migration support
- File encryption verification

#### Phase 5: Performance & Benchmarking
- Comprehensive benchmarks for encryption/decryption
- Key derivation performance tests
- Full file I/O cycle benchmarks
- Memory allocation profiling
- Performance characteristics documented

#### Testing
- 11 core encryption test cases
- 4 key management test suites
- Benchmark suite
- Security tests (password validation, tampering detection)

#### Examples
- `examples/basic/`: Simple usage demonstration
- `examples/advanced/`: Key rotation, multi-key, cipher migration, verification

#### Documentation
- Comprehensive README with security analysis
- FEATURES.md with implementation details
- Package-level documentation (doc.go)
- Inline comments for all public APIs

### Security
- AEAD ciphers for authenticated encryption
- Secure nonce generation (96-bit for GCM, 96-bit for ChaCha20)
- Argon2id with memory-hard parameters for key derivation
- Protection against tampering, corruption, and brute-force attacks

## [Unreleased]

### Planned

#### Phase 4: Advanced Streaming
- True multi-chunk file format implementation
- Incremental encryption for append operations
- Parallel chunk processing
- Compression integration (pre-encryption)
- Seek optimization for large encrypted files

#### Phase 3 Enhancements
- Per-directory encryption policies
- Filename encryption key rotation
- Metadata encryption and compression
- Directory-based key hierarchies

#### Phase 5 Enhancements
- Hardware acceleration detection and usage
- Decrypted block caching
- Metadata caching optimizations
- Additional performance tuning

---

[0.2.0]: https://github.com/absfs/encryptfs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/absfs/encryptfs/releases/tag/v0.1.0
