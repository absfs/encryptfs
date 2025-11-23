// Package encryptfs provides a transparent encryption layer for the AbsFs
// filesystem abstraction, enabling secure at-rest encryption with modern
// cryptographic primitives.
//
// # Overview
//
// encryptfs implements the absfs.FileSystem interface, allowing it to wrap
// any AbsFs-compatible filesystem and provide transparent encryption and
// decryption of file contents.
//
// # Supported Cipher Suites
//
// - AES-256-GCM: Advanced Encryption Standard with 256-bit keys and
//   Galois/Counter Mode for authenticated encryption
// - ChaCha20-Poly1305: Modern stream cipher with Poly1305 message
//   authentication
//
// Both cipher suites provide:
//   - Authenticated Encryption with Associated Data (AEAD)
//   - Protection against tampering and corruption
//   - 128-bit authentication tags
//   - Nonce/IV uniqueness guarantees
//
// # Basic Usage
//
//	// Create base filesystem
//	base := osfs.New()
//
//	// Create encrypted filesystem with password-based key
//	config := &encryptfs.Config{
//	    Cipher: encryptfs.CipherAES256GCM,
//	    KeyProvider: encryptfs.NewPasswordKeyProvider(
//	        []byte("my-secure-password"),
//	        encryptfs.Argon2idParams{
//	            Memory:      64 * 1024, // 64 MB
//	            Iterations:  3,
//	            Parallelism: 4,
//	        },
//	    ),
//	}
//
//	fs, err := encryptfs.New(base, config)
//	if err != nil {
//	    panic(err)
//	}
//
//	// Use like any absfs.FileSystem
//	file, _ := fs.Create("/secret.txt")
//	file.WriteString("This will be encrypted on disk")
//	file.Close()
//
// # Security Considerations
//
// Protected Against:
//   - Unauthorized access to encrypted files at rest
//   - Data tampering and corruption (authenticated encryption)
//   - Known-plaintext attacks (with proper key management)
//   - Offline brute-force attacks (with strong key derivation)
//
// Not Protected Against:
//   - Memory dumps while files are decrypted in memory
//   - Side-channel attacks (timing, cache)
//   - Compromised systems with keyloggers or malware
//   - Physical access attacks on running systems
//   - Metadata leakage (file sizes, access patterns)
//
// # Key Derivation
//
// The package supports two key derivation functions:
//
// PBKDF2 (Password-Based Key Derivation Function 2):
//   - Widely supported and FIPS-approved
//   - Simple implementation
//   - CPU-intensive only (vulnerable to GPU attacks)
//
// Argon2id (Recommended):
//   - Memory-hard function (resistant to GPU/ASIC attacks)
//   - Winner of Password Hashing Competition
//   - Configurable memory, time, and parallelism
//
// # File Format
//
// Encrypted files use the following format:
//   - Magic bytes (4 bytes): "ENCR" (0x454E4352)
//   - Version (1 byte): File format version
//   - Cipher suite (1 byte): Identifies the encryption algorithm
//   - Salt size (2 bytes): Length of the salt
//   - Salt (variable): Random salt for key derivation
//   - Nonce size (2 bytes): Length of the nonce
//   - Nonce (variable): Random nonce for encryption
//   - Ciphertext (variable): Encrypted data + authentication tag
//
// # Performance
//
// The implementation uses Go's standard crypto package which includes
// hardware acceleration (AES-NI) when available. Performance characteristics:
//   - AES-256-GCM: Typically >2 GB/s with AES-NI
//   - ChaCha20-Poly1305: Typically >1 GB/s
//   - Key derivation: Tunable (50-200ms for Argon2id)
package encryptfs
