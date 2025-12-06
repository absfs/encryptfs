package encryptfs

import (
	"testing"
)

func TestCipherSuite_String(t *testing.T) {
	tests := []struct {
		cipher   CipherSuite
		expected string
	}{
		{CipherAuto, "auto"},
		{CipherAES256GCM, "aes-256-gcm"},
		{CipherChaCha20Poly1305, "chacha20-poly1305"},
		{CipherSuite(99), "unknown"},
	}

	for _, tt := range tests {
		result := tt.cipher.String()
		if result != tt.expected {
			t.Errorf("CipherSuite(%d).String() = %q, want %q", tt.cipher, result, tt.expected)
		}
	}
}

func TestHashFuncToHash(t *testing.T) {
	tests := []struct {
		name   string
		hf     HashFunc
		nilFn  bool
	}{
		{"SHA256", SHA256, false},
		{"SHA512", SHA512, false},
		{"unknown", HashFunc(99), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := HashFuncToHash(tt.hf)
			if fn == nil {
				t.Error("HashFuncToHash returned nil function")
			}
			// Call the function to ensure it's callable
			_ = fn()
		})
	}
}

func TestArgon2idParams_ValidateFull(t *testing.T) {
	tests := []struct {
		name      string
		params    Argon2idParams
		expectErr bool
	}{
		{
			name: "valid params",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 4,
				SaltSize:    32,
				KeySize:     32,
			},
			expectErr: false,
		},
		{
			name: "memory too low",
			params: Argon2idParams{
				Memory:      1024, // Less than 8 MiB
				Iterations:  1,
				Parallelism: 4,
				SaltSize:    32,
				KeySize:     32,
			},
			expectErr: true,
		},
		{
			name: "memory too high",
			params: Argon2idParams{
				Memory:      5 * 1024 * 1024, // More than 4 GiB
				Iterations:  1,
				Parallelism: 4,
				SaltSize:    32,
				KeySize:     32,
			},
			expectErr: true,
		},
		{
			name: "iterations zero",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  0,
				Parallelism: 4,
				SaltSize:    32,
				KeySize:     32,
			},
			expectErr: true,
		},
		{
			name: "iterations too high",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  101,
				Parallelism: 4,
				SaltSize:    32,
				KeySize:     32,
			},
			expectErr: true,
		},
		{
			name: "parallelism zero",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 0,
				SaltSize:    32,
				KeySize:     32,
			},
			expectErr: true,
		},
		{
			name: "salt too small",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 4,
				SaltSize:    8, // Less than 16
				KeySize:     32,
			},
			expectErr: true,
		},
		{
			name: "salt too large",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 4,
				SaltSize:    256, // More than 128
				KeySize:     32,
			},
			expectErr: true,
		},
		{
			name: "key too small",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 4,
				SaltSize:    32,
				KeySize:     8, // Less than 16
			},
			expectErr: true,
		},
		{
			name: "key too large",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 4,
				SaltSize:    32,
				KeySize:     128, // More than 64
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.expectErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestPBKDF2Params_ValidateFull(t *testing.T) {
	tests := []struct {
		name      string
		params    PBKDF2Params
		expectErr bool
	}{
		{
			name: "valid params",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    32,
			},
			expectErr: false,
		},
		{
			name: "iterations too low",
			params: PBKDF2Params{
				Iterations: 1000, // Less than 100000
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    32,
			},
			expectErr: true,
		},
		{
			name: "iterations too high",
			params: PBKDF2Params{
				Iterations: 100000000, // More than 10000000
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    32,
			},
			expectErr: true,
		},
		{
			name: "invalid hash func",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   HashFunc(99),
				SaltSize:   32,
				KeySize:    32,
			},
			expectErr: true,
		},
		{
			name: "salt too small",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA256,
				SaltSize:   8, // Less than 16
				KeySize:    32,
			},
			expectErr: true,
		},
		{
			name: "salt too large",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA256,
				SaltSize:   256, // More than 128
				KeySize:    32,
			},
			expectErr: true,
		},
		{
			name: "key too small",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    8, // Less than 16
			},
			expectErr: true,
		},
		{
			name: "key too large",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    128, // More than 64
			},
			expectErr: true,
		},
		{
			name: "SHA512 valid",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA512,
				SaltSize:   32,
				KeySize:    32,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.expectErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestConfig_ValidateFull(t *testing.T) {
	validKeyProvider := NewPasswordKeyProvider([]byte("password"), Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 2,
	})

	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name:      "nil config",
			config:    nil,
			expectErr: true,
		},
		{
			name: "nil key provider",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: nil,
			},
			expectErr: true,
		},
		{
			name: "invalid cipher",
			config: &Config{
				Cipher:      CipherSuite(99),
				KeyProvider: validKeyProvider,
			},
			expectErr: true,
		},
		{
			name: "invalid filename encryption",
			config: &Config{
				Cipher:             CipherAES256GCM,
				KeyProvider:        validKeyProvider,
				FilenameEncryption: FilenameEncryption(99),
			},
			expectErr: true,
		},
		{
			name: "random filename encryption without metadata path",
			config: &Config{
				Cipher:             CipherAES256GCM,
				KeyProvider:        validKeyProvider,
				FilenameEncryption: FilenameEncryptionRandom,
				MetadataPath:       "",
			},
			expectErr: true,
		},
		{
			name: "negative chunk size",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: validKeyProvider,
				ChunkSize:   -1,
			},
			expectErr: true,
		},
		{
			name: "chunk size too small",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: validKeyProvider,
				ChunkSize:   1024, // Less than 4KB
			},
			expectErr: true,
		},
		{
			name: "chunk size too large",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: validKeyProvider,
				ChunkSize:   32 * 1024 * 1024, // More than 16MB
			},
			expectErr: true,
		},
		{
			name: "negative parallel workers",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: validKeyProvider,
				ChunkSize:   64 * 1024,
				Parallel: ParallelConfig{
					Enabled:    true,
					MaxWorkers: -1,
				},
			},
			expectErr: true,
		},
		{
			name: "too many parallel workers",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: validKeyProvider,
				ChunkSize:   64 * 1024,
				Parallel: ParallelConfig{
					Enabled:             true,
					MaxWorkers:          2048,
					MinChunksForParallel: 2,
				},
			},
			expectErr: true,
		},
		{
			name: "parallel without chunked mode",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: validKeyProvider,
				ChunkSize:   0,
				Parallel: ParallelConfig{
					Enabled:             true,
					MaxWorkers:          4,
					MinChunksForParallel: 2,
				},
			},
			expectErr: true,
		},
		{
			name: "min chunks too low",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: validKeyProvider,
				ChunkSize:   64 * 1024,
				Parallel: ParallelConfig{
					Enabled:             true,
					MaxWorkers:          4,
					MinChunksForParallel: 0,
				},
			},
			expectErr: true,
		},
		{
			name: "min chunks too high",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: validKeyProvider,
				ChunkSize:   64 * 1024,
				Parallel: ParallelConfig{
					Enabled:             true,
					MaxWorkers:          4,
					MinChunksForParallel: 10000,
				},
			},
			expectErr: true,
		},
		{
			name: "valid config with all options",
			config: &Config{
				Cipher:             CipherAES256GCM,
				KeyProvider:        validKeyProvider,
				FilenameEncryption: FilenameEncryptionDeterministic,
				ChunkSize:          64 * 1024,
				EnableSeek:         true,
				Parallel: ParallelConfig{
					Enabled:             true,
					MaxWorkers:          4,
					MinChunksForParallel: 2,
				},
			},
			expectErr: false,
		},
		{
			name: "valid config with random filename encryption",
			config: &Config{
				Cipher:             CipherAES256GCM,
				KeyProvider:        validKeyProvider,
				FilenameEncryption: FilenameEncryptionRandom,
				MetadataPath:       "/path/to/metadata",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
