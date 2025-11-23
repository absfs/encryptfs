package encryptfs

import (
	"testing"
)

// TestConfig_Validate tests the Config validation
func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config cannot be nil",
		},
		{
			name: "nil key provider",
			config: &Config{
				Cipher: CipherAES256GCM,
			},
			wantErr: true,
			errMsg:  "key provider cannot be nil",
		},
		{
			name: "unsupported cipher",
			config: &Config{
				Cipher:      CipherSuite(99),
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
			},
			wantErr: true,
			errMsg:  "unsupported cipher suite",
		},
		{
			name: "valid minimal config",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
			},
			wantErr: false,
		},
		{
			name: "negative chunk size",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   -1,
			},
			wantErr: true,
			errMsg:  "chunk size cannot be negative",
		},
		{
			name: "chunk size too small",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   1024, // 1KB - too small
			},
			wantErr: true,
			errMsg:  "chunk size must be at least 4 KiB",
		},
		{
			name: "chunk size too large",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   32 * 1024 * 1024, // 32MB - too large
			},
			wantErr: true,
			errMsg:  "chunk size must not exceed 16 MiB",
		},
		{
			name: "valid chunk size",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   64 * 1024, // 64KB
			},
			wantErr: false,
		},
		{
			name: "unsupported filename encryption",
			config: &Config{
				Cipher:             CipherAES256GCM,
				KeyProvider:        NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				FilenameEncryption: FilenameEncryption(99),
			},
			wantErr: true,
			errMsg:  "unsupported filename encryption mode",
		},
		{
			name: "random filename encryption without metadata path",
			config: &Config{
				Cipher:             CipherAES256GCM,
				KeyProvider:        NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				FilenameEncryption: FilenameEncryptionRandom,
				MetadataPath:       "",
			},
			wantErr: true,
			errMsg:  "metadata path must be set",
		},
		{
			name: "random filename encryption with metadata path",
			config: &Config{
				Cipher:             CipherAES256GCM,
				KeyProvider:        NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				FilenameEncryption: FilenameEncryptionRandom,
				MetadataPath:       "/tmp/metadata.db",
			},
			wantErr: false,
		},
		{
			name: "parallel without chunked mode",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   0, // Traditional mode
				Parallel: ParallelConfig{
					Enabled:              true,
					MaxWorkers:           4,
					MinChunksForParallel: 4,
				},
			},
			wantErr: true,
			errMsg:  "parallel processing requires chunked mode",
		},
		{
			name: "negative max workers",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   64 * 1024,
				Parallel: ParallelConfig{
					Enabled:              true,
					MaxWorkers:           -1,
					MinChunksForParallel: 4,
				},
			},
			wantErr: true,
			errMsg:  "parallel max workers cannot be negative",
		},
		{
			name: "too many workers",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   64 * 1024,
				Parallel: ParallelConfig{
					Enabled:              true,
					MaxWorkers:           2000,
					MinChunksForParallel: 4,
				},
			},
			wantErr: true,
			errMsg:  "parallel max workers must not exceed 1024",
		},
		{
			name: "zero min chunks",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   64 * 1024,
				Parallel: ParallelConfig{
					Enabled:              true,
					MaxWorkers:           4,
					MinChunksForParallel: 0,
				},
			},
			wantErr: true,
			errMsg:  "parallel min chunks threshold must be at least 1",
		},
		{
			name: "too many min chunks",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   64 * 1024,
				Parallel: ParallelConfig{
					Enabled:              true,
					MaxWorkers:           4,
					MinChunksForParallel: 2000,
				},
			},
			wantErr: true,
			errMsg:  "parallel min chunks threshold must not exceed 1000",
		},
		{
			name: "valid parallel config",
			config: &Config{
				Cipher:      CipherAES256GCM,
				KeyProvider: NewPasswordKeyProvider([]byte("test"), Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2}),
				ChunkSize:   64 * 1024,
				Parallel:    DefaultParallelConfig(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Config.Validate() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					// Check if error message contains expected substring
					if len(err.Error()) < len(tt.errMsg) || err.Error()[:len(tt.errMsg)] != tt.errMsg {
						t.Errorf("Config.Validate() error = %q, want error containing %q", err.Error(), tt.errMsg)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Config.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestParallelConfig_Validate tests ParallelConfig validation
func TestParallelConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ParallelConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "disabled - always valid",
			config: ParallelConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "negative workers",
			config: ParallelConfig{
				Enabled:              true,
				MaxWorkers:           -1,
				MinChunksForParallel: 4,
			},
			wantErr: true,
			errMsg:  "parallel max workers cannot be negative",
		},
		{
			name: "too many workers",
			config: ParallelConfig{
				Enabled:              true,
				MaxWorkers:           2000,
				MinChunksForParallel: 4,
			},
			wantErr: true,
			errMsg:  "parallel max workers must not exceed 1024",
		},
		{
			name: "zero min chunks",
			config: ParallelConfig{
				Enabled:              true,
				MaxWorkers:           4,
				MinChunksForParallel: 0,
			},
			wantErr: true,
			errMsg:  "parallel min chunks threshold must be at least 1",
		},
		{
			name: "valid config",
			config: ParallelConfig{
				Enabled:              true,
				MaxWorkers:           8,
				MinChunksForParallel: 4,
			},
			wantErr: false,
		},
		{
			name:    "default config",
			config:  DefaultParallelConfig(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParallelConfig.Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ParallelConfig.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestArgon2idParams_Validate tests Argon2id parameter validation
func TestArgon2idParams_Validate(t *testing.T) {
	tests := []struct {
		name    string
		params  Argon2idParams
		wantErr bool
		errMsg  string
	}{
		{
			name: "memory too low",
			params: Argon2idParams{
				Memory:      4 * 1024, // 4 MiB - too low
				Iterations:  1,
				Parallelism: 2,
				SaltSize:    32,
				KeySize:     32,
			},
			wantErr: true,
			errMsg:  "argon2id memory must be at least 8 MiB",
		},
		{
			name: "memory too high",
			params: Argon2idParams{
				Memory:      5 * 1024 * 1024, // 5 GiB - too high
				Iterations:  1,
				Parallelism: 2,
				SaltSize:    32,
				KeySize:     32,
			},
			wantErr: true,
			errMsg:  "argon2id memory must not exceed 4 GiB",
		},
		{
			name: "iterations too low",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  0,
				Parallelism: 2,
				SaltSize:    32,
				KeySize:     32,
			},
			wantErr: true,
			errMsg:  "argon2id iterations must be at least 1",
		},
		{
			name: "iterations too high",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  200,
				Parallelism: 2,
				SaltSize:    32,
				KeySize:     32,
			},
			wantErr: true,
			errMsg:  "argon2id iterations must not exceed 100",
		},
		{
			name: "parallelism too low",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 0,
				SaltSize:    32,
				KeySize:     32,
			},
			wantErr: true,
			errMsg:  "argon2id parallelism must be at least 1",
		},
		{
			name: "salt size too small",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 2,
				SaltSize:    8,
				KeySize:     32,
			},
			wantErr: true,
			errMsg:  "argon2id salt size must be at least 16 bytes",
		},
		{
			name: "key size too small",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  1,
				Parallelism: 2,
				SaltSize:    32,
				KeySize:     8,
			},
			wantErr: true,
			errMsg:  "argon2id key size must be at least 16 bytes",
		},
		{
			name: "valid params",
			params: Argon2idParams{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 4,
				SaltSize:    32,
				KeySize:     32,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Argon2idParams.Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Argon2idParams.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestPBKDF2Params_Validate tests PBKDF2 parameter validation
func TestPBKDF2Params_Validate(t *testing.T) {
	tests := []struct {
		name    string
		params  PBKDF2Params
		wantErr bool
		errMsg  string
	}{
		{
			name: "iterations too low",
			params: PBKDF2Params{
				Iterations: 50000,
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    32,
			},
			wantErr: true,
			errMsg:  "pbkdf2 iterations must be at least 100,000",
		},
		{
			name: "iterations too high",
			params: PBKDF2Params{
				Iterations: 20000000,
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    32,
			},
			wantErr: true,
			errMsg:  "pbkdf2 iterations must not exceed 10,000,000",
		},
		{
			name: "invalid hash function",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   HashFunc(99),
				SaltSize:   32,
				KeySize:    32,
			},
			wantErr: true,
			errMsg:  "pbkdf2 hash function must be SHA256 or SHA512",
		},
		{
			name: "salt size too small",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA256,
				SaltSize:   8,
				KeySize:    32,
			},
			wantErr: true,
			errMsg:  "pbkdf2 salt size must be at least 16 bytes",
		},
		{
			name: "key size too small",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    8,
			},
			wantErr: true,
			errMsg:  "pbkdf2 key size must be at least 16 bytes",
		},
		{
			name: "valid SHA256 params",
			params: PBKDF2Params{
				Iterations: 200000,
				HashFunc:   SHA256,
				SaltSize:   32,
				KeySize:    32,
			},
			wantErr: false,
		},
		{
			name: "valid SHA512 params",
			params: PBKDF2Params{
				Iterations: 100000,
				HashFunc:   SHA512,
				SaltSize:   32,
				KeySize:    32,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("PBKDF2Params.Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("PBKDF2Params.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}
