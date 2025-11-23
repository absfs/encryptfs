package encryptfs

import (
	"errors"
	"testing"
)

func TestValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		wantMsg  string
		checkMsg func(string) bool
	}{
		{
			name: "with field",
			err: &ValidationError{
				Field:   "chunk_size",
				Value:   1024,
				Message: "too small",
			},
			wantMsg: "validation error: chunk_size: too small",
		},
		{
			name: "without field",
			err: &ValidationError{
				Message: "invalid configuration",
			},
			wantMsg: "validation error: invalid configuration",
		},
		{
			name: "with wrapped error",
			err: &ValidationError{
				Field:   "key",
				Message: "invalid key",
				Err:     ErrInvalidKey,
			},
			checkMsg: func(msg string) bool {
				return msg == "validation error: key: invalid key"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if tt.checkMsg != nil {
				if !tt.checkMsg(got) {
					t.Errorf("ValidationError.Error() = %q, want message matching check", got)
				}
			} else if got != tt.wantMsg {
				t.Errorf("ValidationError.Error() = %q, want %q", got, tt.wantMsg)
			}

			// Test Unwrap
			if tt.err.Err != nil {
				if unwrapped := tt.err.Unwrap(); unwrapped != tt.err.Err {
					t.Errorf("ValidationError.Unwrap() = %v, want %v", unwrapped, tt.err.Err)
				}
			}
		})
	}
}

func TestEncryptionError(t *testing.T) {
	baseErr := errors.New("aead: message authentication failed")

	tests := []struct {
		name    string
		err     *EncryptionError
		wantMsg string
	}{
		{
			name: "with path and chunk",
			err: &EncryptionError{
				Operation: "decrypt",
				Path:      "/test/file.enc",
				ChunkIdx:  5,
				Message:   "auth failed",
				Err:       baseErr,
			},
			wantMsg: "decrypt error: /test/file.enc (chunk 5): auth failed",
		},
		{
			name: "with path only",
			err: &EncryptionError{
				Operation: "encrypt",
				Path:      "/test/file.txt",
				Message:   "key derivation failed",
			},
			wantMsg: "encrypt error: /test/file.txt: key derivation failed",
		},
		{
			name: "minimal",
			err: &EncryptionError{
				Operation: "decrypt",
				Message:   "invalid ciphertext",
			},
			wantMsg: "decrypt error: invalid ciphertext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("EncryptionError.Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

func TestIOError(t *testing.T) {
	baseErr := errors.New("permission denied")

	tests := []struct {
		name    string
		err     *IOError
		wantMsg string
	}{
		{
			name: "with offset",
			err: &IOError{
				Operation: "read",
				Path:      "/test/file.dat",
				Offset:    1024,
				Message:   "permission denied",
				Err:       baseErr,
			},
			wantMsg: "io error: read /test/file.dat at offset 1024: permission denied",
		},
		{
			name: "without offset",
			err: &IOError{
				Operation: "write",
				Path:      "/test/file.dat",
				Offset:    -1,
				Message:   "disk full",
			},
			wantMsg: "io error: write /test/file.dat: disk full",
		},
		{
			name: "operation only",
			err: &IOError{
				Operation: "sync",
				Message:   "failed to sync",
			},
			wantMsg: "io error: sync: failed to sync",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("IOError.Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

func TestCorruptionError(t *testing.T) {
	tests := []struct {
		name    string
		err     *CorruptionError
		wantMsg string
	}{
		{
			name: "with chunk",
			err: &CorruptionError{
				Path:     "/test/file.enc",
				ChunkIdx: 3,
				Message:  "invalid MAC",
			},
			wantMsg: "corruption error: /test/file.enc (chunk 3): invalid MAC",
		},
		{
			name: "without chunk",
			err: &CorruptionError{
				Path:    "/test/file.enc",
				Message: "invalid header",
			},
			wantMsg: "corruption error: /test/file.enc: invalid header",
		},
		{
			name: "generic",
			err: &CorruptionError{
				Message: "data tampering detected",
			},
			wantMsg: "corruption error: data tampering detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("CorruptionError.Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

func TestAuthenticationError(t *testing.T) {
	baseErr := errors.New("wrong password")

	tests := []struct {
		name    string
		err     *AuthenticationError
		wantMsg string
	}{
		{
			name: "with path",
			err: &AuthenticationError{
				Path:    "/test/secret.enc",
				Message: "wrong password",
				Err:     baseErr,
			},
			wantMsg: "authentication error: /test/secret.enc: wrong password",
		},
		{
			name: "without path",
			err: &AuthenticationError{
				Message: "key derivation failed",
			},
			wantMsg: "authentication error: key derivation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("AuthenticationError.Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

func TestErrorCheckers(t *testing.T) {
	ve := &ValidationError{Message: "test"}
	ee := &EncryptionError{Operation: "encrypt", Message: "test"}
	ie := &IOError{Operation: "read", Message: "test"}
	ce := &CorruptionError{Message: "test"}
	ae := &AuthenticationError{Message: "test"}
	genericErr := errors.New("generic error")

	tests := []struct {
		name string
		err  error
		fn   func(error) bool
		want bool
	}{
		{"IsValidationError with ValidationError", ve, IsValidationError, true},
		{"IsValidationError with other error", genericErr, IsValidationError, false},
		{"IsEncryptionError with EncryptionError", ee, IsEncryptionError, true},
		{"IsEncryptionError with other error", genericErr, IsEncryptionError, false},
		{"IsIOError with IOError", ie, IsIOError, true},
		{"IsIOError with other error", genericErr, IsIOError, false},
		{"IsCorruptionError with CorruptionError", ce, IsCorruptionError, true},
		{"IsCorruptionError with other error", genericErr, IsCorruptionError, false},
		{"IsAuthenticationError with AuthenticationError", ae, IsAuthenticationError, true},
		{"IsAuthenticationError with other error", genericErr, IsAuthenticationError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn(tt.err)
			if got != tt.want {
				t.Errorf("error checker = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorConstructors(t *testing.T) {
	t.Run("NewValidationError", func(t *testing.T) {
		err := NewValidationError("field", 123, "invalid value")
		if !IsValidationError(err) {
			t.Error("NewValidationError should create ValidationError")
		}
		ve := err.(*ValidationError)
		if ve.Field != "field" || ve.Value != 123 || ve.Message != "invalid value" {
			t.Errorf("NewValidationError fields incorrect: %+v", ve)
		}
	})

	t.Run("NewEncryptionError", func(t *testing.T) {
		baseErr := errors.New("test")
		err := NewEncryptionError("encrypt", "/path", baseErr)
		if !IsEncryptionError(err) {
			t.Error("NewEncryptionError should create EncryptionError")
		}
		ee := err.(*EncryptionError)
		if ee.Operation != "encrypt" || ee.Path != "/path" {
			t.Errorf("NewEncryptionError fields incorrect: %+v", ee)
		}
	})

	t.Run("NewIOError", func(t *testing.T) {
		baseErr := errors.New("test")
		err := NewIOError("read", "/path", baseErr)
		if !IsIOError(err) {
			t.Error("NewIOError should create IOError")
		}
		ie := err.(*IOError)
		if ie.Operation != "read" || ie.Path != "/path" {
			t.Errorf("NewIOError fields incorrect: %+v", ie)
		}
	})

	t.Run("NewCorruptionError", func(t *testing.T) {
		err := NewCorruptionError("/path", "corrupted")
		if !IsCorruptionError(err) {
			t.Error("NewCorruptionError should create CorruptionError")
		}
		ce := err.(*CorruptionError)
		if ce.Path != "/path" || ce.Message != "corrupted" {
			t.Errorf("NewCorruptionError fields incorrect: %+v", ce)
		}
	})

	t.Run("NewAuthenticationError", func(t *testing.T) {
		baseErr := errors.New("test")
		err := NewAuthenticationError("/path", baseErr)
		if !IsAuthenticationError(err) {
			t.Error("NewAuthenticationError should create AuthenticationError")
		}
		ae := err.(*AuthenticationError)
		if ae.Path != "/path" {
			t.Errorf("NewAuthenticationError fields incorrect: %+v", ae)
		}
	})
}
