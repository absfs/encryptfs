package encryptfs

import (
	"testing"
)

func TestValidateBuffer(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		bufName string
		minSize int
		wantErr bool
	}{
		{
			name:    "nil buffer",
			buf:     nil,
			bufName: "data",
			minSize: 0,
			wantErr: true,
		},
		{
			name:    "valid buffer no min size",
			buf:     make([]byte, 10),
			bufName: "data",
			minSize: 0,
			wantErr: false,
		},
		{
			name:    "buffer too small",
			buf:     make([]byte, 5),
			bufName: "data",
			minSize: 10,
			wantErr: true,
		},
		{
			name:    "buffer exact size",
			buf:     make([]byte, 10),
			bufName: "data",
			minSize: 10,
			wantErr: false,
		},
		{
			name:    "buffer larger than min",
			buf:     make([]byte, 20),
			bufName: "data",
			minSize: 10,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBuffer(tt.buf, tt.bufName, tt.minSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBuffer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !IsValidationError(err) {
				t.Errorf("ValidateBuffer() should return ValidationError, got %T", err)
			}
		})
	}
}

func TestValidateOffset(t *testing.T) {
	tests := []struct {
		name       string
		offset     int64
		offsetName string
		wantErr    bool
	}{
		{
			name:       "negative offset",
			offset:     -1,
			offsetName: "file_offset",
			wantErr:    true,
		},
		{
			name:       "zero offset",
			offset:     0,
			offsetName: "file_offset",
			wantErr:    false,
		},
		{
			name:       "positive offset",
			offset:     1024,
			offsetName: "file_offset",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOffset(tt.offset, tt.offsetName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOffset() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !IsValidationError(err) {
				t.Errorf("ValidateOffset() should return ValidationError, got %T", err)
			}
		})
	}
}

func TestValidateSize(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		sizeName string
		minSize  int
		maxSize  int
		wantErr  bool
	}{
		{
			name:     "negative size",
			size:     -1,
			sizeName: "chunk_size",
			minSize:  0,
			maxSize:  100,
			wantErr:  true,
		},
		{
			name:     "zero size valid",
			size:     0,
			sizeName: "chunk_size",
			minSize:  0,
			maxSize:  100,
			wantErr:  false,
		},
		{
			name:     "size too small",
			size:     5,
			sizeName: "chunk_size",
			minSize:  10,
			maxSize:  100,
			wantErr:  true,
		},
		{
			name:     "size too large",
			size:     150,
			sizeName: "chunk_size",
			minSize:  10,
			maxSize:  100,
			wantErr:  true,
		},
		{
			name:     "size within bounds",
			size:     50,
			sizeName: "chunk_size",
			minSize:  10,
			maxSize:  100,
			wantErr:  false,
		},
		{
			name:     "size at min bound",
			size:     10,
			sizeName: "chunk_size",
			minSize:  10,
			maxSize:  100,
			wantErr:  false,
		},
		{
			name:     "size at max bound",
			size:     100,
			sizeName: "chunk_size",
			minSize:  10,
			maxSize:  100,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSize(tt.size, tt.sizeName, tt.minSize, tt.maxSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !IsValidationError(err) {
				t.Errorf("ValidateSize() should return ValidationError, got %T", err)
			}
		})
	}
}

func TestValidateNonce(t *testing.T) {
	tests := []struct {
		name    string
		nonce   []byte
		cipher  CipherSuite
		wantErr bool
	}{
		{
			name:    "nil nonce",
			nonce:   nil,
			cipher:  CipherAES256GCM,
			wantErr: true,
		},
		{
			name:    "valid AES-GCM nonce",
			nonce:   make([]byte, 12),
			cipher:  CipherAES256GCM,
			wantErr: false,
		},
		{
			name:    "invalid AES-GCM nonce size",
			nonce:   make([]byte, 16),
			cipher:  CipherAES256GCM,
			wantErr: true,
		},
		{
			name:    "valid ChaCha20 nonce",
			nonce:   make([]byte, 12),
			cipher:  CipherChaCha20Poly1305,
			wantErr: false,
		},
		{
			name:    "invalid ChaCha20 nonce size",
			nonce:   make([]byte, 8),
			cipher:  CipherChaCha20Poly1305,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNonce(tt.nonce, tt.cipher)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNonce() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !IsValidationError(err) {
				t.Errorf("ValidateNonce() should return ValidationError, got %T", err)
			}
		})
	}
}

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name         string
		key          []byte
		expectedSize int
		wantErr      bool
	}{
		{
			name:         "nil key",
			key:          nil,
			expectedSize: 32,
			wantErr:      true,
		},
		{
			name:         "valid key",
			key:          make([]byte, 32),
			expectedSize: 32,
			wantErr:      false,
		},
		{
			name:         "key too small",
			key:          make([]byte, 16),
			expectedSize: 32,
			wantErr:      true,
		},
		{
			name:         "key too large",
			key:          make([]byte, 64),
			expectedSize: 32,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKey(tt.key, tt.expectedSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !IsValidationError(err) {
				t.Errorf("ValidateKey() should return ValidationError, got %T", err)
			}
		})
	}
}

func TestValidateChunkIndex(t *testing.T) {
	tests := []struct {
		name     string
		index    uint32
		maxIndex uint32
		context  string
		wantErr  bool
	}{
		{
			name:     "index within bounds",
			index:    5,
			maxIndex: 10,
			context:  "test",
			wantErr:  false,
		},
		{
			name:     "index at max",
			index:    10,
			maxIndex: 10,
			context:  "test",
			wantErr:  false,
		},
		{
			name:     "index exceeds max",
			index:    11,
			maxIndex: 10,
			context:  "test",
			wantErr:  true,
		},
		{
			name:     "zero index",
			index:    0,
			maxIndex: 10,
			context:  "test",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChunkIndex(tt.index, tt.maxIndex, tt.context)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateChunkIndex() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !IsValidationError(err) {
				t.Errorf("ValidateChunkIndex() should return ValidationError, got %T", err)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "valid path",
			path:    "/test/file.txt",
			wantErr: false,
		},
		{
			name:    "relative path",
			path:    "test/file.txt",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !IsValidationError(err) {
				t.Errorf("ValidateFilePath() should return ValidationError, got %T", err)
			}
		})
	}
}

func TestValidateReadWrite(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		position int64
		wantErr  bool
		errType  error
	}{
		{
			name:     "nil buffer",
			buf:      nil,
			position: 0,
			wantErr:  true,
			errType:  ErrNilBuffer,
		},
		{
			name:     "negative position",
			buf:      make([]byte, 10),
			position: -1,
			wantErr:  true,
			errType:  ErrNegativeOffset,
		},
		{
			name:     "valid",
			buf:      make([]byte, 10),
			position: 100,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReadWrite(tt.buf, tt.position)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateReadWrite() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != tt.errType {
				t.Errorf("ValidateReadWrite() error = %v, want %v", err, tt.errType)
			}
		})
	}
}
