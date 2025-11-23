package encryptfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// SIVEngine implements AES-SIV (Synthetic Initialization Vector) mode
// for deterministic authenticated encryption. This is particularly useful
// for filename encryption where we need deterministic output.
//
// SIV provides:
// - Deterministic encryption (same plaintext -> same ciphertext with same key)
// - Authentication (detects tampering)
// - Nonce-misuse resistance
//
// Reference: RFC 5297 - Synthetic Initialization Vector (SIV) Authenticated Encryption
type SIVEngine struct {
	k1    []byte // First half of key for S2V
	k2    []byte // Second half of key for CTR
	block cipher.Block
}

// NewSIVEngine creates a new AES-SIV cipher engine
// Key must be 64 bytes (512 bits) - split into two 32-byte keys
func NewSIVEngine(key []byte) (*SIVEngine, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("AES-SIV requires a 64-byte key, got %d bytes", len(key))
	}

	// Split key into two halves
	k1 := key[:32]
	k2 := key[32:]

	// Create AES block cipher with k2 for CTR mode
	block, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &SIVEngine{
		k1:    k1,
		k2:    k2,
		block: block,
	}, nil
}

// Encrypt encrypts plaintext using AES-SIV
// Additional data (AD) can be provided for authentication
func (e *SIVEngine) Encrypt(plaintext []byte, ad ...[]byte) ([]byte, error) {
	// Step 1: Generate SIV using S2V algorithm
	siv := e.s2v(plaintext, ad...)

	// Step 2: Encrypt plaintext using CTR mode with SIV as IV
	ciphertext := make([]byte, len(plaintext))
	e.ctrMode(siv, plaintext, ciphertext)

	// Step 3: Prepend SIV to ciphertext
	result := make([]byte, 16+len(ciphertext))
	copy(result[:16], siv)
	copy(result[16:], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext using AES-SIV
// Additional data (AD) must match what was used during encryption
func (e *SIVEngine) Decrypt(ciphertext []byte, ad ...[]byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Step 1: Extract SIV and ciphertext
	siv := ciphertext[:16]
	ct := ciphertext[16:]

	// Step 2: Decrypt using CTR mode
	plaintext := make([]byte, len(ct))
	e.ctrMode(siv, ct, plaintext)

	// Step 3: Verify SIV
	expectedSIV := e.s2v(plaintext, ad...)
	if subtle.ConstantTimeCompare(siv, expectedSIV) != 1 {
		return nil, ErrAuthFailed
	}

	return plaintext, nil
}

// s2v implements the S2V (Synthetic IV) algorithm from RFC 5297
func (e *SIVEngine) s2v(plaintext []byte, ad ...[]byte) []byte {
	// Create CMAC with k1
	block, _ := aes.NewCipher(e.k1)

	// D = CMAC(zero_block)
	d := e.cmac(block, make([]byte, 16))

	// For each AD[i]: D = dbl(D) xor CMAC(AD[i])
	for _, a := range ad {
		d = xor(dbl(d), e.cmac(block, a))
	}

	// Handle plaintext
	var t []byte
	if len(plaintext) >= 16 {
		// T = plaintext[0:n-16] || (plaintext[n-16:n] xor D)
		t = make([]byte, len(plaintext))
		copy(t, plaintext)
		xorBytes(t[len(t)-16:], d)
	} else {
		// T = dbl(D) xor pad(plaintext)
		t = xor(dbl(d), pad(plaintext))
	}

	return e.cmac(block, t)
}

// cmac implements CMAC (Cipher-based Message Authentication Code)
func (e *SIVEngine) cmac(block cipher.Block, data []byte) []byte {
	// Generate subkeys
	k1, k2 := generateSubkeys(block)

	// Process data in 16-byte blocks
	n := (len(data) + 15) / 16
	if n == 0 {
		n = 1
	}

	lastBlock := make([]byte, 16)
	if len(data) == 0 || len(data)%16 != 0 {
		// Incomplete last block - use k2 and padding
		copy(lastBlock, data[16*(n-1):])
		lastBlock = pad(lastBlock[:len(data)%16])
		xorBytes(lastBlock, k2)
	} else {
		// Complete last block - use k1
		copy(lastBlock, data[16*(n-1):])
		xorBytes(lastBlock, k1)
	}

	// CBC-MAC
	mac := make([]byte, 16)
	for i := 0; i < n-1; i++ {
		chunk := data[i*16 : (i+1)*16]
		xorBytes(mac, chunk)
		block.Encrypt(mac, mac)
	}
	xorBytes(mac, lastBlock)
	block.Encrypt(mac, mac)

	return mac
}

// ctrMode implements CTR mode encryption/decryption
func (e *SIVEngine) ctrMode(iv, src, dst []byte) {
	// Clear bit 31 and 63 of IV for CTR mode (RFC 5297 Section 2.5)
	ctr := make([]byte, 16)
	copy(ctr, iv)
	ctr[8] &= 0x7f
	ctr[12] &= 0x7f

	stream := cipher.NewCTR(e.block, ctr)
	stream.XORKeyStream(dst, src)
}

// dbl implements the doubling operation in GF(2^128)
func dbl(block []byte) []byte {
	result := make([]byte, 16)
	carry := uint64(0)

	// Process as two 64-bit integers (big-endian)
	for i := 0; i < 2; i++ {
		offset := (1 - i) * 8
		val := binary.BigEndian.Uint64(block[offset:offset+8])
		newVal := (val << 1) | carry
		binary.BigEndian.PutUint64(result[offset:offset+8], newVal)
		carry = val >> 63
	}

	// XOR with R if carry
	if carry != 0 {
		result[15] ^= 0x87
	}

	return result
}

// pad adds PKCS#7-like padding (10* padding for CMAC)
func pad(data []byte) []byte {
	result := make([]byte, 16)
	copy(result, data)
	result[len(data)] = 0x80
	return result
}

// xor XORs two byte slices and returns the result
func xor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a) && i < len(b); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// xorBytes XORs b into a in place
func xorBytes(a, b []byte) {
	for i := 0; i < len(a) && i < len(b); i++ {
		a[i] ^= b[i]
	}
}

// generateSubkeys generates CMAC subkeys k1 and k2
func generateSubkeys(block cipher.Block) ([]byte, []byte) {
	l := make([]byte, 16)
	block.Encrypt(l, l)

	k1 := dbl(l)
	k2 := dbl(k1)

	return k1, k2
}

// NonceSize returns 0 since SIV doesn't use nonces
func (e *SIVEngine) NonceSize() int {
	return 0
}

// Overhead returns the SIV size (16 bytes)
func (e *SIVEngine) Overhead() int {
	return 16
}
