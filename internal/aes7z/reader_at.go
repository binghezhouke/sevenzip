package aes7z

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"io/fs"
	"math"
	"sync"
)

const randomReadChunk = 64 << 10

// ReaderAt owns a copy of a derived key, never the package key-cache slice.
// Calls use independent CBC state and may supply different request readers.
type ReaderAt struct {
	mu     sync.Mutex
	key    []byte
	iv     [aes.BlockSize]byte
	size   int64
	closed bool
}

func NewReaderAt(properties []byte, password string, size int64) (*ReaderAt, error) {
	if size <= 0 || size > math.MaxInt64-(aes.BlockSize-1) {
		return nil, fs.ErrInvalid
	}
	parameters, err := newParameters(properties)
	if err != nil {
		return nil, err
	}
	shared, err := calculateKey(password, parameters.cycles, parameters.salt)
	if err != nil {
		return nil, err
	}
	r := &ReaderAt{key: append([]byte(nil), shared...), size: size}
	copy(r.iv[:], parameters.iv)
	return r, nil
}

// ReadAtWithReader reads ciphertext in stream-relative coordinates. The
// declared plaintext length trims 7z's block padding; it is not PKCS#7.
func (r *ReaderAt) ReadAtWithReader(body io.ReaderAt, p []byte, off int64) (int, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, fs.ErrClosed
	}
	var key [32]byte
	copy(key[:], r.key)
	iv, size := r.iv, r.size
	r.mu.Unlock()
	defer clear(key[:])
	if body == nil || off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= size {
		return 0, io.EOF
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return 0, err
	}
	want := min(int64(len(p)), size-off)
	// One bounded allocation per call, including the predecessor block and
	// both possible alignment fragments. A long request reuses this buffer.
	buffer := make([]byte, min(want, randomReadChunk)+3*aes.BlockSize)
	total := int64(0)
	for total < want {
		position := off + total
		amount := min(want-total, randomReadChunk)
		start := position / aes.BlockSize * aes.BlockSize
		end := (position + amount + aes.BlockSize - 1) / aes.BlockSize * aes.BlockSize
		readStart := start
		if start != 0 {
			readStart -= aes.BlockSize
		}
		ciphertext := buffer[:end-readStart]
		n, readErr := body.ReadAt(ciphertext, readStart)
		if n != len(ciphertext) {
			if readErr == nil || errors.Is(readErr, io.EOF) {
				readErr = io.ErrUnexpectedEOF
			}
			return int(total), readErr
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return int(total), readErr
		}
		if start != 0 {
			copy(iv[:], ciphertext[:aes.BlockSize])
			ciphertext = ciphertext[aes.BlockSize:]
		}
		cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(ciphertext, ciphertext)
		copy(p[total:total+amount], ciphertext[position-start:position-start+amount])
		total += amount
	}
	if total < int64(len(p)) {
		return int(total), io.EOF
	}
	return int(total), nil
}

// Close prevents new calls and clears the owned raw key. Calls already in
// progress retain their own temporary copy until they return. Expanded AES
// state has no wipe API and becomes unreachable when each call returns.
func (r *ReaderAt) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		clear(r.key)
		r.key = nil
		r.closed = true
	}
	return nil
}
