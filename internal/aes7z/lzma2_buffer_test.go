package aes7z

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"testing"
)

// Built-in LZMA2 uses one-byte compressed reads and at most 32KiB copy reads
// for uncompressed chunks. Alternate these sizes across CBC boundaries and
// read offsets to exercise bytes.Buffer's compaction/growth behavior.
func TestLZMA2ConsumerAESBufferBound(t *testing.T) {
	plain := make([]byte, 2<<20)
	for i := range plain {
		plain[i] = byte(i * 17)
	}
	encrypted := make([]byte, len(plain))
	var key [32]byte
	key[0] = 's'
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(encrypted, plain)
	properties := append([]byte{0x7f, 0x0f}, make([]byte, 16)...)
	r, err := NewReader(properties, 0, []io.ReadCloser{io.NopCloser(bytes.NewReader(encrypted))})
	if err != nil {
		t.Fatal(err)
	}
	rc := r.(*readCloser)
	defer rc.Close()
	if err := rc.Password("s"); err != nil {
		t.Fatal(err)
	}
	offset, maxCapacity := 0, 0
	pattern := []int{1, 32768, 5, 32768, 13, 32768, 1, 32767}
	for i := 0; offset < len(plain); i++ {
		size := min(pattern[i%len(pattern)], len(plain)-offset)
		p := make([]byte, size)
		n, err := rc.Read(p)
		if err != nil || n != size {
			t.Fatalf("read n=%d error=%v", n, err)
		}
		if !bytes.Equal(p, plain[offset:offset+n]) {
			t.Fatal("CBC output differs")
		}
		offset += n
		maxCapacity = max(maxCapacity, rc.buf.Cap())
		if rc.buf.Cap() > 128<<10 {
			t.Fatalf("AES buffer cap=%d exceeds charged resident bound", rc.buf.Cap())
		}
	}
	t.Logf("max AES buffer capacity=%d; growth transition<=192KiB, charged256KiB", maxCapacity)
}
