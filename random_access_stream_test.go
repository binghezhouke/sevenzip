package sevenzip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"sync"
	"testing"
)

func randomAccessFixture(t *testing.T, size, prefix int) (*Reader, []byte, []byte) {
	t.Helper()
	plain := make([]byte, size)
	for i := range plain {
		plain[i] = byte(i*17 + 11)
	}
	// The last real byte deliberately looks like padding. It must not be
	// interpreted as a PKCS#7 padding count.
	if len(plain) > 0 {
		plain[len(plain)-1] = 1
	}
	const password = "synthetic-password"
	key := make([]byte, 32)
	for i, r := range password {
		if i*2+1 < len(key) {
			key[i*2] = byte(r)
		}
	}
	iv := bytes.Repeat([]byte{0x23}, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, (size+aes.BlockSize-1)/aes.BlockSize*aes.BlockSize)
	copy(encrypted, plain)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, encrypted)
	body := append(bytes.Repeat([]byte{0xff}, prefix), encrypted...)
	properties := append([]byte{0x7f, 0x0f}, iv...)
	return &Reader{start: int64(prefix), end: int64(len(body)), p: password,
		si: &streamsInfo{packInfo: &packInfo{size: []uint64{uint64(len(encrypted))}}, unpackInfo: &unpackInfo{folder: []*folder{{
			in: 2, out: 2, packedStreams: 1, packed: []uint64{0},
			coder:    []*coder{{id: []byte{0x06, 0xf1, 0x07, 0x01}, in: 1, out: 1, properties: properties}, {id: []byte{0}, in: 1, out: 1}},
			bindPair: []*bindPair{{in: 1, out: 0}}, size: []uint64{uint64(size), uint64(size)},
		}}}}, File: []*File{{FileHeader: FileHeader{Stream: 0, UncompressedSize: uint64(size)}}}}, body, plain
}

type randomAccessCountedBody struct {
	io.ReaderAt
	bytes  int
	ranges [][2]int64
}

func (r *randomAccessCountedBody) ReadAt(p []byte, off int64) (int, error) {
	r.bytes += len(p)
	r.ranges = append(r.ranges, [2]int64{off, int64(len(p))})
	return r.ReaderAt.ReadAt(p, off)
}

func TestRandomAccessStreamSparseTailAvoidsEncryptedPrefix(t *testing.T) {
	z, body, plain := randomAccessFixture(t, (8<<20)+13, 123)
	r, err := z.OpenRandomAccessStream(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	source := &randomAccessCountedBody{ReaderAt: bytes.NewReader(body)}
	got := make([]byte, 4096)
	off := int64(len(plain) - len(got))
	if n, err := r.ReadAtWithReader(source, got, off); err != nil || n != len(got) || !bytes.Equal(got, plain[off:]) {
		t.Fatalf("tail: %d %v", n, err)
	}
	if source.bytes > len(got)+46 {
		t.Fatalf("tail read %d ciphertext bytes for %d plaintext bytes", source.bytes, len(got))
	}
	if len(source.ranges) != 1 || source.ranges[0][0] < z.start+off-31 {
		t.Fatalf("tail read unrelated prefix: %v", source.ranges)
	}
	if z.Streams()[0].Stored {
		t.Fatal("encrypted Copy must retain Stored=false")
	}
}

func TestRandomAccessStreamBoundariesAndPadding(t *testing.T) {
	for _, size := range []int{1, 15, 16, 17, 31, 32, 33, (256 << 10) + 13} {
		z, body, plain := randomAccessFixture(t, size, 37)
		r, err := z.OpenRandomAccessStream(0)
		if err != nil {
			t.Fatal(err)
		}
		for _, off := range []int64{0, 1, 15, 16, 17, int64(size - 1), int64(size), int64(size + 1)} {
			for _, length := range []int{0, 1, 2, 17, size + 1} {
				got, want := make([]byte, length), make([]byte, length)
				n, err := r.ReadAtWithReader(bytes.NewReader(body), got, off)
				wn, we := bytes.NewReader(plain).ReadAt(want, off)
				if length == 0 {
					wn, we = 0, nil
				}
				if n != wn || !errors.Is(err, we) || !bytes.Equal(got[:n], want[:wn]) {
					t.Fatalf("size=%d off=%d len=%d got=%d/%v want=%d/%v", size, off, length, n, err, wn, we)
				}
			}
		}
		if _, err := r.ReadAtWithReader(bytes.NewReader(body), make([]byte, 1), -1); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("negative offset: %v", err)
		}
		if _, err := r.ReadAtWithReader(nil, make([]byte, 1), 0); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("nil body: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadAtWithReader(bytes.NewReader(body), make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
			t.Fatalf("after Close: %v", err)
		}
	}
}

func TestRandomAccessStreamTinyUnalignedReads(t *testing.T) {
	z, body, plain := randomAccessFixture(t, 256, 0)
	r, err := z.OpenRandomAccessStream(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Offset 31/length 2 needs three ciphertext blocks: predecessor plus
	// two crossed data blocks. Small requests must budget both fragments.
	for off := int64(0); off < 64; off++ {
		for length := 1; length <= 65; length++ {
			got := make([]byte, length)
			if n, err := r.ReadAtWithReader(bytes.NewReader(body), got, off); err != nil || n != length || !bytes.Equal(got, plain[off:off+int64(length)]) {
				t.Fatalf("off=%d len=%d: %d %v", off, length, n, err)
			}
		}
	}
}

func TestRandomAccessStreamRejectsUnsupportedAndInvalidGeometry(t *testing.T) {
	for _, change := range []string{"filter", "order", "binding", "packed-input", "copy-properties", "solid", "padding", "sizes", "overflow", "properties", "missing-packed-size"} {
		t.Run(change, func(t *testing.T) {
			z, _, _ := randomAccessFixture(t, 33, 0)
			f := z.si.unpackInfo.folder[0]
			unsupported := true
			switch change {
			case "filter":
				f.coder[1].id = []byte{3}
			case "order":
				f.coder[0], f.coder[1] = f.coder[1], f.coder[0]
			case "binding":
				f.bindPair[0].in = 0
			case "packed-input":
				f.packed[0] = 1
			case "copy-properties":
				f.coder[1].properties = []byte{0}
			case "solid":
				z.File = append(z.File, &File{FileHeader: FileHeader{Stream: 0, UncompressedSize: 1}, offset: 32})
			case "padding":
				z.si.packInfo.size[0]++
				z.end++
				unsupported = false
			case "sizes":
				f.size[0]++
				unsupported = false
			case "overflow":
				f.size = []uint64{math.MaxUint64, math.MaxUint64}
				z.File[0].UncompressedSize = math.MaxUint64
				unsupported = false
			case "properties":
				f.coder[0].properties = []byte{0}
				unsupported = false
			case "missing-packed-size":
				z.si.packInfo.size = nil
				unsupported = false
			}
			r, err := z.OpenRandomAccessStream(0)
			if r != nil {
				r.Close()
				t.Fatal("accepted unsupported/invalid layout")
			}
			if err == nil || (unsupported && !errors.Is(err, ErrUnsupportedRandomAccess)) || (!unsupported && errors.Is(err, ErrUnsupportedRandomAccess)) {
				t.Fatalf("error: %v", err)
			}
		})
	}
	z, _, _ := randomAccessFixture(t, 33, 0)
	for _, index := range []int{-1, 1} {
		if _, err := z.OpenRandomAccessStream(index); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("invalid index: %v", err)
		}
	}
}

func TestRandomAccessStreamShortBodyAndConcurrentClose(t *testing.T) {
	z, body, plain := randomAccessFixture(t, (128<<10)+13, 0)
	r, err := z.OpenRandomAccessStream(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAtWithReader(bytes.NewReader(body[:len(body)-1]), make([]byte, 32), int64(len(plain)-32)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated ciphertext: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			off := int64(i * 17)
			got := make([]byte, 1000)
			n, err := r.ReadAtWithReader(bytes.NewReader(body), got, off)
			if errors.Is(err, fs.ErrClosed) {
				return
			}
			if err != nil || n != len(got) || !bytes.Equal(got, plain[off:off+int64(len(got))]) {
				t.Errorf("concurrent read: %d %v", n, err)
			}
		}(i)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestRandomAccessStreamRealAESCopyFixtureAndSharedKeySurvivesClose(t *testing.T) {
	body, err := os.ReadFile("testdata/aes_copy_random_access.7z")
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat(func() []byte {
		p := make([]byte, 256)
		for i := range p {
			p[i] = byte(i)
		}
		return p
	}(), 513), []byte("random-tail\x01")...)
	z, err := NewReaderWithPassword(bytes.NewReader(body), int64(len(body)), "synthetic-密码-🙂")
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != 1 || z.File[0].UncompressedSize != uint64(len(want)) {
		t.Fatal("unexpected real Copy fixture geometry")
	}
	r, err := z.OpenRandomAccessStream(z.File[0].Stream)
	if err != nil {
		f := z.si.unpackInfo.folder[z.File[0].Stream]
		var ids []string
		for _, c := range f.coder {
			ids = append(ids, fmt.Sprintf("%x", c.id))
		}
		t.Fatalf("synthetic fixture %v: coder IDs=%v sizes=%v in=%d out=%d packed=%v", err, ids, f.size, f.in, f.out, f.packed)
	}
	for _, off := range []int64{0, 15, 16, 31, 64 << 10, int64(len(want) - 37)} {
		got := make([]byte, 37)
		if n, err := r.ReadAtWithReader(bytes.NewReader(body), got, off); err != nil || n != len(got) || !bytes.Equal(got, want[off:off+37]) {
			t.Fatalf("real fixture offset=%d: %d %v", off, n, err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// The sequential decoder now retrieves the same shared KDF entry. Closing
	// the random reader must not have zeroed or changed its key-cache slice.
	sequential, err := z.OpenStream(z.File[0].Stream)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(sequential)
	if err != nil {
		t.Fatal(err)
	}
	if err := sequential.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("random Close corrupted the shared KDF key")
	}
}

type randomAccessBlockedBody struct {
	io.ReaderAt
	started, release chan struct{}
}

func (r randomAccessBlockedBody) ReadAt(p []byte, off int64) (int, error) {
	close(r.started)
	<-r.release
	return r.ReaderAt.ReadAt(p, off)
}

func TestRandomAccessStreamCloseAllowsActiveReadAndRejectsNewReads(t *testing.T) {
	z, body, plain := randomAccessFixture(t, 123, 0)
	r, err := z.OpenRandomAccessStream(0)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		got := make([]byte, 17)
		_, err := r.ReadAtWithReader(randomAccessBlockedBody{bytes.NewReader(body), started, release}, got, 31)
		if err == nil && !bytes.Equal(got, plain[31:48]) {
			err = errors.New("active reader lost its key")
		}
		done <- err
	}()
	<-started
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAtWithReader(bytes.NewReader(body), make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("new read after close: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type randomAccessShortNilBody struct{}

func (randomAccessShortNilBody) ReadAt(p []byte, _ int64) (int, error) {
	return copy(p, []byte{1, 2, 3}), nil
}

func TestRandomAccessStreamRejectsShortNilBody(t *testing.T) {
	z, _, _ := randomAccessFixture(t, 123, 0)
	r, err := z.OpenRandomAccessStream(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if n, err := r.ReadAtWithReader(randomAccessShortNilBody{}, make([]byte, 17), 31); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short nil: %d %v", n, err)
	}
}
