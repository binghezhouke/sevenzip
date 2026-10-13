package sevenzip

import (
	"bytes"
	"crypto/aes"
	"errors"
	"io"
	"io/fs"
	"math"

	"github.com/bodgit/sevenzip/internal/aes7z"
)

// ErrUnsupportedRandomAccess means a stream requires the generic sequential
// decoder. It is distinct from malformed metadata and source read errors.
var ErrUnsupportedRandomAccess = errors.New("sevenzip: stream does not support random access")

// RandomAccessStream reads an independent AES+Copy stream without decoding its
// prefix. These reads do not authenticate data or check the stream/member CRC;
// callers must validate CRCs when they consume complete content. The caller
// retains ownership of every injected body reader.
type RandomAccessStream struct {
	packed PackedRange
	reader *aes7z.ReaderAt
}

// OpenRandomAccessStream accepts only the canonical single-input AES→Copy
// graph with one independent, complete member. It does not read stream body
// bytes. Stored metadata and generic decoder behavior are unchanged.
func (z *Reader) OpenRandomAccessStream(index int) (*RandomAccessStream, error) {
	if z == nil || z.si == nil || z.si.unpackInfo == nil || z.si.packInfo == nil || index < 0 || index >= len(z.si.unpackInfo.folder) {
		return nil, fs.ErrInvalid
	}
	f := z.si.unpackInfo.folder[index]
	if f == nil {
		return nil, fs.ErrInvalid
	}
	if len(f.coder) != 2 || f.coder[0] == nil || f.coder[1] == nil || f.in != 2 || f.out != 2 ||
		f.packedStreams != 1 || len(f.packed) != 1 || f.packed[0] != 0 || len(f.bindPair) != 1 || f.bindPair[0] == nil ||
		f.bindPair[0].in != 1 || f.bindPair[0].out != 0 ||
		!bytes.Equal(f.coder[0].id, []byte{0x06, 0xf1, 0x07, 0x01}) || !bytes.Equal(f.coder[1].id, []byte{0}) ||
		f.coder[0].in != 1 || f.coder[0].out != 1 || f.coder[1].in != 1 || f.coder[1].out != 1 || len(f.coder[1].properties) != 0 {
		return nil, ErrUnsupportedRandomAccess
	}
	if len(f.size) != 2 {
		return nil, fs.ErrInvalid
	}
	if f.size[0] != f.size[1] {
		return nil, fs.ErrInvalid
	}
	size := f.size[1]
	if size == 0 || size > math.MaxInt64-(aes.BlockSize-1) {
		return nil, fs.ErrInvalid
	}
	members := 0
	for _, file := range z.File {
		if file == nil {
			return nil, fs.ErrInvalid
		}
		if offset, hasStream := file.StreamOffset(); hasStream && file.Stream == index {
			if offset != 0 || file.UncompressedSize != size {
				return nil, ErrUnsupportedRandomAccess
			}
			members++
		}
	}
	if members != 1 {
		return nil, ErrUnsupportedRandomAccess
	}
	// PackedRanges assumes parsed pack metadata is complete. Validate that
	// premise here too, so malformed/injected metadata cannot index past it.
	packed := 0
	for i := 0; i <= index; i++ {
		folder := z.si.unpackInfo.folder[i]
		if folder == nil || len(folder.packed) > len(z.si.packInfo.size)-packed {
			return nil, fs.ErrInvalid
		}
		packed += len(folder.packed)
	}
	ranges, err := z.PackedRanges(index)
	if err != nil {
		return nil, err
	}
	if len(ranges) != 1 || ranges[0].Size != int64((size+aes.BlockSize-1)/aes.BlockSize*aes.BlockSize) {
		return nil, fs.ErrInvalid
	}
	r, err := aes7z.NewReaderAt(f.coder[0].properties, z.p, int64(size))
	if err != nil {
		return nil, &ReadError{Encrypted: true, Err: err}
	}
	return &RandomAccessStream{packed: ranges[0], reader: r}, nil
}

// ReadAtWithReader takes body in the original archive's absolute coordinates,
// and off in plaintext stream coordinates. Each call may use its own request
// context through body; the stream does not retain body or the opening reader.
// Concurrent reads are independent. Close prevents new reads; already active
// reads may finish. Reads spanning plaintext EOF return the available bytes
// and io.EOF, without returning the cipher's alignment padding.
func (s *RandomAccessStream) ReadAtWithReader(body io.ReaderAt, p []byte, off int64) (int, error) {
	if s == nil || s.reader == nil || body == nil {
		return 0, fs.ErrInvalid
	}
	return s.reader.ReadAtWithReader(io.NewSectionReader(body, s.packed.Offset, s.packed.Size), p, off)
}

// Close clears the stream's owned derived-key copy. It never closes a source
// reader or changes the existing shared KDF cache. Repeated Close is harmless.
func (s *RandomAccessStream) Close() error {
	if s == nil || s.reader == nil {
		return nil
	}
	return s.reader.Close()
}
