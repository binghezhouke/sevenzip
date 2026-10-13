package sevenzip

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"math"

	"github.com/bodgit/sevenzip/internal/util"
)

const ownedStreamPackedBufferSize = 1 << 20

// StreamInfo describes one independently decoded stream (a solid group).
// Index is the same identifier as File.Stream. Sizes and offsets are bytes.
type StreamInfo struct {
	Index            int
	UncompressedSize uint64
	// Stored is true only for one Copy coder with no filters, properties, or
	// encryption, one packed input, and matching packed/unpacked sizes. Its
	// packed bytes are the uncompressed stream; direct reads do not verify CRCs.
	Stored bool
	// Encrypted reports an AES coder in this body stream, independently of headers.
	Encrypted bool
}

// Streams returns a metadata snapshot without opening any content decoders.
func (z *Reader) Streams() []StreamInfo {
	result := make([]StreamInfo, z.si.Folders())
	packed := 0
	for i := range result {
		folder := z.si.unpackInfo.folder[i]
		size := folder.unpackSize()
		stored := false
		if len(folder.coder) == 1 && folder.in == 1 && folder.out == 1 &&
			len(folder.bindPair) == 0 && folder.packedStreams == 1 &&
			len(folder.packed) == 1 && folder.packed[0] == 0 {
			coder := folder.coder[0]
			stored = len(coder.id) == 1 && coder.id[0] == 0 &&
				len(coder.properties) == 0 && coder.in == 1 && coder.out == 1 &&
				packed < len(z.si.packInfo.size) && z.si.packInfo.size[packed] == size
		}
		encrypted := false
		for _, coder := range folder.coder {
			encrypted = encrypted || bytes.Equal(coder.id, []byte{0x06, 0xf1, 0x07, 0x01})
		}
		result[i] = StreamInfo{Index: i, UncompressedSize: size, Stored: stored, Encrypted: encrypted}
		packed += len(folder.packed)
	}
	return result
}

// PackedRange is a compressed input's byte interval in the original ReaderAt.
// Offsets include any executable prefix and the archive start header.
type PackedRange struct {
	Offset int64
	Size   int64
}

// PackedRanges returns independently buffered inputs for a group's decoder.
// The snapshot does not open decoders or retain the caller's ReaderAt.
func (z *Reader) PackedRanges(index int) ([]PackedRange, error) {
	if index < 0 || index >= z.si.Folders() {
		return nil, fs.ErrInvalid
	}
	packed := 0
	offset := z.si.packInfo.position
	for i := 0; i < index; i++ {
		for range z.si.unpackInfo.folder[i].packed {
			size := z.si.packInfo.size[packed]
			if size > math.MaxInt64 || offset > math.MaxInt64-size {
				return nil, fs.ErrInvalid
			}
			offset += size
			packed++
		}
	}
	if z.start < 0 || offset > uint64(math.MaxInt64-z.start) {
		return nil, fs.ErrInvalid
	}
	absolute := z.start + int64(offset)
	result := make([]PackedRange, 0, len(z.si.unpackInfo.folder[index].packed))
	for range z.si.unpackInfo.folder[index].packed {
		size := z.si.packInfo.size[packed]
		if absolute > z.end || size > uint64(z.end-absolute) {
			return nil, fs.ErrInvalid
		}
		result = append(result, PackedRange{Offset: absolute, Size: int64(size)})
		absolute += int64(size)
		packed++
	}
	return result, nil
}

// StreamOffset returns the file's uncompressed byte offset in File.Stream.
// Directories and empty files have no stream and return false.
func (f *File) StreamOffset() (int64, bool) {
	return f.offset, !f.isEmptyStream && !f.isEmptyFile
}

// OpenStream decodes an entire stream from its beginning. Each call owns an
// independent decoder; Close releases it directly rather than returning it to
// File.Open's pool. Reading to EOF checks the stream CRC when present. Early
// Close does not validate unread data. Multiple streams may be read concurrently.
// The caller must keep the underlying ReaderAt available until Close.
func (z *Reader) OpenStream(index int) (io.ReadCloser, error) {
	return z.OpenStreamWithReader(index, z.r)
}

// OpenStreamWithReader decodes group content using r in the same absolute
// coordinates as the original ReaderAt. Metadata has already been parsed.
// The caller owns r, including cleanup on decoder construction failure.
func (z *Reader) OpenStreamWithReader(index int, body io.ReaderAt) (io.ReadCloser, error) {
	if body == nil {
		return nil, fs.ErrInvalid
	}
	if _, err := z.PackedRanges(index); err != nil {
		return nil, err
	}
	if index < 0 || index >= z.si.Folders() {
		return nil, fs.ErrInvalid
	}
	if z.si.unpackInfo.folder[index].unpackSize() > math.MaxInt64 {
		return nil, fs.ErrInvalid
	}
	// Larger packed input reads avoid thousands of ReaderAt calls for network
	// sources. Header parsing and File.Open retain their original buffering.
	r, crc, encrypted, err := z.si.folderReaderBuffered(io.NewSectionReader(body, z.start, z.end-z.start), index, z.p, ownedStreamPackedBufferSize)
	if err != nil {
		return nil, &ReadError{Encrypted: encrypted, Err: err}
	}
	defined := crcInfo(z.si.unpackInfo.digest, z.si.unpackInfo.digestDefined, index).Defined
	return &streamReader{reader: r, crc: crc, crcDefined: defined, remaining: r.Size()}, nil
}

type streamReader struct {
	reader     *folderReadCloser
	crc        uint32
	crcDefined bool
	remaining  int64
	err        error
	closed     bool
}

func (r *streamReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, fs.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	if err == io.EOF && r.remaining != 0 {
		err = io.ErrUnexpectedEOF
	}
	if err == nil && r.remaining == 0 {
		err = io.EOF
	}
	if err == io.EOF && r.crcDefined && !util.CRC32Equal(r.reader.Checksum(), r.crc) {
		err = errChecksum
	}
	if err != nil && !errors.Is(err, io.EOF) {
		err = &ReadError{Encrypted: r.reader.hasEncryption, Err: err}
	}
	r.err = err
	return n, err
}

func (r *streamReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.reader.Close()
}
