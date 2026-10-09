package sevenzip

import (
	"errors"
	"io"
	"io/fs"
	"math"

	"github.com/bodgit/sevenzip/internal/util"
)

// StreamInfo describes one independently decoded stream (a solid group).
// Index is the same identifier as File.Stream. Sizes and offsets are bytes.
type StreamInfo struct {
	Index            int
	UncompressedSize uint64
}

// Streams returns a metadata snapshot without opening any content decoders.
func (z *Reader) Streams() []StreamInfo {
	result := make([]StreamInfo, z.si.Folders())
	for i := range result {
		result[i] = StreamInfo{Index: i, UncompressedSize: z.si.unpackInfo.folder[i].unpackSize()}
	}
	return result
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
	if index < 0 || index >= z.si.Folders() {
		return nil, fs.ErrInvalid
	}
	if z.si.unpackInfo.folder[index].unpackSize() > math.MaxInt64 {
		return nil, fs.ErrInvalid
	}
	// Larger packed input reads avoid thousands of ReaderAt calls for network
	// sources. Header parsing and File.Open retain their original buffering.
	r, crc, encrypted, err := z.si.folderReaderBuffered(io.NewSectionReader(z.r, z.start, z.end-z.start), index, z.p, 1<<20)
	if err != nil {
		return nil, &ReadError{Encrypted: encrypted, Err: err}
	}
	return &streamReader{reader: r, crc: crc, remaining: r.Size()}, nil
}

type streamReader struct {
	reader    *folderReadCloser
	crc       uint32
	remaining int64
	err       error
	closed    bool
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
	if err == io.EOF && r.crc != 0 && !util.CRC32Equal(r.reader.Checksum(), r.crc) {
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
