package sevenzip

import (
	"bytes"
	"errors"
	"io/fs"
	"math"
	"strconv"

	"github.com/bodgit/sevenzip/internal/aes7z"
	"github.com/ulikunitz/xz/lzma"
)

// ErrUnsupportedDecoderInfo means the graph is outside the metadata cost
// description's allowlist. It does not mean the archive cannot be decoded.
var ErrUnsupportedDecoderInfo = errors.New("sevenzip: unsupported decoder metadata")

// CRCInfo distinguishes a declared checksum (including zero) from no checksum.
type CRCInfo struct {
	Defined bool
	Value   uint32
}

// StreamCoderInfo is a copy of one parsed coder's header fields.
type StreamCoderInfo struct {
	ID, Properties  []byte
	Inputs, Outputs uint64
}

// StreamBindPair connects absolute input/output indices within the folder.
type StreamBindPair struct{ Input, Output uint64 }

// StreamMemberInfo identifies a nonempty-stream file without retaining its name.
type StreamMemberInfo struct {
	Ordinal int
	Offset  int64
	Size    uint64
	CRC     CRCInfo
}

// StreamLayout is an owned metadata snapshot. It contains no decoder, ReaderAt,
// password or reference to Reader. Empty files/directories have no stream and
// are omitted from Members. Slice order is the original header order.
type StreamLayout struct {
	Index            int
	UncompressedSize uint64
	Inputs, Outputs  uint64
	Coders           []StreamCoderInfo
	BindPairs        []StreamBindPair
	PackedIndices    []uint64
	OutputSizes      []uint64
	PackedRanges     []PackedRange
	CRC              CRCInfo
	Members          []StreamMemberInfo
}

// LZMA2DecoderInfo describes buffers in the current built-in implementation;
// these are not format limits or a total process-memory budget. DictionarySize
// excludes its ring buffer's extra byte. MaxLiteralModelBytes describes one
// model; chunk property changes can temporarily retain old and new models.
type LZMA2DecoderInfo struct {
	DictionarySize       uint64
	PackedBufferSize     uint64
	MaxLiteralModelBytes uint64
}

// AESLZMA2DecoderInfo describes the built-in sequential AES-to-LZMA2 graph.
// AdditionalMemoryBytes bounds AES buffering, including a buffer growth
// transition, and fixed cipher state. It does not describe KDF CPU time, the
// existing process-wide key cache, caller password storage or custom codecs.
type AESLZMA2DecoderInfo struct {
	LZMA2                 LZMA2DecoderInfo
	AdditionalMemoryBytes uint64
}

// AESLZMA2DecoderInfo recognizes exactly one AES-256-CBC coder feeding one
// LZMA2 coder, with one packed input. No source is read and no cipher or key is
// constructed. Invalid properties/geometry return fs.ErrInvalid; other graphs
// return ErrUnsupportedDecoderInfo. PlainLZMA2DecoderInfo remains unencrypted.
// Built-in LZMA2 requests at most 32KiB from AES: compressed chunks use
// ReadByte, and uncompressed chunks use io.CopyN's 32KiB copy buffer. AES may
// round this up by 15 bytes. bytes.Buffer can retain 128KiB due to read offsets
// and doubling; a growth can temporarily retain old/new buffers. 256KiB covers
// that transition plus CBC state, IV, salt and reader structs. These facts do
// not cover RegisterDecompressor overrides or arbitrary direct AES consumers.
func (s *StreamLayout) AESLZMA2DecoderInfo() (*AESLZMA2DecoderInfo, error) {
	if s == nil {
		return nil, fs.ErrInvalid
	}
	if len(s.Coders) != 2 || s.Inputs != 2 || s.Outputs != 2 || len(s.BindPairs) != 1 ||
		len(s.PackedIndices) != 1 || s.PackedIndices[0] != 0 || len(s.OutputSizes) != 2 || len(s.PackedRanges) != 1 ||
		s.BindPairs[0] != (StreamBindPair{Input: 1, Output: 0}) {
		return nil, ErrUnsupportedDecoderInfo
	}
	a, l := s.Coders[0], s.Coders[1]
	if a.Inputs != 1 || a.Outputs != 1 || l.Inputs != 1 || l.Outputs != 1 ||
		!bytes.Equal(a.ID, []byte{0x06, 0xf1, 0x07, 0x01}) || !bytes.Equal(l.ID, []byte{0x21}) {
		return nil, ErrUnsupportedDecoderInfo
	}
	p := s.PackedRanges[0]
	if err := aes7z.ValidateProperties(a.Properties); err != nil {
		return nil, fs.ErrInvalid
	}
	if p.Offset < 0 || p.Size <= 0 || p.Size%16 != 0 || p.Offset > math.MaxInt64-p.Size ||
		s.OutputSizes[0] == 0 || s.OutputSizes[0] > uint64(p.Size) || uint64(p.Size)-s.OutputSizes[0] >= 16 ||
		s.UncompressedSize > math.MaxInt64 || s.OutputSizes[1] != s.UncompressedSize {
		return nil, fs.ErrInvalid
	}
	plain := &StreamLayout{Inputs: 1, Outputs: 1, Coders: []StreamCoderInfo{l}, PackedIndices: []uint64{0},
		OutputSizes: []uint64{s.UncompressedSize}, PackedRanges: []PackedRange{{Offset: p.Offset, Size: int64(s.OutputSizes[0])}}, UncompressedSize: s.UncompressedSize}
	info, err := plain.PlainLZMA2DecoderInfo()
	if err != nil {
		return nil, err
	}
	return &AESLZMA2DecoderInfo{LZMA2: *info, AdditionalMemoryBytes: 256 << 10}, nil
}

// PlainLZMA2DecoderInfo recognizes only one unfiltered, unencrypted LZMA2 coder
// with one packed input and one output. No decoder is constructed. Invalid
// properties (including platform integer overflow) return fs.ErrInvalid;
// other graph/coder combinations return ErrUnsupportedDecoderInfo. A custom
// RegisterDecompressor override is not described by these built-in facts.
func (s *StreamLayout) PlainLZMA2DecoderInfo() (*LZMA2DecoderInfo, error) {
	if s == nil {
		return nil, fs.ErrInvalid
	}
	if len(s.Coders) != 1 || s.Inputs != 1 || s.Outputs != 1 || len(s.BindPairs) != 0 || len(s.PackedIndices) != 1 || s.PackedIndices[0] != 0 || len(s.OutputSizes) != 1 || len(s.PackedRanges) != 1 {
		return nil, ErrUnsupportedDecoderInfo
	}
	c := s.Coders[0]
	if c.Inputs != 1 || c.Outputs != 1 || !bytes.Equal(c.ID, []byte{0x21}) {
		return nil, ErrUnsupportedDecoderInfo
	}
	if len(c.Properties) != 1 || c.Properties[0] > 40 || s.UncompressedSize > math.MaxInt64 || s.OutputSizes[0] != s.UncompressedSize {
		return nil, fs.ErrInvalid
	}
	p := c.Properties[0]
	// Match internal/lzma2.NewReader, including its current rejection of prop
	// 40: that constructor computes 4GiB, beyond xz's MaxDictCap (4GiB-1).
	dict := (uint64(2) | (uint64(p) & 1)) << (p/2 + 11)
	if dict > uint64(math.MaxInt64) || (strconv.IntSize == 32 && dict > math.MaxInt32) {
		return nil, fs.ErrInvalid
	}
	config := lzma.Reader2Config{DictCap: int(dict)}
	if err := config.Verify(); err != nil {
		return nil, fs.ErrInvalid
	}
	return &LZMA2DecoderInfo{DictionarySize: dict, PackedBufferSize: ownedStreamPackedBufferSize, MaxLiteralModelBytes: 6 << 20}, nil
}

// StreamLayout returns header facts without reading the source or constructing
// a decoder. Slices, coder properties and member metadata are independent copies.
func (z *Reader) StreamLayout(index int) (*StreamLayout, error) {
	if z == nil || index < 0 || index >= z.si.Folders() {
		return nil, fs.ErrInvalid
	}
	f := z.si.unpackInfo.folder[index]
	if err := validStreamFolder(f); err != nil {
		return nil, err
	}
	if z.si.packInfo == nil {
		return nil, fs.ErrInvalid
	}
	count := uint64(0)
	for _, folder := range z.si.unpackInfo.folder {
		if folder == nil || uint64(len(folder.packed)) > math.MaxUint64-count {
			return nil, fs.ErrInvalid
		}
		count += uint64(len(folder.packed))
	}
	if count != uint64(len(z.si.packInfo.size)) {
		return nil, fs.ErrInvalid
	}
	packed, err := z.PackedRanges(index)
	if err != nil {
		return nil, err
	}
	s := &StreamLayout{Index: index, UncompressedSize: f.unpackSize(), Inputs: f.in, Outputs: f.out,
		PackedRanges: packed, PackedIndices: append([]uint64(nil), f.packed...), OutputSizes: append([]uint64(nil), f.size...)}
	s.CRC = crcInfo(z.si.unpackInfo.digest, z.si.unpackInfo.digestDefined, index)
	for _, c := range f.coder {
		s.Coders = append(s.Coders, StreamCoderInfo{ID: append([]byte(nil), c.id...), Properties: append([]byte(nil), c.properties...), Inputs: c.in, Outputs: c.out})
	}
	for _, b := range f.bindPair {
		s.BindPairs = append(s.BindPairs, StreamBindPair{Input: b.in, Output: b.out})
	}
	position := int64(0)
	for ordinal, file := range z.File {
		if file == nil {
			return nil, fs.ErrInvalid
		}
		offset, ok := file.StreamOffset()
		if !ok {
			continue
		}
		if file.folder == index {
			if offset != position || offset < 0 || uint64(offset) > s.UncompressedSize || file.UncompressedSize > s.UncompressedSize-uint64(offset) {
				return nil, fs.ErrInvalid
			}
			s.Members = append(s.Members, StreamMemberInfo{Ordinal: ordinal, Offset: offset, Size: file.UncompressedSize, CRC: file.Checksum()})
			position += int64(file.UncompressedSize)
		}
	}
	if uint64(position) != s.UncompressedSize {
		return nil, fs.ErrInvalid
	}
	return s, nil
}

func validStreamFolder(f *folder) error {
	if f == nil || len(f.coder) == 0 || f.in == 0 || f.out == 0 || uint64(len(f.size)) != f.out || uint64(len(f.bindPair)) != f.out-1 || uint64(len(f.bindPair)) > f.in || uint64(len(f.packed)) != f.in-uint64(len(f.bindPair)) || f.packedStreams != uint64(len(f.packed)) {
		return fs.ErrInvalid
	}
	inputs, outputs := uint64(0), uint64(0)
	for _, c := range f.coder {
		if c == nil || len(c.id) == 0 || c.in == 0 || c.out == 0 || c.in > math.MaxUint64-inputs || c.out > math.MaxUint64-outputs {
			return fs.ErrInvalid
		}
		inputs += c.in
		outputs += c.out
	}
	if inputs != f.in || outputs != f.out {
		return fs.ErrInvalid
	}
	for _, size := range f.size {
		if size > math.MaxInt64 {
			return fs.ErrInvalid
		}
	}
	inOwner, outOwner := make([]int, inputs), make([]int, outputs)
	in, out := 0, 0
	for i, c := range f.coder {
		for j := uint64(0); j < c.in; j++ {
			inOwner[in] = i
			in++
		}
		for j := uint64(0); j < c.out; j++ {
			outOwner[out] = i
			out++
		}
	}
	boundIn, boundOut := make([]bool, inputs), make([]bool, outputs)
	edges := make([][]int, len(f.coder))
	degree := make([]int, len(f.coder))
	for _, b := range f.bindPair {
		if b == nil || b.in >= inputs || b.out >= outputs || boundIn[b.in] || boundOut[b.out] {
			return fs.ErrInvalid
		}
		boundIn[b.in] = true
		boundOut[b.out] = true
		from, to := outOwner[b.out], inOwner[b.in]
		edges[from] = append(edges[from], to)
		degree[to]++
	}
	for _, p := range f.packed {
		if p >= inputs || boundIn[p] {
			return fs.ErrInvalid
		}
		boundIn[p] = true
	}
	queue := make([]int, 0, len(f.coder))
	for i, d := range degree {
		if d == 0 {
			queue = append(queue, i)
		}
	}
	for i := 0; i < len(queue); i++ {
		for _, to := range edges[queue[i]] {
			degree[to]--
			if degree[to] == 0 {
				queue = append(queue, to)
			}
		}
	}
	if len(queue) != len(f.coder) {
		return fs.ErrInvalid
	}
	return nil
}
