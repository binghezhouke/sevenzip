package sevenzip_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/bodgit/sevenzip"
)

type layoutCountingSource struct {
	io.ReaderAt
	reads int
}

func (r *layoutCountingSource) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	return r.ReaderAt.ReadAt(p, off)
}

func TestStreamLayoutHeaderOnlySnapshot(t *testing.T) {
	data, err := os.ReadFile("testdata/lzma2.7z")
	if err != nil {
		t.Fatal(err)
	}
	source := &layoutCountingSource{ReaderAt: bytes.NewReader(data)}
	z, err := sevenzip.NewReader(source, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	source.reads = 0
	got, err := z.StreamLayout(0)
	if err != nil {
		t.Fatal(err)
	}
	if source.reads != 0 {
		t.Fatalf("metadata read source %d times", source.reads)
	}
	info, err := got.PlainLZMA2DecoderInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.DictionarySize != 49152 || info.PackedBufferSize != 1<<20 || info.MaxLiteralModelBytes != 6<<20 {
		t.Fatalf("codec facts: %+v", info)
	}
	if len(got.Members) != len(z.File) || got.Members[0].Ordinal != 0 || got.Members[0].Offset != 0 || !got.Members[0].CRC.Defined || got.Members[0].CRC.Value != 0x328aa043 {
		t.Fatalf("members: %+v", got.Members)
	}
	if got.BindPairs != nil {
		t.Fatal("empty bind snapshot must be nil")
	}
	got.Coders[0].ID[0] = 0
	got.Coders[0].Properties[0] = 255
	got.PackedIndices[0] = 99
	got.OutputSizes[0] = 0
	got.PackedRanges[0].Offset = -1
	got.Members[0].Offset = 999
	fresh, err := z.StreamLayout(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.PlainLZMA2DecoderInfo(); err != nil {
		t.Fatalf("snapshot mutation leaked: %v", err)
	}
	if fresh.PackedIndices[0] != 0 || fresh.OutputSizes[0] == 0 || fresh.PackedRanges[0].Offset < 0 || fresh.Members[0].Offset != 0 {
		t.Fatal("snapshot aliases parsed header")
	}
}

// A clear, synthetic header makes metadata tests independent of codec/body
// construction. Packed bytes are deliberately not valid compressed content.
func layoutUint(v uint64) []byte {
	if v < 128 {
		return []byte{byte(v)}
	}
	out := make([]byte, 9)
	out[0] = 255
	binary.LittleEndian.PutUint64(out[1:], v)
	return out
}
func layoutCRC(defined []bool, values []uint32) []byte {
	out := []byte{0}
	bits := make([]byte, (len(defined)+7)/8)
	for i, b := range defined {
		if b {
			bits[i/8] |= 128 >> uint(i%8)
		}
	}
	out = append(out, bits...)
	for i, b := range defined {
		if b {
			var p [4]byte
			binary.LittleEndian.PutUint32(p[:], values[i])
			out = append(out, p[:]...)
		}
	}
	return out
}
func layoutArchive(t *testing.T, id, props []byte, size uint64, group *sevenzip.CRCInfo, memberDefined []bool, memberCRC []uint32) []byte {
	t.Helper()
	h := []byte{1, 4, 6, 0, 1, 9, 4, 0, 7, 11, 1, 0, 1}
	flag := byte(len(id))
	if len(props) > 0 {
		flag |= 32
	}
	h = append(h, flag)
	h = append(h, id...)
	if len(props) > 0 {
		h = append(h, layoutUint(uint64(len(props)))...)
		h = append(h, props...)
	}
	h = append(h, 12)
	h = append(h, layoutUint(size)...)
	if group != nil {
		h = append(h, 10)
		h = append(h, layoutCRC([]bool{group.Defined}, []uint32{group.Value})...)
	}
	h = append(h, 0)
	count := len(memberDefined)
	if count == 0 {
		count = 1
	}
	if len(memberDefined) > 0 {
		h = append(h, 8, 13, byte(count))
		if count > 1 {
			h = append(h, 9)
			for i := 1; i < count; i++ {
				h = append(h, 1)
			}
		}
		h = append(h, 10)
		h = append(h, layoutCRC(memberDefined, memberCRC)...)
		h = append(h, 0)
	}
	h = append(h, 0, 5, byte(count), 17)
	names := []byte{0}
	for i := 0; i < count; i++ {
		names = append(names, byte('a'+i), 0, 0, 0)
	}
	h = append(h, layoutUint(uint64(len(names)))...)
	h = append(h, names...)
	h = append(h, 0, 0)
	return layoutWrapHeader(h)
}

func layoutWrapHeader(h []byte) []byte {
	start := make([]byte, 20)
	binary.LittleEndian.PutUint64(start, 4)
	binary.LittleEndian.PutUint64(start[8:], uint64(len(h)))
	binary.LittleEndian.PutUint32(start[16:], crc32.ChecksumIEEE(h))
	out := append([]byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4}, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[8:], crc32.ChecksumIEEE(start))
	out = append(out, start...)
	out = append(out, 0, 0, 0, 0)
	return append(out, h...)
}
func layoutReader(t *testing.T, data []byte) *sevenzip.Reader {
	t.Helper()
	z, err := sevenzip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestStreamLayoutCRCPresence(t *testing.T) {
	for _, group := range []*sevenzip.CRCInfo{nil, {Defined: false}, {Defined: true}, {Defined: true, Value: 0x12345678}} {
		z := layoutReader(t, layoutArchive(t, []byte{0}, nil, 4, group, nil, nil))
		got, err := z.StreamLayout(0)
		if err != nil {
			t.Fatal(err)
		}
		want := sevenzip.CRCInfo{}
		if group != nil && group.Defined {
			want = *group
		}
		if got.CRC != want || got.Members[0].CRC != want {
			t.Fatalf("single inherited CRC: group=%+v member=%+v want=%+v", got.CRC, got.Members[0].CRC, want)
		}
	}
	z := layoutReader(t, layoutArchive(t, []byte{0}, nil, 4, &sevenzip.CRCInfo{Defined: true}, []bool{true, false, true}, []uint32{0, 0, 0x76543210}))
	got, err := z.StreamLayout(0)
	if err != nil {
		t.Fatal(err)
	}
	want := []sevenzip.CRCInfo{{Defined: true}, {}, {Defined: true, Value: 0x76543210}}
	for i, crc := range want {
		if got.Members[i].CRC != crc {
			t.Fatalf("member %d: %+v want %+v", i, got.Members[i].CRC, crc)
		}
	}
}

func TestStreamLayoutPlainLZMA2Properties(t *testing.T) {
	for _, tc := range []struct {
		prop  byte
		dict  uint64
		valid bool
	}{
		{0, 4096, true}, {16, 1 << 20, true}, {20, 4 << 20, true}, {24, 16 << 20, true}, {28, 64 << 20, true},
		{37, 3 << 29, true}, {38, 2 << 30, strconv.IntSize == 64}, {39, 3 << 30, strconv.IntSize == 64}, {40, 0, false}, {41, 0, false}, {255, 0, false},
	} {
		t.Run(strconv.Itoa(int(tc.prop)), func(t *testing.T) {
			z := layoutReader(t, layoutArchive(t, []byte{0x21}, []byte{tc.prop}, 4, nil, nil, nil))
			got, err := z.StreamLayout(0)
			if err != nil {
				t.Fatal(err)
			}
			info, err := got.PlainLZMA2DecoderInfo()
			if tc.valid {
				if err != nil || info.DictionarySize != tc.dict {
					t.Fatalf("got %+v %v, want dict %d", info, err, tc.dict)
				}
			} else if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("invalid props: %v", err)
			}
		})
	}
	for _, props := range [][]byte{nil, {16, 0}} {
		z := layoutReader(t, layoutArchive(t, []byte{0x21}, props, 4, nil, nil, nil))
		got, err := z.StreamLayout(0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := got.PlainLZMA2DecoderInfo(); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("bad props %x: %v", props, err)
		}
	}
}

func TestStreamLayoutNoDecoderAndUnsupportedGraphs(t *testing.T) {
	// A registered trap verifies that a metadata query does not consult/open
	// even an available custom decoder. The unique method ID avoids overrides.
	id := []byte{0xf7, 0x55, 0x01}
	calls := 0
	sevenzip.RegisterDecompressor(id, func([]byte, uint64, []io.ReadCloser) (io.ReadCloser, error) {
		calls++
		return nil, errors.New("unexpected decoder")
	})
	source := &layoutCountingSource{ReaderAt: bytes.NewReader(layoutArchive(t, id, nil, 4, nil, nil, nil))}
	z, err := sevenzip.NewReader(source, source.ReaderAt.(*bytes.Reader).Size())
	if err != nil {
		t.Fatal(err)
	}
	source.reads = 0
	got, err := z.StreamLayout(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.PlainLZMA2DecoderInfo(); !errors.Is(err, sevenzip.ErrUnsupportedDecoderInfo) {
		t.Fatal(err)
	}
	if got.Coders[0].Properties != nil || got.BindPairs != nil {
		t.Fatal("absent properties/binds must stay nil")
	}
	if source.reads != 0 || calls != 0 {
		t.Fatalf("query source=%d decoder=%d", source.reads, calls)
	}
	for _, fixture := range []string{"copy.7z", "bcj2.7z", "delta_copy_equal_sizes.7z", "aes_copy_random_access.7z"} {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + fixture)
			if err != nil {
				t.Fatal(err)
			}
			z, err := sevenzip.NewReaderWithPassword(bytes.NewReader(data), int64(len(data)), "synthetic-密码-🙂")
			if err != nil {
				t.Fatal(err)
			}
			got, err := z.StreamLayout(0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := got.PlainLZMA2DecoderInfo(); !errors.Is(err, sevenzip.ErrUnsupportedDecoderInfo) {
				t.Fatalf("graph: %v", err)
			}
			if len(got.BindPairs) > 0 {
				got.BindPairs[0].Input = 999
				fresh, err := z.StreamLayout(0)
				if err != nil || fresh.BindPairs[0].Input == 999 {
					t.Fatal("bind snapshot aliases header")
				}
			}
		})
	}
}

func TestStreamLayoutInvalidAndOverflow(t *testing.T) {
	z := layoutReader(t, layoutArchive(t, []byte{0x21}, []byte{16}, 4, nil, nil, nil))
	for _, index := range []int{-1, 1} {
		if _, err := z.StreamLayout(index); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("index %d: %v", index, err)
		}
	}
	var nilReader *sevenzip.Reader
	if _, err := nilReader.StreamLayout(0); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	z = layoutReader(t, layoutArchive(t, []byte{0x21}, []byte{16}, math.MaxUint64, nil, nil, nil))
	if _, err := z.StreamLayout(0); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("size overflow: %v", err)
	}
}

// Malformed graph facts must be rejected without invoking any codec.
func TestStreamLayoutMalformedGraph(t *testing.T) {
	for _, tc := range []struct {
		name   string
		folder []byte
		sizes  []uint64
	}{
		{"bind-out-of-range", []byte{2, 1, 0, 1, 0, 2, 0}, []uint64{4, 4}},
		{"self-cycle", []byte{2, 1, 0, 1, 0, 0, 0}, []uint64{4, 4}},
		{"duplicate-bind", []byte{3, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1}, []uint64{4, 4, 4}},
		{"output-overflow", []byte{1, 1, 0}, []uint64{math.MaxUint64}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := []byte{1, 4, 6, 0, 1, 9, 4, 0, 7, 11, 1, 0}
			h = append(h, tc.folder...)
			h = append(h, 12)
			for _, size := range tc.sizes {
				h = append(h, layoutUint(size)...)
			}
			h = append(h, 0, 0, 5, 1, 17, 5, 0, 'a', 0, 0, 0, 0, 0)
			z := layoutReader(t, layoutWrapHeader(h))
			if _, err := z.StreamLayout(0); !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("malformed graph: %v", err)
			}
		})
	}
}

func TestStreamLayoutMixedFolderCRCSlots(t *testing.T) {
	for _, firstInherited := range []bool{true, false} {
		t.Run(strconv.FormatBool(firstInherited), func(t *testing.T) {
			// The single file inherits declared-zero folder CRC and consumes
			// no substream digest slot. Explicit slots are absent, AABBCCDD;
			// bitmap padding is false. Test both folder orders.
			groupBits := byte(0x40)
			counts := []byte{2, 1}
			inherited, explicit := 1, 0
			if firstInherited {
				groupBits = 0x80
				counts = []byte{1, 2}
				inherited, explicit = 0, 1
			}
			h := []byte{1, 4, 6, 0, 2, 9, 4, 4, 0, 7, 11, 2, 0, 1, 1, 0, 1, 1, 0, 12, 4, 4, 10, 0, groupBits}
			h = append(h, 0, 0, 0, 0, 0, 8, 13)
			h = append(h, counts...)
			h = append(h, 9, 2, 10, 0, 0x40)
			var crc [4]byte
			binary.LittleEndian.PutUint32(crc[:], 0xaabbccdd)
			h = append(h, crc[:]...)
			h = append(h, 0, 0, 5, 3, 17, 13, 0, 'a', 0, 0, 0, 'b', 0, 0, 0, 'c', 0, 0, 0, 0, 0)
			// Two four-byte packed inputs, unlike the single-input helper.
			data := layoutWrapHeader(h)
			data = append(data[:36], append(make([]byte, 4), data[36:]...)...)
			binary.LittleEndian.PutUint64(data[12:20], 8)
			binary.LittleEndian.PutUint32(data[8:12], crc32.ChecksumIEEE(data[12:32]))
			z := layoutReader(t, data)
			own, err := z.StreamLayout(inherited)
			if err != nil {
				t.Fatal(err)
			}
			if own.CRC != (sevenzip.CRCInfo{Defined: true}) || own.Members[0].CRC != own.CRC {
				t.Fatalf("inherit: %+v", own)
			}
			other, err := z.StreamLayout(explicit)
			if err != nil {
				t.Fatal(err)
			}
			if other.CRC.Defined || other.Members[0].CRC != (sevenzip.CRCInfo{}) || other.Members[1].CRC != (sevenzip.CRCInfo{Defined: true, Value: 0xaabbccdd}) {
				t.Fatalf("compact CRC slots: %+v", other.Members)
			}
		})
	}
}
