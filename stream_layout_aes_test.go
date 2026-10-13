package sevenzip_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"testing"

	"github.com/bodgit/sevenzip"
)

const aesLayoutPassword = "mount-synthetic-password"

func aesLayoutFixture(t *testing.T) (*sevenzip.Reader, *layoutCountingSource, *sevenzip.StreamLayout) {
	t.Helper()
	data, err := os.ReadFile("testdata/aes-lzma2-solid.7z")
	if err != nil {
		t.Fatal(err)
	}
	source := &layoutCountingSource{ReaderAt: bytes.NewReader(data)}
	z, err := sevenzip.NewReaderWithPassword(source, int64(len(data)), aesLayoutPassword)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := z.StreamLayout(0)
	if err != nil {
		t.Fatal(err)
	}
	return z, source, layout
}

func TestAESLZMA2DecoderMetadata(t *testing.T) {
	_, source, layout := aesLayoutFixture(t)
	source.reads = 0
	info, err := layout.AESLZMA2DecoderInfo()
	if err != nil {
		t.Fatal(err)
	}
	if source.reads != 0 {
		t.Fatal("metadata read source")
	}
	if info.LZMA2.DictionarySize != 1<<20 || info.LZMA2.PackedBufferSize != 1<<20 || info.LZMA2.MaxLiteralModelBytes != 6<<20 || info.AdditionalMemoryBytes != 256<<10 {
		t.Fatalf("unaccounted decoder: %+v", info)
	}
	if _, err := layout.PlainLZMA2DecoderInfo(); !errors.Is(err, sevenzip.ErrUnsupportedDecoderInfo) {
		t.Fatalf("plain helper accepted encryption: %v", err)
	}
}

func aesLayoutPayload(i int) []byte {
	state := uint32(4100 + i)
	block := make([]byte, 16384)
	for i := range block {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		block[i] = byte(state)
	}
	result := make([]byte, (4<<20)+13)
	for off := 0; off < len(result); off += len(block) {
		copy(result[off:], block)
	}
	return result
}

func TestAESLZMA2DecoderRealStreamOracle(t *testing.T) {
	z, _, layout := aesLayoutFixture(t)
	if len(layout.Members) != 3 || layout.UncompressedSize != 12582951 {
		t.Fatal("fixture no longer three-member solid group")
	}
	rc, err := z.OpenStream(0)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	for i, m := range layout.Members {
		p := aesLayoutPayload(i)
		if m.Ordinal != i || m.Offset != int64(len(want)) || m.Size != uint64(len(p)) {
			t.Fatal("unexpected fixture geometry")
		}
		want = append(want, p...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("built-in AES/LZMA2 differs from independent payload oracle")
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Read(make([]byte, 1)); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("stream read after close: %v", err)
	}
}

func TestAESLZMA2DecoderMetadataRejectsOtherGraphsAndMalformed(t *testing.T) {
	_, _, base := aesLayoutFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*sevenzip.StreamLayout)
		want   error
	}{
		{"additional filter", func(s *sevenzip.StreamLayout) { s.Coders = append(s.Coders, s.Coders[1]) }, sevenzip.ErrUnsupportedDecoderInfo},
		{"wrong bind", func(s *sevenzip.StreamLayout) { s.BindPairs[0].Input = 0 }, sevenzip.ErrUnsupportedDecoderInfo},
		{"wrong packed", func(s *sevenzip.StreamLayout) { s.PackedIndices[0] = 1 }, sevenzip.ErrUnsupportedDecoderInfo},
		{"multiple packed", func(s *sevenzip.StreamLayout) { s.PackedRanges = append(s.PackedRanges, s.PackedRanges[0]) }, sevenzip.ErrUnsupportedDecoderInfo},
		{"wrong cipher", func(s *sevenzip.StreamLayout) { s.Coders[0].ID = []byte{0} }, sevenzip.ErrUnsupportedDecoderInfo},
		{"wrong compressor", func(s *sevenzip.StreamLayout) { s.Coders[1].ID = []byte{0} }, sevenzip.ErrUnsupportedDecoderInfo},
		{"cipher property short", func(s *sevenzip.StreamLayout) { s.Coders[0].Properties = []byte{0x53} }, fs.ErrInvalid},
		{"cipher property flags", func(s *sevenzip.StreamLayout) { s.Coders[0].Properties = []byte{0x13, 0} }, fs.ErrInvalid},
		{"cipher property tail", func(s *sevenzip.StreamLayout) { s.Coders[0].Properties = append(s.Coders[0].Properties, 0) }, fs.ErrInvalid},
		{"dict property short", func(s *sevenzip.StreamLayout) { s.Coders[1].Properties = nil }, fs.ErrInvalid},
		{"dict property invalid", func(s *sevenzip.StreamLayout) { s.Coders[1].Properties = []byte{41} }, fs.ErrInvalid},
		{"dict constructor rejected", func(s *sevenzip.StreamLayout) { s.Coders[1].Properties = []byte{40} }, fs.ErrInvalid},
		{"packed alignment", func(s *sevenzip.StreamLayout) { s.PackedRanges[0].Size-- }, fs.ErrInvalid},
		{"empty packed", func(s *sevenzip.StreamLayout) { s.PackedRanges[0].Size = 0 }, fs.ErrInvalid},
		{"negative packed", func(s *sevenzip.StreamLayout) { s.PackedRanges[0].Size = -16 }, fs.ErrInvalid},
		{"negative offset", func(s *sevenzip.StreamLayout) { s.PackedRanges[0].Offset = -1 }, fs.ErrInvalid},
		{"packed overflow", func(s *sevenzip.StreamLayout) { s.PackedRanges[0].Offset = math.MaxInt64 }, fs.ErrInvalid},
		{"padding oversized", func(s *sevenzip.StreamLayout) { s.OutputSizes[0] = uint64(s.PackedRanges[0].Size) - 16 }, fs.ErrInvalid},
		{"cipher output overrun", func(s *sevenzip.StreamLayout) { s.OutputSizes[0] = uint64(s.PackedRanges[0].Size) + 1 }, fs.ErrInvalid},
		{"cipher output empty", func(s *sevenzip.StreamLayout) { s.OutputSizes[0] = 0 }, fs.ErrInvalid},
		{"group size mismatch", func(s *sevenzip.StreamLayout) { s.OutputSizes[1]++ }, fs.ErrInvalid},
		{"group size overflow", func(s *sevenzip.StreamLayout) { s.UncompressedSize = math.MaxUint64; s.OutputSizes[1] = math.MaxUint64 }, fs.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var s sevenzip.StreamLayout
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&s)
			if _, err := s.AESLZMA2DecoderInfo(); !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
		})
	}
	var missing *sevenzip.StreamLayout
	if _, err := missing.AESLZMA2DecoderInfo(); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}
