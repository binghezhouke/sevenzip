package sevenzip_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"testing"

	"github.com/bodgit/sevenzip"
)

type defaultSubstreamMember struct {
	name    string
	payload []byte
	stream  int
	dir     bool
}

// Build the default layout directly: UnpackInfo is followed by End, with no
// SubStreamsInfo property. Empty filesystem entries consume no stream ordinal.
func defaultSubstreamsArchive(payloads [][]byte, empty bool, extra int) ([]byte, []defaultSubstreamMember) {
	h := []byte{1, 4, 6, 0, byte(len(payloads)), 9}
	var body []byte
	for _, p := range payloads {
		h = append(h, layoutUint(uint64(len(p)))...)
		body = append(body, p...)
	}
	h = append(h, 0, 7, 11, byte(len(payloads)), 0)
	for range payloads {
		h = append(h, 1, 1, 0) // One Copy coder per independent folder.
	}
	h = append(h, 12)
	for _, p := range payloads {
		h = append(h, layoutUint(uint64(len(p)))...)
	}
	h = append(h, 10, 1)
	for _, p := range payloads {
		h = binary.LittleEndian.AppendUint32(h, crc32.ChecksumIEEE(p))
	}
	h = append(h, 0, 0, 5)
	var members []defaultSubstreamMember
	if empty {
		members = append(members, defaultSubstreamMember{name: "folder/", stream: -1, dir: true})
	}
	for i, p := range payloads {
		members = append(members, defaultSubstreamMember{name: fmt.Sprintf("member-%02d.bin", i), payload: p, stream: i})
		if empty && i == 0 {
			members = append(members, defaultSubstreamMember{name: "empty.txt", stream: -1})
		}
	}
	if extra < 0 {
		members = members[:len(members)-1]
	} else if extra > 0 {
		members = append(members, defaultSubstreamMember{name: "extra.bin", stream: len(payloads)})
	}
	h = append(h, layoutUint(uint64(len(members)))...)
	if empty {
		h = append(h, 14, 1, 0xa0, 15, 1, 0x40) // folder, data, empty, data...
	}
	names := []byte{0}
	for _, m := range members {
		for _, ch := range m.name {
			names = append(names, byte(ch), 0)
		}
		names = append(names, 0, 0)
	}
	h = append(h, 17)
	h = append(h, layoutUint(uint64(len(names)))...)
	h = append(h, names...)
	if empty {
		// Explicit file attributes keep this fixture focused on stream
		// ordinals rather than directory-mode inference from absent attrs.
		h = append(h, 21)
		h = append(h, layoutUint(uint64(2+4*len(members)))...)
		h = append(h, 1, 0)
		for _, m := range members {
			attr := uint32(0x20)
			if m.dir {
				attr = 0x10
			}
			h = binary.LittleEndian.AppendUint32(h, attr)
		}
	}
	h = append(h, 0, 0)
	start := make([]byte, 20)
	binary.LittleEndian.PutUint64(start, uint64(len(body)))
	binary.LittleEndian.PutUint64(start[8:], uint64(len(h)))
	binary.LittleEndian.PutUint32(start[16:], crc32.ChecksumIEEE(h))
	data := []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4}
	data = binary.LittleEndian.AppendUint32(data, crc32.ChecksumIEEE(start))
	data = append(data, start...)
	data = append(data, body...)
	return append(data, h...), members
}

func TestDefaultSubstreamsIndependentFolders(t *testing.T) {
	for _, payloads := range [][][]byte{{[]byte("A"), []byte("BC")}, {{0x9d, 0x0a, 0xd9, 0x6d}, []byte("BC"), []byte("DEF")}} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("groups=%d/empty=%t", len(payloads), empty), func(t *testing.T) {
				data, members := defaultSubstreamsArchive(payloads, empty, 0)
				z, err := sevenzip.NewReader(bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatal(err)
				}
				if len(z.File) != len(members) {
					t.Fatalf("file count: %d want %d", len(z.File), len(members))
				}
				for ordinal, want := range members {
					file := z.File[ordinal]
					if file.Name != want.name || file.UncompressedSize != uint64(len(want.payload)) || file.FileInfo().IsDir() != want.dir {
						t.Errorf("member %d name=%s size=%d directory=%t", ordinal, file.Name, file.UncompressedSize, file.FileInfo().IsDir())
					}
					rc, err := file.Open()
					if err != nil {
						t.Fatal(err)
					}
					got, readErr := io.ReadAll(rc)
					closeErr := rc.Close()
					if readErr != nil || closeErr != nil || !bytes.Equal(got, want.payload) {
						t.Errorf("member %d bytes=%x want=%x read=%v close=%v", ordinal, got, want.payload, readErr, closeErr)
					}
					if want.stream < 0 {
						continue
					}
					crc := crc32.ChecksumIEEE(want.payload)
					if file.Stream != want.stream || file.CRC32 != crc {
						t.Errorf("member %d stream=%d CRC=%08x", ordinal, file.Stream, file.CRC32)
					}
					if offset, ok := file.StreamOffset(); !ok || offset != 0 {
						t.Errorf("member %d offset=%d known=%t", ordinal, offset, ok)
					}
					layout, err := z.StreamLayout(want.stream)
					if err != nil {
						t.Errorf("layout %d: %v", want.stream, err)
						continue
					}
					if len(layout.Members) != 1 || layout.Members[0].Ordinal != ordinal || layout.Members[0].Offset != 0 || layout.Members[0].CRC != (sevenzip.CRCInfo{Defined: true, Value: crc}) {
						t.Errorf("layout %d members=%+v", want.stream, layout.Members)
					}
				}
			})
		}
	}
}

func TestDefaultSubstreamsRejectMismatchedFileCount(t *testing.T) {
	for _, extra := range []int{-1, 1} {
		data, _ := defaultSubstreamsArchive([][]byte{[]byte("A"), []byte("BC")}, false, extra)
		if _, err := sevenzip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
			t.Errorf("accepted default stream count mismatch %d", extra)
		}
	}
}
