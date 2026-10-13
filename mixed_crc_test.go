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

type mixedCRCGroup struct {
	members       int
	defined, zero bool
}

// Two independently encoded CRC tables: folder digests and compact substream
// digests. A single-file folder with a declared digest consumes no compact slot.
// Payloads and Copy coders make the expected bytes independent of any codec.
func mixedCRCArchive(groups []mixedCRCGroup, absent bool, shortNames bool) ([]byte, [][]byte, []sevenzip.CRCInfo) {
	var body []byte
	var files [][]byte
	var want []sevenzip.CRCInfo
	var groupData [][]byte
	var groupBits, memberBits []bool
	var groupValues, memberValues []uint32
	for _, group := range groups {
		var packed []byte
		for i := 0; i < group.members; i++ {
			payload := []byte{byte(65 + len(files))}
			if group.zero && group.members == 1 {
				payload = []byte{0x9d, 0x0a, 0xd9, 0x6d}
			}
			checksum := crc32.ChecksumIEEE(payload)
			present := !absent || len(files)%3 != 1
			if group.members == 1 && group.defined {
				present = true
			} else {
				memberBits = append(memberBits, present)
				memberValues = append(memberValues, checksum)
			}
			crc := sevenzip.CRCInfo{}
			if present {
				crc = sevenzip.CRCInfo{Defined: true, Value: checksum}
			}
			want = append(want, crc)
			files = append(files, payload)
			packed = append(packed, payload...)
		}
		groupData = append(groupData, packed)
		groupBits = append(groupBits, group.defined)
		groupValues = append(groupValues, crc32.ChecksumIEEE(packed))
		body = append(body, packed...)
	}
	h := []byte{1, 4, 6, 0, byte(len(groups)), 9}
	for _, data := range groupData {
		h = append(h, layoutUint(uint64(len(data)))...)
	}
	h = append(h, 0, 7, 11, byte(len(groups)), 0)
	for range groups {
		h = append(h, 1, 1, 0)
	}
	h = append(h, 12)
	for _, data := range groupData {
		h = append(h, layoutUint(uint64(len(data)))...)
	}
	h = append(h, 10)
	h = append(h, layoutCRC(groupBits, groupValues)...)
	h = append(h, 0, 8, 13)
	for _, g := range groups {
		h = append(h, layoutUint(uint64(g.members))...)
	}
	h = append(h, 9)
	file := 0
	for _, g := range groups {
		for i := 0; i < g.members-1; i++ {
			h = append(h, layoutUint(uint64(len(files[file+i])))...)
		}
		file += g.members
	}
	if len(memberBits) > 0 {
		h = append(h, 10)
		h = append(h, layoutCRC(memberBits, memberValues)...)
	}
	h = append(h, 0, 0, 5)
	h = append(h, layoutUint(uint64(len(files)))...)
	h = append(h, 17)
	names := []byte{0}
	for i := range files {
		name := fmt.Sprintf("member-%02d.bin", i)
		if shortNames {
			name = string(rune('a' + i))
		}
		for _, ch := range name {
			names = append(names, byte(ch), 0)
		}
		names = append(names, 0, 0)
	}
	h = append(h, layoutUint(uint64(len(names)))...)
	h = append(h, names...)
	h = append(h, 0, 0)
	start := make([]byte, 20)
	binary.LittleEndian.PutUint64(start, uint64(len(body)))
	binary.LittleEndian.PutUint64(start[8:], uint64(len(h)))
	binary.LittleEndian.PutUint32(start[16:], crc32.ChecksumIEEE(h))
	data := []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(data[8:], crc32.ChecksumIEEE(start))
	data = append(data, start...)
	data = append(data, body...)
	data = append(data, h...)
	return data, files, want
}

func TestMixedFolderCRCDigests(t *testing.T) {
	for _, count := range []int{1, 7, 8, 9, 16} {
		for _, last := range []bool{false, true} {
			for _, absent := range []bool{false, true} {
				for _, short := range []bool{false, true} {
					name := fmt.Sprintf("explicit=%d/inherited_last=%t/absent=%t/short_names=%t", count, last, absent, short)
					t.Run(name, func(t *testing.T) {
						inherited := mixedCRCGroup{members: 1, defined: true}
						explicit := mixedCRCGroup{members: count}
						groups := []mixedCRCGroup{inherited, explicit}
						if last {
							groups[0], groups[1] = groups[1], groups[0]
						}
						testMixedCRCRead(t, groups, absent, short)
					})
				}
			}
		}
	}
	t.Run("declared_zero_inherited", func(t *testing.T) {
		testMixedCRCRead(t, []mixedCRCGroup{{1, true, true}, {8, false, false}}, false, false)
	})
	t.Run("inherited_both_sides", func(t *testing.T) {
		testMixedCRCRead(t, []mixedCRCGroup{{1, true, false}, {8, true, false}, {1, true, true}}, true, false)
	})
	t.Run("all_inherited", func(t *testing.T) {
		testMixedCRCRead(t, []mixedCRCGroup{{1, true, false}, {1, true, true}}, false, false)
	})
}

func testMixedCRCRead(t *testing.T, groups []mixedCRCGroup, absent, short bool) {
	t.Helper()
	data, files, want := mixedCRCArchive(groups, absent, short)
	z, err := sevenzip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != len(files) {
		t.Fatalf("file count %d want%d", len(z.File), len(files))
	}
	for i, file := range z.File {
		if got := file.Checksum(); got != want[i] {
			t.Errorf("file%d checksum=%+v want=%+v", i, got, want[i])
		}
		if file.CRC32 != want[i].Value {
			t.Errorf("file%d CRC=%08x want=%08x", i, file.CRC32, want[i].Value)
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(got, files[i]) {
			t.Fatalf("file%d bytes=%x want=%x read=%v close=%v", i, got, files[i], readErr, closeErr)
		}
	}
	offset := 0
	for i, g := range groups {
		layout, err := z.StreamLayout(i)
		if err != nil {
			t.Fatal(err)
		}
		if len(layout.Members) != g.members {
			t.Fatalf("group%d member count", i)
		}
		for j, m := range layout.Members {
			if m.CRC != want[offset+j] {
				t.Errorf("group%d member%d CRC=%+v want=%+v", i, j, m.CRC, want[offset+j])
			}
		}
		offset += g.members
	}
}

func TestMixedFolderCRCStillRejectsCorruptGroup(t *testing.T) {
	data, _, _ := mixedCRCArchive([]mixedCRCGroup{{1, true, false}, {8, false, false}}, false, false)
	data[32] ^= 1
	z, err := sevenzip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := z.OpenStream(0)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err = io.ReadAll(rc); err == nil {
		t.Fatal("corrupt group accepted")
	}
}
