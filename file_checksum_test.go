package sevenzip_test

import (
	"bytes"
	"testing"

	"github.com/bodgit/sevenzip"
)

func TestFileChecksumUsesParsedMetadata(t *testing.T) {
	data, _, want := mixedCRCArchive([]mixedCRCGroup{{members: 2, defined: true}, {members: 1, defined: true, zero: true}}, true, true)
	source := &layoutCountingSource{ReaderAt: bytes.NewReader(data)}
	z, err := sevenzip.NewReader(source, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	source.reads = 0
	for i, file := range z.File {
		if got := file.Checksum(); got != want[i] {
			t.Fatalf("member%d checksum=%+v want=%+v", i, got, want[i])
		}
		// Returned values are copies and never alias public mutable headers.
		copied := file.Checksum()
		copied.Value++
		file.CRC32++
		if got := file.Checksum(); got != want[i] {
			t.Fatalf("member%d parsed checksum changed: %+v", i, got)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() {
		for i, file := range z.File {
			if file.Checksum() != want[i] {
				t.Fatal("parsed checksum changed")
			}
		}
	}); allocs != 0 {
		t.Errorf("checksum query allocates %g times", allocs)
	}
	if source.reads != 0 {
		t.Errorf("checksum queries performed %d source reads", source.reads)
	}
	var absent *sevenzip.File
	if absent.Checksum() != (sevenzip.CRCInfo{}) || new(sevenzip.File).Checksum() != (sevenzip.CRCInfo{}) {
		t.Fatal("unparsed files must not declare a checksum")
	}
}
