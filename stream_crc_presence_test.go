package sevenzip_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/bodgit/sevenzip"
)

func TestStreamDeclaredZeroGroupCRC(t *testing.T) {
	for _, defined := range []bool{false, true} {
		for _, corrupt := range []bool{false, true} {
			t.Run(fmt.Sprintf("defined=%t/corrupt=%t", defined, corrupt), func(t *testing.T) {
				data := layoutArchive(t, []byte{0}, nil, 4, &sevenzip.CRCInfo{Defined: defined}, []bool{false, false}, []uint32{0, 0})
				copy(data[32:36], []byte{0x9d, 0x0a, 0xd9, 0x6d}) // IEEE CRC zero.
				if corrupt {
					data[32] ^= 1
				}
				z := layoutReader(t, data)
				for _, f := range z.File {
					if f.Checksum().Defined {
						t.Fatal("test requires absent member checksums")
					}
				}
				r, err := z.OpenStream(0)
				if err != nil {
					t.Fatal(err)
				}
				got, readErr := io.ReadAll(r)
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				if defined && corrupt {
					if readErr == nil {
						t.Fatal("declared zero group CRC was not checked")
					}
				} else if readErr != nil || !bytes.Equal(got, data[32:36]) {
					t.Fatalf("valid group read=%v bytes=%x", readErr, got)
				}
			})
		}
	}
}
