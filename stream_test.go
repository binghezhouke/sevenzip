package sevenzip_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/bodgit/sevenzip"
)

func TestStreamMatchesMembers(t *testing.T) {
	for _, fixture := range []string{"lzma2.7z", "bcj2.7z", "copy.7z", "empty.7z", "file_and_empty.7z", "t2.7z", "t3.7z", "t4.7z", "t5.7z"} {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + fixture)
			if err != nil {
				t.Fatal(err)
			}
			z, err := sevenzip.NewReaderWithPassword(bytes.NewReader(data), int64(len(data)), "password")
			if err != nil {
				t.Fatal(err)
			}
			streams := z.Streams()
			for _, info := range streams {
				r, err := z.OpenStream(info.Index)
				if err != nil {
					t.Fatal(err)
				}
				plain, err := io.ReadAll(r)
				if err != nil {
					t.Fatal(err)
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				if uint64(len(plain)) != info.UncompressedSize {
					t.Fatal("stream size mismatch")
				}
				for _, f := range z.File {
					offset, ok := f.StreamOffset()
					if !ok || f.Stream != info.Index {
						continue
					}
					member, err := f.Open()
					if err != nil {
						t.Fatal(err)
					}
					want, err := io.ReadAll(member)
					if err != nil {
						t.Fatal(err)
					}
					if err := member.Close(); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(plain[offset:offset+int64(f.UncompressedSize)], want) {
						t.Fatalf("stream differs for %s", f.Name)
					}
				}
			}
			for _, index := range []int{-1, len(streams)} {
				if _, err := z.OpenStream(index); !errors.Is(err, os.ErrInvalid) {
					t.Fatalf("invalid stream: %v", err)
				}
			}
		})
	}
}
