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

// Only body reads go through the injected source; metadata remains independent.
func TestPackedRangesAndInjectedBody(t *testing.T) {
	for _, fixture := range []string{"lzma2.7z", "bcj2.7z", "copy.7z", "t2.7z"} {
		for _, prefix := range []int{0, 123} {
			t.Run(fixture+string(rune('A'+prefix)), func(t *testing.T) {
				data, err := os.ReadFile("testdata/" + fixture)
				if err != nil {
					t.Fatal(err)
				}
				data = append(bytes.Repeat([]byte{0}, prefix), data...)
				z, err := sevenzip.NewReaderWithPassword(bytes.NewReader(data), int64(len(data)), "password")
				if err != nil {
					t.Fatal(err)
				}
				for _, info := range z.Streams() {
					ranges, err := z.PackedRanges(info.Index)
					if err != nil {
						t.Fatal(err)
					}
					source := &packedOnlyReader{t: t, r: bytes.NewReader(data), ranges: ranges}
					actual, err := z.OpenStreamWithReader(info.Index, source)
					if err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(actual)
					if err != nil {
						t.Fatal(err)
					}
					actual.Close()
					expected, err := z.OpenStream(info.Index)
					if err != nil {
						t.Fatal(err)
					}
					want, err := io.ReadAll(expected)
					if err != nil {
						t.Fatal(err)
					}
					expected.Close()
					if !bytes.Equal(got, want) {
						t.Fatal("injected decoder differs")
					}
					if len(ranges) > 0 {
						ranges[0].Offset = -1
						fresh, _ := z.PackedRanges(info.Index)
						if fresh[0].Offset < 0 {
							t.Fatal("snapshot mutated reader")
						}
					}
				}
				if _, err := z.PackedRanges(-1); !errors.Is(err, os.ErrInvalid) {
					t.Fatal(err)
				}
				if _, err := z.OpenStreamWithReader(0, nil); !errors.Is(err, os.ErrInvalid) {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestStoredStreamMetadata(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		stored bool
	}{
		{"copy.7z", true},
		{"lzma2.7z", false},
		{"bcj2.7z", false},
		{"t2.7z", false},
		{"delta_copy_equal_sizes.7z", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + fixture.name)
			if err != nil {
				t.Fatal(err)
			}
			z, err := sevenzip.NewReaderWithPassword(bytes.NewReader(data), int64(len(data)), "password")
			if err != nil {
				t.Fatal(err)
			}
			streams := z.Streams()
			if len(streams) == 0 {
				t.Fatal("fixture has no streams")
			}
			for _, stream := range streams {
				if stream.Stored != fixture.stored {
					t.Fatalf("stream %d Stored = %v, want %v", stream.Index, stream.Stored, fixture.stored)
				}
				if !stream.Stored && fixture.name != "delta_copy_equal_sizes.7z" {
					continue
				}
				ranges, err := z.PackedRanges(stream.Index)
				if err != nil || len(ranges) != 1 || uint64(ranges[0].Size) != stream.UncompressedSize {
					t.Fatalf("equal-size stream ranges = %+v, %v", ranges, err)
				}
				r, err := z.OpenStream(stream.Index)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					t.Fatal(err)
				}
				packed := data[ranges[0].Offset : ranges[0].Offset+ranges[0].Size]
				if stream.Stored && !bytes.Equal(packed, decoded) {
					t.Fatal("stored stream packed bytes differ from decoded content")
				}
				if fixture.name == "delta_copy_equal_sizes.7z" {
					want := bytes.Repeat([]byte("AAAA-sevenzip-delta-noncopy\n"), 40)
					if !bytes.Equal(decoded, want) || bytes.Equal(packed, want) {
						t.Fatal("Delta+Copy fixture must decode to golden bytes while its equal-size packed bytes differ")
					}
				}
			}
		})
	}
}

type packedOnlyReader struct {
	t      *testing.T
	r      io.ReaderAt
	ranges []sevenzip.PackedRange
}

func (r *packedOnlyReader) ReadAt(p []byte, off int64) (int, error) {
	for _, v := range r.ranges {
		if off >= v.Offset && off+int64(len(p)) <= v.Offset+v.Size {
			return r.r.ReadAt(p, off)
		}
	}
	r.t.Errorf("body read outside packed intervals: %d + %d", off, len(p))
	return 0, io.ErrUnexpectedEOF
}
