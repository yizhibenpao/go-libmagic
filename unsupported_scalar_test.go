package libmagic

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestUnsupportedScalarWithoutReference(t *testing.T) {
	data := []byte{0x81, 2, 3, 4}
	for _, typ := range []uint8{typeBEID3, typeLEID3, typeBEVarint, typeLEVarint} {
		for _, off := range []int{0, len(data), len(data) + 5} {
			s := state{line: 17, buf: &strings.Builder{}}
			s.buf.WriteString("root")
			m := entry{typ: typ, reln: 'x', lineno: 99}
			got := s.copyValue(&m, data, off, off)
			want := fmt.Sprintf("line 17: invalid type %d in mconvert()", typ)
			var raw [maxString]byte
			if off < len(data) {
				copy(raw[:], data[off:])
			}
			if got || s.err == nil || s.err.Error() != want || !bytes.Equal(s.value.raw[:], raw[:]) {
				t.Fatalf("type %d offset %d: result/error/raw = %v/%v/%x", typ, off, got, s.err, s.value.raw)
			}
		}
	}
}

func TestMagicErrorLineWithoutReference(t *testing.T) {
	for _, line := range []uint32{0, 73} {
		for _, prefix := range []string{"", "root"} {
			s := state{line: line, buf: &strings.Builder{}}
			s.buf.WriteString(prefix)
			s.magerror("invalid conversion")
			want := "invalid conversion"
			if line != 0 {
				want = fmt.Sprintf("line %d: %s", line, want)
			} else if prefix != "" {
				want = prefix + " " + want
			}
			if s.err == nil || s.err.Error() != want {
				t.Fatalf("line %d prefix %q: error = %v, want %q", line, prefix, s.err, want)
			}
		}
	}
}

func TestUnsupportedScalarPointerWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeBEID3, typeLEID3, typeBEVarint, typeLEVarint} {
		for _, target := range []uint32{0, 4, 30} {
			data := make([]byte, 4)
			binary.LittleEndian.PutUint32(data, target)
			m := entry{typ: typ, flag: flagIndir, inType: typeLELong, reln: 'x'}
			s := state{line: 21, buf: &strings.Builder{}}
			indir := 0
			got := s.mget(&m, data, data, 0, 1, flagBinTest, &indir, 0)
			want := fmt.Sprintf("line 21: invalid type %d in mconvert()", typ)
			if got || s.err == nil || s.err.Error() != want {
				t.Fatalf("type %d target %d: result/error = %v/%v, want %q", typ, target, got, s.err, want)
			}
		}
		m := entry{typ: typ, flag: flagIndir, inType: typeLELong, reln: 'x'}
		s := state{offset: 30, line: 21, buf: &strings.Builder{}}
		indir := 0
		if s.mget(&m, nil, nil, 0, 1, flagBinTest, &indir, 0) || s.err != nil {
			t.Fatalf("type %d invalid pointer: error = %v", typ, s.err)
		}
	}
}
