package libmagic

import (
	"bytes"
	"strings"
	"testing"
)

func TestString16UnionWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint8
		data []byte
		want []byte
	}{
		{"little embedded NUL", typeLEStr16, []byte{'A', 0, 0, 0, 'B', 0}, []byte{'A', 0, 'B'}},
		{"big embedded NUL", typeBEStr16, []byte{0, 'A', 0, 0, 0, 'B'}, []byte{'A', 0, 'B'}},
		{"little nonzero high byte", typeLEStr16, []byte{0, 1}, []byte{' '}},
		{"big nonzero high byte", typeBEStr16, []byte{1, 0}, []byte{' '}},
		{"little odd input", typeLEStr16, []byte{'Z'}, []byte{'Z'}},
		{"big odd input", typeBEStr16, []byte{'Z'}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &state{}
			copy(s.value.raw[:], bytes.Repeat([]byte{'X'}, maxString))
			s.copyRaw(tc.typ, tc.data, 0, false)
			want := bytes.Repeat([]byte{'X'}, maxString)
			copy(want, tc.want)
			want[maxString-1] = 0
			if !bytes.Equal(s.value.raw[:], want) || s.value.n != maxString {
				t.Fatalf("union = %x/%d, want %x/%d", s.value.raw, s.value.n, want, maxString)
			}
			s.copyRaw(tc.typ, tc.data, len(tc.data), false)
			if s.value.raw != [maxString]byte{} {
				t.Fatal("copy at EOF retained the old union")
			}
		})
	}
	for _, typ := range []uint8{typeLEStr16, typeBEStr16} {
		s := &state{}
		s.copyRaw(typ, bytes.Repeat([]byte{'Z'}, 2*maxString), 0, false)
		if !bytes.Equal(s.value.raw[:maxString-1], bytes.Repeat([]byte{'Z'}, maxString-1)) || s.value.raw[maxString-1] != 0 {
			t.Fatal("16-bit string did not terminate byte 127")
		}
	}
}

func TestNumericUnionWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		typ  uint8
		data []byte
		mask uint64
		want []byte
	}{
		{typeByte, []byte{'A', 'B', 'C'}, 1, []byte{'B', 'B', 'C'}},
		{typeBEShort, []byte{'P', 'Q', 'R', 'S'}, 0, []byte{'Q', 'P', 'R', 'S'}},
		{typeBELong, []byte{'P', 'Q', 'R', 'S', 'T'}, 0, []byte{'S', 'R', 'Q', 'P', 'T'}},
		{typeBEQuad, []byte("PQRSTUVW"), 0, []byte("WVUTSRQP")},
		{typeBEFloat, []byte{0x40, 0x40, 0, 0, 'T'}, 2, []byte{0, 0, 0xa0, 0x40, 'T'}},
		{typeBEDouble, []byte{0x40, 8, 0, 0, 0, 0, 0, 0, 'T'}, 2, []byte{0, 0, 0, 0, 0, 0, 0x14, 0x40, 'T'}},
	} {
		s := &state{}
		m := &entry{typ: tc.typ, maskOp: opAdd, numMask: tc.mask, reln: 'x'}
		if !s.copyValue(m, tc.data, 0, 0) {
			t.Fatalf("type %d copy failed", tc.typ)
		}
		var want [maxString]byte
		copy(want[:], tc.want)
		if s.value.raw != want {
			t.Errorf("type %d union = %x, want %x", tc.typ, s.value.raw, want)
		}
	}
}

func TestSearchRegionPreservesUnionWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeSearch, typeRegex, typeDER} {
		s := &state{}
		s.copyRaw(typeString, []byte("prior"), 0, false)
		previous := s.value
		s.copyRaw(typ, []byte("next"), 0, false)
		if s.value != previous {
			t.Errorf("type %d changed union when copying its search region", typ)
		}
		s.copyRaw(typ, []byte("next"), 0, true)
		if string(s.value.raw[:4]) != "next" {
			t.Errorf("type %d indirect pointer did not copy the raw union", typ)
		}
	}
}

func TestStringOutputMutatesUnionWithoutReference(t *testing.T) {
	for _, print := range []bool{false, true} {
		s := &state{buf: &strings.Builder{}}
		m := &entry{typ: typeString, reln: 'x', desc: "[%s]"}
		if !s.copyValue(m, []byte("P\rQ\x00"), 0, 0) {
			t.Fatal("string copy failed")
		}
		if print {
			s.print(m, false)
			if s.buf.String() != "[P]" {
				t.Fatalf("print = %q", s.buf.String())
			}
		} else if off, ok := s.moffset(m, 4); !ok || off != 1 {
			t.Fatalf("moffset = %d/%v", off, ok)
		}
		if !bytes.Equal(s.value.raw[:4], []byte{'P', 0, 'Q', 0}) {
			t.Errorf("print %v did not write the CR terminator into the union", print)
		}
	}
}

func TestStringTrimUnionWithoutReference(t *testing.T) {
	s := &state{buf: &strings.Builder{}}
	m := &entry{typ: typeString, strFlags: stringTrim, reln: 'x', desc: "[%s]"}
	if !s.copyValue(m, []byte("  P Q \t\x00"), 0, 0) {
		t.Fatal("string copy failed")
	}
	s.print(m, false)
	if s.buf.String() != "[P Q]" || !bytes.Equal(s.value.raw[:8], []byte("  P Q\x00\t\x00")) {
		t.Fatalf("trim = %q, union %x", s.buf.String(), s.value.raw[:8])
	}
}
