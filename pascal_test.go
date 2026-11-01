package libmagic

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPascalLengthsWithoutReference(t *testing.T) {
	for _, p := range []struct {
		flags uint32
		size  int
		order binary.ByteOrder
	}{
		{pstring1BE, 1, binary.BigEndian},
		{pstring2BE, 2, binary.BigEndian},
		{pstring2LE, 2, binary.LittleEndian},
		{pstring4BE, 4, binary.BigEndian},
		{pstring4LE, 4, binary.LittleEndian},
	} {
		for _, n := range []uint64{0, uint64(p.size - 1), uint64(p.size), 255, 1<<uint(p.size*8) - 1} {
			raw := make([]byte, p.size)
			switch p.size {
			case 1:
				raw[0] = byte(n)
			case 2:
				p.order.PutUint16(raw, uint16(n))
			case 4:
				p.order.PutUint32(raw, uint32(n))
			}
			for _, includes := range []bool{false, true} {
				flags, want := p.flags, n
				if includes {
					flags |= pstringLenIncludesItself
					want -= uint64(p.size)
				}
				got, ok := pascalLength(flags, raw)
				if got != want || ok != (want != ^uint64(0)) {
					t.Errorf("flags %#x length %d: %d/%v, want %d/%v", flags, n, got, ok, want, want != ^uint64(0))
				}
			}
		}
	}
}

func TestPascalValuesWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint32
		data  []byte
		n     int
		text  string
		ok    bool
	}{
		{"long-byte", pstring1BE, append([]byte{255}, bytes.Repeat([]byte{'A'}, 200)...), 127, strings.Repeat("A", 127), true},
		{"long-short", pstring2BE, append([]byte{255, 255}, bytes.Repeat([]byte{'A'}, 200)...), 126, strings.Repeat("A", 126), true},
		{"long-long", pstring4LE, append([]byte{255, 255, 255, 255}, bytes.Repeat([]byte{'A'}, 200)...), 124, strings.Repeat("A", 124), true},
		{"short-body", pstring1BE, []byte{5, 'A', 'B'}, 5, "AB", true},
		{"short-prefix", pstring4BE, []byte{1}, 124, "", true},
		{"missing-prefix", pstring2BE, nil, 0, "", true},
		{"missing-wrap", pstring2BE | pstringLenIncludesItself, nil, 126, "", true},
		{"missing-badsize", pstring1BE | pstringLenIncludesItself, nil, 0, "", false},
		{"NUL", pstring1BE, []byte{6, 'A', 'B', 0, 'X', 'Y', 'Z'}, 6, "AB", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &state{}
			m := entry{typ: typePString, reln: 'x', strFlags: tc.flags}
			if got := s.copyValue(&m, tc.data, 0, 0); got != tc.ok {
				t.Fatalf("copied %v, want %v", got, tc.ok)
			}
			if tc.ok && (s.value.n != tc.n || s.value.text != tc.text || s.value.raw[tc.n] != 0) {
				t.Errorf("length %d text %q terminator %#x, want %d/%q/0", s.value.n, s.value.text, s.value.raw[tc.n], tc.n, tc.text)
			}
		})
	}
	s := &state{}
	m := entry{typ: typePString, reln: 'x', strFlags: pstring2BE}
	if !s.copyValue(&m, []byte{0, 1, 'A', 'B', 'C'}, 0, 0) {
		t.Fatal("cannot read one-byte body")
	}
	if want := []byte{'A', 0, 'A', 'B', 'C'}; !bytes.Equal(s.value.raw[:len(want)], want) {
		t.Errorf("shifted value %v, want %v (only the terminator is overwritten)", s.value.raw[:len(want)], want)
	}
}

func TestPascalPublishedRules(t *testing.T) {
	counts := make(map[uint32]int)
	for _, set := range testDB(t).sets {
		for _, m := range set.rules {
			if m.typ == typePString {
				counts[m.strFlags&(pstringLen|pstringLenIncludesItself)]++
			}
		}
	}
	t.Logf("published Pascal rules by length flags: %v", counts)
}

func TestPrintableBufferWithoutReference(t *testing.T) {
	for _, tc := range []struct{ data, want string }{
		{strings.Repeat("A", 600), strings.Repeat("A", 511)},
		{strings.Repeat("\xff", 128), strings.Repeat("\\377", 127)},
		{strings.Repeat("A", 507) + "\xff", strings.Repeat("A", 507) + "\\377"},
		{strings.Repeat("A", 508) + "\xff", strings.Repeat("A", 508)},
		{"A\x00B", "A"},
	} {
		if got := printable(tc.data); got != tc.want {
			t.Errorf("input length %d: got %q, want %q", len(tc.data), got, tc.want)
		}
	}
	s := &state{}
	m := entry{typ: typeString, reln: 'x'}
	if !s.copyValue(&m, bytes.Repeat([]byte{'A'}, 200), 0, 0) || cString(s.value.raw[:]) != strings.Repeat("A", 127) {
		t.Fatal("string conversion must terminate byte 127")
	}
	if !s.copyValue(&m, []byte{'A', 0, 'B', 'C'}, 0, 0) || s.value.raw[2] != 'B' {
		t.Fatal("embedded NUL must not erase following comparison bytes")
	}
}

func FuzzPascal(f *testing.F) {
	for _, data := range [][]byte{nil, {255, 'A'}, {0, 1, 'A', 'B'}, {255, 255, 255, 255}, {0, 0, 0, 3, 'A', 0, 'B'}} {
		f.Add(data, uint8(0), false)
		f.Add(data, uint8(3), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, kind uint8, includes bool) {
		flags := []uint32{pstring1BE, pstring2BE, pstring2LE, pstring4BE, pstring4LE}[kind%5]
		if includes {
			flags |= pstringLenIncludesItself
		}
		s := &state{}
		if s.copyValue(&entry{typ: typePString, reln: 'x', strFlags: flags}, data, 0, 0) {
			size, _ := pascalLengthSize(flags)
			if s.value.n > maxString-size || s.value.raw[s.value.n] != 0 || s.value.text != cString(s.value.raw[:s.value.n]) {
				t.Fatalf("bad Pascal value: length %d, flags %#x, text %q", s.value.n, flags, s.value.text)
			}
		}
	})
}
