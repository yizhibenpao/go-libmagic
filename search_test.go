package libmagic

import (
	"bytes"
	"strings"
	"testing"
)

func TestSearchRangesWithoutReference(t *testing.T) {
	for _, flags := range []uint32{0, stringBinTest, regexOffsetStart} {
		for _, limit := range []uint32{0, 1, 2, 3} {
			for _, needle := range []string{"A", "AB", "A\x00B"} {
				for pos := 0; pos <= 4; pos++ {
					data := []byte(strings.Repeat("x", pos) + needle + "Z")
					m := entry{typ: typeSearch, reln: '=', strRange: limit, strFlags: flags, vallen: byte(len(needle))}
					copy(m.value[:], needle)
					s := &state{search: search{s: data, offset: 10, rmLen: 99}}
					want := limit == 0 || pos < int(limit) || flags == 0 && pos == int(limit)
					if got := s.searchMatch(&m); got != want {
						t.Fatalf("flags %#x limit %d needle %q pos %d: %v, want %v", flags, limit, needle, pos, got, want)
					}
					off, length := 10, 99
					if want {
						off, length = 10+pos, len(data)-pos
					}
					if s.search.offset != off || s.search.rmLen != length || !bytes.Equal(s.search.s, data) {
						t.Fatalf("flags %#x limit %d pos %d: offset %d length %d, want %d/%d", flags, limit, pos, s.search.offset, s.search.rmLen, off, length)
					}
				}
			}
		}
	}
	for _, flags := range []uint32{0, stringBinTest, regexOffsetStart} {
		m := entry{typ: typeSearch, reln: 'x', strRange: 1, strFlags: flags}
		s := &state{search: search{s: []byte{}, offset: 4, rmLen: 9}}
		if !s.searchMatch(&m) || s.search.offset != 4 || s.search.rmLen != 0 {
			t.Errorf("empty EOF search flags %#x: offset %d length %d", flags, s.search.offset, s.search.rmLen)
		}
	}
}

func TestSearchRelationsWithoutReference(t *testing.T) {
	for _, flags := range []uint32{0, stringBinTest} {
		for _, unsigned := range []bool{false, true} {
			for _, data := range []string{"A", "B", "@"} {
				v := int64(data[0]) - int64('A')
				if flags == 0 && v != 0 {
					v = 1 // memmem reports missing, not the last comparison.
				}
				gt, lt := v > 0, v < 0
				if unsigned {
					gt, lt = uint64(v) > 0, false
				}
				for op, want := range map[byte]bool{'=': v == 0, '!': v != 0, '>': gt, '<': lt, '&': true, '^': false, 'x': true} {
					m := entry{typ: typeSearch, reln: op, strRange: 1, strFlags: flags, vallen: 1}
					m.value[0] = 'A'
					if unsigned {
						m.flag |= flagUnsigned
					}
					s := &state{search: search{s: []byte(data)}}
					if got := s.searchMatch(&m); got != want {
						t.Errorf("flags %#x unsigned %v data %q relation %c: %v, want %v", flags, unsigned, data, op, got, want)
					}
				}
			}
		}
	}
}

func TestSearchCopyStateWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		off, length int
		ok          bool
		text        string
		start       int
	}{
		{1, 1, true, "BCD", 1},
		{3, 2, false, "D", 3},
		{4, 1, false, "", 4},
		{9, 1, false, "", 4},
	} {
		s := &state{search: search{s: []byte("old"), offset: 20, rmLen: 3}}
		m := entry{typ: typeSearch, reln: '!', vallen: byte(tc.length)}
		if got := s.copyValue(&m, []byte("ABCD"), tc.off, tc.off); got != tc.ok || string(s.search.s) != tc.text || s.search.offset != tc.start || s.search.rmLen != 3 {
			t.Errorf("offset %d length %d: copied %v region %q offset %d rm_len %d", tc.off, tc.length, got, s.search.s, s.search.offset, s.search.rmLen)
		}
	}
}

func TestSearchWhitespaceWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		pattern, data string
		flags         uint32
		want          int
	}{
		{"A B", "A   B", stringCompactWhitespace, 0},
		{"A B", "ABZ", stringCompactWhitespace, 1},
		{"A  B", "A   B", stringCompactWhitespace, 0},
		{"A  B", "A BZZ", stringCompactWhitespace, 1},
		{"A B", "ABZ", stringCompactOptionalWhitespace, 0},
		{"A B", "AB\x00Z", stringCompactOptionalWhitespace | stringFullWord, 0},
		{"A B", "ABZ", stringCompactWhitespace | stringCompactOptionalWhitespace, 1},
		{"A", "A\x00Z", stringFullWord, 0},
		{"A", "A!Z", stringFullWord, 1},
	} {
		if got := fileStrncmp([]byte(tc.pattern), []byte(tc.data), len(tc.pattern), tc.flags); got != tc.want {
			t.Errorf("pattern %q data %q flags %#x: %d, want %d", tc.pattern, tc.data, tc.flags, got, tc.want)
		}
	}
}

func TestSearchPublishedRules(t *testing.T) {
	plain, flagged, zero := 0, 0, 0
	for _, set := range testDB(t).sets {
		for _, m := range set.rules {
			if m.typ != typeSearch {
				continue
			}
			if m.strFlags == 0 {
				plain++
			} else {
				flagged++
			}
			if m.strRange == 0 {
				zero++
			}
		}
	}
	t.Logf("published search rules: %d plain, %d flagged, %d zero-range", plain, flagged, zero)
}

func FuzzSearch(f *testing.F) {
	for _, seed := range []struct{ data, needle string }{{"", ""}, {"xAZ", "A"}, {"A   BZ", "A B"}, {"A\x00BZ", "A\x00B"}} {
		f.Add([]byte(seed.data), []byte(seed.needle), uint32(2), uint8(0))
	}
	f.Fuzz(func(t *testing.T, data, needle []byte, limit uint32, kind uint8) {
		flags := []uint32{0, stringBinTest, stringIgnoreLower, stringFullWord, stringCompactWhitespace, stringCompactOptionalWhitespace}[kind%6]
		m := entry{typ: typeSearch, reln: '=', strRange: limit, strFlags: flags}
		m.vallen = byte(copy(m.value[:], needle))
		s := &state{}
		if s.copyValue(&m, data, 0, 0) {
			s.searchMatch(&m)
			if s.search.offset < 0 || s.search.offset > len(data) || s.search.rmLen < 0 || s.search.rmLen > len(data) {
				t.Fatalf("bad search state: offset %d length %d data length %d", s.search.offset, s.search.rmLen, len(data))
			}
		}
	})
}
