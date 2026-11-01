package libmagic

import (
	"strings"
	"testing"
)

func TestString16FlagsWithoutReference(t *testing.T) {
	pairs := []struct{ pattern, actual string }{
		{"", "AB"},
		{"ab", "AB"},
		{"AB", "ab"},
		{"A B", "A  B"},
		{"A B", "AB"},
		{"AB", "ABC"},
		{"A\x00B", "A\x00C"},
		{"\xfe", "\x01"},
	}
	relations := []byte{'=', '!', '<', '>', '&', '^', 'x'}
	for _, typ := range []uint8{typeLEStr16, typeBEStr16} {
		for _, pair := range pairs {
			var raw [maxString]byte
			copy(raw[:], pair.actual)
			difference := 0
			for i := range pair.pattern {
				if raw[i] != pair.pattern[i] {
					difference = int(raw[i]) - int(pair.pattern[i])
					break
				}
			}
			want := []bool{difference == 0, difference != 0, difference < 0, difference > 0, true, false, true}
			for flags := uint32(0); flags < 1<<15; flags++ {
				m := entry{typ: typ, vallen: uint8(len(pair.pattern)), strFlags: flags}
				copy(m.value[:], pair.pattern)
				s := state{value: value{raw: raw}}
				for i, relation := range relations {
					m.reln = relation
					if got := s.check(&m); got != want[i] || m.strFlags != flags {
						t.Fatalf("type %d flags %#x pattern %q actual %q relation %c: match %v, want %v; stored flags %#x", typ, flags, pair.pattern, pair.actual, relation, got, want[i], m.strFlags)
					}
				}
			}
		}
	}
}

func TestString16OtherFlagConsumersWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeLEStr16, typeBEStr16} {
		m := entry{typ: typ, reln: 'x', strFlags: stringTrim | stringTextTest | stringIgnoreLower, desc: "[%s]"}
		s := state{value: value{text: " AB \t", n: maxString}, buf: &strings.Builder{}}
		copy(s.value.raw[:], s.value.text)
		if !s.check(&m) || !skipByMode(&m, false, flagBinTest) || m.strFlags != stringTrim|stringTextTest|stringIgnoreLower {
			t.Fatal("comparison changed stored mode/output flags")
		}
		if !s.print(&m, false) || s.buf.String() != "[AB]" {
			t.Fatalf("type %d: trimmed output %q", typ, s.buf.String())
		}
	}
	for _, typ := range []uint8{typeString, typePString} {
		for _, tc := range []struct {
			flag    uint32
			pattern string
			actual  string
		}{
			{stringIgnoreLower, "ab", "AB"},
			{stringIgnoreUpper, "AB", "ab"},
			{stringCompactWhitespace, "A B", "A  B"},
			{stringCompactOptionalWhitespace, "A B", "AB"},
		} {
			m := entry{typ: typ, reln: '=', vallen: uint8(len(tc.pattern)), strFlags: tc.flag}
			copy(m.value[:], tc.pattern)
			s := state{}
			copy(s.value.raw[:], tc.actual)
			if !s.check(&m) {
				t.Fatalf("ordinary string type %d lost modifier %#x", typ, tc.flag)
			}
		}
	}
}
