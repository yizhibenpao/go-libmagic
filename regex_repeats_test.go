package libmagic

import (
	"reflect"
	"regexp/syntax"
	"strings"
	"testing"
)

func TestRegexRepeatsWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		pattern, data string
		start, end    int
		fold          bool
	}{
		{"A{1001}", "x" + strings.Repeat("A", 1001), 1, 1002, false},
		{"A{1001}", strings.Repeat("A", 1000), -1, -1, false},
		{"A{1000,1001}", strings.Repeat("A", 1002), 0, 1001, false},
		{"A{1001,}", strings.Repeat("A", 1002), 0, 1002, false},
		{"A{0,1001}", "AAA", 0, 3, false},
		{"A{0,1001}", "", 0, 0, false},
		{"(A{40}){40}", strings.Repeat("A", 1600), 0, 1600, false},
		{"A**", "AAAB", 0, 3, false},
		{"A++", "AAAB", 0, 3, false},
		{"A{1}{2}", "AAAB", 0, 2, false},
		{"A{2}*", "AAAAAB", 0, 4, false},
		{"A*{2}", "AAAAAB", 0, 5, false},
		{"A{,2}", "AAAB", 0, 2, false},
		{"A{,}", "AAAB", 0, 3, false},
		{"A{,0}", "AAAB", 0, 0, false},
		{"A{32767}", "AAA", -1, -1, false},
		{`(A){2}{2}\1`, "AAAAAB", 0, 5, false},
		{`((A){2}){2}\2`, "AAAAAB", 0, 5, false},
		{`(A){0}\1`, "AAA", -1, -1, false},
		{`(){1001}\1`, "AAA", 0, 0, false},
		{`\<([a-z]){2}{2}\1\>`, " AAAAAB", -1, -1, true},
		{`\<([a-z]){2}{2}\1\>`, " AAAAA ", 1, 6, true},
		{`(a){1001}\1`, strings.Repeat("A", 1002), 0, 1002, true},
		{"\xe9{1001}", strings.Repeat("\xe9", 1001), 0, 1001, false},
		{"(\xe9){2}{2}\\1", strings.Repeat("\xe9", 5), 0, 5, false},
		{`[?+*{]{2}`, "*+Z", 0, 2, false},
		{`\*{2}`, "**Z", 0, 2, false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			m := entry{}
			copy(m.value[:], tc.pattern)
			if tc.fold {
				m.strFlags = stringIgnoreLower
			}
			re := compileRule(&m)
			if re == nil {
				t.Fatal("cannot compile valid GNU repetition")
			}
			data, offsets := bytesAsRunes([]byte(tc.data))
			got := re.FindStringIndex(data)
			if got != nil {
				got = []int{byteIndex(offsets, got[0]), byteIndex(offsets, got[1])}
			}
			var want []int
			if tc.start >= 0 {
				want = []int{tc.start, tc.end}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("match %v, want %v", got, want)
			}
		})
	}
}

func TestRegexRepeatCapturesWithoutReference(t *testing.T) {
	tree, ops, err := parseRegex(`\<((A){2}){2}\2`, false)
	if err != nil {
		t.Fatal(err)
	}
	var caps []int
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		if r.Op == syntax.OpCapture {
			caps = append(caps, r.Cap)
			if strings.HasPrefix(r.Name, "magicRepeat") {
				t.Error("temporary repetition capture leaked into the tree")
			}
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(tree)
	if !reflect.DeepEqual(caps, []int{1, 2, 3, 4}) || ops[4].target != 3 || ops[1].kind != '<' {
		t.Errorf("capture numbers %v ops %v", caps, ops)
	}
	for _, pattern := range []string{"A{32768}", "A{2,1}", "A{}", "A{x}"} {
		if _, err := parseRegexRepeats(pattern); err == nil {
			t.Errorf("accepted invalid GNU count %q", pattern)
		}
	}
}

func TestRegexRepeatBackendSelection(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		program bool
		prefix  int
	}{
		{"A{1000}", false, 0},
		{"A{1001}", true, 1001},
		{"A**", false, 0},
		{"A{1}{2}", false, 0},
		{"A{,2}", false, 0},
		{"(A{40}){40}", true, 1600},
		{"A{0,1001}", true, 0},
	} {
		m := entry{}
		copy(m.value[:], tc.pattern)
		re := compileRule(&m)
		if re == nil || (re.extended != nil) != tc.program {
			t.Errorf("pattern %q: wrong repetition backend", tc.pattern)
		} else if tc.program && re.extended.prefixLen != tc.prefix {
			t.Errorf("pattern %q: literal prefix length %d, want %d", tc.pattern, re.extended.prefixLen, tc.prefix)
		}
	}
}

func TestRegexRelationsWithoutReference(t *testing.T) {
	for _, matched := range []bool{false, true} {
		v := int64(1)
		data := "BZ"
		if matched {
			v, data = 0, "AZ"
		}
		for _, unsigned := range []bool{false, true} {
			for _, op := range []byte{'=', '!', '>', '<', '&', '^', 'x'} {
				m := entry{reln: op}
				m.value[0] = 'A'
				if unsigned {
					m.flag |= flagUnsigned
				}
				m.re = compileRule(&m)
				s := &state{search: search{s: []byte(data), offset: 4, rmLen: 9}}
				if got, want := s.regexMatch(&m), s.rel(v, 0, op, unsigned); got != want {
					t.Errorf("match %v unsigned %v relation %c: %v, want %v", matched, unsigned, op, got, want)
				}
				length := 9
				if matched {
					length = 1
				}
				if s.search.offset != 4 || s.search.rmLen != length {
					t.Errorf("match %v relation %c: state offset %d length %d", matched, op, s.search.offset, s.search.rmLen)
				}
			}
		}
	}
}

func TestRegexCopyEOFWithoutReference(t *testing.T) {
	m := entry{typ: typeRegex, reln: '!'}
	s := &state{search: search{s: []byte("old"), offset: 2, rmLen: 1}}
	if s.copyValue(&m, []byte("AB"), 3, 3) || s.search.s != nil || s.search.offset != 2 || s.search.rmLen != 1 {
		t.Fatalf("past-EOF read/state: %+v", s.search)
	}
	if !s.copyValue(&m, []byte("AB"), 2, 2) || s.search.s == nil || s.search.offset != 2 || s.search.rmLen != 0 {
		t.Fatalf("EOF read/state: %+v", s.search)
	}
}
