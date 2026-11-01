package libmagic

import "testing"

func TestRegexASCIIClassesWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		match   func(byte) bool
	}{
		{"a", func(c byte) bool { return c == 'a' || c == 'A' }},
		{"[a]", func(c byte) bool { return c == 'a' || c == 'A' }},
		{"[^a]", func(c byte) bool { return c != 'a' && c != 'A' && c != '\n' }},
		{"[a-c]", func(c byte) bool { return c >= 'a' && c <= 'c' || c >= 'A' && c <= 'C' }},
		{"[^a-c]", func(c byte) bool { return !(c >= 'a' && c <= 'c' || c >= 'A' && c <= 'C' || c == '\n') }},
		{"\xe9", func(c byte) bool { return c == 0xe9 }},
		{"[\xe9]", func(c byte) bool { return c == 0xe9 }},
		{"[^\xe9]", func(c byte) bool { return c != 0xe9 && c != '\n' }},
		{"[a\xe9]", func(c byte) bool { return c == 'a' || c == 'A' || c == 0xe9 }},
		{"[^a\xe9]", func(c byte) bool { return c != 'a' && c != 'A' && c != 0xe9 && c != '\n' }},
		{"[A-\xff]", func(c byte) bool { return c >= 'A' }},
		{"[]a]", func(c byte) bool { return c == ']' || c == 'a' || c == 'A' }},
		{"[[:upper:]]", func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }},
		{"[[:space:]]", func(c byte) bool { return c == ' ' || c >= '\t' && c <= '\r' }},
		{`[\s]`, func(c byte) bool { return c == '\\' || c == 's' || c == 'S' }},
		{`[^\s]`, func(c byte) bool { return c != '\\' && c != 's' && c != 'S' && c != '\n' }},
		{`[[.a.]]`, func(c byte) bool { return c == 'a' || c == 'A' }},
		{`[[=a=]]`, func(c byte) bool { return c == 'a' || c == 'A' }},
		{`[[:space:]\]`, func(c byte) bool { return c == '\\' || c == ' ' || c >= '\t' && c <= '\r' }},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			m := entry{reln: '=', strFlags: stringIgnoreLower}
			copy(m.value[:], tc.pattern)
			m.re = compileRule(&m)
			if m.re == nil {
				t.Fatal("cannot compile pattern")
			}
			for c := 0; c < 256; c++ {
				s := &state{search: search{s: []byte{byte(c), 'Z'}, offset: 4}}
				want := c != 0 && tc.match(byte(c))
				if got := s.regexMatch(&m); got != want {
					t.Errorf("byte %#02x: match %v, want %v", c, got, want)
				}
				if want && (s.search.offset != 4 || s.search.rmLen != 1) {
					t.Errorf("byte %#02x: offset %d length %d, want 4/1", c, s.search.offset, s.search.rmLen)
				}
			}
		})
	}
}

func TestRegexGNUEscapesWithoutReference(t *testing.T) {
	for _, letter := range "acdefghijklmnoqrtuvxyzACDEFGHIJKLMNOQRTUVXYZ" {
		for _, fold := range []bool{false, true} {
			m := entry{reln: '='}
			m.value[0], m.value[1] = '\\', byte(letter)
			if fold {
				m.strFlags = stringIgnoreLower
			}
			m.re = compileRule(&m)
			if m.re == nil {
				t.Fatalf("cannot compile escape %c, fold %v", letter, fold)
			}
			for c := 0; c < 256; c++ {
				want := rune(c) == letter
				if fold {
					want = letter >= 'A' && letter <= 'Z' && (rune(c) == letter || rune(c) == letter+('a'-'A'))
				}
				s := &state{search: search{s: []byte{byte(c), 'Z'}, offset: 4}}
				if got := s.regexMatch(&m); got != want {
					t.Errorf("escape %c, fold %v, byte %#02x: match %v, want %v", letter, fold, c, got, want)
				}
			}
		}
	}
}

func TestRegexFoldRangesWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		lo, hi  byte
		negated bool
	}{
		{"[A-z]", 'A', 'Z', false},
		{"[^A-z]", 'A', 'Z', true},
		{"[A-c]", 'A', 'C', false},
		{"[^A-c]", 'A', 'C', true},
		{"[B-y]", 'B', 'Y', false},
		{"[^B-y]", 'B', 'Y', true},
		{"[a-{]", 'A', '{', false},
		{"[^a-{]", 'A', '{', true},
		{"[[.A.]-[.z.]]", 'A', 'Z', false},
		{"[a-~]", 'A', '~', false},
	} {
		for _, flag := range []uint32{stringIgnoreLower, stringIgnoreUpper} {
			m := entry{reln: '=', strFlags: flag}
			copy(m.value[:], tc.pattern)
			m.re = compileRule(&m)
			if m.re == nil {
				t.Fatalf("cannot compile %q, flag %d", tc.pattern, flag)
			}
			for c := 0; c < 256; c++ {
				folded := byte(c)
				if folded >= 'a' && folded <= 'z' {
					folded -= 'a' - 'A'
				}
				want := folded >= tc.lo && folded <= tc.hi
				if tc.negated {
					want = !want && c != '\n'
				}
				want = want && c != 0
				s := &state{search: search{s: []byte{byte(c), 'Z'}}}
				if got := s.regexMatch(&m); got != want {
					t.Errorf("%q flag %d byte %#02x: match %v, want %v", tc.pattern, flag, c, got, want)
				}
			}
		}
	}
}

func TestRegexMatchingWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		pattern, data string
		match         bool
		start, length int
	}{
		{"(A|AB)", "ABZ", true, 0, 2},
		{"^B", "A\nBZ", true, 2, 1},
		{"A$", "A\nBZ", true, 0, 1},
		{"[^A]+", "A\nBZ", true, 2, 1},
		{"[[:space:]]+", "A\nBZ", true, 1, 1},
		{"A.B", "A\nBZ", false, 0, 0},
		{"B", "AB", false, 0, 0},
		{"B", "A\x00BZ", false, 0, 0},
		{"$", "", true, 0, 0},
		{"\\w+", "ABZ", true, 0, 2},
		{"\\bB", "A BZ", true, 2, 1},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			m := entry{reln: '='}
			copy(m.value[:], tc.pattern)
			s := &state{search: search{s: []byte(tc.data), offset: 4}}
			if got := s.regexMatch(&m); got != tc.match || s.search.offset != 4+tc.start || s.search.rmLen != tc.length {
				t.Fatalf("match %v offset %d length %d, want %v/%d/%d", got, s.search.offset, s.search.rmLen, tc.match, 4+tc.start, tc.length)
			}
		})
	}
}

func TestRegexLineRegionsWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		data string
		end  int
	}{
		{"AB\n", 2},
		{"AB\r\n", 3},
		{"AB\rCD\nEF", 6},
		{"AB\nCD", 3},
		{"AB\rCD", 2},
		{"AB", 2},
	} {
		s := &state{}
		m := entry{strRange: 1, strFlags: pstring4LE}
		s.copyRegex(&m, []byte(tc.data), 0)
		if got := string(s.search.s); got != tc.data[:tc.end] {
			t.Errorf("data %q: region %q, want %q", tc.data, got, tc.data[:tc.end])
		}
	}
}

func TestRegexPublishedPatterns(t *testing.T) {
	db := testDB(t)
	n, standard, extended := 0, 0, 0
	for _, set := range db.sets {
		for _, m := range set.rules {
			if m.typ == typeRegex {
				n++
				if m.re == nil {
					t.Errorf("cannot compile published regex %q", cString(m.value[:]))
				} else if m.re.standard != nil {
					standard++
				} else {
					extended++
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("published database has no regex rules")
	}
	t.Logf("compiled %d published regex rules (%d standard, %d GNU extended)", n, standard, extended)
}

func FuzzRegex(f *testing.F) {
	for _, seed := range []struct{ pattern, text string }{
		{`((A)|(B))*(A|B)*\1(A|B)*\1`, "ABAB"},
		{`((A|B)*)+(\1B?)*\1`, "ABA"},
		{`(AB|A)*((A|B)*){1,3}\2(A*)+\1`, "ABBAB"},
	} {
		f.Add([]byte(seed.pattern), []byte(seed.text), false)
	}
	for _, pattern := range []string{"(A|AB)", "[^a-c]+", "[[:space:]]+", "\\w+", "[]a]", "[a\xe9]+", "[", "\\", `\x61+`, `[\]a]+`, `[[=a=]]`, `\q*`, `[\s]+`, `\<A\>`, `(A|AB)\1`, `()*\1*`, `A**`, `A{,2}`, `A{1001}`, `(A){2}{2}\1`, `[A-z]`, `[^B-y]`, `[[.A.]-[.z.]]`, `(A){0,2}\1`, `(A?){0,2}\1`, `((A)|(B)){0,3}\2`} {
		f.Add([]byte(pattern), []byte("A\nB\x00Z"), true)
	}
	f.Fuzz(func(t *testing.T, pattern, data []byte, fold bool) {
		m := entry{reln: '='}
		copy(m.value[:maxString-1], pattern)
		if fold {
			m.strFlags = stringIgnoreLower
		}
		m.re = compileRule(&m)
		if m.re == nil {
			return
		}
		s := &state{}
		s.copyRegex(&m, data, 0)
		s.regexMatch(&m)
	})
}
