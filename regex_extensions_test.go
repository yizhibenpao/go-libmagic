package libmagic

import "testing"

func TestRegexWordDirectionsWithoutReference(t *testing.T) {
	word := func(c int) bool {
		return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
	}
	for _, direction := range []byte{'<', '>'} {
		m := entry{}
		copy(m.value[:], []byte{'\\', direction})
		re := compileRule(&m)
		if re == nil || re.extended == nil {
			t.Fatalf("missing GNU direction backend for %c", direction)
		}
		for before := 0; before < 256; before++ {
			for after := 0; after < 256; after++ {
				want := !word(before) && word(after)
				if direction == '>' {
					want = word(before) && !word(after)
				}
				got := re.extended.matchAt([]rune{rune(before), rune(after)}, 1)
				if (got == 1) != want {
					t.Fatalf("direction %c, bytes %#02x/%#02x: end %d, want match %v", direction, before, after, got, want)
				}
			}
		}
		for _, tc := range []struct {
			data       []rune
			pos        int
			begin, end bool
		}{
			{nil, 0, false, false},
			{[]rune{'A'}, 0, true, false},
			{[]rune{'A'}, 1, false, true},
			{[]rune{'!'}, 0, false, false},
			{[]rune{'!'}, 1, false, false},
		} {
			want := tc.begin
			if direction == '>' {
				want = tc.end
			}
			if got := re.extended.matchAt(tc.data, tc.pos); (got == tc.pos) != want {
				t.Errorf("direction %c, edge data %v pos %d: end %d, want %v", direction, tc.data, tc.pos, got, want)
			}
		}
	}
}

func TestRegexBackreferencesWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		pattern, data string
		start, end    int
		fold          bool
	}{
		{`(A|AB)\1`, "ABABZ", 0, 4, false},
		{`(A*)\1`, "AAAZ", 0, 2, false},
		{`(A)?\1`, "BZ", -1, -1, false},
		{`()\1`, "AZ", 0, 0, false},
		{`(A)\1{2,3}`, "AAAAZ", 0, 4, false},
		{`(A)\10`, "AA0Z", 0, 3, false},
		{`((A)|(B))+\2`, "ABAZ", 0, 3, false},
		{`(A)(B)(C)(D)(E)(F)(G)(H)(I)\9\1`, "ABCDEFGHIIAZ", 0, 11, false},
		{`\<\<\<\<\<\<\<\<\<\<\<\<(A)\1`, "AAZ", 0, 2, false},
		{"(\xffA)\\1", "\xffA\xffAZ", 0, 4, false},
		{`(a)\1`, "aAZ", 0, 2, true},
		{"(\xe9)\\1", "\xe9\xc9Z", -1, -1, true},
		{"(\xe9)\\1", "\xe9\xe9Z", 0, 2, true},
		{`\<([A-Z]+)-\1\>`, " AB-AB!Z", 1, 6, false},
		{`(A)\1`, "A\x00AZ", -1, -1, false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			m := entry{reln: '='}
			copy(m.value[:], tc.pattern)
			if tc.fold {
				m.strFlags = stringIgnoreLower
			}
			m.re = compileRule(&m)
			if m.re == nil || m.re.extended == nil {
				t.Fatal("cannot compile GNU backreference")
			}
			s := &state{search: search{s: []byte(tc.data), offset: 4}}
			got := s.regexMatch(&m)
			if got != (tc.start >= 0) {
				t.Fatalf("match %v, want %v", got, tc.start >= 0)
			}
			if got && (s.search.offset != 4+tc.start || s.search.rmLen != tc.end-tc.start) {
				t.Errorf("offset %d length %d, want %d/%d", s.search.offset, s.search.rmLen, 4+tc.start, tc.end-tc.start)
			}
		})
	}
}

func TestRegexBackendSelection(t *testing.T) {
	for _, pattern := range []string{`AB`, `(A|AB)`, `[[:space:]]+`, `\w+`, `\bB`, `[\1<>]`} {
		m := entry{}
		copy(m.value[:], pattern)
		re := compileRule(&m)
		if re == nil || re.standard == nil || re.extended != nil {
			t.Errorf("ordinary pattern %q did not retain standard engine", pattern)
		}
	}
	for _, pattern := range []string{`\1`, `(A\1)`, `(\2)(A)`, `(A)(\2)`} {
		m := entry{}
		copy(m.value[:], pattern)
		if re := compileRule(&m); re != nil {
			t.Errorf("accepted GNU reference to an unclosed/missing capture: %q", pattern)
		}
	}
}
