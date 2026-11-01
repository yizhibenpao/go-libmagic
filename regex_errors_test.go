package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Expected codes were recorded from glibc 2.35 regcomp in the C locale,
// REG_EXTENDED|REG_NEWLINE, with and without REG_ICASE.
func TestRegexSyntaxErrorsWithoutReference(t *testing.T) {
	cases := []struct {
		pattern string
		codes   [2]int
	}{
		{"", [2]int{0, 0}},
		{"[", [2]int{2, 2}},
		{"[^", [2]int{2, 2}},
		{"[]", [2]int{7, 7}},
		{"[^]", [2]int{7, 7}},
		{"[a", [2]int{7, 7}},
		{"[z-a", [2]int{11, 11}},
		{"[z-a]", [2]int{11, 11}},
		{"[Z-a]", [2]int{0, 11}},
		{"[a\\-c]", [2]int{0, 11}},
		{"[[.ab.]]", [2]int{3, 3}},
		{"[[.ab.]", [2]int{7, 7}},
		{"[[=ab=]]", [2]int{3, 3}},
		{"[[=ab=]", [2]int{3, 3}},
		{"[[:bad:]]", [2]int{4, 4}},
		{"[[:bad:]", [2]int{4, 4}},
		{"[[:digit:]-a]", [2]int{11, 11}},
		{"[[:digit:]-]", [2]int{0, 0}},
		{"[a-[:digit:]]", [2]int{11, 11}},
		{"[a--b]", [2]int{11, 11}},
		{"[-a]", [2]int{0, 0}},
		{"[a\\]", [2]int{0, 0}},
		{"[\\]", [2]int{0, 0}},
		{"[]a]", [2]int{0, 0}},
		{"[[:DIGIT:]]", [2]int{4, 4}},
		{"[[..]]", [2]int{3, 3}},
		{"[[==]]", [2]int{3, 3}},
		{"[[::]]", [2]int{4, 4}},
		{"\\", [2]int{5, 5}},
		{"(\\", [2]int{5, 5}},
		{"\\1", [2]int{6, 6}},
		{"(A\\1)", [2]int{6, 6}},
		{"(A)(\\2)", [2]int{6, 6}},
		{"(A)|\\1", [2]int{6, 6}},
		{"(A)|B\\1", [2]int{6, 6}},
		{"(A)|\\1|B", [2]int{6, 6}},
		{"(A)||\\1", [2]int{6, 6}},
		{"(A)||", [2]int{0, 0}},
		{"(A)|()\\1", [2]int{6, 6}},
		{"(A)\\1", [2]int{0, 0}},
		{"(A)|(B)\\2", [2]int{0, 0}},
		{"((A)|\\2)", [2]int{6, 6}},
		{"((A)|\\2)\\1", [2]int{6, 6}},
		{"(A)(B|\\1)", [2]int{0, 0}},
		{"(A)|((B)|\\3)", [2]int{6, 6}},
		{"(", [2]int{8, 8}},
		{"(()", [2]int{8, 8}},
		{")", [2]int{0, 0}},
		{")*", [2]int{0, 0}},
		{"(*", [2]int{13, 13}},
		{"^*", [2]int{13, 13}},
		{"$?", [2]int{13, 13}},
		{"\\b*", [2]int{13, 13}},
		{"\\B+", [2]int{13, 13}},
		{"\\<*", [2]int{13, 13}},
		{"\\>*", [2]int{13, 13}},
		{"\\`+", [2]int{13, 13}},
		{"\\'*", [2]int{13, 13}},
		{"\\w*", [2]int{0, 0}},
		{"\\s+", [2]int{0, 0}},
		{"(?a)", [2]int{13, 13}},
		{"(?:a)", [2]int{13, 13}},
		{"a{", [2]int{9, 9}},
		{"a{}", [2]int{10, 10}},
		{"a{,}", [2]int{0, 0}},
		{"a{0}*", [2]int{0, 0}},
		{"a{1}{2}", [2]int{0, 0}},
		{"a{q", [2]int{9, 9}},
		{"a{q}", [2]int{10, 10}},
		{"a{1,", [2]int{9, 9}},
		{"a{,q}", [2]int{10, 10}},
		{"a{1,2,3}", [2]int{10, 10}},
		{"a{1\\}", [2]int{9, 9}},
		{"a{32768}", [2]int{15, 15}},
		{"a{99999999999999999999999}", [2]int{15, 15}},
		{"a{32768,1}", [2]int{10, 10}},
		{"a{1,32768}", [2]int{15, 15}},
		{"*", [2]int{13, 13}},
		{"{", [2]int{13, 13}},
		{"{q}", [2]int{13, 13}},
		{"a}", [2]int{0, 0}},
		{"a{,2}", [2]int{0, 0}},
		{"a{2,}", [2]int{0, 0}},
		{"a{01}", [2]int{0, 0}},
		{"a{,0}", [2]int{0, 0}},
		{"[a-b-c]", [2]int{11, 11}},
		{"[[:", [2]int{7, 7}},
		{"[[::", [2]int{7, 7}},
		{"[[::]", [2]int{4, 4}},
		{"[[:a", [2]int{7, 7}},
		{"[[:a:", [2]int{7, 7}},
		{"[[:a:]", [2]int{4, 4}},
		{"[[:a:]]", [2]int{4, 4}},
		{"[[:ab", [2]int{7, 7}},
		{"[[:ab:", [2]int{7, 7}},
		{"[[:ab:]", [2]int{4, 4}},
		{"[[:ab:]]", [2]int{4, 4}},
		{"[[:digit", [2]int{7, 7}},
		{"[[:digit:", [2]int{7, 7}},
		{"[[:digit:]", [2]int{7, 7}},
		{"[[:digit:]]", [2]int{0, 0}},
		{"[[:DIGIT", [2]int{7, 7}},
		{"[[:DIGIT:", [2]int{7, 7}},
		{"[[:DIGIT:]", [2]int{4, 4}},
		{"[[:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [2]int{7, 7}},
		{"[[:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:", [2]int{7, 7}},
		{"[[:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:]", [2]int{4, 4}},
		{"[[:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:]]", [2]int{4, 4}},
		{"[[:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [2]int{7, 7}},
		{"[[:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:", [2]int{7, 7}},
		{"[[:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:]", [2]int{7, 7}},
		{"[[:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:]]", [2]int{7, 7}},
		{"[[.", [2]int{7, 7}},
		{"[[..", [2]int{7, 7}},
		{"[[..]", [2]int{7, 7}},
		{"[[.a", [2]int{7, 7}},
		{"[[.a.", [2]int{7, 7}},
		{"[[.a.]", [2]int{7, 7}},
		{"[[.a.]]", [2]int{0, 0}},
		{"[[.ab", [2]int{7, 7}},
		{"[[.ab.", [2]int{7, 7}},
		{"[[.digit", [2]int{7, 7}},
		{"[[.digit.", [2]int{7, 7}},
		{"[[.digit.]", [2]int{7, 7}},
		{"[[.digit.]]", [2]int{3, 3}},
		{"[[.DIGIT", [2]int{7, 7}},
		{"[[.DIGIT.", [2]int{7, 7}},
		{"[[.DIGIT.]", [2]int{7, 7}},
		{"[[.DIGIT.]]", [2]int{3, 3}},
		{"[[.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [2]int{7, 7}},
		{"[[.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.", [2]int{7, 7}},
		{"[[.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.]", [2]int{7, 7}},
		{"[[.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.]]", [2]int{3, 3}},
		{"[[.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [2]int{7, 7}},
		{"[[.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.", [2]int{7, 7}},
		{"[[.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.]", [2]int{7, 7}},
		{"[[.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.]]", [2]int{7, 7}},
		{"[[=", [2]int{7, 7}},
		{"[[==", [2]int{7, 7}},
		{"[[==]", [2]int{3, 3}},
		{"[[=a", [2]int{7, 7}},
		{"[[=a=", [2]int{7, 7}},
		{"[[=a=]", [2]int{7, 7}},
		{"[[=a=]]", [2]int{0, 0}},
		{"[[=ab", [2]int{7, 7}},
		{"[[=ab=", [2]int{7, 7}},
		{"[[=digit", [2]int{7, 7}},
		{"[[=digit=", [2]int{7, 7}},
		{"[[=digit=]", [2]int{3, 3}},
		{"[[=digit=]]", [2]int{3, 3}},
		{"[[=DIGIT", [2]int{7, 7}},
		{"[[=DIGIT=", [2]int{7, 7}},
		{"[[=DIGIT=]", [2]int{3, 3}},
		{"[[=DIGIT=]]", [2]int{3, 3}},
		{"[[=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [2]int{7, 7}},
		{"[[=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", [2]int{7, 7}},
		{"[[=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=]", [2]int{3, 3}},
		{"[[=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=]]", [2]int{3, 3}},
		{"[[=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [2]int{7, 7}},
		{"[[=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", [2]int{7, 7}},
		{"[[=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=]", [2]int{7, 7}},
		{"[[=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=]]", [2]int{7, 7}},
	}
	for _, tc := range cases {
		for fold, want := range tc.codes {
			if got := regexErrorCode(tc.pattern, fold == 1); got != want {
				t.Errorf("pattern %q fold %d: code %d, want %d", tc.pattern, fold, got, want)
			}
		}
	}
}

func TestRegexCompiledErrorsWithoutReference(t *testing.T) {
	for _, tc := range softprobe.RegexErrorPatches() {
		t.Run(tc.Name, func(t *testing.T) {
			root := entry{typ: typeString, flag: flagBinTest, reln: '=', vallen: 2, lineno: 1, desc: "root"}
			copy(root.value[:], "AB")
			rule := entry{typ: typeRegex, contLevel: 1, reln: '=', lineno: 2, desc: "hit", mime: "application/x-regex"}
			copy(rule.value[:], tc.Pattern)
			rule.re = compileRule(&rule)
			if tc.ZeroLine {
				rule.lineno = 0
			}
			missing := entry{typ: typeUse, contLevel: 1, reln: '=', lineno: 4}
			copy(missing.value[:], "Missing")
			db := &Database{sets: []magicSet{{rules: []entry{root, rule, missing}, n0: 3}}}
			data := []byte("AB\x00\x01CDEFGHIJ\x00\x01")
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(data)
					if mime == 1 {
						got, err = db.BufferMIMEType(data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func TestRegexErrorNoSearchWithoutReference(t *testing.T) {
	m := entry{typ: typeRegex, reln: '='}
	copy(m.value[:], "[")
	s := state{line: 29, buf: &strings.Builder{}}
	if s.regexMatch(&m) || s.err != nil {
		t.Fatalf("nil search: %v", s.err)
	}
	s.search.s = []byte{}
	if s.regexMatch(&m) || s.err == nil || s.err.Error() != "line 29: regex error 2 for `[', (Invalid regular expression)" {
		t.Fatalf("empty non-nil search: %v", s.err)
	}
}
