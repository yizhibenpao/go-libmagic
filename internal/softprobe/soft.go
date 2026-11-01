// Package softprobe holds small FILE5_41 source databases and contracts.
package softprobe

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type Case struct {
	Name    string
	Sources []string
	Data    []byte
	Desc    string
	MIME    string
}

const LiteralPercentDescription = "literal=%d/%%/%s/${x?yes:no}"

func Printable() []Case {
	var cases []Case
	for _, p := range []struct {
		name, typ, check, payload, text string
	}{
		{"string-120", "string/b", "x", strings.Repeat("A", 120), strings.Repeat("A", 120)},
		{"string-200", "string/b", "x", strings.Repeat("A", 200), strings.Repeat("A", 127)},
		{"regex-120", "regex", "A+", strings.Repeat("A", 120) + "Z", strings.Repeat("A", 120)},
		{"regex-511", "regex", "A+", strings.Repeat("A", 511) + "Z", strings.Repeat("A", 511)},
		{"regex-512", "regex", "A+", strings.Repeat("A", 512) + "Z", strings.Repeat("A", 511)},
		{"regex-600", "regex", "A+", strings.Repeat("A", 600) + "Z", strings.Repeat("A", 511)},
		{"search-512", "search", "A", strings.Repeat("A", 512), strings.Repeat("A", 511)},
		{"pascal-raw", "pstring/B", "x", "\x7f" + strings.Repeat("\xff", 127), strings.Repeat("\\377", 127)},
		{"regex-raw-127", "regex", ".+", strings.Repeat("\xff", 127) + "Z", strings.Repeat("\\377", 127)},
		{"search-raw-128", "search", "\\377", strings.Repeat("\xff", 128), strings.Repeat("\\377", 127)},
		{"escape-fits", "regex", ".+", strings.Repeat("A", 507) + "\xffZ", strings.Repeat("A", 507) + "\\377"},
		{"escape-exceeds", "regex", ".+", strings.Repeat("A", 508) + "\xffZ", strings.Repeat("A", 508)},
	} {
		source := "0 string/b AB root\n>4 " + p.typ + " " + p.check + " hit=[%s]\n!:mime application/x-printable\n"
		cases = append(cases, Case{p.name, []string{source}, []byte("AB\x00\x01" + p.payload), "root hit=[" + p.text + "]", "application/x-printable"})
	}
	return cases
}

func Pascal() []Case {
	var cases []Case
	for _, p := range []struct {
		mod   string
		size  int
		order binary.ByteOrder
	}{
		{"B", 1, binary.BigEndian},
		{"H", 2, binary.BigEndian},
		{"h", 2, binary.LittleEndian},
		{"L", 4, binary.BigEndian},
		{"l", 4, binary.LittleEndian},
	} {
		prefix := func(n uint64) []byte {
			raw := make([]byte, p.size)
			switch p.size {
			case 1:
				raw[0] = byte(n)
			case 2:
				p.order.PutUint16(raw, uint16(n))
			case 4:
				p.order.PutUint32(raw, uint32(n))
			}
			return raw
		}
		add := func(name, mod string, data []byte, check, text string, hit, next bool, extra string) {
			source := "0 string/b AB root\n>4 pstring/" + mod + " " + check + " hit=[%s]\n!:mime application/x-pascal\n" + extra
			desc, mime := "root", "application/octet-stream"
			if hit {
				desc += " hit=[" + text + "]"
				mime = "application/x-pascal"
				if next {
					desc += " next"
				}
			}
			cases = append(cases, Case{p.mod + "-" + name, []string{source}, append([]byte("AB\x00\x01"), data...), desc, mime})
		}
		capacity := 128 - p.size
		for _, n := range []uint64{0, 1, 3, uint64(capacity - 1), uint64(capacity), uint64(capacity + 1), 1<<uint(p.size*8) - 1} {
			bodyLen, textLen := n+2, n
			if bodyLen < 3 {
				bodyLen = 3
			}
			if bodyLen > 180 {
				bodyLen = 180
			}
			if textLen > uint64(capacity) {
				textLen = uint64(capacity)
			}
			add(fmt.Sprintf("len-%d", n), p.mod, append(prefix(n), strings.Repeat("A", int(bodyLen))...), "x", strings.Repeat("A", int(textLen)), true, false, "")
		}
		add("short-body", p.mod, append(prefix(5), "AB"...), "x", "AB", true, false, "")
		add("no-body", p.mod, prefix(5), "x", "", true, false, "")
		add("empty-region", p.mod, nil, "x", "", true, false, "")
		add("J-empty-region", p.mod+"J", nil, "x", "", p.size != 1, false, "")
		if p.size > 1 {
			add("short-prefix", p.mod, []byte{1}, "x", "", true, false, "")
		}
		add("NUL", p.mod, append(prefix(6), "AB\x00XYZ"...), "x", "AB", true, false, "")
		add("line", p.mod, append(prefix(3), "A\nB"...), "x", "A", true, false, "")
		for n := 0; n < p.size+2; n++ {
			length := n - p.size
			if length < 0 {
				length = capacity
			}
			add(fmt.Sprintf("J-%d", n), p.mod+"J", append(prefix(uint64(n)), strings.Repeat("A", 140)...), "x", strings.Repeat("A", length), n != p.size-1, false, "")
		}
		for _, rel := range []struct {
			name, op string
			hit      bool
		}{
			{"eq", "=", p.size == 1},
			{"ne", "!", p.size != 1},
			{"gt", ">", p.size != 1},
			{"lt", "<", false},
		} {
			// Only the terminator is overwritten after shifting. Wide
			// prefixes leave tail bytes in the reference's value union.
			add("relation-"+rel.name, p.mod, append(prefix(1), "ABC"...), rel.op+"A", "A", rel.hit, false, "")
		}
		extra := ">>&0 byte =0x5a next\n!:mime application/x-next\n"
		add("next", p.mod, append(prefix(3), "ABCZ"...), "x", "ABC", true, true, extra)
		add("eq-next", p.mod, append(prefix(3), "ABCZ"...), "=ABC", "ABC", p.size == 1, p.size == 1, extra)
	}
	cases = append(cases, Case{"default-prefix", []string{"0 string/b AB root\n>4 pstring x hit=[%s]\n!:mime application/x-pascal\n"}, []byte("AB\x00\x01\x03ABCZ"), "root hit=[ABC]", "application/x-pascal"})
	return cases
}

func RegexExtensions() []Case {
	var cases []Case
	for _, p := range []struct {
		name, pattern, payload, match string
		hit, fold                     bool
	}{
		{"word-start", "\\<A", "A!Z", "A", true, false},
		{"word-start-space", "\\<A", " A!Z", "A", true, false},
		{"word-start-word", "\\<A", "BA!Z", "", false, false},
		{"word-start-underscore", "\\<A", "_AZ", "", false, false},
		{"word-start-digit", "\\<A", "1AZ", "", false, false},
		{"word-start-raw", "\\<A", "\xffAZ", "A", true, false},
		{"word-start-LF", "\\<A", "x\nAZ", "A", true, false},
		{"word-start-not-end", "\\<$", "AZ", "", false, false},
		{"word-start-empty", "\\<", " AZ", "", true, false},
		{"word-end", "A\\>", "A!Z", "A", true, false},
		{"word-end-word", "A\\>", "ABZ", "", false, false},
		{"word-end-underscore", "A\\>", "A_Z", "", false, false},
		{"word-end-digit", "A\\>", "A1Z", "", false, false},
		{"word-end-raw", "A\\>", "A\xffZ", "A", true, false},
		{"word-end-not-start", "(^\\>)", "AZ", "", false, false},
		{"word-end-empty", "\\>", "AZ", "", true, false},
		{"word-both", "\\<[A-Z]+\\>", " AB!Z", "AB", true, false},
		{"word-alternative-longest", "(\\<|A)", "AZ", "A", true, false},
		{"word-alternative-invalid", "(\\<$|A)", "AZ", "A", true, false},
		{"word-alternative-late", "(\\>A|AB)", "ABZ", "AB", true, false},
		{"word-repeat", "(\\<){2}A", "AZ", "A", true, false},
		{"word-star", "(\\<)*A", "AZ", "A", true, false},
		{"word-fold", "\\<ab\\>", " AB!Z", "AB", true, true},
		{"backref", "(A)\\1", "AAZ", "AA", true, false},
		{"backref-pair", "(AB)\\1", "ABABZ", "ABAB", true, false},
		{"backref-long-alternative", "(A|AB)\\1", "ABABZ", "ABAB", true, false},
		{"backref-short-alternative", "(A|AB)\\1", "AAZ", "AA", true, false},
		{"backref-fallback-alternative", "(AB|A)\\1", "AAZ", "AA", true, false},
		{"backref-longest-even", "(A*)\\1", "AAAAZ", "AAAA", true, false},
		{"backref-longest-odd", "(A*)\\1", "AAAZ", "AA", true, false},
		{"backref-greedy-tail", "(A*)\\1B", "AAAABZ", "AAAAB", true, false},
		{"backref-shorter-capture", "(A*)\\1A", "AAAZ", "AAA", true, false},
		{"backref-optional-missing", "(A)?\\1", "BZ", "", false, false},
		{"backref-optional-hit", "(A)?\\1", "AAZ", "AA", true, false},
		{"backref-optional-empty", "(A)?\\1", "Z", "", false, false},
		{"backref-star-empty", "(A*)\\1", "Z", "", true, false},
		{"backref-empty-group", "()\\1", "AZ", "", true, false},
		{"backref-plus", "(A)\\1+", "AAAAAZ", "AAAAA", true, false},
		{"backref-bounded", "(A)\\1{2,3}", "AAAAZ", "AAAA", true, false},
		{"backref-option-no", "(A)\\1?B", "ABZ", "AB", true, false},
		{"backref-option-yes", "(A)\\1?B", "AABZ", "AAB", true, false},
		{"backref-star", "(A)\\1*B", "AAABZ", "AAAB", true, false},
		{"backref-digit-tail", "(A)\\10", "AA0Z", "AA0", true, false},
		{"backref-two-reversed", "(A)(B)\\2\\1", "ABBAZ", "ABBA", true, false},
		{"backref-two-forward", "(A)(B)\\1\\2", "ABABZ", "ABAB", true, false},
		{"backref-nested-inner-first", "((A)B)\\2\\1", "ABAABZ", "ABAAB", true, false},
		{"backref-nested-outer-first", "((A)B)\\1\\2", "ABABAZ", "ABABA", true, false},
		{"backref-alternative-capture", "(A|(B))\\2", "BBZ", "BB", true, false},
		{"backref-unmatched-capture", "(A|(B))\\2", "ABZ", "", false, false},
		{"backref-repeated-old-capture", "((A)|(B))+\\2", "ABAZ", "ABA", true, false},
		{"backref-repeated-last-capture", "((A)|(B))+\\3", "ABBZ", "ABB", true, false},
		{"backref-repeated-group", "(A|B)+\\1", "ABBZ", "ABB", true, false},
		{"backref-repeated-long-alternative", "(A|AB)+\\1", "ABAABZ", "ABAA", true, false},
		{"backref-raw", "(\xffA)\\1", "\xffA\xffAZ", "\\377A\\377A", true, false},
		{"backref-fold", "(a)\\1", "aAZ", "aA", true, true},
		{"backref-not-fold", "(a)\\1", "aAZ", "", false, false},
		{"backref-latin1-not-fold", "(\xe9)\\1", "\xe9\xc9Z", "", false, true},
		{"backref-latin1-same", "(\xe9)\\1", "\xe9\xe9Z", "\\351\\351", true, true},
		{"backref-space-LF", "([[:space:]])\\1", "\n\nZ", "\\012\\012", true, false},
		{"backref-dot-not-LF", "(A.)\\1", "A\nA\nZ", "", false, false},
		{"backref-NUL-stop", "(A)\\1", "A\x00AZ", "", false, false},
		{"backref-last-byte", "(A)\\1", "AA", "", false, false},
		{"word-backref", "\\<([A-Z]+)-\\1\\>", " AB-AB!Z", "AB-AB", true, false},
		{"backref-nine-captures", "(A)(B)(C)(D)(E)(F)(G)(H)(I)\\9\\1", "ABCDEFGHIIAZ", "ABCDEFGHIIA", true, false},
		{"backref-ten-captures", "(A)(B)(C)(D)(E)(F)(G)(H)(I)(J)\\10", "ABCDEFGHIJA0Z", "ABCDEFGHIJA0", true, false},
		{"backref-after-many-assertions", "\\<\\<\\<\\<\\<\\<\\<\\<\\<\\<\\<\\<(A)\\1", "AAZ", "AA", true, false},
		{"backref-empty-cycle", "()*\\1*", "AZ", "", true, false},
		{"word-only-plus", "(\\<)+", " AZ", "", true, false},
		{"backref-empty-plus", "(A*)\\1+", "Z", "", true, false},
		{"word-backref-fold", "\\<(ab)-\\1\\>", " AB-aB!Z", "AB-aB", true, true},
	} {
		var pattern strings.Builder
		for _, c := range []byte(p.pattern) {
			switch {
			case c == '\\':
				pattern.WriteString("\\\\")
			case c >= 128:
				fmt.Fprintf(&pattern, "\\%03o", c)
			default:
				pattern.WriteByte(c)
			}
		}
		typ := "regex"
		if p.fold {
			typ += "/c"
		}
		source := "0 string/b AB root\n>4 " + typ + " " + pattern.String() + " hit=%s\n!:mime application/x-extensions\n"
		desc, mime := "root", "application/octet-stream"
		if p.hit {
			desc, mime = "root hit="+p.match, "application/x-extensions"
		}
		cases = append(cases, Case{p.name, []string{source}, []byte("AB\x00\x01" + p.payload), desc, mime})
	}
	for _, p := range []struct{ name, flags, value string }{
		{"extension-offset-end", "", "90"},
		{"extension-offset-start", "/s", "65"},
	} {
		source := "0 string/b AB root\n>4 regex" + p.flags + " (A|AB)\\\\1 hit=%s\n!:mime application/x-extensions\n>>&0 byte =" + p.value + " child\n"
		cases = append(cases, Case{p.name, []string{source}, []byte("AB\x00\x01ABABZ"), "root hit=ABAB child", "application/x-extensions"})
	}
	return cases
}

func RegexEscapes() []Case {
	var cases []Case
	add := func(name, pattern, payload, match string, hit, fold bool) {
		typ := "regex"
		if fold {
			typ += "/c"
		}
		// The magic source reader consumes one layer of backslashes.
		source := "0 string/b AB root\n>4 " + typ + " " + strings.ReplaceAll(pattern, "\\", "\\\\") + " hit=%s\n!:mime application/x-gnu\n"
		desc, mime := "root", "application/octet-stream"
		if hit {
			desc, mime = "root hit="+match, "application/x-gnu"
		}
		cases = append(cases, Case{name, []string{source}, []byte("AB\x00\x01" + payload), desc, mime})
	}
	for _, c := range "acdefghijklmnoqrtuvxyzACDEFGHIJKLMNOQRTUVXYZ" {
		s := string(c)
		add("escaped-"+s, "\\"+s+"+", s+s+"Z", s+s, true, false)
	}
	for _, p := range []struct {
		name, pattern, payload, match string
		hit, fold                     bool
	}{
		{"hex-not-A", `\x61+`, "AZ", "", false, false},
		{"hex-literal", `\x61+`, "x611Z", "x611", true, false},
		{"digit-not-number", `\d+`, "123Z", "", false, false},
		{"n-not-LF", `\n+`, "A\nZ", "", false, false},
		{"space-VT", `\s+`, "A\vBZ", "\\013", true, false},
		{"space-all", `\s+`, "A \t\r\n\f\vBZ", " \\011\\015\\012\\014\\013", true, false},
		{"nonspace-VT", `\S+`, "\vBZ", "B", true, false},
		{"bracket-escaped-close", `[\]a]+`, "]AZ", "", false, false},
		{"bracket-backslash-a-close", `[\]a]+`, "\\a]Z", "\\a]", true, false},
		{"bracket-s-literal", `[\s]+`, "\\ssZ", "\\ss", true, false},
		{"bracket-s-not-space", `[\s]+`, " \tZ", "", false, false},
		{"bracket-n-not-LF", `[\n]+`, "\nZ", "", false, false},
		{"bracket-n-literal", `[\n]+`, "\\nnZ", "\\nn", true, false},
		{"bracket-d-literal", `[\d]+`, "\\ddZ", "\\dd", true, false},
		{"bracket-hyphen", `[\-]+`, "\\--Z", "\\--", true, false},
		{"bracket-backslash-range", `[a\-c]+`, "\\]abcZ", "\\]abc", true, false},
		{"bracket-double-backslash", `[\\]+`, "\\\\Z", "\\\\", true, false},
		{"posix-bracket-backslash", `[[:space:]\]+`, " \\Z", " \\", true, false},
		{"collating-element", `[[.a.]]+`, "aazZ", "aa", true, false},
		{"equivalence-class", `[[=a=]]+`, "aaAZ", "aa", true, false},
		{"equivalence-upper", `[[=a=]]+`, "AAZ", "", false, false},
		{"collating-hyphen", `[[.-.]]+`, "--Z", "--", true, false},
		{"zero-literal", `\012+`, "0122Z", "0122", true, false},
		{"nonword-LF", `\W+`, "A\nBZ", "\\012", true, false},
		{"word-raw-byte", `\w+`, "\xe9AZ", "A", true, false},
		{"buffer-start", "\\`B", "A\nBZ", "", false, false},
		{"buffer-end", `A\'`, "A\nBZ", "", false, false},
		{"buffer-start-hit", "\\`A", "ABZ", "A", true, false},
		{"buffer-end-hit", `B\'`, "ABZ", "B", true, false},
		{"unmatched-right-parenthesis", ")+", "))Z", "))", true, false},
		{"matched-parentheses", "(A|AB)", "ABZ", "AB", true, false},
		{"literal-parentheses", `\(A\)`, "(A)Z", "(A)", true, false},
		{"fold-escaped-x-upper", `\x61+`, "X611Z", "", false, true},
		{"fold-escaped-x-lower", `\x61+`, "x611Z", "", false, true},
		{"fold-escaped-X-lower", `\X61+`, "x611Z", "x611", true, true},
		{"fold-escaped-n-upper", `\n+`, "NNZ", "", false, true},
		{"fold-escaped-N-lower", `\N+`, "nnZ", "nn", true, true},
		{"fold-escaped-q-alternative", `(\q|A)+`, "aAZ", "aA", true, true},
		{"fold-escaped-q-repeat", `\q*`, "aZ", "", true, true},
		{"fold-escaped-Q-lower", `\Q+`, "qqZ", "qq", true, true},
		{"fold-s-space", `\s+`, "\vZ", "\\013", true, true},
		{"fold-bracket-s", `[\s]+`, "\\SSZ", "\\SS", true, true},
		{"fold-negative-bracket-s", `[^\s]+`, "\\sSAZ", "A", true, true},
		{"fold-collating", `[[.a.]]+`, "AAZ", "AA", true, true},
	} {
		add(p.name, p.pattern, p.payload, p.match, p.hit, p.fold)
	}
	return cases
}

func Regex() []Case {
	var cases []Case
	for _, p := range []struct {
		name, typ, pattern, payload, match, child string
		hit                                       bool
	}{
		{"left-longest", "regex", "(A|AB)", "ABZ", "AB", "", true},
		{"line-start", "regex", "\\^B", "A\nBZ", "B", "", true},
		{"line-end", "regex", "A$", "A\nBZ", "A", "", true},
		{"negated-class", "regex", "[^A]+", "A\nBZ", "B", "", true},
		{"positive-space", "regex", "[[:space:]]+", "A\nBZ", "\\012", "", true},
		{"dot-no-newline", "regex", "A.B", "A\nBZ", "", "", false},
		{"drop-last-byte", "regex", "B", "AB", "", "", false},
		{"byte-range", "regex/2", "B", "ABZ", "", "", false},
		{"regex-max", "regex", "B", strings.Repeat("A", 8191) + "BZ", "", "", false},
		{"nul-stop", "regex", "B", "A\x00BZ", "", "", false},
		{"empty-region", "regex", "$", "", "", "", true},
		{"past-region", "regex", ".*", "ABZ", "", "", false},
		{"offset-end", "regex", "(A|AB)", "ABZ", "AB", ">>&0 byte =90 child\n", true},
		{"offset-start", "regex/s", "(A|AB)", "ABZ", "AB", ">>&0 byte =65 child\n", true},
		{"ignore-ascii", "regex/c", "AB", "aBZ", "aB", "", true},
		{"ignore-latin1", "regex/c", "\\351", "\xc9Z", "", "", false},
		{"raw-byte", "regex", "\\377A", "\xffAZ", "\\377A", "", true},
		{"line-lf-at-end", "regex/1l", "B", "AB\n", "", "", false},
		{"line-crlf-at-end", "regex/1l", "B", "AB\r\n", "B", "", true},
		{"line-cr-before-lf", "regex/1l", "CD", "AB\rCD\nEF", "CD", "", true},
		{"gnu-word", "regex", "\\\\w+", "ABZ", "AB", "", true},
		{"gnu-boundary", "regex", "\\\\bB", "A BZ", "B", "", true},
		{"fold-class", "regex/c", "[a]+", "AZ", "A", "", true},
		{"fold-negative", "regex/c", "[^a]+", "aABZ", "B", "", true},
		{"fold-range", "regex/c", "[a-c]+", "aBCZ", "aBC", "", true},
		{"fold-negative-range", "regex/c", "[^a-c]+", "aBCdZ", "d", "", true},
		{"fold-latin-class", "regex/c", "[\\351]+", "\xc9Z", "", "", false},
		{"fold-negative-latin-class", "regex/c", "[^\\351]+", "\xc9Z", "\\311", "", true},
		{"fold-mixed-class", "regex/c", "[a\\351]+", "A\xc9\xe9Z", "A", "", true},
		{"fold-mixed-range", "regex/c", "[A-\\377]+", "az\xc9Z", "az\\311", "", true},
		{"fold-posix-class", "regex/c", "[[:upper:]]+", "\xe9Z", "", "", false},
		{"fold-ascii-control", "regex/c", "[[:lower:]]+", "AZ", "A", "", true},
		{"fold-newline-negative", "regex/c", "[^a]+", "a\nBZ", "B", "", true},
		{"fold-close-first", "regex/c", "[]a]+", "]AZ", "]A", "", true},
		{"fold-latin-literal", "regex/c", "\\351", "\xe9Z", "\\351", "", true},
	} {
		offset := 4
		if p.name == "past-region" {
			offset = 99
		}
		source := fmt.Sprintf("0 string/b AB root\n>%d %s %s hit=%%s\n!:mime application/x-regex\n%s", offset, p.typ, p.pattern, p.child)
		desc, mime := "root", "application/octet-stream"
		if p.hit {
			desc, mime = "root hit="+p.match, "application/x-regex"
			if p.child != "" {
				desc += " child"
			}
		}
		cases = append(cases, Case{p.name, []string{source}, []byte("AB\x00\x01" + p.payload), desc, mime})
	}
	source := []string{"0 regex \\377A match %s\n"}
	cases = append(cases,
		Case{"top-nul-stop", source, []byte{0, 'Z', 0xff, 'A', 'X'}, "data", "application/octet-stream"},
		Case{"top-raw-byte", source, []byte{1, 'Z', 0xff, 'A', 'X'}, "match \\377A", "application/octet-stream"},
	)
	return cases
}

func DefaultClear() []Case {
	data := []byte("AB\x00\x01")
	root := "0 string/b AB root\n"
	var cases []Case
	for _, typ := range []string{"default", "clear"} {
		for _, p := range []struct {
			name, desc, want, mime string
		}{
			{"query", "${x?executable:plain}", "root ${x?executable:plain}", ""},
			{"query-nospace-looking", "${x?yes:\\bno}", "root ${x?yes:\\bno}", ""},
			{"nospace", "\\b${x?yes:no}", "root${x?yes:no}", ""},
			{"mime-query", "literal/${x?yes:no}", "root literal/${x?yes:no}", "application/x-${x?yes:no}"},
		} {
			source := root + ">0 " + typ + " x " + p.desc + "\n"
			mime := "application/octet-stream"
			if p.mime != "" {
				source += "!:mime " + p.mime + "\n"
				mime = "application/x-no"
			}
			cases = append(cases, Case{typ + "-" + p.name, []string{source}, data, p.want, mime})
		}
		cases = append(cases, Case{typ + "-top", []string{"0 " + typ + " x ${x?yes:no}\n"}, data, "data", "application/octet-stream"})
	}
	cases = append(cases,
		Case{"clear-repeated", []string{root + ">0 clear x one=${x?yes:no}\n>0 clear x two=${x?yes:no}\n>0 default x fallback=${x?yes:no}\n"}, data, "root one=${x?yes:no} two=${x?yes:no} fallback=${x?yes:no}", "application/octet-stream"},
		Case{"default-suppressed", []string{root + ">0 byte =65 first\n>0 default x fallback=${x?yes:no}\n!:mime application/x-fallback\n"}, data, "root first", "application/octet-stream"},
		Case{"literal-number-control", []string{root + ">2 byte x value=%u\n"}, data, "root value=0", "application/octet-stream"},
		Case{"literal-string-control", []string{root + ">0 string x query=${x?yes:no}:%s\n"}, data, "root query=no:AB", "application/octet-stream"},
	)
	return cases
}

func Bounds() []Case {
	data := []byte("AB\x00\x01")
	return []Case{
		{"string-past-end", []string{"0 string/b AB root\n>5 string x past-end\n"}, data, "root", "application/octet-stream"},
		{"string-at-end", []string{"0 string/b AB root\n>4 string x at-end\n"}, data, "root at-end", "application/octet-stream"},
		{"string-last-byte", []string{"0 string/b AB root\n>3 string x last-byte\n"}, data, "root last-byte", "application/octet-stream"},
		{"string-partial-literal", []string{"0 string/b AB root\n>3 string ABCD partial\n"}, data, "root", "application/octet-stream"},
		{"pstring-past-end", []string{"0 string/b AB root\n>5 pstring x past-end\n"}, data, "root", "application/octet-stream"},
		{"pstring-at-end", []string{"0 string/b AB root\n>4 pstring x at-end\n"}, data, "root at-end", "application/octet-stream"},
		{"search-past-end", []string{"0 string/b AB root\n>5 search/8 x past-end\n"}, data, "root", "application/octet-stream"},
		{"past-end-mime", []string{"0 string/b AB root\n>5 string x past-end\n!:mime application/x-past-end\n"}, data, "root", "application/octet-stream"},
		{"at-end-mime", []string{"0 string/b AB root\n>4 string x at-end\n!:mime application/x-at-end\n"}, data, "root at-end", "application/x-at-end"},
		{"negated-string-past-end", []string{"0 string/b AB root\n>5 string !Z absent\n"}, data, "root absent", "application/octet-stream"},
		{"negated-pstring-past-end", []string{"0 string/b AB root\n>5 pstring !Z absent\n"}, data, "root absent", "application/octet-stream"},
		{"negated-search-partial", []string{"0 string/b AB root\n>3 search/8 !XYZ absent\n"}, data, "root absent", "application/octet-stream"},
	}
}

func Indirect() []Case {
	data := []byte("AB\x00\x01CD\x00\x01")
	leaf := "0 string/b CD child-CD\n!:mime application/x-child-cd\n0 string/b EF child-EF\n!:mime application/x-child-ef\n"
	root := "0 string/b AB root\n>4 indirect x off=%u:\n"
	named := "0 string/b AB root\n>4 use nested\n0 name nested\n"
	return []Case{
		{"indirect-description", []string{root + leaf}, data, "rootoff=4:child-CD ", "application/x-child-cd"},
		{"indirect-no-description", []string{"0 string/b AB root\n>4 indirect x\n" + leaf}, data, "rootchild-CD", "application/x-child-cd"},
		{"indirect-query-literal", []string{"0 string/b AB root\n>4 indirect x ${x?yes:no}=%u:\n" + leaf}, data, "root${x?yes:no}=4:child-CD ", "application/x-child-cd"},
		{"indirect-no-space", []string{"0 string/b AB root\n>4 indirect x \\boff=%u:\n" + leaf}, data, "rootoff=4:child-CD", "application/x-child-cd"},
		{"indirect-parent-mime", []string{"0 string/b AB root\n>4 indirect x off=%u:\n!:mime application/x-parent\n" + leaf}, data, "rootoff=4:child-CD ", "application/x-child-cdapplication/x-parent"},
		{"indirect-second-library", []string{root, leaf}, data, "rootoff=4:child-CD ", "application/x-child-cd"},
		{"indirect-first-library", []string{leaf, root}, data, "rootoff=4:child-CD ", "application/x-child-cd"},
		{"indirect-named-absolute", []string{named + ">4 indirect x off=%u:\n" + leaf}, []byte("AB\x00\x01CD\x00\x01EF\x00\x01"), "rootoff=4:child-CD ", "application/x-child-cd"},
		{"indirect-named-relative", []string{named + ">4 indirect/r x off=%u:\n" + leaf}, []byte("AB\x00\x01CD\x00\x01EF\x00\x01"), "rootoff=8:child-EF ", "application/x-child-ef"},
		{"indirect-zero", []string{"0 string/b AB root\n>0 indirect x bad=%u:\n" + leaf}, data, "root", "application/octet-stream"},
		{"indirect-at-end", []string{"0 string/b AB root\n>4 indirect x off=%u:\n0 default x eof\n!:mime application/x-eof\n"}, []byte("AB\x00\x01"), "root", "application/octet-stream"},
		{"indirect-no-leaf", []string{root + leaf}, []byte("AB\x00\x01ZZ\x00\x01"), "root", "application/octet-stream"},
		{"indirect-child-continuation", []string{root + "0 string/b CD\n>2 byte x value=%u\n!:mime application/x-value\n"}, data, "rootoff=4: value=0 ", "application/x-value"},
		{"indirect-after-child", []string{root + ">8 byte x after=%u\n" + leaf}, []byte("AB\x00\x01CD\x00\x01\x02"), "rootoff=4:child-CD  after=2", "application/x-child-cd"},
		{"indirect-empty-root", []string{"0 string/b AB\n>4 indirect x\n>8 byte x after=%u\n" + leaf}, []byte("AB\x00\x01CD\x00\x01\x02"), "child-CD after=2", "application/x-child-cd"},
		{"indirect-empty-root-description", []string{"0 string/b AB\n>4 indirect x off=%u:\n>8 byte x after=%u\n" + leaf}, []byte("AB\x00\x01CD\x00\x01\x02"), "off=4:child-CD  after=2", "application/x-child-cd"},
		{"indirect-child-relative-offset", []string{root + ">>&0 byte x relative=%u\n" + leaf}, data, "rootoff=4:child-CD  relative=67", "application/x-child-cd"},
		{"indirect-nested", []string{"0 string/b AB root\n>4 indirect x outer=%u:\n0 string/b CD child\n>4 indirect x inner=%u:\n0 string/b EF leaf\n!:mime application/x-leaf\n"}, []byte("AB\x00\x01CD\x00\x01EF\x00\x01"), "rootouter=4:childinner=4:leaf  ", "application/x-leaf"},
	}
}

func IndirectCounts() []Case {
	data := []byte("AB\x00\x01CD\x00\x01")
	root := "0 string/b AB root\n"
	leaf := "0 string/b CD child\n!:mime application/x-child\n"
	step := ">4 indirect x X\n"
	repeated := "root" + strings.Repeat("Xchild ", 49)
	return []Case{
		{"indirect-total-49", []string{root + strings.Repeat(step, 49) + leaf}, data, repeated, strings.Repeat("application/x-child", 49)},
		{"indirect-depth-49", []string{root + step + leaf}, []byte(strings.Repeat("AB\x00\x01", 49) + "CD\x00\x01"), strings.Repeat("rootX", 49) + "child" + strings.Repeat(" ", 49), "application/x-child"},
		{"indirect-miss-49", []string{root + strings.Repeat(step, 49) + leaf}, []byte("AB\x00\x01ZZ\x00\x01"), "root", "application/octet-stream"},
		{"indirect-zero-not-counted", []string{root + strings.Repeat(">0 indirect x X\n", 60) + leaf}, data, "root", "application/octet-stream"},
		{"indirect-past-eof-not-counted", []string{root + strings.Repeat(">9 indirect x X\n", 60) + leaf}, data, "root", "application/octet-stream"},
		{"indirect-binary-text-reset", []string{"0 byte =65\n" + strings.Repeat(step, 25) + "0 string/t AB Troot\n" + strings.Repeat(step, 25)}, []byte("ABCDEFGH\n"), "Troot, ASCII text", "text/plain"},
		{"indirect-use-total-49", []string{root + ">0 use N\n>0 use O\n0 name N\n" + strings.Repeat(step, 24) + "0 name O\n" + strings.Repeat(step, 25) + leaf}, data, repeated, strings.Repeat("application/x-child", 49)},
	}
}

func IndirectCountFailures() []Failure {
	data := []byte("AB\x00\x01CD\x00\x01")
	root := "0 string/b AB root\n"
	leaf := "0 string/b CD child\n!:mime application/x-child\n"
	step := ">4 indirect x X\n"
	cases := []Case{
		{Name: "indirect-total-50", Sources: []string{root + strings.Repeat(step, 50) + leaf}, Data: data},
		{Name: "indirect-miss-50", Sources: []string{root + strings.Repeat(step, 50) + leaf}, Data: []byte("AB\x00\x01ZZ\x00\x01")},
		{Name: "indirect-eof-50", Sources: []string{root + strings.Repeat(">8 indirect x X\n", 50) + leaf}, Data: data},
		{Name: "indirect-libraries-total-50", Sources: []string{"0 string/b AB\n" + strings.Repeat(step, 25), root + strings.Repeat(step, 25)}, Data: data},
		{Name: "indirect-use-total-50", Sources: []string{root + ">0 use N\n>0 use O\n0 name N\n" + strings.Repeat(step, 25) + "0 name O\n" + strings.Repeat(step, 25) + leaf}, Data: data},
		{Name: "indirect-depth-50", Sources: []string{root + step + leaf}, Data: []byte(strings.Repeat("AB\x00\x01", 50) + "CD\x00\x01")},
	}
	failures := make([]Failure, 0, len(cases))
	for _, tc := range cases {
		failures = append(failures, Failure{tc, "indirect count (50) exceeded", "indirect count (50) exceeded"})
	}
	return failures
}

func Moffset() []Case {
	data := []byte("AB\x00\x01")
	first := "10 string/b !AB first\n!:strength +200\n>0 byte x skipped\n"
	second := "0 string/b AB second\n!:mime application/x-second\n"
	dates := []byte("AB\x00\x00\x00\x00\x00\x00\x00\x00CD")
	cases := []Case{
		{"moffset-flush-next-top", []string{first + second}, data, "firstsecond", "application/x-second"},
		{"moffset-flush-no-next", []string{first}, data, "first", "application/octet-stream"},
		{"moffset-flush-quad", []string{"0 bequad !0 first\n!:strength +200\n" + second}, data, "firstsecond", "application/x-second"},
		{"moffset-flush-named-continuation", []string{"0 string/b AB root\n>0 use N\n0 name N\n>10 string !AB first\n>0 string AB same-level\n!:mime application/x-same\n"}, data, "root first same-level", "application/x-same"},
		{"moffset-negative-continuation", []string{"0 string/b AB root\n>&-9 byte !0 neg\n>>&9 byte =0 deep\n!:mime application/x-deep\n>0 byte =65 sibling\n!:mime application/x-sibling\n"}, dates, "root neg sibling", "application/x-sibling"},
		{"moffset-past-end-continuation", []string{"0 string/b AB root\n>20 byte !0 past\n>>&0 byte !0 deep\n!:mime application/x-deep\n>0 byte =65 sibling\n!:mime application/x-sibling\n"}, dates, "root past sibling", "application/x-sibling"},
	}
	for _, typ := range []string{"qwdate", "leqwdate", "beqwdate", "qdate", "leqdate", "beqdate"} {
		value, word := 67, "next"
		if strings.Contains(typ, "wdate") {
			value, word = 65, "zero"
		}
		for _, cont := range []bool{false, true} {
			root, depth, desc, name := "", "", "clock "+word, typ+"-top"
			if cont {
				root, depth, desc, name = "0 string/b AB root\n", ">", "root "+desc, typ+"-continuation"
			}
			source := root + depth + "2 " + typ + " x clock\n" + depth + fmt.Sprintf(">&0 byte =%d %s\n!:mime application/x-%s\n", value, word, word)
			cases = append(cases, Case{"moffset-" + name, []string{source}, dates, desc, "application/x-" + word})
		}
	}
	return cases
}

func ID3() []Case {
	var cases []Case
	probes := []struct {
		name, operation string
		raw, rhs        uint32
		target          int
		flip            bool
	}{
		{"syncsafe", "", 0x100, 0, 128, false},
		{"high-bits", "", 0x80808180, 0, 128, false},
		{"add", "+4", 0x100, 0, 132, false},
		{"multiply", "*2", 0x100, 0, 256, false},
		{"rhs-indirect", "+(4)", 0x100, 0x100, 384, false},
		{"flip-small", "", 32, 0, 32, true},
		{"flip-syncsafe", "", 0x100, 0, 128, true},
		{"zero", "", 0, 0, 0, false},
	}
	for _, little := range []bool{false, true} {
		var order binary.ByteOrder = binary.BigEndian
		letter, long := "I", "L"
		if little {
			order, letter, long = binary.LittleEndian, "i", "l"
		}
		for _, p := range probes {
			data := make([]byte, 600)
			copy(data, "AB")
			order.PutUint32(data[4:], p.raw)
			order.PutUint32(data[8:], p.rhs)
			want := 65
			if p.target != 0 {
				want = 126
				data[p.target] = byte(want)
			}
			source := "0 string/b AB root\n"
			if p.flip {
				source += ">0 use \\^N\n0 name N\n"
			}
			source += fmt.Sprintf(">(4.%s%s) byte =%d hit\n!:mime application/x-id3\n", letter, p.operation, want)
			cases = append(cases, Case{"id3-" + letter + "-" + p.name, []string{source}, data, "root hit", "application/x-id3"})
		}
		data := make([]byte, 600)
		copy(data, "AB")
		// Unlike ID3 types, ordinary longs still flip in a named call.
		if little {
			binary.BigEndian.PutUint32(data[4:], 32)
		} else {
			binary.LittleEndian.PutUint32(data[4:], 32)
		}
		data[32] = 126
		source := "0 string/b AB root\n>0 use \\^N\n0 name N\n" + fmt.Sprintf(">(4.%s) byte =126 hit\n!:mime application/x-id3\n", long)
		cases = append(cases, Case{"id3-long-flip-" + long, []string{source}, data, "root hit", "application/x-id3"})
	}
	return cases
}

func Use() []Case {
	data := []byte("AB\x00\x01")
	root := "0 string/b AB root\n>0 use N\n"
	name := "0 name N\n>0 string AB child\n!:mime application/x-child\n"
	nospace := "0 string/b AB root\n>0 use N \\b\n"
	cases := []Case{
		{"use-same-library", []string{root + name}, data, "root child", "application/x-child"},
		{"use-second-library", []string{root, name}, data, "root child", "application/x-child"},
		{"use-first-library", []string{name, root}, data, "root child", "application/x-child"},
		{"use-first-definition", []string{"0 name N\n>0 string AB first\n!:mime application/x-first\n", root + name}, data, "root first", "application/x-first"},
		{"use-nested-libraries", []string{root, "0 name N\n>0 use leaf\n", "0 name leaf\n>0 string AB child\n!:mime application/x-child\n"}, data, "root child", "application/x-child"},
		{"use-no-space", []string{nospace + name}, data, "rootchild", "application/x-child"},
		{"use-description", []string{"0 string/b AB root\n>0 use N use-desc\n" + name}, data, "root child ", "application/x-child"},
		{"use-name-description", []string{root + "0 name N name-desc\n>0 string AB child\n!:mime application/x-child\n"}, data, "rootname-desc child", "application/x-child"},
		{"use-name-query-literal", []string{root + "0 name N name-${x?yes:no}\n>0 string AB child\n!:mime application/x-child\n"}, data, "rootname-${x?yes:no} child", "application/x-child"},
		{"use-parent-mime", []string{"0 string/b AB root\n>0 use N use-desc\n!:mime application/x-parent\n" + name}, data, "root child ", "application/x-childapplication/x-parent"},
		{"use-next-parent-mime", []string{root + ">2 byte x after=%u\n!:mime application/x-after\n" + name}, data, "root child after=0", "application/x-childapplication/x-after"},
		{"use-caller-indirect-mime", []string{"0 string/b AB root\n>4 indirect x off=%u:\n>2 byte x after=%u\n!:mime application/x-after\n0 string/b CD child\n!:mime application/x-child\n"}, []byte("AB\x00\x01CD\x00\x01"), "rootoff=4:child  after=0", "application/x-childapplication/x-after"},
		{"use-name-mime", []string{root + "0 name N name-desc\n!:mime application/x-name\n>0 string AB child\n!:mime application/x-child\n"}, data, "rootname-desc child", "application/x-name"},
		{"use-default-level", []string{"0 string/b AB root\n>0 string AB first\n>0 use N\n0 name N\n>0 default x fallback\n"}, data, "root first fallback", "application/octet-stream"},
		{"use-else-level", []string{"0 string/b AB root\n>0 string AB first\n>0 use N\n0 name N\n>50 if byte =1 unread\n>0 else default x fallback\n"}, data, "root first fallback", "application/octet-stream"},
		{"use-deeper-else", []string{root + "0 name N\n>0 string AB one\n>>0 if byte =65 first\n>0 string AB two\n>>50 if byte =1 unread\n>>0 else default x fallback\n"}, data, "root one first two fallback", "application/octet-stream"},
		{"use-no-space-no-match", []string{nospace + ">2 byte x after=%u\n0 name N\n>0 string ZZ miss\n"}, data, "rootafter=0", "application/octet-stream"},
		{"use-no-space-two", []string{nospace + name + ">2 byte x second=%u\n"}, data, "rootchild second=0", "application/x-child"},
		{"use-at-eof", []string{"0 string/b AB root\n>4 use N\n0 name N\n>0 default x eof\n"}, data, "root eof", "application/octet-stream"},
		{"use-past-eof", []string{"0 string/b AB root\n>5 use N\n0 name N\n>0 default x eof\n"}, data, "root", "application/octet-stream"},
		{"use-bare-caret", []string{"0 string/b AB root\n>2 use ^N\n0 name N\n>0 beshort =0x1234 flipped\n!:mime application/x-flipped\n"}, []byte("AB\x34\x12"), "root", "application/octet-stream"},
		{"use-flip", []string{"0 string/b AB root\n>2 use \\^N\n0 name N\n>0 beshort =0x1234 flipped\n!:mime application/x-flipped\n"}, []byte("AB\x34\x12"), "root flipped", "application/x-flipped"},
		{"use-flip-back", []string{"0 string/b AB root\n>2 use \\^outer\n0 name outer\n>0 use \\^N\n0 name N\n>0 beshort =0x1234 original\n!:mime application/x-original\n"}, []byte("AB\x12\x34"), "root original", "application/x-original"},
		{"use-mime-description-only", []string{root + "0 string/b AB later\n!:mime application/x-later\n0 name N\n>0 string AB child\n>2 byte x after=%u\n"}, data, "root child after=0", "application/octet-stream"},
	}
	cases = append(cases, Case{"use-depth-49", []string{nameChain(49)}, data, "root leaf", "application/x-leaf"})
	return cases
}

type Failure struct {
	Case
	DescErr string
	MIMEErr string
}

func UseFailures() []Failure {
	data := []byte("AB\x00\x01")
	root := "0 string/b AB root\n>0 use N\n"
	return []Failure{
		{Case{Name: "use-missing", Sources: []string{root}, Data: data}, "root cannot find entry `N'", "cannot find entry `N'"},
		{Case{Name: "use-missing-no-description", Sources: []string{"0 string/b AB\n>0 use N\n"}, Data: data}, "cannot find entry `N'", "cannot find entry `N'"},
		{Case{Name: "use-missing-text", Sources: []string{"0 string/t AB root\n>0 use N\n"}, Data: []byte("AB ordinary text\n")}, "root cannot find entry `N'", "cannot find entry `N'"},
		{Case{Name: "use-recursive", Sources: []string{root + "0 name N\n>0 use N\n"}, Data: data}, "root name use count (50) exceeded", "name use count (50) exceeded"},
		{Case{Name: "use-depth-50", Sources: []string{nameChain(50)}, Data: data}, "root name use count (50) exceeded", "name use count (50) exceeded"},
		{Case{Name: "use-missing-after-mime", Sources: []string{root + ">0 use Missing\n0 name N\n>0 string AB child\n!:mime application/x-child\n"}, Data: data}, "root child cannot find entry `Missing'", "application/x-child cannot find entry `Missing'"},
		{Case{Name: "use-missing-in-indirect", Sources: []string{"0 string/b AB root\n>4 indirect x off=%u:\n0 string/b CD child\n>0 use Missing\n"}, Data: []byte("AB\x00\x01CD\x00\x01")}, "child cannot find entry `Missing'", "cannot find entry `Missing'"},
	}
}

func nameChain(count int) string {
	source := "0 string/b AB root\n>0 use N0\n"
	for i := 0; i < count; i++ {
		source += fmt.Sprintf("0 name N%d\n", i)
		if i+1 < count {
			source += fmt.Sprintf(">0 use N%d\n", i+1)
		} else {
			source += ">0 string AB leaf\n!:mime application/x-leaf\n"
		}
	}
	return source
}
