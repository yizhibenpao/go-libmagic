package libmagic

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
)

// REG_NEWLINE excludes LF from dot and negated classes and makes anchors
// line-based. PerlX retains GNU escapes such as \w and \b, unlike CompilePOSIX.
const regexSyntax = syntax.PerlX

func parseRegex(pat string, fold bool) (*syntax.Regexp, map[uint32]regexOp, error) {
	pat, ops := normalizeRegex(pat, fold)
	if fold {
		// Expand classes before parsing the whole expression: after parsing,
		// [^a] no longer carries the negation needed for ASCII case folding.
		var b strings.Builder
		for i := 0; i < len(pat); {
			switch pat[i] {
			case '\\':
				end := i + 2
				if end > len(pat) {
					end = len(pat)
				}
				b.WriteString(pat[i:end])
				i = end
			case '[':
				var class *syntax.Regexp
				var err error
				end := i + 1
				for ; end < len(pat); end++ {
					if pat[end] != ']' {
						continue
					}
					class, err = syntax.Parse(pat[i:end+1], regexSyntax)
					if err == nil {
						break
					}
				}
				if class == nil || end == len(pat) {
					tree, err := syntax.Parse(pat, regexSyntax)
					return tree, ops, err
				}
				foldRegexClass(class, pat[i+1] == '^')
				b.WriteString(class.String())
				i = end + 1
			default:
				b.WriteByte(pat[i])
				i++
			}
		}
		pat = b.String()
	}
	tree, err := parseRegexRepeats(pat)
	if err == nil && fold {
		foldRegex(tree)
	}
	return tree, ops, err
}

// POSIX_EXTENDED does not set RE_BACKSLASH_ESCAPE_IN_LISTS: inside a
// bracket expression, backslash is an ordinary member, not an escape.
func normalizeRegex(pat string, fold bool) (string, map[uint32]regexOp) {
	chars := []rune(pat)
	var b strings.Builder
	bracket := -1
	var capCount uint32
	var groups []uint32
	var closed []bool
	var stack []int
	var ops map[uint32]regexOp
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		if bracket >= 0 {
			if c == ']' && i != bracket+1 && !(i == bracket+2 && chars[bracket+1] == '^') {
				bracket = -1
			}
			if c == '[' && i+1 < len(chars) {
				kind := chars[i+1]
				if kind == ':' || kind == '.' || kind == '=' {
					end := i + 2
					for end+1 < len(chars) && !(chars[end] == kind && chars[end+1] == ']') {
						end++
					}
					if end+1 < len(chars) {
						// C locale collating/equivalence elements name
						// a single byte; POSIX character classes stay intact.
						if kind != ':' && end == i+3 {
							literal := chars[i+2]
							if fold {
								literal = regexUpper(literal)
							}
							if strings.ContainsRune(`\^-][`, literal) {
								b.WriteRune('\\')
							}
							b.WriteRune(literal)
						} else {
							b.WriteString(string(chars[i : end+2]))
						}
						i = end + 1
						continue
					}
				}
			}
			if c == '\\' {
				b.WriteString(`\\`)
			} else {
				// glibc folds bracket bytes before building ranges;
				// [A-z]/c is [A-Z], not a case-folded [A-z] set.
				if fold {
					c = regexUpper(c)
				}
				b.WriteRune(c)
			}
			continue
		}
		switch c {
		case '[':
			bracket = i
			b.WriteRune(c)
		case '(':
			capCount++
			groups = append(groups, capCount)
			closed = append(closed, false)
			stack = append(stack, len(groups)-1)
			b.WriteRune(c)
		case ')':
			if len(stack) == 0 {
				// RE_UNMATCHED_RIGHT_PAREN_ORD.
				b.WriteRune('\\')
			} else {
				closed[stack[len(stack)-1]] = true
				stack = stack[:len(stack)-1]
			}
			b.WriteRune(c)
		case '\\':
			if i+1 == len(chars) {
				b.WriteRune(c)
				continue
			}
			i++
			switch chars[i] {
			case 'b', 'B', 'w', 'W':
				b.WriteRune('\\')
				b.WriteRune(chars[i])
			case '<', '>', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				capCount++
				op := regexOp{kind: chars[i]}
				if chars[i] >= '1' && chars[i] <= '9' {
					n := int(chars[i] - '1')
					if n < len(groups) && closed[n] {
						op.target = groups[n]
					}
				}
				if ops == nil {
					ops = make(map[uint32]regexOp)
				}
				ops[capCount] = op
				// An empty capture marks an extension in syntax.Prog;
				// it must survive simplification and repeated groups.
				fmt.Fprintf(&b, "(?P<magicGNU%d>)", capCount)
			case 's':
				b.WriteString(`[[:space:]]`)
			case 'S':
				b.WriteString(`[^[:space:]]`)
			case '`':
				b.WriteString(`\A`)
			case '\'':
				b.WriteString(`\z`)
			default:
				// GNU ERE quotes other characters literally, including
				// \d, \n, \x and \0; none are Perl byte/class escapes.
				if fold && chars[i] >= 'a' && chars[i] <= 'z' {
					// glibc peek_token keeps this escaped byte raw,
					// while REG_ICASE folds input to uppercase. An
					// escaped lowercase literal cannot match a byte.
					b.WriteString(`[^\x00-\x{10FFFF}]`)
				} else {
					b.WriteString(regexp.QuoteMeta(string(chars[i])))
				}
			}
		default:
			b.WriteRune(c)
		}
	}
	return b.String(), ops
}

func foldRegex(r *syntax.Regexp) {
	switch r.Op {
	case syntax.OpLiteral:
		subs := make([]*syntax.Regexp, 0, len(r.Rune))
		for _, c := range r.Rune {
			sub := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{c}}
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
				foldRegexClass(sub, false)
			}
			subs = append(subs, sub)
		}
		r.Op, r.Rune, r.Sub = syntax.OpConcat, nil, subs
	case syntax.OpCharClass:
		foldRegexClass(r, false)
	default:
		for _, sub := range r.Sub {
			foldRegex(sub)
		}
	}
}

// C LC_CTYPE folds A-Z only. Go's FoldCase would also equate raw Latin-1
// bytes such as 0xE9 and 0xC9, so leave all non-ASCII class ranges untouched.
func foldRegexClass(r *syntax.Regexp, negated bool) {
	ranges := r.Rune
	switch r.Op {
	case syntax.OpLiteral:
		ranges = []rune{r.Rune[0], r.Rune[0]}
	case syntax.OpCharClass:
	default:
		return
	}
	var allowed [128]bool
	for c := range allowed {
		for i := 0; i < len(ranges); i += 2 {
			if rune(c) >= ranges[i] && rune(c) <= ranges[i+1] {
				allowed[c] = true
				break
			}
		}
	}
	for c := byte('A'); c <= 'Z'; c++ {
		match := allowed[c] || allowed[c+('a'-'A')]
		if negated {
			match = allowed[c] && allowed[c+('a'-'A')]
		}
		allowed[c], allowed[c+('a'-'A')] = match, match
	}
	var folded []rune
	for c := 0; c < len(allowed); c++ {
		if !allowed[c] {
			continue
		}
		start := c
		for c+1 < len(allowed) && allowed[c+1] {
			c++
		}
		folded = append(folded, rune(start), rune(c))
	}
	for i := 0; i < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if hi < 128 {
			continue
		}
		if lo < 128 {
			lo = 128
		}
		if len(folded) > 0 && folded[len(folded)-1]+1 == lo {
			folded[len(folded)-1] = hi
		} else {
			folded = append(folded, lo, hi)
		}
	}
	r.Op, r.Rune = syntax.OpCharClass, folded
}
