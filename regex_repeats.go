package libmagic

import (
	"fmt"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"
)

type regexRepeat struct {
	min, max int
}

// GNU ERE applies consecutive duplications in order and accepts counts through
// RE_DUP_MAX (32767). Go's parser rejects consecutive operators and counts above
// 1000, including products of nested counts. Parse atoms with temporary captures,
// then restore repetitions directly in the syntax tree, without copying captures.
func parseRegexRepeats(pat string) (*syntax.Regexp, error) {
	var out string
	var groups []int
	repeats := make(map[string]regexRepeat)
	last := -1
	for i := 0; i < len(pat); {
		start, end := i, i+1
		switch pat[i] {
		case '(':
			groups = append(groups, len(out))
			if strings.HasPrefix(pat[i:], "(?P<") {
				if j := strings.IndexByte(pat[i:], '>'); j >= 0 {
					end = i + j + 1
				}
			}
			last = -1
		case ')':
			if len(groups) == 0 {
				return syntax.Parse(pat, regexSyntax)
			}
			last = groups[len(groups)-1]
			groups = groups[:len(groups)-1]
		case '|', '^', '$':
			last = -1
		case '[':
			for end < len(pat) {
				end++
				if pat[end-1] == ']' {
					if _, err := syntax.Parse(pat[i:end], regexSyntax); err == nil {
						break
					}
				}
			}
			last = len(out)
		case '\\':
			if end < len(pat) {
				end++
			}
			last = len(out)
		case '*', '+', '?', '{':
			if last < 0 {
				return nil, &syntax.Error{Code: syntax.ErrMissingRepeatArgument, Expr: pat[i:]}
			}
			r := regexRepeat{max: -1}
			switch pat[i] {
			case '+':
				r.min = 1
			case '?':
				r.max = 1
			case '{':
				j := strings.IndexByte(pat[i:], '}')
				if j < 0 {
					return nil, &syntax.Error{Code: syntax.ErrInvalidRepeatSize, Expr: pat[i:]}
				}
				end = i + j + 1
				bounds := strings.Split(pat[i+1:end-1], ",")
				if len(bounds) > 2 || len(bounds) == 1 && bounds[0] == "" {
					return nil, &syntax.Error{Code: syntax.ErrInvalidRepeatSize, Expr: pat[i:end]}
				}
				r.max = 0
				for k, bound := range bounds {
					n := 0
					if bound != "" {
						for _, c := range bound {
							if c < '0' || c > '9' {
								return nil, &syntax.Error{Code: syntax.ErrInvalidRepeatSize, Expr: pat[i:end]}
							}
						}
						var err error
						n, err = strconv.Atoi(bound)
						if err != nil || n > 32767 {
							return nil, &syntax.Error{Code: syntax.ErrInvalidRepeatSize, Expr: pat[i:end]}
						}
					} else if k == 1 {
						n = -1
					}
					if k == 0 {
						r.min, r.max = n, n
					} else {
						r.max = n
					}
				}
				if r.max >= 0 && r.min > r.max {
					return nil, &syntax.Error{Code: syntax.ErrInvalidRepeatSize, Expr: pat[i:end]}
				}
			}
			name := fmt.Sprintf("magicRepeat%d", len(repeats))
			repeats[name] = r
			out = out[:last] + "(?P<" + name + ">" + out[last:] + ")"
			i = end
			continue
		default:
			_, size := utf8.DecodeRuneInString(pat[i:])
			end = i + size
			last = len(out)
		}
		out += pat[start:end]
		i = end
	}
	if strings.Contains(out, "(?P<magicGNU") {
		out = protectRegexAlternatives(out, repeats)
	}
	tree, err := syntax.Parse(out, regexSyntax)
	if err != nil {
		return nil, err
	}
	cap := 0
	return restoreRegexRepeats(tree, repeats, &cap), nil
}

func restoreRegexRepeats(tree *syntax.Regexp, repeats map[string]regexRepeat, cap *int) *syntax.Regexp {
	if tree.Op == syntax.OpCapture {
		if r, ok := repeats[tree.Name]; ok {
			child := restoreRegexRepeats(tree.Sub[0], repeats, cap)
			return &syntax.Regexp{Op: syntax.OpRepeat, Min: r.min, Max: r.max, Sub: []*syntax.Regexp{child}}
		}
		// Removing temporary captures restores the numbering used by
		// normalizeRegex's GNU backreferences and directional markers.
		*cap++
		tree.Cap = *cap
	}
	for i, child := range tree.Sub {
		tree.Sub[i] = restoreRegexRepeats(child, repeats, cap)
	}
	return tree
}

// protectRegexAlternatives keeps GNU branches distinct before Go's parser
// factors common prefixes or merges alternatives into a character class.
func protectRegexAlternatives(text string, repeats map[string]regexRepeat) string {
	pos := 0
	var group func() string
	group = func() string {
		var part strings.Builder
		var branches []string
		for pos < len(text) && text[pos] != ')' {
			start := pos
			switch text[pos] {
			case '\\':
				pos++
				if pos < len(text) {
					pos++
				}
				part.WriteString(text[start:pos])
			case '[':
				pos++
				for pos < len(text) {
					pos++
					if text[pos-1] == ']' {
						if _, err := syntax.Parse(text[start:pos], regexSyntax); err == nil {
							break
						}
					}
				}
				part.WriteString(text[start:pos])
			case '(':
				pos++
				if strings.HasPrefix(text[start:], "(?P<") {
					if end := strings.IndexByte(text[start:], '>'); end >= 0 {
						pos = start + end + 1
					}
				}
				part.WriteString(text[start:pos])
				part.WriteString(group())
				if pos < len(text) && text[pos] == ')' {
					part.WriteByte(')')
					pos++
				}
			case '|':
				branches = append(branches, part.String())
				part.Reset()
				pos++
			default:
				part.WriteByte(text[pos])
				pos++
			}
		}
		if len(branches) == 0 {
			return part.String()
		}
		branches = append(branches, part.String())
		for i, branch := range branches {
			name := fmt.Sprintf("magicAlternative%d", len(repeats))
			repeats[name] = regexRepeat{min: 1, max: 1}
			branches[i] = "(?P<" + name + ">" + branch + ")"
		}
		return strings.Join(branches, "|")
	}
	return group()
}
