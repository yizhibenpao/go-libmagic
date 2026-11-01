package libmagic

// file 5.41 uses glibc REG_EXTENDED|REG_NEWLINE in the C locale. Go's
// syntax errors have different codes and precedence, and its parser accepts
// some patterns glibc rejects. Follow regcomp.c's syntax checks on the original
// bytes, before normalization loses the bracket, escape and branch context.
type regexSyntaxCheck struct {
	pattern string
	pos     int
	groups  int
	closed  uint16
	fold    bool
}

var regexErrorMessages = [...]string{
	2:  "Invalid regular expression",
	3:  "Invalid collation character",
	4:  "Invalid character class name",
	5:  "Trailing backslash",
	6:  "Invalid back reference",
	7:  "Unmatched [, [^, [:, [., or [=",
	8:  `Unmatched ( or \(`,
	9:  `Unmatched \{`,
	10: `Invalid content of \{\}`,
	11: "Invalid range end",
	13: "Invalid preceding regular expression",
	15: "Regular expression too big",
}

func regexErrorCode(pattern string, fold bool) int {
	p := regexSyntaxCheck{pattern: pattern, fold: fold}
	return p.expression(false)
}

func (p *regexSyntaxCheck) atEnd() bool { return p.pos == len(p.pattern) }

func (p *regexSyntaxCheck) expression(nested bool) int {
	initial := p.closed
	if code := p.branch(nested); code != 0 {
		return code
	}
	for !p.atEnd() && p.pattern[p.pos] == '|' {
		p.pos++
		if p.atEnd() || p.pattern[p.pos] == '|' || nested && p.pattern[p.pos] == ')' {
			continue
		}
		accumulated := p.closed
		p.closed = initial
		if code := p.branch(nested); code != 0 {
			return code
		}
		p.closed |= accumulated
	}
	return 0
}

func (p *regexSyntaxCheck) branch(nested bool) int {
	for !p.atEnd() && p.pattern[p.pos] != '|' && !(nested && p.pattern[p.pos] == ')') {
		c := p.pattern[p.pos]
		p.pos++
		switch c {
		case '*', '+', '?', '{':
			return 13
		case '(':
			p.groups++
			group := p.groups
			if code := p.expression(true); code != 0 {
				return code
			}
			if p.atEnd() {
				return 8
			}
			p.pos++ // Closing parenthesis.
			if group <= 9 {
				p.closed |= 1 << uint(group-1)
			}
		case '[':
			if code := p.bracket(); code != 0 {
				return code
			}
		case '\\':
			if p.atEnd() {
				return 5
			}
			c = p.pattern[p.pos]
			p.pos++
			if c >= '1' && c <= '9' && p.closed&(1<<uint(c-'1')) == 0 {
				return 6
			}
			if c == 'b' || c == 'B' || c == '<' || c == '>' || c == '`' || c == '\'' {
				continue // GNU anchors cannot be repeated.
			}
		case '^', '$':
			continue
		}
		for !p.atEnd() {
			switch p.pattern[p.pos] {
			case '*', '+', '?':
				p.pos++
			case '{':
				p.pos++
				if code := p.interval(); code != 0 {
					return code
				}
			default:
				goto next
			}
		}
	next:
	}
	return 0
}

func (p *regexSyntaxCheck) interval() int {
	start, token := p.number()
	if start == -1 {
		if token != ',' {
			return 10
		}
		start = 0
	}
	end := start
	if start != -2 && token == ',' {
		end, token = p.number()
	}
	if start == -2 || end == -2 {
		if token == 0 {
			return 9
		}
		return 10
	}
	if token != '}' || end != -1 && start > end {
		return 10
	}
	if end == -1 {
		end = start
	}
	if end > 32767 {
		return 15
	}
	return 0
}

// fetch_number keeps scanning an invalid number until comma, closing brace
// or EOF. In particular "a{q" is EBRACE, not BADBR. A quoted digit 1..9 is
// a backreference token, whereas quoted 0 remains a character token.
func (p *regexSyntaxCheck) number() (int, byte) {
	n := -1
	for !p.atEnd() {
		c := p.pattern[p.pos]
		p.pos++
		quoted := c == '\\'
		character := true
		if quoted && !p.atEnd() {
			c = p.pattern[p.pos]
			p.pos++
			character = c < '1' || c > '9'
		}
		if c == ',' || c == '}' && !quoted {
			return n, c
		}
		if !character || c < '0' || c > '9' || n == -2 {
			n = -2
		} else if n == -1 {
			n = int(c - '0')
		} else {
			n = n*10 + int(c-'0')
			if n > 32768 {
				n = 32768
			}
		}
	}
	return -2, 0
}

func (p *regexSyntaxCheck) bracket() int {
	if p.atEnd() {
		return 2
	}
	if p.pattern[p.pos] == '^' {
		p.pos++
		if p.atEnd() {
			return 2
		}
	}
	first := true
	for {
		kind, name, code := p.element(first)
		if code != 0 {
			return code
		}
		first = false
		ranged := false
		if kind != ':' && kind != '=' {
			if p.atEnd() {
				return 7
			}
			if p.pattern[p.pos] == '-' {
				if p.pos+1 == len(p.pattern) {
					return 7
				}
				if p.pattern[p.pos+1] != ']' {
					p.pos++
					endKind, end, code := p.element(true)
					if code != 0 {
						return code
					}
					if endKind == ':' || endKind == '=' {
						return 11
					}
					if len(name) != 1 || len(end) != 1 {
						return 3
					}
					if name[0] > end[0] {
						return 11
					}
					ranged = true
				}
			}
		}
		if !ranged {
			switch kind {
			case ':':
				switch name {
				case "alnum", "cntrl", "lower", "space", "alpha", "digit",
					"print", "upper", "blank", "graph", "punct", "xdigit":
				default:
					return 4
				}
			case '.', '=':
				if len(name) != 1 {
					return 3
				}
			}
		}
		if p.atEnd() {
			return 7
		}
		if p.pattern[p.pos] == ']' {
			p.pos++
			return 0
		}
	}
}

func (p *regexSyntaxCheck) element(acceptHyphen bool) (byte, string, int) {
	c := p.pattern[p.pos]
	p.pos++
	if c == '[' && !p.atEnd() {
		kind := p.pattern[p.pos]
		if kind == ':' || kind == '.' || kind == '=' {
			p.pos++
			start := p.pos
			for !p.atEnd() && p.pos-start < 32 {
				if p.pattern[p.pos] == kind && p.pos+1 < len(p.pattern) && p.pattern[p.pos+1] == ']' {
					name := p.pattern[start:p.pos]
					p.pos += 2
					if p.fold && kind != ':' && len(name) == 1 {
						name = string([]byte{byte(regexUpper(rune(name[0])))})
					}
					return kind, name, 0
				}
				p.pos++
			}
			return 0, "", 7
		}
	}
	if c == '-' && !acceptHyphen && (p.atEnd() || p.pattern[p.pos] != ']') {
		return 0, "", 11
	}
	if p.fold {
		c = byte(regexUpper(rune(c)))
	}
	return 0, string([]byte{c}), 0
}
