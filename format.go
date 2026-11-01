package libmagic

import (
	"fmt"
	"strings"
)

// file_getbuffer escapes non-printing bytes in the wrapper's C locale.
// Unlike mprint's file_printable, it has no 511-byte output limit.
func magicResult(desc string, err error) (string, error) {
	if err != nil {
		return desc, err
	}
	var b strings.Builder
	for i := 0; i < len(desc) && desc[i] != 0; i++ {
		c := desc[i]
		if c >= 32 && c < 127 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\%03o", c)
		}
	}
	return b.String(), nil
}

func padNumber(text string, width int, zero bool, spec byte) string {
	if width <= len(text) {
		return text
	}
	fill := byte(' ')
	if zero {
		fill = '0'
	}
	sign := ""
	body := text
	if fill == '0' && len(text) > 0 && (text[0] == '-' || text[0] == '+') {
		sign = text[:1]
		body = text[1:]
	}
	pad := width - len(sign) - len(body)
	if pad < 0 {
		pad = 0
	}
	return sign + strings.Repeat(string(fill), pad) + body
}

type formatOptions struct {
	spec  byte
	width int
	prec  int
	zero  bool
	left  bool
	alt   bool
	short bool
	sign  byte
}

// FILE5_41 file_checkfmt treats an initial dot as a flag, before field width.
func formatError(desc string) string {
	for i := 0; i < len(desc); i++ {
		if desc[i] != '%' {
			continue
		}
		i++
		if i < len(desc) && desc[i] == '%' {
			continue
		}
		for i < len(desc) && strings.ContainsRune("#0.'+- ", rune(desc[i])) {
			i++
		}
		if i < len(desc) && desc[i] == '*' {
			return "* not allowed in format"
		}
		field := func(what string) string {
			var n int32
			for i < len(desc) && desc[i] >= '0' && desc[i] <= '9' {
				n = n*10 + int32(desc[i]-'0')
				i++
			}
			if n >= 1024 {
				return fmt.Sprintf("field %s too large: %d", what, n)
			}
			return ""
		}
		if msg := field("width"); msg != "" {
			return msg
		}
		if i < len(desc) && desc[i] == '.' {
			i++
			if msg := field("precision"); msg != "" {
				return msg
			}
		}
		var c byte
		if i < len(desc) {
			c = desc[i]
		}
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return "bad format char: " + string([]byte{c})
		}
	}
	return ""
}

func parseFormat(desc string) formatOptions {
	o := formatOptions{spec: 'd', prec: -1}
	for i := 0; i < len(desc); i++ {
		if desc[i] != '%' || i+1 >= len(desc) {
			continue
		}
		if desc[i+1] == '%' {
			i++
			continue
		}
		j := i + 1
		for j < len(desc) {
			switch desc[j] {
			case '#':
				o.alt = true
			case '0':
				o.zero = true
			case '-':
				o.left = true
				o.zero = false
			case '+':
				o.sign = '+'
			case ' ':
				if o.sign == 0 {
					o.sign = ' '
				}
			case '\'':
			default:
				goto flagsDone
			}
			j++
		}
	flagsDone:
		for j < len(desc) && desc[j] >= '0' && desc[j] <= '9' {
			o.width = o.width*10 + int(desc[j]-'0')
			j++
		}
		if j < len(desc) && desc[j] == '.' {
			j++
			o.prec = 0
			for j < len(desc) && desc[j] >= '0' && desc[j] <= '9' {
				o.prec = o.prec*10 + int(desc[j]-'0')
				j++
			}
		}
		for j < len(desc) && strings.ContainsRune("hqljztL", rune(desc[j])) {
			if desc[j] == 'h' {
				o.short = true
			}
			j++
		}
		if j < len(desc) {
			o.spec = desc[j]
		}
		return o
	}
	return o
}

func formatLayout(desc string) (spec byte, width, prec int, zero bool) {
	o := parseFormat(desc)
	return o.spec, o.width, o.prec, o.zero
}

func formatString(desc, text string) string {
	o := parseFormat(desc)
	if o.prec >= 0 && len(text) > o.prec {
		text = text[:o.prec]
	}
	return applyWidth(text, o)
}

func applyWidth(text string, o formatOptions) string {
	if o.width <= len(text) {
		return text
	}
	pad := strings.Repeat(" ", o.width-len(text))
	if o.left {
		return text + pad
	}
	if o.zero && o.spec != 's' && o.spec != 'c' {
		prefix := ""
		if len(text) > 0 && (text[0] == '-' || text[0] == '+' || text[0] == ' ') {
			prefix, text = text[:1], text[1:]
		} else if o.spec == 'x' && strings.HasPrefix(text, "0x") || o.spec == 'X' && strings.HasPrefix(text, "0X") {
			prefix, text = text[:2], text[2:]
		}
		return prefix + strings.Repeat("0", o.width-len(prefix)-len(text)) + text
	}
	return pad + text
}

func formatGUID(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		uint32(raw[0])|uint32(raw[1])<<8|uint32(raw[2])<<16|uint32(raw[3])<<24,
		uint16(raw[4])|uint16(raw[5])<<8,
		uint16(raw[6])|uint16(raw[7])<<8,
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
}

func trimString(s string) string {
	// file_strtrim uses C isspace. The loop stops at NUL, so a NUL
	// and the bytes after it stay. NBSP is not a C space.
	i := 0
	for i < len(s) && s[i] != 0 && isCSpace(s[i]) {
		i++
	}
	s = s[i:]
	j := 0
	for j < len(s) && s[j] != 0 {
		j++
	}
	end := j
	for end > 0 && isCSpace(s[end-1]) {
		end--
	}
	if end == j {
		return s
	}
	return s[:end] + s[j:]
}

func isCSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r'
}
