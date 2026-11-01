/*-
 * Copyright (c) 2018 Christos Zoulas
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package libmagic

// FILE5_41 is_json.c is a format detector, not an RFC validation API.
// In particular it accepts a parsed container prefix without requiring EOF.
func jsonDescription(data []byte) (string, bool) {
	p := jsonProbe{data: data}
	p.space()
	if p.pos == len(data) || data[p.pos] != '{' && data[p.pos] != '[' {
		return "", false
	}
	if !p.value(0) {
		return "", false
	}
	return "JSON data", true
}

type jsonProbe struct {
	data []byte
	pos  int
}

func (p *jsonProbe) space() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\n', '\r', '\t':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonProbe) value(level int) bool {
	p.space()
	if p.pos == len(p.data) || level > 20 {
		return false
	}
	c := p.data[p.pos]
	p.pos++
	var ok bool
	switch c {
	case '"':
		ok = p.stringValue()
	case '[':
		ok = p.array(level + 1)
	case '{':
		ok = p.object(level + 1)
	case 't', 'n':
		ok = p.constant(3)
	case 'f':
		ok = p.constant(4)
	default:
		p.pos--
		ok = p.number()
	}
	p.space()
	return ok
}

func (p *jsonProbe) stringValue() bool {
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		p.pos++
		switch c {
		case 0:
			return false
		case '"':
			return true
		case '\\':
			if p.pos == len(p.data) {
				return false
			}
			c = p.data[p.pos]
			p.pos++
			switch c {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				if len(p.data)-p.pos < 4 {
					return false
				}
				for i := 0; i < 4; i++ {
					c = p.data[p.pos]
					p.pos++
					if !jsonDigit(c) && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
						return false
					}
				}
			default:
				return false
			}
		}
	}
	return false
}

func (p *jsonProbe) array(level int) bool {
	for p.pos < len(p.data) {
		if p.data[p.pos] == ']' {
			p.pos++
			return true
		}
		if !p.value(level+1) || p.pos == len(p.data) {
			return false
		}
		c := p.data[p.pos]
		p.pos++
		switch c {
		case ',':
		case ']':
			return true
		default:
			return false
		}
	}
	return false
}

func (p *jsonProbe) object(level int) bool {
	for p.pos < len(p.data) {
		p.space()
		if p.pos == len(p.data) {
			return false
		}
		c := p.data[p.pos]
		p.pos++
		if c == '}' {
			return true
		}
		if c != '"' || !p.stringValue() {
			return false
		}
		p.space()
		if p.pos == len(p.data) || p.data[p.pos] != ':' {
			return false
		}
		p.pos++
		if !p.value(level+1) || p.pos == len(p.data) {
			return false
		}
		c = p.data[p.pos]
		p.pos++
		switch c {
		case ',':
		case '}':
			return true
		default:
			return false
		}
	}
	return false
}

func jsonDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *jsonProbe) number() bool {
	if p.pos == len(p.data) {
		return false
	}
	if p.data[p.pos] == '-' {
		p.pos++
	}
	got := false
	for p.pos < len(p.data) && jsonDigit(p.data[p.pos]) {
		p.pos++
		got = true
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
	}
	for p.pos < len(p.data) && jsonDigit(p.data[p.pos]) {
		p.pos++
		got = true
	}
	if got && p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		got = false
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		for p.pos < len(p.data) && jsonDigit(p.data[p.pos]) {
			p.pos++
			got = true
		}
	}
	return got
}

// 5.41 json_parse_const advances through each suffix byte even on a
// mismatch. Preserve that observable detector behavior; do not use this
// implementation to validate or consume untrusted JSON as application data.
func (p *jsonProbe) constant(suffix int) bool {
	if len(p.data)-p.pos <= suffix {
		p.pos = len(p.data)
		return false
	}
	p.pos += suffix
	return true
}
