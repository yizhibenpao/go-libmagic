/*-
 * Copyright (c) 2016 Christos Zoulas
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

import (
	"fmt"
)

const derBad = ^uint32(0)

var derTags = []string{
	"eoc", "bool", "int", "bit_str", "octet_str",
	"null", "obj_id", "obj_desc", "ext", "real",
	"enum", "embed", "utf8_str", "rel_oid", "time",
	"res2", "seq", "set", "num_str", "prt_str",
	"t61_str", "vid_str", "ia5_str", "utc_time", "gen_time",
	"gr_str", "vis_str", "gen_str", "univ_str", "char_str",
	"bmp_str", "date", "tod", "datetime", "duration",
	"oid-iri", "rel-oid-iri",
}

func (s *state) copyDER(data []byte, off int) bool {
	if off > len(data) {
		off = len(data)
	}
	s.search.s = data[off:]
	s.search.offset = off
	return true
}

func (s *state) derMatch(m *entry) bool {
	b := s.search.s
	offs := 0
	tag, ok := derTag(b, &offs)
	if !ok {
		return false
	}
	tlen, ok := derLength(b, &offs)
	if !ok {
		return false
	}
	got := derTagName(tag)
	want := cString(m.value[:])
	if len(want) < len(got) || want[:len(got)] != got {
		return false
	}
	rest := want[len(got):]
	for {
		if rest == "" {
			if !m.version16 {
				s.value.text = derData(tag, b[offs:], tlen)
			}
			return true
		}
		if rest[0] == '=' {
			data := derData(tag, b[offs:], tlen)
			if data != rest[1:] && rest[1:] != "x" {
				return false
			}
			s.value.text = data
			if m.version16 {
				n := copy(s.value.raw[:len(s.value.raw)-1], data)
				s.value.raw[n] = 0 // strlcpy does not clear the remaining bytes.
			}
			return true
		}
		if rest[0] < '0' || rest[0] > '9' {
			return false
		}
		var n uint64
		for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
			n = n*10 + uint64(rest[0]-'0')
			rest = rest[1:]
		}
		if uint64(tlen) != n {
			return false
		}
	}
}

func (s *state) derOffset(m *entry, nbytes int) (int, bool) {
	b := s.search.s
	length := len(b)
	if length == 0 {
		length = nbytes
	}
	offs := 0
	if _, ok := derTag(b, &offs); !ok {
		return 0, false
	}
	tlen, ok := derLength(b, &offs)
	if !ok {
		return 0, false
	}
	out := offs + s.offset + int(m.offset)
	if m.contLevel != 0 {
		if out+int(tlen) > nbytes {
			return 0, false
		}
		s.ensureLevel(int(m.contLevel) - 1)
		s.levels[m.contLevel-1].off = int32(out + int(tlen))
	}
	return out, true
}

func derTag(c []byte, p *int) (uint32, bool) {
	if *p >= len(c) {
		return 0, false
	}
	tag := uint32(c[*p] & 0x1f)
	*p++
	if tag != 0x1f {
		return tag, true
	}
	if *p >= len(c) {
		return 0, false
	}
	for c[*p] >= 0x80 {
		tag = tag*128 + uint32(c[*p]-0x80)
		*p++
		if *p >= len(c) {
			return 0, false
		}
	}
	return tag, tag != derBad
}

func derLength(c []byte, p *int) (uint32, bool) {
	if *p >= len(c) {
		return 0, false
	}
	one := c[*p]&0x80 == 0
	digits := int(c[*p] & 0x7f)
	*p++
	if *p+digits >= len(c) {
		return 0, false
	}
	if one {
		return uint32(digits), true
	}
	// FILE5_41 accumulates all declared digits in 64-bit size_t.
	// Zero digits and leading zeroes beyond four bytes are not rejected.
	var n uint64
	for i := 0; i < digits; i++ {
		n = n<<8 | uint64(c[*p])
		*p++
	}
	if n > uint64(derBad)-uint64(*p) || n > uint64(len(c)-*p) {
		return 0, false
	}
	return uint32(n), true
}

func derTagName(tag uint32) string {
	if int(tag) < len(derTags) {
		return derTags[tag]
	}
	return fmt.Sprintf("%#x", tag)
}

func derData(tag uint32, q []byte, n uint32) string {
	if int(n) > len(q) {
		n = uint32(len(q))
	}
	d := q[:n]
	switch tag {
	case 0x13, 0x0c, 0x16:
		if len(d) > 127 {
			d = d[:127] // snprintf's 128-byte buffer includes its NUL.
		}
		return cString(d)
	case 0x17:
		if n < 12 {
			break
		}
		text := "20" + string(d[:2]) + "-" + string(d[2:4]) + "-" + string(d[4:6]) +
			" " + string(d[6:8]) + ":" + string(d[8:10]) + ":" + string(d[10:12]) + " GMT"
		return text[:cLen(text)] // %c inserts raw bytes, including NUL.
	}
	if len(d) == 0 {
		// der_cmp seeded the same buffer with der_tag; an empty hex
		// loop does not overwrite that text.
		return derTagName(tag)
	}
	if len(d) > 63 {
		d = d[:63] // The native loop writes only while 2*i < 128-2.
	}
	return fmt.Sprintf("%x", d)
}

func pascalLengthSize(flags uint32) (int, bool) {
	switch flags & pstringLen {
	case pstring1BE:
		return 1, true
	case pstring2LE, pstring2BE:
		return 2, true
	case pstring4LE, pstring4BE:
		return 4, true
	default:
		return 0, false
	}
}

func pascalLength(flags uint32, s []byte) (uint64, bool) {
	size, ok := pascalLengthSize(flags)
	if !ok || len(s) < size {
		return 0, false
	}
	var n uint64
	switch flags & pstringLen {
	case pstring1BE:
		n = uint64(s[0])
	case pstring2LE:
		n = uint64(s[1])<<8 | uint64(s[0])
	case pstring2BE:
		n = uint64(s[0])<<8 | uint64(s[1])
	case pstring4LE:
		n = uint64(s[3])<<24 | uint64(s[2])<<16 | uint64(s[1])<<8 | uint64(s[0])
	case pstring4BE:
		n = uint64(s[0])<<24 | uint64(s[1])<<16 | uint64(s[2])<<8 | uint64(s[3])
	}
	if flags&pstringLenIncludesItself != 0 {
		n -= uint64(size)
	}
	// FILE5_41 uses 64-bit size_t on the supported Linux targets.
	// Only SIZE_MAX is FILE_BADSIZE; other wrapped values are clipped.
	return n, n != ^uint64(0)
}

func pascalBody(m *entry, raw []byte) ([]byte, bool) {
	size, ok := pascalLengthSize(m.strFlags)
	if !ok {
		return nil, false
	}
	n, ok := pascalLength(m.strFlags, raw)
	if !ok {
		return nil, false
	}
	if n > uint64(len(raw)-size) {
		n = uint64(len(raw) - size)
	}
	return raw[size : size+int(n)], true
}
