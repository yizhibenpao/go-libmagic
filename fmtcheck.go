/*
 * Copyright (c) Ian F. Darwin 1986-1995.
 * Software written by Ian F. Darwin and others;
 * maintained 1995-present by Christos Zoulas and others.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code was contributed to The NetBSD Foundation by Allen Briggs.
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
	"strings"
)

// FILE5_41 fmtcheck.c (NetBSD 1.8), using its Linux/C-locale argument types.
// This checks the arguments, not whether libc can render a conversion.
type fmtKind uint8

const (
	fmtStart fmtKind = iota
	fmtInt
	fmtLong
	fmtQuad
	fmtShortPointer
	fmtIntPointer
	fmtLongPointer
	fmtQuadPointer
	fmtDouble
	fmtLongDouble
	fmtString
	fmtWidth
	fmtPrecision
	fmtDone
	fmtUnknown
)

func fmtMatches(actual, expected string) bool {
	actual, expected = actual[:cLen(actual)], expected[:cLen(expected)]
	a, b := 0, 0
	ak, bk := fmtStart, fmtStart
	for {
		ak = nextFmt(actual, &a, ak)
		if ak == fmtDone {
			return true // Unused supplied arguments are allowed.
		}
		if ak == fmtUnknown {
			return false
		}
		bk = nextFmt(expected, &b, bk)
		if ak != bk {
			return false
		}
	}
}

func (s *state) checkNativeFormat(desc, def string, line int) bool {
	if fmtMatches(desc, def) {
		return true
	}
	s.magerror(fmt.Sprintf("softmagic.c, %d: format `%s' does not match with `%s'", line, desc, def))
	return false
}

func nextFmt(s string, pos *int, last fmtKind) fmtKind {
	if last == fmtPrecision {
		*pos++
		return fmtConversion(s, pos)
	}
	if last == fmtWidth {
		*pos++
		return fmtAfterWidth(s, pos)
	}
	for {
		n := strings.IndexByte(s[*pos:], '%')
		if n < 0 {
			*pos = len(s)
			return fmtDone
		}
		*pos += n + 1
		if *pos == len(s) {
			return fmtUnknown
		}
		if s[*pos] != '%' {
			break
		}
		*pos++
	}
	for *pos < len(s) && strings.ContainsRune("#0- +", rune(s[*pos])) {
		*pos++
	}
	if *pos < len(s) && s[*pos] == '*' {
		return fmtWidth
	}
	fmtDigits(s, pos)
	return fmtAfterWidth(s, pos)
}

func fmtDigits(s string, pos *int) {
	for *pos < len(s) && s[*pos] >= '0' && s[*pos] <= '9' {
		*pos++
	}
}

func fmtAfterWidth(s string, pos *int) fmtKind {
	if *pos < len(s) && s[*pos] == '.' {
		*pos++
		if *pos < len(s) && s[*pos] == '*' {
			return fmtPrecision
		}
		fmtDigits(s, pos)
	}
	return fmtConversion(s, pos)
}

func fmtConversion(s string, pos *int) fmtKind {
	length := byte(0)
	if *pos < len(s) {
		switch s[*pos] {
		case 'h', 'q', 'L':
			length = s[*pos]
			*pos++
		case 'l':
			length = 'l'
			*pos++
			if *pos < len(s) && s[*pos] == 'l' {
				length = 'q'
				*pos++
			}
		}
	}
	if *pos == len(s) {
		return fmtUnknown
	}
	spec := s[*pos] // Leave the cursor on the conversion, like the C code.
	if strings.ContainsRune("diouxX", rune(spec)) {
		switch length {
		case 'L':
			return fmtUnknown
		case 'l':
			return fmtLong
		case 'q':
			return fmtQuad
		default:
			return fmtInt // h still consumes a promoted int.
		}
	}
	if spec == 'n' {
		switch length {
		case 'L':
			return fmtUnknown
		case 'h':
			return fmtShortPointer
		case 'l':
			return fmtLongPointer
		case 'q':
			return fmtQuadPointer
		default:
			return fmtIntPointer
		}
	}
	if strings.ContainsRune("eEfg", rune(spec)) {
		if length == 'L' {
			return fmtLongDouble
		}
		if length == 0 {
			return fmtDouble
		}
		return fmtUnknown
	}
	if length != 0 {
		return fmtUnknown
	}
	switch spec {
	case 'D', 'O', 'U', 'p':
		return fmtLong
	case 'c':
		return fmtInt
	case 's':
		return fmtString
	}
	return fmtUnknown
}

// FILE5_41 check_fmt uses %[-0-9\.]*s as a POSIX ERE, without skipping %%.
// In glibc's bracket expression, both the backslash and dot are literal.
func numericStringFormat(desc string) bool {
	desc = desc[:cLen(desc)]
	for i := 0; i < len(desc); i++ {
		if desc[i] != '%' {
			continue
		}
		j := i + 1
		for j < len(desc) && (desc[j] == '-' || desc[j] == '.' || desc[j] == '\\' || desc[j] >= '0' && desc[j] <= '9') {
			j++
		}
		if j < len(desc) && desc[j] == 's' {
			return true
		}
	}
	return false
}

// Return the exact F() default and source callsite used by FILE5_41 mprint.
func nativePrintFormat(m *entry, desc string) (def string, line int, asString bool) {
	switch m.typ {
	case typeByte:
		line = 617
	case typeShort, typeBEShort, typeLEShort:
		line = 622
	case typeLong, typeBELong, typeLELong, typeMELong:
		line = 628
	case typeQuad, typeBEQuad, typeLEQuad, typeOffset:
		line = 634
	case typeFloat, typeBEFloat, typeLEFloat:
		line = 734
		if numericStringFormat(desc) {
			return "%s", 730, true
		}
		return "%g", line, false
	case typeDouble, typeBEDouble, typeLEDouble:
		line = 754
		if numericStringFormat(desc) {
			return "%s", 750, true
		}
		return "%g", line, false
	case typeString, typePString, typeBEStr16, typeLEStr16:
		if m.reln == '=' || m.reln == '!' {
			return "%s", 641, false
		}
		return "%s", 659, false
	case typeDate, typeBEDate, typeLEDate, typeMEDate:
		return "%s", 677, false
	case typeLDate, typeBELDate, typeLELDate, typeMELDate:
		return "%s", 687, false
	case typeQDate, typeBEQDate, typeLEQDate:
		return "%s", 696, false
	case typeQLDate, typeBEQLDate, typeLEQLDate:
		return "%s", 705, false
	case typeQWDate, typeBEQWDate, typeLEQWDate:
		return "%s", 714, false
	case typeSearch, typeRegex:
		return "%s", 774, false
	case typeDER:
		return "%s", 801, false
	case typeGUID:
		return "%s", 809, false
	default:
		return "", 0, false
	}
	if numericStringFormat(desc) {
		return "%s", line, true
	}
	def = "%d"
	if line == 634 {
		def = "%lld"
	}
	if m.flag&flagUnsigned != 0 {
		def = strings.TrimSuffix(def, "d") + "u"
	}
	return def, line, false
}
