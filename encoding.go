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
package libmagic

import "encoding/binary"

const encodingBytesMax = 65536

type encodingKind uint8

const (
	encodingBinary encodingKind = iota
	encodingASCII
	encodingUTF8
	encodingUTF8BOM
	encodingUTF16LE
	encodingUTF16BE
	encodingUTF32LE
	encodingUTF32BE
	encodingLatin1
	encodingExtended
	encodingEBCDIC
	encodingInternationalEBCDIC
	encodingUTF7
)

type encodingInfo struct {
	kind       encodingKind
	text       bool
	label      string
	characters []uint32
	normalized []byte
}

// detectEncoding follows FILE5_41 encoding.c. Unlike ascmagic, the first
// encoding pass does not trim NULs. Both passes examine at most 65536 bytes.
func detectEncoding(data []byte) encodingInfo {
	if len(data) > encodingBytesMax {
		data = data[:encodingBytesMax]
	}
	if looksASCII(data) {
		if len(data) > 4 && data[0] == '+' && data[1] == '/' && data[2] == 'v' &&
			(data[3] == '8' || data[3] == '9' || data[3] == '+' || data[3] == '/') {
			return textEncoding(encodingUTF7, "Unicode text, UTF-7 text", nil)
		}
		return byteEncoding(encodingASCII, "ASCII text", data)
	}
	if len(data) > 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		if chars, status := decodeTextUTF8(data[3:]); status > 0 {
			return textEncoding(encodingUTF8BOM, "Unicode text, UTF-8 (with BOM) text", chars)
		}
	}
	if chars, status := decodeTextUTF8(data); status > 1 {
		return textEncoding(encodingUTF8, "Unicode text, UTF-8 text", chars)
	}
	if looksUCS32(data) {
		order, kind, label := binary.ByteOrder(binary.LittleEndian), encodingUTF32LE, "Unicode text, UTF-32, little-endian text"
		if data[0] == 0 {
			order, kind, label = binary.BigEndian, encodingUTF32BE, "Unicode text, UTF-32, big-endian text"
		}
		chars := make([]uint32, 0, (len(data)-4)/4)
		for i := 4; i+3 < len(data); i += 4 {
			chars = append(chars, order.Uint32(data[i:]))
		}
		return textEncoding(kind, label, chars)
	}
	if looksUCS16(data) {
		order, kind, label := binary.ByteOrder(binary.LittleEndian), encodingUTF16LE, "Unicode text, UTF-16, little-endian text"
		if data[0] == 0xfe {
			order, kind, label = binary.BigEndian, encodingUTF16BE, "Unicode text, UTF-16, big-endian text"
		}
		chars := make([]uint32, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			// 5.41 treats UTF-16 code units independently, including surrogates.
			chars = append(chars, uint32(order.Uint16(data[i:])))
		}
		return textEncoding(kind, label, chars)
	}
	if looksLatin1(data) {
		return byteEncoding(encodingLatin1, "ISO-8859 text", data)
	}
	if looksExtended(data) {
		return byteEncoding(encodingExtended, "Non-ISO extended-ASCII text", data)
	}
	translated := fromEBCDIC(data)
	if looksASCII(translated) {
		return byteEncoding(encodingEBCDIC, "EBCDIC text", translated)
	}
	if looksLatin1(translated) {
		return byteEncoding(encodingInternationalEBCDIC, "International EBCDIC text", translated)
	}
	return encodingInfo{kind: encodingBinary}
}

func byteEncoding(kind encodingKind, label string, data []byte) encodingInfo {
	chars := make([]uint32, len(data))
	for i, c := range data {
		chars[i] = uint32(c)
	}
	return textEncoding(kind, label, chars)
}

func textEncoding(kind encodingKind, label string, chars []uint32) encodingInfo {
	return encodingInfo{kind: kind, text: true, label: label, characters: chars, normalized: encodeTextUTF8(chars)}
}

func trimNuls(data []byte) []byte {
	end := len(data)
	for end > 1 && data[end-1] == 0 {
		end--
	}
	return data[:end]
}

func validUTF8(data []byte) bool {
	_, status := decodeTextUTF8(data)
	return status > 0
}

// Returns the 5.41 statuses: -1 invalid, 0 controls, 1 ASCII, 2 UTF-8.
// A final incomplete sequence is ignored, even below the encoding limit.
func decodeTextUTF8(data []byte) ([]uint32, int) {
	chars := make([]uint32, 0, len(data))
	gotOne, control := false, false
	for i := 0; i < len(data); {
		c := data[i]
		if c < 0x80 {
			control = control || textChars[c] != 1
			chars = append(chars, uint32(c))
			i++
			continue
		}
		var n int
		var value uint32
		low, high := byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			n, value = 2, uint32(c&0x1f)
		case c >= 0xe0 && c <= 0xef:
			n, value = 3, uint32(c&0x0f)
			if c == 0xe0 {
				low = 0xa0
			}
			if c == 0xed {
				high = 0x9f
			}
		case c >= 0xf0 && c <= 0xf4:
			n, value = 4, uint32(c&0x07)
			if c == 0xf0 {
				low = 0x90
			}
			if c == 0xf4 {
				high = 0x8f
			}
		default:
			return nil, -1
		}
		for j := 1; j < n; j++ {
			if i+j >= len(data) {
				goto done
			}
			b := data[i+j]
			if b < 0x80 || b > 0xbf || j == 1 && (b < low || b > high) {
				return nil, -1
			}
			value = value<<6 | uint32(b&0x3f)
		}
		chars = append(chars, value)
		gotOne = true
		i += n
	}
done:
	if control {
		return chars, 0
	}
	if gotOne {
		return chars, 2
	}
	return chars, 1
}

// FILE5_41 ascmagic.c encode_utf8 predates Unicode scalar restrictions.
// Preserve its 1..6 byte encoding instead of Go's replacement-rune behavior.
func encodeTextUTF8(chars []uint32) []byte {
	out := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c <= 0x7f {
			out = append(out, byte(c))
			continue
		}
		n, head := 0, byte(0)
		switch {
		case c <= 0x7ff:
			n, head = 2, 0xc0
		case c <= 0xffff:
			n, head = 3, 0xe0
		case c <= 0x1fffff:
			n, head = 4, 0xf0
		case c <= 0x3ffffff:
			n, head = 5, 0xf8
		case c <= 0x7fffffff:
			n, head = 6, 0xfc
		default:
			return nil
		}
		var encoded [6]byte
		for i := n - 1; i > 0; i-- {
			encoded[i] = 0x80 | byte(c&0x3f)
			c >>= 6
		}
		encoded[0] = head | byte(c)
		out = append(out, encoded[:n]...)
	}
	return out
}
