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

import (
	"errors"
	"fmt"
	"strings"
)

// textDescription is FILE5_41 file_ascmagic followed by
// file_ascmagic_with_encoding. Language recognition comes from the loaded
// TEXTTEST rules, never from a second hard-coded set of language guesses.
func (db *Database) textDescription(source *tail, data []byte, mime, text bool, prefix string, elfFlag string, previous value, previousSearch search, previousLine uint32) (string, bool, error) {
	trimmed := trimNuls(data)
	if len(trimmed)&1 != 0 && len(data)&1 == 0 {
		trimmed = data[:len(trimmed)+1]
	}
	enc := detectEncoding(trimmed)
	if !enc.text || len(trimNuls(trimmed)) <= 1 {
		return "", false, nil
	}
	if len(enc.characters) > 0 && enc.normalized == nil {
		// encode_utf8 fails without setting magic_error in this C branch.
		return "", false, errors.New("")
	}
	desc := ""
	if len(enc.characters) > 0 {
		// ascmagic initializes a new buffer for normalized text.
		end := &tail{reader: source.reader, size: source.size, regular: source.regular}
		indir := 0
		for i := range db.sets {
			st := &state{db: db, set: &db.sets[i], value: previous, search: previousSearch, line: previousLine, mime: mime, text: text, buf: &strings.Builder{}, tail: end, elfFlag: elfFlag}
			matched := st.soft(enc.normalized, 0, flagTextTest, &indir, 0)
			previous = st.value
			previousSearch = st.search
			previousLine = st.line
			if st.err != nil {
				return "", false, st.err
			}
			if matched {
				desc = st.buf.String()
				break
			}
		}
	}
	if mime {
		if desc == "" {
			desc = "text/plain"
		}
		return desc, true, nil
	}
	executable := false
	switch {
	case strings.HasSuffix(desc, " text"):
		desc = strings.TrimSuffix(desc, " text") + ", "
	case strings.HasSuffix(desc, " text executable"):
		desc = strings.TrimSuffix(desc, " text executable") + ", "
		executable = true
	case desc != "" || prefix != "":
		desc += ", "
	}
	desc += enc.label
	if executable {
		desc += " executable"
	}
	return desc + textProperties(enc.characters, len(trimNuls(trimmed))), true, nil
}

// Properties use decoded character indices, including the 5.41 treatment of
// UTF-16 code units. Counting UTF-8 bytes changes both long lines and NEL.
func textProperties(chars []uint32, nbytes int) string {
	crlf, lf, cr, nel := 0, 0, 0, 0
	seenCR, escapes, backspace := false, false, false
	lastEnd, longest := -1, 0
	for i, c := range chars {
		if c == '\n' {
			if seenCR {
				crlf++
			} else {
				lf++
			}
			lastEnd = i
		} else if seenCR {
			cr++
		}
		seenCR = c == '\r'
		if seenCR {
			lastEnd = i
		}
		if c == 0x85 {
			nel++
			lastEnd = i
		}
		if i > lastEnd+300 && i-lastEnd > longest {
			longest = i - lastEnd
		}
		escapes = escapes || c == 0x1b
		backspace = backspace || c == '\b'
	}
	if seenCR && nbytes < fileBytesMax {
		cr++
	}
	var result strings.Builder
	if longest != 0 {
		fmt.Fprintf(&result, ", with very long lines (%d)", longest)
	}
	if crlf == 0 && cr == 0 && nel == 0 && lf == 0 {
		result.WriteString(", with no line terminators")
	} else if crlf != 0 || cr != 0 || nel != 0 {
		var terms []string
		if crlf != 0 {
			terms = append(terms, "CRLF")
		}
		if cr != 0 {
			terms = append(terms, "CR")
		}
		if lf != 0 {
			terms = append(terms, "LF")
		}
		if nel != 0 {
			terms = append(terms, "NEL")
		}
		result.WriteString(", with " + strings.Join(terms, ", ") + " line terminators")
	}
	if escapes {
		result.WriteString(", with escape sequences")
	}
	if backspace {
		result.WriteString(", with overstriking")
	}
	return result.String()
}
