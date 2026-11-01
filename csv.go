/*-
 * Copyright (c) 2019 Christos Zoulas
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

// FILE5_41 counts comma separators on LF-terminated records, ignoring
// line breaks inside quotes and any unfinished last record. It stops at 10.
func csvDescription(data []byte, text bool) (string, bool) {
	if !text {
		return "", false
	}
	fields, expected, lines := 0, 0, 0
	for i := 0; i < len(data); {
		c := data[i]
		i++
		switch c {
		case '"':
			quote := false
			for i < len(data) {
				c = data[i]
				i++
				if c != '"' {
					if quote {
						i--
						break
					}
					continue
				}
				quote = !quote
			}
		case ',':
			fields++
		case '\n':
			lines++
			if lines == 10 {
				if expected != 0 && expected == fields {
					return "CSV text", true
				}
				return "", false
			}
			if expected == 0 {
				if fields == 0 {
					return "", false
				}
				expected = fields
			} else if expected != fields {
				return "", false
			}
			fields = 0
		}
	}
	if expected != 0 && lines > 2 {
		return "CSV text", true
	}
	return "", false
}
