/*
 * Copyright (c) Christos Zoulas 2017.
 * All Rights Reserved.
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

import "io"

// tail is buffer_init's fd/status snapshot and its lazy raw end window.
// Text normalization starts a fresh cache but keeps the same fd/status.
type tail struct {
	reader  io.ReaderAt
	size    int64
	regular bool
	done    bool
	buf     []byte
}

// loadTail is FILE5_41 buffer_fill. A successful short pread keeps the
// requested window length; bytes not supplied by C's pread are unspecified.
func (s *state) loadTail(front []byte) ([]byte, bool) {
	if s.tail == nil {
		s.tail = &tail{}
	}
	if s.tail.done {
		return s.tail.buf, s.tail.buf != nil
	}
	s.tail.done = true
	s.tail.buf = nil
	if !s.tail.regular {
		return nil, false
	}
	n := len(front)
	if uint64(s.tail.size) < uint64(n) {
		n = int(s.tail.size)
	}
	buf := make([]byte, n)
	if _, err := readMagicAt(s.tail.reader, buf, s.tail.size-int64(n)); err != nil {
		return nil, false
	}
	s.tail.buf = buf
	// buffer_fill caches nonzero elen (including failure), not a zero window.
	s.tail.done = n != 0
	return buf, true
}
