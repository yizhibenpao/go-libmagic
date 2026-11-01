/*
 * Copyright (c) Christos Zoulas 2003.
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

import (
	"io"
	"os"
)

// readMagicPrefix is the ordinary-file prefix read, separate from fd-based
// ELF/CDF/tail reads. The caller supplies FILE5_41's bytes_max budget.
func readMagicPrefix(reader io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, limit)
	n, err := readMagicPrefixOnce(reader, buf)
	if err != nil {
		n = 0
	}
	if err == io.EOF {
		err = nil
	}
	return buf[:n], err
}

// readMagicFile uses the opened descriptor's status, not the earlier path
// probe. FILE5_41 buffer_init retries a failed fstat after the prefix read.
func readMagicFile(file interface {
	io.Reader
	Stat() (os.FileInfo, error)
}) ([]byte, os.FileInfo, error) {
	data, info, readErr, _ := readMagicFileState(file)
	return data, info, readErr
}

func readMagicFileState(file interface {
	io.Reader
	Stat() (os.FileInfo, error)
}) ([]byte, os.FileInfo, error, error) {
	info, statErr := file.Stat()
	data, err := readMagicPrefix(file, fileBytesMax)
	if err != nil && len(data) == 0 {
		return data, info, err, statErr
	}
	if statErr != nil {
		info, statErr = file.Stat()
	}
	return data, info, err, statErr
}
