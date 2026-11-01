/*
 * Copyright (c) 2008, 2016 Christos Zoulas
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
	"bytes"
	"encoding/binary"
	"io"
	"strings"
)

// Compound-file reading and dispatch follow FILE5_41 cdf.c and readcdf.c.
// Stream bounds are allocated sector bounds, not the directory's logical size.
const cdfLoopLimit = 10000

var cdfSignature = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}
var cdfLE = binary.LittleEndian

type cdfInput struct {
	data   []byte
	reader io.ReaderAt
	ss     int
	short  int
	min    uint32
}

type cdfDirectory struct {
	name  [32]uint16
	kind  byte
	clsid [2]uint64
	first int32
	size  uint32
}

// FILE5_41 cdf_read uses the prefix or pread, without a stat-size bound.
func (c *cdfInput) read(pos int64, n int) ([]byte, bool) {
	if pos < 0 || n < 0 {
		return nil, false
	}
	if pos <= int64(len(c.data)) && int64(n) <= int64(len(c.data))-pos {
		return c.data[pos : pos+int64(n)], true
	}
	if c.reader == nil {
		return nil, false
	}
	b := make([]byte, n)
	nread, err := readMagicAt(c.reader, b, pos)
	return b, nread == n && err == nil
}

func (c *cdfInput) sector(id int32) ([]byte, bool) {
	if id < 0 {
		return nil, false
	}
	return c.read((int64(id)+1)*int64(c.ss), c.ss)
}

func (c *cdfInput) sat(h []byte) ([]byte, bool) {
	entries := 0
	for entries < 109 && cdfLE.Uint32(h[76+4*entries:]) != 0xffffffff {
		entries++
	}
	per := c.ss/4 - 1
	limit := uint64(0xffffffff) / (64 * uint64(c.ss))
	masters := uint64(cdfLE.Uint32(h[72:]))
	// For one/two-byte sectors C's unsigned per-sector count wraps to
	// SIZE_MAX; this limit rejects any nonzero master count.
	if uint64(entries) > limit || (per != 0 && masters > limit/uint64(per)) {
		return nil, false
	}
	capacity := masters*uint64(per) + uint64(entries)
	var table []byte
	for i := 0; i < 109; i++ {
		id := int32(cdfLE.Uint32(h[76+4*i:]))
		if id < 0 {
			break
		}
		b, ok := c.sector(id)
		if !ok {
			return nil, false
		}
		table = append(table, b...)
	}
	id := int32(cdfLE.Uint32(h[68:]))
	for j := uint64(0); j < masters; j++ {
		if id < 0 {
			break
		}
		if j >= cdfLoopLimit {
			return nil, false
		}
		master, ok := c.sector(id)
		if !ok || len(master) < 4 {
			return nil, false
		}
		for k := 0; k < per; k++ {
			sec := int32(cdfLE.Uint32(master[4*k:]))
			if sec < 0 {
				return table, true
			}
			if uint64(len(table)/c.ss) >= capacity {
				return nil, false
			}
			b, ok := c.sector(sec)
			if !ok {
				return nil, false
			}
			table = append(table, b...)
		}
		id = int32(cdfLE.Uint32(master[4*per:]))
	}
	return table, true
}

func cdfChain(table []byte, id int32) ([]int32, bool) {
	if id == -2 {
		return nil, true
	}
	var chain []int32
	for id >= 0 {
		if len(chain) >= cdfLoopLimit || int64(id) >= int64(len(table)/4) {
			return nil, false
		}
		chain = append(chain, id)
		id = int32(cdfLE.Uint32(table[int(id)*4:]))
	}
	return chain, len(chain) > 0
}

func (c *cdfInput) chainBytes(table []byte, id int32, short []byte) ([]byte, bool) {
	chain, ok := cdfChain(table, id)
	if !ok {
		return nil, false
	}
	var data []byte
	for _, sec := range chain {
		var b []byte
		if short == nil {
			b, ok = c.sector(sec)
		} else {
			pos := int64(sec) * int64(c.short)
			ok = pos <= int64(len(short)) && int64(c.short) <= int64(len(short))-pos
			if ok {
				b = short[pos : pos+int64(c.short)]
			}
		}
		if !ok {
			return nil, false
		}
		data = append(data, b...)
	}
	return data, true
}

func (c *cdfInput) directories(table []byte, id int32) ([]cdfDirectory, bool) {
	data, ok := c.chainBytes(table, id, nil)
	if !ok {
		return nil, false
	}
	var dirs []cdfDirectory
	for sector := 0; sector < len(data); sector += c.ss {
		for j := 0; j+128 <= c.ss; j += 128 {
			b := data[sector+j:][:128]
			d := cdfDirectory{kind: b[66], first: int32(cdfLE.Uint32(b[116:])), size: cdfLE.Uint32(b[120:])}
			for k := range d.name {
				d.name[k] = cdfLE.Uint16(b[2*k:])
			}
			d.clsid = [2]uint64{cdfLE.Uint64(b[80:]), cdfLE.Uint64(b[88:])}
			dirs = append(dirs, d)
		}
	}
	return dirs, true
}

func cdfFind(dirs []cdfDirectory, name string, kind byte) *cdfDirectory {
	for i := len(dirs) - 1; i >= 0; i-- {
		d := &dirs[i]
		if d.kind != kind || len(name) >= len(d.name) || d.name[len(name)] != 0 {
			continue
		}
		match := true
		for j := range name {
			if d.name[j] != uint16(name[j]) {
				match = false
				break
			}
		}
		if match {
			return d
		}
	}
	return nil
}

func (c *cdfInput) stream(d *cdfDirectory, sat, ssat, short []byte) ([]byte, bool) {
	if d == nil {
		return nil, false
	}
	if d.size < c.min && short != nil {
		return c.chainBytes(ssat, d.first, short)
	}
	if d.size == 0 || d.first == -2 {
		return nil, false
	}
	return c.chainBytes(sat, d.first, nil)
}

func cdfSections(dirs []cdfDirectory, mime bool) string {
	sections := []struct {
		name, mime string
		streams    []string
	}{
		{"Encrypted", "encrypted", []string{"EncryptedPackage", "EncryptedSummary"}},
		{"QuickBooks", "quickbooks", []string{"mfbu_header"}},
		{"Microsoft Excel", "vnd.ms-excel", []string{"Book", "Workbook"}},
		{"Microsoft Word", "msword", []string{"WordDocument"}},
		{"Microsoft PowerPoint", "vnd.ms-powerpoint", []string{"PowerPoint"}},
		{"Microsoft Outlook Message", "vnd.ms-outlook", []string{"__properties_version1.0", "__recip_version1.0_#00000000"}},
	}
	for _, s := range sections {
		for _, name := range s.streams {
			kind := byte(2)
			if name == "__recip_version1.0_#00000000" {
				kind = 1
			}
			if cdfFind(dirs, name, kind) != nil {
				if mime {
					return "application/" + s.mime
				}
				return "CDFV2 " + s.name
			}
		}
	}
	return ""
}

// The same open file supplies out-of-prefix sectors. Buffer calls have no
// reader and cannot silently fetch bytes beyond the supplied buffer.
func cdfDescription(data []byte, reader io.ReaderAt, mime bool) (string, bool) {
	h := data
	if len(h) < 512 {
		if reader == nil {
			return "", false
		}
		// FILE5_41 cdf_read_header/cdf_read falls back to pread when
		// the initial prefix does not contain the complete header.
		h = make([]byte, 512)
		if n, _ := readMagicAt(reader, h, 0); n != len(h) {
			return "", false
		}
	} else {
		h = h[:512]
	}
	if !bytes.HasPrefix(h, cdfSignature) {
		return "", false
	}
	shift, shortShift := cdfLE.Uint16(h[30:]), cdfLE.Uint16(h[32:])
	if shift > 20 || shortShift > 20 {
		return "", false
	}
	c := cdfInput{data: data, reader: reader, ss: 1 << shift, short: 1 << shortShift, min: cdfLE.Uint32(h[56:])}
	fallback := func(expn string) (string, bool) {
		if mime {
			return "application/CDFV2", true
		}
		return "Composite Document File V2 Document, " + expn, true
	}
	sat, ok := c.sat(h)
	if !ok {
		return fallback("Can't read SAT")
	}
	ssat, ok := c.chainBytes(sat, int32(cdfLE.Uint32(h[60:])), nil)
	if !ok {
		return fallback("Can't read SSAT")
	}
	dirs, ok := c.directories(sat, int32(cdfLE.Uint32(h[48:])))
	if !ok {
		return fallback("Can't read directory")
	}
	var root *cdfDirectory
	var short []byte
	for i := range dirs {
		if dirs[i].kind == 5 {
			root = &dirs[i]
			break
		}
	}
	if root != nil && root.first >= 0 {
		short, ok = c.stream(root, sat, nil, nil)
		if !ok {
			return fallback("Cannot read short stream")
		}
	}
	if b, ok := c.stream(cdfFind(dirs, "FileHeader", 2), sat, ssat, short); ok && bytes.HasPrefix(b, []byte("HWP Document File")) {
		if mime {
			return "application/x-hwp", true
		}
		return "Hangul (Korean) Word Processor File 5.x", true
	}
	var out strings.Builder
	for _, name := range []string{"\x05SummaryInformation", "\x05DocumentSummaryInformation"} {
		b, ok := c.stream(cdfFind(dirs, name, 2), sat, ssat, short)
		if !ok {
			continue
		}
		if cdfSummary(&out, b, root, dirs, mime) {
			return out.String(), true
		}
	}
	if s := cdfSections(dirs, mime); s != "" {
		out.WriteString(s)
	} else {
		s, _ := fallback("Cannot read section info")
		out.WriteString(s)
	}
	return out.String(), true
}
