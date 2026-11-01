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
	"fmt"
	"math"
	"strconv"
	"strings"
)

type cdfProperty struct {
	id, kind uint32
	value    uint64
	text     []byte
}

func cdfProperties(b []byte) ([]cdfProperty, bool) {
	if len(b) < 48 {
		return nil, false
	}
	offset := uint64(cdfLE.Uint32(b[44:]))
	if offset > 0xffffffff/4 || offset+8 > uint64(len(b)) {
		return nil, false
	}
	length := uint64(cdfLE.Uint32(b[offset:]))
	count := uint64(cdfLE.Uint32(b[offset+4:]))
	// sizeof(cdf_property_info_t) is 24 on the target's 64-bit ABI.
	const propertyLimit = 0xffffffff / (64 * 24)
	end, table := offset+length, offset+8
	if length > 0xffffffff/64 || end > uint64(len(b)) || table >= end || count > propertyLimit {
		return nil, false
	}
	var props []cdfProperty
	capacity := count
	for i := uint64(0); i < count; i++ {
		if table+(i+1)*8 > uint64(len(b)) {
			return nil, false
		}
		pos := uint64(cdfLE.Uint32(b[table+i*8+4:]))
		if pos < 8 || pos > length {
			return nil, false
		}
		pos += offset
		if pos+4 > end {
			return nil, false
		}
		props = append(props, cdfProperty{})
		p := &props[i]
		p.id, p.kind = cdfLE.Uint32(b[table+i*8:]), cdfLE.Uint32(b[pos:])
		slen, elements := uint64(1), uint64(1)
		if p.kind&0x1000 != 0 {
			if pos+8 > end {
				return nil, false
			}
			slen, elements = 2, uint64(cdfLE.Uint32(b[pos+4:]))
			if elements == 0 || elements > 100000 {
				return nil, false
			}
		}
		if p.kind&0xe000 != 0 {
			continue
		}
		width := uint64(0)
		switch p.kind & 0xfff {
		case 2:
			width = 2
		case 3, 4, 11, 19:
			width = 4
		case 5, 20, 21, 64:
			width = 8
		case 30, 31:
			if elements > 1 {
				capacity += elements
				if capacity > propertyLimit {
					return nil, false
				}
			}
			for j := uint64(0); j < elements && i < count; j, i = j+1, i+1 {
				o := pos + slen*4
				if o+4 > end {
					return nil, false
				}
				n := uint64(cdfLE.Uint32(b[o:]))
				if o+4+n > end {
					return nil, false
				}
				if j != 0 {
					props = append(props, cdfProperty{})
				}
				props[i].text = b[o+4 : o+4+n]
				// Preserve FILE5_41's vector stepping, not PROPVARIANT's
				// conventional four-byte string alignment.
				slen += (n + 1) / 2
			}
			i--
		}
		if width > 0 && p.kind&0x1000 == 0 && pos+slen*4+width <= end {
			v := b[pos+slen*4:][:width]
			switch width {
			case 2:
				p.value = uint64(cdfLE.Uint16(v))
			case 4:
				p.value = uint64(cdfLE.Uint32(v))
			case 8:
				p.value = cdfLE.Uint64(v)
			}
		}
	}
	return props, true
}

var cdfPropertyNames = []string{
	"", "Code page", "Title", "Subject", "Author", "Keywords", "Comments",
	"Template", "Last Saved By", "Revision Number", "Total Editing Time",
	"Last Printed", "Create Time/Date", "Last Saved Time/Date",
	"Number of Pages", "Number of Words", "Number of Characters", "Thumbnail",
	"Name of Creating Application", "Security",
}

func cdfPropertyName(id uint32) string {
	if id > 0 && id < uint32(len(cdfPropertyNames)) {
		return cdfPropertyNames[id]
	}
	if id == 0x80000000 {
		return "Locale ID"
	}
	if id == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", id)
}

func cdfString(p cdfProperty) string {
	if len(p.text) <= 1 {
		return ""
	}
	step := 1
	if p.kind == 31 {
		step = 2
	}
	value := make([]byte, 0, 1024)
	for i := 0; i < len(p.text) && len(value) < 1024; i += step {
		ch := p.text[i]
		if ch == 0 {
			break
		}
		if ch >= 32 && ch <= 126 {
			value = append(value, ch)
		}
	}
	if len(value) == 1024 {
		value = value[:1023]
	}
	return string(value)
}

func cdfAppMIME(value string, directory bool) string {
	patterns := [][2]string{
		{"word", "msword"}, {"excel", "vnd.ms-excel"}, {"powerpoint", "vnd.ms-powerpoint"},
		{"crystal reports", "x-rpt"}, {"advanced installer", "vnd.ms-msi"},
		{"installshield", "vnd.ms-msi"}, {"microsoft patch compiler", "vnd.ms-msi"},
		{"nant", "vnd.ms-msi"}, {"windows installer", "vnd.ms-msi"},
	}
	if directory {
		patterns = [][2]string{{"book", "vnd.ms-excel"}, {"workbook", "vnd.ms-excel"}, {"worddocument", "msword"}, {"powerpoint", "vnd.ms-powerpoint"}, {"digitalsignature", "vnd.ms-msi"}}
	}
	value = strings.ToLower(value)
	for _, p := range patterns {
		if strings.Contains(value, p[0]) {
			return p[1]
		}
	}
	return ""
}

func cdfFloat(value float64) string {
	switch {
	case math.IsNaN(value):
		if math.Signbit(value) {
			return "-nan"
		}
		return "nan"
	case math.IsInf(value, 1):
		return "inf"
	case math.IsInf(value, -1):
		return "-inf"
	default:
		return strconv.FormatFloat(value, 'g', 6, 64)
	}
}

func cdfSummary(out *strings.Builder, b []byte, root *cdfDirectory, dirs []cdfDirectory, mime bool) bool {
	props, ok := cdfProperties(b)
	if !ok {
		return false
	}
	msi := root != nil && root.clsid == [2]uint64{0x00000000000c1084, 0x46000000000000c0}
	mt := ""
	if msi {
		mt = "x-msi"
	}
	if !mime {
		endian := "Big"
		if cdfLE.Uint16(b) == 0xfffe {
			endian = "Little"
		}
		fmt.Fprintf(out, "Composite Document File V2 Document, %s Endian", endian)
		version, os := cdfLE.Uint16(b[4:]), cdfLE.Uint16(b[6:])
		switch os {
		case 1:
			fmt.Fprintf(out, ", Os: MacOS, Version %d.%d", version>>8, version&0xff)
		case 2:
			fmt.Fprintf(out, ", Os: Windows, Version %d.%d", version&0xff, version>>8)
		default:
			fmt.Fprintf(out, ", Os %d, Version: %d.%d", os, version&0xff, version>>8)
		}
		if msi {
			out.WriteString(", MSI Installer")
		}
	}
	for _, p := range props {
		var value string
		switch p.kind {
		case 1, 71:
			continue
		case 2:
			value = strconv.FormatInt(int64(int16(p.value)), 10)
		case 3:
			value = strconv.FormatInt(int64(int32(p.value)), 10)
		case 19:
			value = strconv.FormatUint(uint64(uint32(p.value)), 10)
		case 4:
			value = cdfFloat(float64(math.Float32frombits(uint32(p.value))))
		case 5:
			value = cdfFloat(math.Float64frombits(p.value))
		case 30, 31:
			value = cdfString(p)
			if mime && mt == "" && p.id == 18 {
				mt = cdfAppMIME(value, false)
			}
		case 64:
			if p.value != 0 {
				value = cdfTime(int64(p.value))
			}
		default:
			return false
		}
		if !mime && value != "" {
			fmt.Fprintf(out, ", %s: %s", cdfPropertyName(p.id), value)
		}
	}
	if mime {
		for i := 0; mt == "" && i < len(dirs); i++ {
			var name []byte
			for _, ch := range dirs[i].name {
				if byte(ch) == 0 {
					break
				}
				name = append(name, byte(ch))
			}
			mt = cdfAppMIME(string(name), true)
		}
		if mt == "" {
			mt = "vnd.ms-office"
		}
		out.WriteString("application/" + mt)
	}
	return true
}
