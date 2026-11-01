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
/*
 * Copyright (c) Christos Zoulas 2008.
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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// FILE5_41 readelf.c/elfclass.h only supply a suffix and update mode.
// The loaded magic database still decides the base description and MIME.
type elfScan struct {
	reader  io.ReaderAt
	size    int64
	class   byte
	order   binary.ByteOrder
	mime    bool
	execute bool
	out     strings.Builder
	err     error
	flags   uint32
	notes   int
	phoff   uint64
	phnum   uint16
}

type elfProgram struct {
	kind                         uint32
	offset, size, align, virtual uint64
}

type elfSection struct {
	name, kind   uint32
	offset, size uint64
}

const elfSizeUnknown int64 = -1

type elfCapabilitySeekError struct {
	err error
}

func (e elfCapabilitySeekError) Error() string {
	return e.err.Error()
}

func (e elfCapabilitySeekError) Unwrap() error {
	return e.err
}

func elfSupplement(data []byte, reader io.ReaderAt, size int64, mime, execute bool) (string, bool, error) {
	return elfSupplementStatus(data, reader, size, mime, execute, nil)
}

func elfSupplementStatus(data []byte, reader io.ReaderAt, size int64, mime, execute bool, statErr error) (string, bool, error) {
	if reader == nil || !elfPrefix(data) {
		return "", execute, nil
	}
	if statErr != nil && size <= 0 {
		return "", execute, fmt.Errorf("error reading (%s)", systemError(statErr))
	}
	e := &elfScan{reader: reader, size: size, class: data[4], order: binary.LittleEndian, mime: mime, execute: execute, notes: 256}
	if data[5] != 1 {
		e.order = binary.BigEndian
	}
	finish := func() (string, bool, error) {
		if e.err != nil && e.out.Len() != 0 {
			return "", e.execute, fmt.Errorf("%s %s", e.out.String(), e.err)
		}
		return filesystemString(e.out.String()), e.execute, e.err
	}
	headerSize := 52
	switch e.class {
	case 1:
	case 2:
		headerSize = 64
	default:
		fmt.Fprintf(&e.out, ", unknown class %d", e.class)
		return finish()
	}
	// elfclass.h requires one byte MORE than the complete ELF header.
	if len(data) <= headerSize {
		return finish()
	}
	var shoff uint64
	var phsize, shsize, shnum, strtab uint16
	if e.class == 1 {
		e.phoff, shoff = uint64(e.order.Uint32(data[28:])), uint64(e.order.Uint32(data[32:]))
		phsize, e.phnum = e.order.Uint16(data[42:]), e.order.Uint16(data[44:])
		shsize, shnum, strtab = e.order.Uint16(data[46:]), e.order.Uint16(data[48:]), e.order.Uint16(data[50:])
	} else {
		e.phoff, shoff = e.order.Uint64(data[32:]), e.order.Uint64(data[40:])
		phsize, e.phnum = e.order.Uint16(data[54:]), e.order.Uint16(data[56:])
		shsize, shnum, strtab = e.order.Uint16(data[58:]), e.order.Uint16(data[60:]), e.order.Uint16(data[62:])
	}
	typ := e.order.Uint16(data[16:])
	switch typ {
	case 4:
		if e.phnum > 2048 {
			e.toomany("program headers", e.phnum)
			return finish()
		}
		e.flags |= elfIsCore
		e.corePrograms(phsize)
	case 1, 2, 3:
		if typ != 1 {
			if e.phnum > 2048 {
				e.toomany("program", e.phnum)
				return finish()
			}
			if shnum > 32768 {
				e.toomany("section", shnum)
				return finish()
			}
			e.programs(phsize, shnum)
		}
		if e.err != nil {
			return finish()
		}
		if shnum > 32768 {
			e.toomany("section headers", shnum)
			return finish()
		}
		e.sections(shoff, shsize, shnum, strtab, e.order.Uint16(data[18:]))
	}
	if e.notes == 0 && e.err == nil {
		e.toomany("notes", 256)
	}
	return finish()
}

func (e *elfScan) toomany(name string, count uint16) {
	if !e.mime {
		fmt.Fprintf(&e.out, ", too many %s (%d)", name, count)
	}
}

// FILE5_41 rereads ELF structures from the fd, without a prefix cache or
// stat-size clipping. EOF is a successful short pread; negative offsets fail.
func (e *elfScan) read(offset, count uint64) ([]byte, error) {
	if int64(offset) < 0 {
		return nil, errors.New("Invalid argument")
	}
	b := make([]byte, int(count))
	n, err := readMagicAt(e.reader, b, int64(offset))
	return b[:n], err
}

// readCapability is the SHT_SUNW_cap path in FILE5_41 doshn: lseek followed
// by one read on the descriptor. Other ELF structures use pread and leave the
// descriptor position unchanged.
func (e *elfScan) readCapability(offset, count uint64) ([]byte, error) {
	if int64(offset) < 0 {
		return nil, errors.New("Invalid argument")
	}
	b := make([]byte, int(count))
	if file, ok := e.reader.(*os.File); ok {
		if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
			return nil, elfCapabilitySeekError{err: err}
		}
		n, err := file.Read(b)
		return b[:n], err
	}
	n, err := readMagicAt(e.reader, b, int64(offset))
	return b[:n], err
}

func (e *elfScan) phsize() uint64 {
	if e.class == 1 {
		return 32
	}
	return 56
}

func (e *elfScan) program(offset uint64) (elfProgram, bool) {
	b, err := e.read(offset, e.phsize())
	if err != nil || uint64(len(b)) != e.phsize() {
		return elfProgram{}, false
	}
	p := elfProgram{kind: e.order.Uint32(b)}
	if e.class == 1 {
		p.offset, p.virtual = uint64(e.order.Uint32(b[4:])), uint64(e.order.Uint32(b[8:]))
		p.size, p.align = uint64(e.order.Uint32(b[16:])), uint64(e.order.Uint32(b[28:]))
	} else {
		p.offset, p.virtual = e.order.Uint64(b[8:]), e.order.Uint64(b[16:])
		p.size, p.align = e.order.Uint64(b[32:]), e.order.Uint64(b[48:])
	}
	if p.align == 0 {
		p.align = 4
	}
	if p.virtual == 0 {
		p.virtual = 4
	}
	return p, true
}

func (e *elfScan) programs(size, shnum uint16) {
	if e.phnum == 0 {
		e.out.WriteString(", no program header")
		return
	}
	if uint64(size) != e.phsize() {
		e.out.WriteString(", corrupted program header size")
		return
	}
	dynamic, flags1, need, interp := false, false, 0, ""
	for i := uint16(0); i < e.phnum; i++ {
		offset := e.phoff + uint64(i)*uint64(size)
		p, ok := e.program(offset)
		if !ok {
			fmt.Fprintf(&e.out, ", can't read elf program headers at %d", int64(offset))
			return
		}
		if p.kind == 4 && shnum != 0 {
			continue
		}
		align := p.align
		if p.kind == 4 && (align&0x80000000 != 0 || align < 4) {
			fmt.Fprintf(&e.out, ", invalid note alignment %#x", align)
			align = 4
		}
		var b []byte
		if p.kind == 2 || p.kind == 3 || p.kind == 4 {
			count := p.size
			if count > 8192 { // glibc BUFSIZ on both target architectures
				count = 8192
			}
			var err error
			b, err = e.read(p.offset, count)
			if err != nil {
				fmt.Fprintf(&e.out, ", can't read section at %d", int64(p.offset))
				return
			}
		}
		switch p.kind {
		case 2:
			dynamic, e.execute = true, false
			width := 8
			if e.class == 2 {
				width = 16
			}
			for j := 0; j+width <= len(b); j += width {
				tag, value := uint64(e.order.Uint32(b[j:])), uint64(e.order.Uint32(b[j+4:]))
				if e.class == 2 {
					tag, value = e.order.Uint64(b[j:]), e.order.Uint64(b[j+8:])
				}
				switch tag {
				case 0x6ffffffb:
					flags1, e.execute = true, value&0x08000000 != 0
				case 1:
					need++
				}
				// 5.41 does not stop at DT_NULL.
			}
		case 3:
			need++
			if !e.mime {
				if len(b) > 0 && b[0] != 0 {
					interp = cString(b[:len(b)-1])
				} else {
					interp = "*empty*"
				}
			}
		case 4:
			if e.mime {
				return
			}
			e.noteBlock(b, align, 0, 0, 0)
		}
	}
	if e.mime {
		return
	}
	style := "statically"
	if dynamic {
		style = "dynamically"
		if flags1 && need == 0 {
			style = "static-pie"
		}
	}
	fmt.Fprintf(&e.out, ", %s linked", style)
	if interp != "" {
		e.printf(", interpreter %s", elfPrintable([]byte(interp), 8192))
	}
}

// file_vprintf bounds each individual print, even inside the ELF suffix.
func (e *elfScan) printf(format string, args ...interface{}) {
	if e.err != nil {
		return
	}
	s := fmt.Sprintf(format, args...)
	if len(s) > 1024 || len(s)+e.out.Len() > 1024*1024 {
		e.err = fmt.Errorf("Output buffer space exceeded %d+%d", len(s), e.out.Len())
		e.out.Reset()
		return
	}
	e.out.WriteString(s)
}

func (e *elfScan) shsize() uint64 {
	if e.class == 1 {
		return 40
	}
	return 64
}

func (e *elfScan) section(offset uint64) (elfSection, bool) {
	b, err := e.read(offset, e.shsize())
	if err != nil || uint64(len(b)) != e.shsize() {
		return elfSection{}, false
	}
	s := elfSection{name: e.order.Uint32(b), kind: e.order.Uint32(b[4:])}
	if e.class == 1 {
		s.offset, s.size = uint64(e.order.Uint32(b[16:])), uint64(e.order.Uint32(b[20:]))
	} else {
		s.offset, s.size = e.order.Uint64(b[24:]), e.order.Uint64(b[32:])
	}
	return s, true
}

func (e *elfScan) sections(off uint64, size, num, strtab, machine uint16) {
	if e.mime {
		return
	}
	if num == 0 {
		e.out.WriteString(", no section header")
		return
	}
	if uint64(size) != e.shsize() {
		e.out.WriteString(", corrupted section header size")
		return
	}
	stripped, debug := true, false
	s, ok := e.section(off + uint64(size)*uint64(strtab))
	if !ok {
		fmt.Fprintf(&e.out, ", missing section headers at %d", int64(off+uint64(size)*uint64(strtab)))
		return
	}
	nameOff := s.offset
	if e.size != elfSizeUnknown && e.size < int64(nameOff) {
		fmt.Fprintf(&e.out, ", too large section header offset %d", int64(nameOff))
		return
	}
	var hw, sf uint64
	badcap := 0
	for i := uint16(0); i < num; i++ {
		// 5.41 checks the previous header's name before loading this one.
		b, err := e.read(nameOff+uint64(s.name), 49)
		if err != nil {
			fmt.Fprintf(&e.out, ", can't read name of elf section at %d", int64(nameOff+uint64(s.name)))
			return
		}
		if cString(b) == ".debug_info" {
			debug, stripped = true, false
		}
		s, ok = e.section(off)
		if !ok {
			fmt.Fprintf(&e.out, ", can't read elf section at %d", int64(off))
			return
		}
		off += uint64(size)
		if s.kind == 2 {
			stripped = false
		} else if e.size != elfSizeUnknown && int64(s.offset) > e.size {
			continue
		}
		switch s.kind {
		case 7:
			if e.size != elfSizeUnknown && s.size+s.offset > uint64(e.size) {
				fmt.Fprintf(&e.out, ", note offset/size %s+%s exceeds file size %s", elfHex(s.offset), elfHex(s.size), elfHex(uint64(e.size)))
				return
			}
			// The native wrap contracts fail malloc, not the following pread.
			if s.size > uint64(^uint(0)>>1) {
				e.err = errors.New("Cannot allocate memory for note (Cannot allocate memory)")
				return
			}
			b, err := e.read(s.offset, s.size)
			if err != nil || uint64(len(b)) != s.size {
				fmt.Fprintf(&e.out, ", can't read elf note at %d", int64(s.offset))
				return
			}
			e.noteBlock(b, 4, 0, 0, 0)
		case 0x6ffffff5:
			if machine != 2 && machine != 43 && machine != 50 && machine != 3 && machine != 62 {
				continue
			}
			if badcap > 5 {
				continue
			}
			if int64(s.offset) < 0 {
				e.err = errors.New("error seeking (Invalid argument)")
				return
			}
			width := uint64(8)
			if e.class == 2 {
				width = 16
			}
		capabilities:
			for pos := uint64(0); pos < s.size; pos += width {
				if s.size-pos < width {
					break
				}
				b, err := e.readCapability(s.offset+pos, width)
				if err != nil || uint64(len(b)) != width {
					// The preceding CDF header probe rejects ELF with
					// EFTYPE (= EINVAL on the Linux 5.41 reference).
					// A short read leaves that errno unchanged. A real
					// descriptor error replaces it with the read errno.
					var seekErr elfCapabilitySeekError
					if errors.As(err, &seekErr) {
						e.err = fmt.Errorf("error seeking (%s)", systemError(seekErr.err))
					} else if err == nil || errors.Is(err, io.EOF) {
						e.err = errors.New("error reading (Invalid argument)")
					} else {
						e.err = fmt.Errorf("error reading (%s)", systemError(err))
					}
					return
				}
				if b[0] == 'A' {
					break
				}
				tag, value := uint64(e.order.Uint32(b)), uint64(e.order.Uint32(b[4:]))
				if e.class == 2 {
					tag, value = e.order.Uint64(b), e.order.Uint64(b[8:])
				}
				switch tag {
				case 0:
				case 1:
					hw |= value
				case 2:
					sf |= value
				default:
					fmt.Fprintf(&e.out, ", with unknown capability %s = %s", elfHex(tag), elfHex(value))
					badcap++
					if badcap > 3 {
						break capabilities
					}
				}
			}
		}
		if e.err != nil {
			return
		}
	}
	if debug {
		e.out.WriteString(", with debug_info")
	}
	if stripped {
		e.out.WriteString(", stripped")
	} else {
		e.out.WriteString(", not stripped")
	}
	e.capabilities(machine, hw, sf)
}

func elfHex(value uint64) string {
	if value == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", value)
}

func elfPrintable(b []byte, capacity int) string {
	var out strings.Builder
	for _, ch := range b {
		if ch == 0 || out.Len() >= capacity-1 {
			break
		}
		if ch >= 32 && ch < 127 {
			out.WriteByte(ch)
		} else {
			if out.Len() >= capacity-4 {
				break
			}
			fmt.Fprintf(&out, "\\%03o", ch)
		}
	}
	return out.String()
}

func (e *elfScan) capabilities(machine uint16, hw, sf uint64) {
	if hw != 0 {
		names := strings.Fields("FPU TSC CX8 SEP AMD_SYSC CMOV MMX AMD_MMX AMD_3DNow AMD_3DNowx FXSR SSE SSE2 PAUSE SSE3 MON CX16 AHF TSCP AMD_SSE4A POPCNT AMD_LZCNT SSSE3 SSE4.1 SSE4.2")
		masks := make([]uint64, len(names))
		for i := range masks {
			masks[i] = 1 << uint(i)
		}
		if machine == 2 || machine == 18 || machine == 43 {
			names = strings.Fields("MUL32 DIV32 FSMULD V8PLUS POPC VIS VIS2 ASI_BLK_INIT FMAF FJFMAU IMA")
			masks = []uint64{1, 2, 4, 8, 16, 32, 64, 128, 256, 0x4000, 0x8000}
		}
		e.out.WriteString(", uses")
		for i, name := range names {
			if hw&masks[i] != 0 {
				e.out.WriteString(" " + name)
				hw &^= masks[i]
			}
		}
		if hw != 0 {
			fmt.Fprintf(&e.out, " unknown hardware capability %#x", hw)
		}
	}
	if sf&2 != 0 {
		if sf&1 != 0 {
			e.out.WriteString(", uses frame pointer")
		} else {
			e.out.WriteString(", not known to use frame pointer")
		}
	}
	if sf&^uint64(3) != 0 {
		fmt.Fprintf(&e.out, ", with unknown software capability %#x", sf&^uint64(3))
	}
}
