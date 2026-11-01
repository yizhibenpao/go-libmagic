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
	"errors"
	"fmt"
	"strings"
)

func (e *elfScan) corePrograms(size uint16) {
	if e.mime {
		return
	}
	if e.phnum == 0 {
		e.out.WriteString(", no program header")
		return
	}
	if uint64(size) != e.phsize() {
		e.out.WriteString(", corrupted program header size")
		return
	}
	for i := uint16(0); i < e.phnum; i++ {
		offset := e.phoff + uint64(i)*uint64(size)
		p, ok := e.program(offset)
		if !ok {
			fmt.Fprintf(&e.out, ", can't read elf program headers at %d", int64(offset))
			return
		}
		if (e.size != elfSizeUnknown && int64(p.offset) > e.size) || p.kind != 4 {
			continue
		}
		count := p.size
		if count > 8192 {
			count = 8192
		}
		b, err := e.read(p.offset, count)
		if err != nil {
			fmt.Fprintf(&e.out, " can't read note section at %d", int64(p.offset))
			return
		}
		e.noteBlock(b, 4, e.phoff, e.phnum, e.size)
		if e.err != nil {
			return
		}
	}
}

func (e *elfScan) coreNote(name string, namesz, kind uint32, desc, block []byte, doff uint64) bool {
	style := -1
	switch {
	case namesz == 4 && strings.HasPrefix(name, "CORE"), namesz == 5 && name == "CORE":
		style = 0
	case namesz == 8 && name == "FreeBSD":
		style = 1
	case namesz >= 11 && strings.HasPrefix(name, "NetBSD-CORE"):
		style = 2
	}
	if style != -1 && e.flags&elfDidCoreStyle == 0 {
		fmt.Fprintf(&e.out, ", %s-style", []string{"SVR4", "FreeBSD", "NetBSD"}[style])
		e.flags |= elfDidCoreStyle | uint32(style)
	}
	switch style {
	case 2:
		if kind == 1 {
			pi := make([]byte, 160)
			copy(pi, desc)
			fmt.Fprintf(&e.out, ", from '%.31s', pid=%d, uid=%d, gid=%d, nlwps=%d, lwp=%d (signal %d/code %d)",
				elfPrintable(pi[124:156], 512), e.order.Uint32(pi[80:]), e.order.Uint32(pi[100:]), e.order.Uint32(pi[112:]),
				e.order.Uint32(pi[120:]), e.order.Uint32(pi[156:]), e.order.Uint32(pi[8:]), e.order.Uint32(pi[12:]))
			e.flags |= elfDidCore
			return true
		}
	case 1:
		if kind == 3 && e.flags&elfIsCore != 0 {
			argoff := uint64(25)
			if e.class == 2 {
				argoff = 33
			}
			arg := ""
			if doff+argoff < uint64(len(block)) {
				b := block[doff+argoff:]
				if len(b) > 80 {
					b = b[:80]
				}
				arg = cString(b)
			}
			fmt.Fprintf(&e.out, ", from '%s'", arg)
			pid := doff + argoff + 83
			if pid+4 <= uint64(len(block)) {
				fmt.Fprintf(&e.out, ", pid=%d", e.order.Uint32(block[pid:]))
			}
			e.flags |= elfDidCore
			// The C branch deliberately falls through to the caller's
			// subsequent note handlers (returns zero).
		}
	default:
		if kind != 3 || e.flags&elfIsCore == 0 {
			return false
		}
		offsets := []int{100, 84, 44, 28, 48, 32, 8}
		if e.class == 2 {
			offsets = []int{136, 120, 56, 40, 16}
		}
		for i := 0; i < len(offsets); i++ {
			start := doff + uint64(offsets[i])
			valid := true
			for j := 0; j < 16; j++ {
				pos := start + uint64(j)
				if pos >= uint64(len(block)) || offsets[i]+j >= len(desc) {
					valid = false
					break
				}
				ch := block[pos]
				if ch == 0 {
					valid = j != 0
					break
				}
				if ch < 32 || ch >= 127 || strings.ContainsRune("'\"`", rune(ch)) {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			for k := i + 1; k < len(offsets); k++ {
				if offsets[k] >= offsets[i] {
					continue
				}
				adjust := true
				for pos := doff + uint64(offsets[k]); pos < doff+uint64(offsets[i]); pos++ {
					adjust = adjust && block[pos] >= 32 && block[pos] < 127
				}
				if adjust {
					i = k
				}
			}
			start = doff + uint64(offsets[i])
			end := start
			for end < uint64(len(block)) && block[end] >= 32 && block[end] < 127 {
				end++
			}
			for end > start && block[end-1] == ' ' {
				end--
			}
			if end-start > 255 {
				end = start + 255
			}
			fmt.Fprintf(&e.out, ", from '%s'", block[start:end])
			e.flags |= elfDidCore
			return true
		}
	}
	return false
}

func (e *elfScan) auxvNote(kind uint32, desc []byte, phoff uint64, phnum uint16, fsize int64) bool {
	if e.flags&(elfIsCore|elfDidCoreStyle) != elfIsCore|elfDidCoreStyle || e.flags&3 != 0 || kind != 6 {
		return false
	}
	e.flags |= elfDidAuxv
	width := 8
	if e.class == 2 {
		width = 16
	}
	count := 0
	for pos := 0; pos+width <= len(desc); pos += width {
		if count >= 50 {
			e.err = errors.New("Too many ELF Auxv elements")
			return true
		}
		count++
		tag, value := uint64(e.order.Uint32(desc[pos:])), uint64(e.order.Uint32(desc[pos+4:]))
		if e.class == 2 {
			tag, value = e.order.Uint64(desc[pos:]), e.order.Uint64(desc[pos+8:])
		}
		names := map[uint64]string{11: "real uid", 12: "effective uid", 13: "real gid", 14: "effective gid", 15: "platform", 31: "execfn"}
		name := names[tag]
		if name == "" {
			continue
		}
		if tag == 15 || tag == 31 {
			text := e.virtualString(value, phoff, phnum, fsize)
			if text != "" {
				fmt.Fprintf(&e.out, ", %s: '%s'", name, text)
			}
		} else {
			fmt.Fprintf(&e.out, ", %s: %d", name, int32(value))
		}
	}
	return true
}

func (e *elfScan) virtualString(address, off uint64, num uint16, fsize int64) string {
	var offset uint64
	for i := uint16(0); i < num; i++ {
		p, ok := e.program(off)
		if !ok {
			fmt.Fprintf(&e.out, ", can't read elf program header at %d", int64(off))
			break
		}
		off += e.phsize()
		if fsize != -1 && int64(p.offset) > fsize {
			continue
		}
		if address >= p.virtual && address < p.virtual+p.size {
			offset = p.offset + (address - p.virtual)
			break
		}
	}
	b, err := e.read(offset, 256)
	if err != nil || len(b) == 0 {
		fmt.Fprintf(&e.out, ", can't read elf string at %d", int64(offset))
		return ""
	}
	text := cString(b[:len(b)-1])
	for _, ch := range []byte(text) {
		if ch < 32 || ch >= 127 {
			return ""
		}
	}
	return text
}
