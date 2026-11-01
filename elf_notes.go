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
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	elfDidCore = uint32(1) << (2 + iota)
	elfDidOS
	elfDidBuildID
	elfDidCoreStyle
	elfDidPaX
	elfDidMarch
	elfDidCmodel
	elfDidEmulation
	elfDidUnknown
	elfIsCore
	elfDidAuxv
)

func (e *elfScan) noteBlock(b []byte, align, phoff uint64, phnum uint16, fsize int64) {
	for off := uint64(0); off < uint64(len(b)); {
		if e.notes == 0 {
			return
		}
		e.notes--
		if off+12 > uint64(len(b)) {
			return
		}
		namesz := e.order.Uint32(b[off:])
		descsz := e.order.Uint32(b[off+4:])
		kind := e.order.Uint32(b[off+8:])
		off += 12
		if namesz == 0 && descsz == 0 {
			return
		}
		if namesz&0x80000000 != 0 {
			fmt.Fprintf(&e.out, ", bad note name size %#x", namesz)
			return
		}
		if descsz&0x80000000 != 0 {
			fmt.Fprintf(&e.out, ", bad note description size %#x", descsz)
			return
		}
		aligned := func(value uint64) uint64 { return (value + align - 1) / align * align }
		noff := off
		doff := aligned(off + uint64(namesz))
		if off+uint64(namesz) > uint64(len(b)) {
			// donote returns the aligned description offset; the caller
			// tries that offset as the next note header.
			off = doff
			continue
		}
		next := aligned(doff + uint64(descsz))
		if doff > uint64(len(b)) || uint64(descsz) > uint64(len(b))-doff {
			return
		}
		name := cString(b[noff : noff+uint64(namesz)])
		desc := b[doff : doff+uint64(descsz)]
		switch {
		case e.flags&elfDidOS == 0 && e.osNote(name, namesz, kind, desc):
		case e.flags&elfDidBuildID == 0 && e.buildNote(name, namesz, kind, desc):
		case e.flags&elfDidPaX == 0 && name == "PaX" && namesz == 4 && kind == 3 && len(desc) == 4:
			e.flags |= elfDidPaX
			value := e.order.Uint32(desc)
			if value != 0 {
				e.out.WriteString(", PaX: ")
			}
			var found []string
			for i, tag := range []string{"+mprotect", "-mprotect", "+segvguard", "-segvguard", "+ASLR", "-ASLR"} {
				if value&(1<<uint(i)) != 0 {
					found = append(found, tag)
				}
			}
			e.out.WriteString(strings.Join(found, ","))
		case e.flags&elfDidCore == 0 && e.coreNote(name, namesz, kind, desc, b, doff):
		case e.flags&elfDidAuxv == 0 && e.auxvNote(kind, desc, phoff, phnum, fsize):
		default:
			if namesz == 7 && name == "NetBSD" {
				e.netbsdNote(kind, desc)
			}
		}
		if next == 0 || e.err != nil {
			return
		}
		off = next
	}
}

func (e *elfScan) buildNote(name string, namesz, kind uint32, desc []byte) bool {
	if namesz == 4 && name == "GNU" && kind == 3 && len(desc) >= 4 && len(desc) <= 20 {
		e.flags |= elfDidBuildID
		algorithm := "unknown"
		switch len(desc) {
		case 8:
			algorithm = "xxHash"
		case 16:
			algorithm = "md5/uuid"
		case 20:
			algorithm = "sha1"
		}
		fmt.Fprintf(&e.out, ", BuildID[%s]=%s", algorithm, hex.EncodeToString(desc))
		return true
	}
	if namesz == 4 && name == "Go" && kind == 4 && len(desc) < 128 {
		// This branch does NOT set FLAGS_DID_BUILD_ID in 5.41.
		fmt.Fprintf(&e.out, ", Go BuildID=%s", cString(desc))
		return true
	}
	return false
}

func (e *elfScan) osNote(name string, namesz, kind uint32, desc []byte) bool {
	switch {
	case namesz == 5 && name == "SuSE" && kind == 1 && len(desc) == 2:
		fmt.Fprintf(&e.out, ", for SuSE %d.%d", desc[0], desc[1])
	case namesz == 4 && name == "GNU" && kind == 1 && len(desc) == 16:
		os := "<unknown>"
		names := []string{"Linux", "Hurd", "Solaris", "kFreeBSD", "kNetBSD"}
		n := e.order.Uint32(desc)
		if n < uint32(len(names)) {
			os = names[n]
		}
		fmt.Fprintf(&e.out, ", for GNU/%s %d.%d.%d", os, int32(e.order.Uint32(desc[4:])), int32(e.order.Uint32(desc[8:])), int32(e.order.Uint32(desc[12:])))
	case namesz == 7 && name == "NetBSD" && kind == 1 && len(desc) == 4:
		value := e.order.Uint32(desc)
		e.out.WriteString(", for NetBSD")
		if value > 100000000 {
			patch, rel, minor, major := value/100%100, value/10000%100, value/1000000%100, value/100000000
			fmt.Fprintf(&e.out, " %d.%d", major, minor)
			if rel == 0 && patch != 0 {
				fmt.Fprintf(&e.out, ".%d", patch)
			} else if rel != 0 {
				for rel > 26 {
					e.out.WriteByte('Z')
					rel -= 26
				}
				e.out.WriteByte(byte('A' + rel - 1))
			}
		}
	case namesz == 8 && name == "FreeBSD" && kind == 1 && len(desc) == 4:
		e.freebsdVersion(e.order.Uint32(desc))
	case namesz == 8 && name == "OpenBSD" && kind == 1 && len(desc) == 4:
		e.out.WriteString(", for OpenBSD")
	case namesz == 10 && name == "DragonFly" && kind == 1 && len(desc) == 4:
		value := e.order.Uint32(desc)
		fmt.Fprintf(&e.out, ", for DragonFly %d.%d.%d", value/100000, value/10000%10, value%10000)
	default:
		return false
	}
	e.flags |= elfDidOS
	return true
}

func (e *elfScan) freebsdVersion(value uint32) {
	e.out.WriteString(", for FreeBSD")
	switch {
	case value == 460002:
		e.out.WriteString(" 4.6.2")
	case value < 460100:
		fmt.Fprintf(&e.out, " %d.%d", value/100000, value/10000%10)
		if value/1000%10 > 0 {
			fmt.Fprintf(&e.out, ".%d", value/1000%10)
		}
		if value%1000 > 0 || value%100000 == 0 {
			fmt.Fprintf(&e.out, " (%d)", value)
		}
	case value < 500000:
		fmt.Fprintf(&e.out, " %d.%d", value/100000, value/10000%10+value/1000%10)
		if value/100%10 > 0 {
			fmt.Fprintf(&e.out, " (%d)", value)
		} else if value/10%10 > 0 {
			fmt.Fprintf(&e.out, ".%d", value/10%10)
		}
	default:
		fmt.Fprintf(&e.out, " %d.%d", value/100000, value/1000%100)
		if value/100%10 > 0 || value%100000/100 == 0 {
			fmt.Fprintf(&e.out, " (%d)", int32(value))
		} else if value/10%10 > 0 {
			fmt.Fprintf(&e.out, ".%d", value/10%10)
		}
	}
}

func (e *elfScan) netbsdNote(kind uint32, desc []byte) {
	var flag uint32
	tag := ""
	switch kind {
	case 1:
		return
	case 5:
		flag, tag = elfDidMarch, "compiled for"
	case 6:
		flag, tag = elfDidCmodel, "compiler model"
	case 2:
		flag, tag = elfDidEmulation, "emulation:"
	default:
		if e.flags&elfDidUnknown == 0 {
			e.flags |= elfDidUnknown
			fmt.Fprintf(&e.out, ", note=%d", kind)
		}
		return
	}
	if e.flags&flag != 0 {
		return
	}
	e.flags |= flag
	if len(desc) > 100 {
		desc = desc[:100]
	}
	fmt.Fprintf(&e.out, ", %s: %s", tag, cString(desc))
}
