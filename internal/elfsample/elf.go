// Package elfsample builds deterministic ELF inputs for the pure-Go parser,
// the independently linked 5.41 oracle, and the strict dispatch corpus.
package elfsample

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type program struct {
	kind, align uint32
	data        []byte
}

type section struct {
	name string
	kind uint32
	data []byte
}

func words(order binary.ByteOrder, values ...uint32) []byte {
	b := make([]byte, len(values)*4)
	for i, v := range values {
		order.PutUint32(b[4*i:], v)
	}
	return b
}

func pairs(class int, order binary.ByteOrder, values ...uint64) []byte {
	width := 4
	if class == 2 {
		width = 8
	}
	b := make([]byte, len(values)*width)
	for i, v := range values {
		if width == 4 {
			order.PutUint32(b[4*i:], uint32(v))
		} else {
			order.PutUint64(b[8*i:], v)
		}
	}
	return b
}

func note(order binary.ByteOrder, name string, kind uint32, desc []byte) []byte {
	b := words(order, uint32(len(name)), uint32(len(desc)), kind)
	b = append(b, []byte(name)...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	b = append(b, desc...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func image(class int, order binary.ByteOrder, kind, machine uint16, ph []program, sh []section) []byte {
	header, phsize, shsize := 52, 32, 40
	if class == 2 {
		header, phsize, shsize = 64, 56, 64
	}
	b := make([]byte, 1024)
	copy(b, []byte{0x7f, 'E', 'L', 'F', byte(class), 1, 1})
	if order == binary.BigEndian {
		b[5] = 2
	}
	order.PutUint16(b[16:], kind)
	order.PutUint16(b[18:], machine)
	order.PutUint32(b[20:], 1)
	for i, p := range ph {
		h := b[header+i*phsize:][:phsize]
		order.PutUint32(h, p.kind)
		if class == 1 {
			order.PutUint32(h[4:], uint32(len(b)))
			order.PutUint32(h[8:], 0x400000+uint32(len(b)))
			order.PutUint32(h[16:], uint32(len(p.data)))
			order.PutUint32(h[20:], uint32(len(p.data)))
			order.PutUint32(h[28:], p.align)
		} else {
			order.PutUint64(h[8:], uint64(len(b)))
			order.PutUint64(h[16:], 0x400000+uint64(len(b)))
			order.PutUint64(h[32:], uint64(len(p.data)))
			order.PutUint64(h[40:], uint64(len(p.data)))
			order.PutUint64(h[48:], uint64(p.align))
		}
		b = append(b, p.data...)
	}
	var names []byte
	var nameOffsets []uint32
	var dataOffsets []uint64
	if len(sh) > 0 {
		sh = append(append([]section{{}}, sh...), section{".shstrtab", 3, nil})
		names = []byte{0}
		for _, s := range sh {
			nameOffsets = append(nameOffsets, uint32(len(names)))
			names = append(names, append([]byte(s.name), 0)...)
		}
		sh[len(sh)-1].data = names
		for _, s := range sh {
			dataOffsets = append(dataOffsets, uint64(len(b)))
			b = append(b, s.data...)
		}
	}
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	shoff := len(b)
	b = append(b, make([]byte, shsize*len(sh))...)
	for i, s := range sh {
		h := b[shoff+i*shsize:][:shsize]
		order.PutUint32(h, nameOffsets[i])
		order.PutUint32(h[4:], s.kind)
		if class == 1 {
			order.PutUint32(h[16:], uint32(dataOffsets[i]))
			order.PutUint32(h[20:], uint32(len(s.data)))
		} else {
			order.PutUint64(h[24:], dataOffsets[i])
			order.PutUint64(h[32:], uint64(len(s.data)))
		}
	}
	if class == 1 {
		order.PutUint32(b[28:], uint32(header))
		order.PutUint32(b[32:], uint32(shoff))
		order.PutUint16(b[40:], uint16(header))
		order.PutUint16(b[42:], uint16(phsize))
		order.PutUint16(b[44:], uint16(len(ph)))
		order.PutUint16(b[46:], uint16(shsize))
		order.PutUint16(b[48:], uint16(len(sh)))
		if len(sh) > 0 {
			order.PutUint16(b[50:], uint16(len(sh)-1))
		}
	} else {
		order.PutUint64(b[32:], uint64(header))
		order.PutUint64(b[40:], uint64(shoff))
		order.PutUint16(b[52:], uint16(header))
		order.PutUint16(b[54:], uint16(phsize))
		order.PutUint16(b[56:], uint16(len(ph)))
		order.PutUint16(b[58:], uint16(shsize))
		order.PutUint16(b[60:], uint16(len(sh)))
		if len(sh) > 0 {
			order.PutUint16(b[62:], uint16(len(sh)-1))
		}
	}
	return b
}

func Cases() map[string][]byte {
	cases := make(map[string][]byte)
	for _, class := range []int{1, 2} {
		for _, be := range []bool{false, true} {
			var order binary.ByteOrder = binary.LittleEndian
			machine, endian := uint16(62), "le"
			if class == 1 {
				machine = 3
			}
			if be {
				order, machine, endian = binary.BigEndian, 20, "be"
			}
			prefix := fmt.Sprintf("%d-%s-", class*32, endian)
			dynamic := func(vals ...uint64) program { return program{2, 4, pairs(class, order, vals...)} }
			interp := program{3, 1, []byte("/lib/ld-test.so\x00")}
			load := program{1, 4096, []byte{0x90}}
			for _, typ := range []uint16{0, 1, 2, 3, 4, 0xffff} {
				cases[prefix+fmt.Sprint("type-", typ)] = image(class, order, typ, machine, nil, nil)
			}
			cases[prefix+"static"] = image(class, order, 2, machine, []program{load}, nil)
			cases[prefix+"shared"] = image(class, order, 3, machine, []program{dynamic(1, 1, 0, 0)}, nil)
			cases[prefix+"pie"] = image(class, order, 3, machine, []program{dynamic(0x6ffffffb, 0x08000000), interp}, nil)
			cases[prefix+"static-pie"] = image(class, order, 3, machine, []program{dynamic(0x6ffffffb, 0x08000000)}, nil)
			cases[prefix+"flags-zero"] = image(class, order, 3, machine, []program{dynamic(0x6ffffffb, 0)}, nil)
			cases[prefix+"after-null"] = image(class, order, 3, machine, []program{dynamic(0, 0, 0x6ffffffb, 0x08000000)}, nil)
			cases[prefix+"second-dynamic"] = image(class, order, 3, machine, []program{dynamic(0x6ffffffb, 0x08000000), dynamic(0, 0)}, nil)
			cases[prefix+"interp-empty"] = image(class, order, 2, machine, []program{{3, 1, nil}}, nil)
			cases[prefix+"interp-control"] = image(class, order, 2, machine, []program{{3, 1, []byte("/lib/\x01test.so\x00")}}, nil)
			cases[prefix+"interp-too-long"] = image(class, order, 2, machine, []program{{3, 1, []byte(strings.Repeat("a", 1100) + "\x00")}}, nil)
			cases[prefix+"interp-escaped-too-long"] = image(class, order, 2, machine, []program{{3, 1, []byte(strings.Repeat("\x01", 300) + "\x00")}}, nil)
			cases[prefix+"debug"] = image(class, order, 2, machine, []program{load}, []section{{".debug_info", 1, []byte{1}}})
			cases[prefix+"symbols"] = image(class, order, 1, machine, nil, []section{{".symtab", 2, nil}})
			cases[prefix+"stripped"] = image(class, order, 1, machine, nil, []section{{".text", 1, []byte{1}}})
			bid := note(order, "GNU\x00", 3, []byte("12345678901234567890"))
			abi := note(order, "GNU\x00", 1, words(order, 0, 3, 2, 0))
			goid := note(order, "Go\x00\x00", 4, []byte("asky/go-build-id"))
			cases[prefix+"notes-section"] = image(class, order, 2, machine, []program{load}, []section{{".note", 7, append(bid, abi...)}})
			cases[prefix+"notes-program"] = image(class, order, 2, machine, []program{{4, 4, append(append(bid, abi...), goid...)}}, nil)
			cases[prefix+"notes-duplicate"] = image(class, order, 2, machine, []program{{4, 4, append(append(goid, goid...), append(bid, bid...)...)}}, nil)
			cases[prefix+"notes-ignored-program"] = image(class, order, 2, machine, []program{{4, 4, bid}}, []section{{".text", 1, nil}})
			cases[prefix+"notes-alignment"] = image(class, order, 2, machine, []program{{4, 2, bid}}, nil)
			cases[prefix+"notes-bad-name"] = image(class, order, 2, machine, []program{{4, 4, words(order, 0x80000001, 1, 3)}}, nil)
			cases[prefix+"notes-bad-desc"] = image(class, order, 2, machine, []program{{4, 4, words(order, 4, 0x80000001, 3)}}, nil)
			cases[prefix+"notes-limit"] = image(class, order, 2, machine, nil, []section{{".note", 7, []byte(strings.Repeat(string(note(order, "Other\x00", 99, nil)), 257))}})
			for _, length := range []int{0, 4, 8, 16, 20, 21} {
				cases[prefix+fmt.Sprint("build-id-", length)] = image(class, order, 2, machine, []program{{4, 4, note(order, "GNU\x00", 3, []byte(strings.Repeat("x", length)))}}, nil)
			}
			cases[prefix+"go-id-control"] = image(class, order, 2, machine, []program{{4, 4, note(order, "Go\x00\x00", 4, []byte("go\x01id"))}}, nil)
			cases[prefix+"notes-nonpower-align"] = image(class, order, 2, machine, []program{{4, 5, bid}}, nil)
			cases[prefix+"notes-before-dynamic"] = image(class, order, 3, machine, []program{{4, 4, bid}, dynamic(0x6ffffffb, 0x08000000)}, nil)
			for _, os := range []uint32{0, 1, 2, 3, 4, 99} {
				n := note(order, "GNU\x00", 1, words(order, os, 1, 2, 3))
				cases[prefix+fmt.Sprint("os-gnu-", os)] = image(class, order, 2, machine, []program{{4, 4, n}}, nil)
			}
			for _, os := range []struct {
				name string
				desc []byte
			}{{"SuSE\x00", []byte{12, 3}}, {"NetBSD\x00", words(order, 903270000)}, {"FreeBSD\x00", words(order, 491000)}, {"OpenBSD\x00", words(order, 0)}, {"DragonFly\x00", words(order, 600123)}} {
				cases[prefix+"os-"+strings.TrimRight(os.name, "\x00")] = image(class, order, 2, machine, []program{{4, 4, note(order, os.name, 1, os.desc)}}, nil)
			}
			netbsd := append(note(order, "PaX\x00", 3, words(order, 0x3f)), note(order, "NetBSD\x00", 5, []byte("amd64\x00"))...)
			netbsd = append(netbsd, note(order, "NetBSD\x00", 6, []byte("kernel\x00"))...)
			netbsd = append(netbsd, note(order, "NetBSD\x00", 2, []byte("netbsd\x00"))...)
			netbsd = append(netbsd, note(order, "NetBSD\x00", 100, nil)...)
			cases[prefix+"netbsd"] = image(class, order, 2, machine, []program{{4, 4, netbsd}}, nil)
			caps := pairs(class, order, 1, 0x80000401, 2, 7, 0, 0, 9, 0x23)
			cases[prefix+"capabilities"] = image(class, order, 1, machine, nil, []section{{".SUNW_cap", 0x6ffffff5, caps}})
			args := make([]byte, 160)
			argoff := 44
			if class == 2 {
				argoff = 56
			}
			copy(args[argoff:], []byte("asky --scan \x00"))
			core := note(order, "CORE\x00", 3, args)
			cases[prefix+"core-svr4"] = image(class, order, 4, machine, []program{{4, 4, core}}, nil)
			aux := note(order, "CORE\x00", 6, pairs(class, order, 11, 1000, 12, 1001, 13, 1002, 14, 1003))
			cases[prefix+"core-auxv"] = image(class, order, 4, machine, []program{{4, 4, append(core, aux...)}}, nil)
			manyAux := note(order, "CORE\x00", 6, []byte(strings.Repeat(string(pairs(class, order, 0, 0)), 51)))
			cases[prefix+"core-auxv-limit"] = image(class, order, 4, machine, []program{{4, 4, append(core, manyAux...)}}, nil)
			freebsd := make([]byte, 160)
			argoff = 25
			if class == 2 {
				argoff = 33
			}
			copy(freebsd[argoff:], "asky --freebsd")
			order.PutUint32(freebsd[argoff+83:], 1234)
			cases[prefix+"core-freebsd"] = image(class, order, 4, machine, []program{{4, 4, note(order, "FreeBSD\x00", 3, freebsd)}}, nil)
			netbsdCore := make([]byte, 160)
			for _, off := range []int{8, 12, 80, 100, 112, 120, 156} {
				order.PutUint32(netbsdCore[off:], uint32(off))
			}
			copy(netbsdCore[124:], "asky\x01netbsd")
			cases[prefix+"core-netbsd"] = image(class, order, 4, machine, []program{{4, 4, note(order, "NetBSD-CORE\x00", 1, netbsdCore)}}, nil)
			stringsAux := note(order, "CORE\x00", 6, pairs(class, order, 15, 0, 31, 0))
			b := image(class, order, 4, machine, []program{{4, 4, append(core, stringsAux...)}, {1, 4, []byte("platform\x00asky\x00")}}, nil)
			// Point AUXV entries into the second program's mapped bytes.
			start := len(b) - len("platform\x00asky\x00")
			auxStart := 1024 + len(core) + 20
			copy(b[auxStart:], pairs(class, order, 15, uint64(0x400000+start), 31, uint64(0x400000+start+9)))
			cases[prefix+"core-auxv-strings"] = b
			for _, version := range []uint32{100000000, 901000300, 903270000, 901000000} {
				cases[prefix+fmt.Sprint("netbsd-", version)] = image(class, order, 2, machine, []program{{4, 4, note(order, "NetBSD\x00", 1, words(order, version))}}, nil)
			}
			for _, version := range []uint32{400000, 460002, 460100, 491000, 500000, 1301000} {
				cases[prefix+fmt.Sprint("freebsd-", version)] = image(class, order, 2, machine, []program{{4, 4, note(order, "FreeBSD\x00", 1, words(order, version))}}, nil)
			}
		}
	}
	mutate := func(name, src string, off int, n int, value uint64) {
		b := append([]byte(nil), cases[src]...)
		switch n {
		case 1:
			b[off] = byte(value)
		case 2:
			binary.LittleEndian.PutUint16(b[off:], uint16(value))
		case 4:
			binary.LittleEndian.PutUint32(b[off:], uint32(value))
		case 8:
			binary.LittleEndian.PutUint64(b[off:], value)
		}
		cases[name] = b
	}
	mutate("unknown-class", "64-le-static", 4, 1, 9)
	mutate("invalid-data", "64-le-static", 5, 1, 9)
	mutate("olf", "64-le-static", 1, 1, 'O')
	mutate("bad-ph-size", "64-le-static", 54, 2, 1)
	mutate("bad-ph-offset", "64-le-static", 32, 8, 1<<30)
	mutate("negative-ph-offset", "64-le-static", 32, 8, ^uint64(0))
	mutate("too-many-ph", "64-le-static", 56, 2, 2049)
	mutate("too-many-sh-exec", "64-le-static", 60, 2, 32769)
	mutate("too-many-sh-rel", "64-le-symbols", 60, 2, 32769)
	mutate("too-many-ph-core", "64-le-core-svr4", 56, 2, 2049)
	mutate("bad-sh-size", "64-le-symbols", 58, 2, 1)
	mutate("bad-sh-offset", "64-le-symbols", 40, 8, 1<<30)
	mutate("bad-shstr-index", "64-le-symbols", 62, 2, 0xffff)
	capSh := int(binary.LittleEndian.Uint64(cases["64-le-capabilities"][40:])) + 64
	mutate("truncated-capability", "64-le-capabilities", capSh+24, 8, uint64(len(cases["64-le-capabilities"])-1))
	mutate("negative-capability", "64-le-capabilities", capSh+24, 8, ^uint64(0))
	mutate("bad-interp-offset", "64-le-interp-empty", 64+8, 8, ^uint64(0))
	mutate("far-dynamic", "64-le-pie", 64+8, 8, 1<<30)
	mutate("machine-none", "32-be-static", 18, 2, 0)
	mutate("machine-unknown", "32-be-static", 18, 2, 0xff7f) // big-endian 0x7fff
	cases["cisco-powerpc-ambiguous"] = append([]byte(nil), cases["32-be-static"]...)
	mutate("cisco-powerpc-osabi", "32-be-static", 7, 1, 255)
	mutate("cisco-svip", "32-be-static", 18, 2, 0x1800)
	mutate("cisco-7200", "32-be-static", 18, 2, 0x1900)
	cases["capabilities-sparc32"] = image(1, binary.BigEndian, 1, 2, nil, []section{{".SUNW_cap", 0x6ffffff5, pairs(1, binary.BigEndian, 1, 0x8000c1ff, 2, 2)}})
	cases["capabilities-sparc64"] = image(2, binary.BigEndian, 1, 43, nil, []section{{".SUNW_cap", 0x6ffffff5, pairs(2, binary.BigEndian, 1, 0x8000c1ff, 2, 2)}})
	cases["capabilities-ia64"] = image(2, binary.LittleEndian, 1, 50, nil, []section{{".SUNW_cap", 0x6ffffff5, pairs(2, binary.LittleEndian, 1, 0x8000c1ff, 2, 2)}})
	cases["capabilities-gnu"] = image(2, binary.LittleEndian, 1, 62, nil, []section{{".SUNW_cap", 0x6ffffff5, []byte("Agnu attributes\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")}})
	// A real file can have tables beyond the initial bytes_max prefix.
	far := append([]byte(nil), cases["64-le-notes-section"]...)
	shoff := binary.LittleEndian.Uint64(far[40:])
	tables := append([]byte(nil), far[shoff:]...)
	far = append(make([]byte, (1<<20)+512), tables...)
	copy(far, cases["64-le-notes-section"][:shoff])
	binary.LittleEndian.PutUint64(far[40:], (1<<20)+512)
	cases["far-section-table"] = far
	cases["header-only-64"] = cases["64-le-static"][:64]
	cases["header-only-32"] = cases["32-le-static"][:52]
	cases["short-elf"] = []byte{0x7f, 'E', 'L', 'F', 2, 1}
	return cases
}
