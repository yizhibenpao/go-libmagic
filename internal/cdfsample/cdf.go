// Package cdfsample constructs deterministic compound-file fixtures for the
// pure-Go tests and the independently linked libmagic 5.41 comparisons.
package cdfsample

import (
	"encoding/binary"
	"math"
	"strconv"
	"time"
)

var le = binary.LittleEndian

type entry struct {
	name string
	kind byte
	data []byte
}

type property struct {
	id, kind uint32
	data     []byte
}

func number(value uint64, size int) []byte {
	b := make([]byte, 8)
	le.PutUint64(b, value)
	return b[:size]
}

func text(value string) []byte {
	return append(number(uint64(len(value)+1), 4), append([]byte(value), 0)...)
}

func summary(os, version uint16, props ...property) []byte {
	b := make([]byte, 48+8+8*len(props))
	le.PutUint16(b, 0xfffe)
	le.PutUint16(b[4:], version)
	le.PutUint16(b[6:], os)
	le.PutUint32(b[24:], 1)
	le.PutUint32(b[44:], 48)
	le.PutUint32(b[52:], uint32(len(props)))
	for i, p := range props {
		le.PutUint32(b[56+8*i:], p.id)
		le.PutUint32(b[60+8*i:], uint32(len(b)-48))
		b = append(b, number(uint64(p.kind), 4)...)
		b = append(b, p.data...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	le.PutUint32(b[48:], uint32(len(b)-48))
	return b
}

func compound(ss int, mini, msi, far, difat bool, entries ...entry) []byte {
	nd := (len(entries) + 1 + ss/128 - 1) / (ss / 128)
	sectors := make([][]byte, nd)
	for i := range sectors {
		sectors[i] = make([]byte, ss)
	}
	var fat []int32
	for i := 0; i < nd; i++ {
		fat = append(fat, int32(i+1))
	}
	fat[nd-1] = -2
	add := func(data []byte) (int32, int) {
		first := len(sectors)
		n := (len(data) + ss - 1) / ss
		for i := 0; i < n; i++ {
			b := make([]byte, ss)
			start, end := i*ss, (i+1)*ss
			if end > len(data) {
				end = len(data)
			}
			copy(b, data[start:end])
			sectors = append(sectors, b)
			next := int32(len(sectors))
			if i == n-1 {
				next = -2
			}
			fat = append(fat, next)
		}
		return int32(first), n
	}
	if far {
		for len(sectors) < 2100 {
			sectors = append(sectors, make([]byte, ss))
			fat = append(fat, -1)
		}
	}
	dir := func(i int, name string, kind byte, first int32, size int) {
		d := sectors[i/(ss/128)][i%(ss/128)*128:][:128]
		for j := range name {
			le.PutUint16(d[2*j:], uint16(name[j]))
		}
		le.PutUint16(d[64:], uint16(2*(len(name)+1)))
		d[66] = kind
		for _, offset := range []int{68, 72, 76} {
			le.PutUint32(d[offset:], 0xffffffff)
		}
		le.PutUint32(d[116:], uint32(first))
		le.PutUint32(d[120:], uint32(size))
	}
	var short []byte
	var shortFAT []int32
	for i, e := range entries {
		first := int32(-2)
		if len(e.data) > 0 {
			if mini {
				first = int32(len(shortFAT))
				n := (len(e.data) + 63) / 64
				start := len(short)
				short = append(short, make([]byte, n*64)...)
				copy(short[start:], e.data)
				for j := 0; j < n; j++ {
					next := int32(len(shortFAT) + 1)
					if j == n-1 {
						next = -2
					}
					shortFAT = append(shortFAT, next)
				}
			} else {
				data := e.data
				if len(data) < 4096 {
					data = append(append([]byte(nil), data...), make([]byte, 4096-len(data))...)
				}
				first, _ = add(data)
			}
		}
		size := len(e.data)
		if !mini && size > 0 && size < 4096 {
			size = 4096
		}
		dir(i+1, e.name, e.kind, first, size)
	}
	rootFirst, rootSize, miniFirst, miniCount := int32(-2), 0, int32(-2), 0
	if mini && len(short) > 0 {
		rootFirst, _ = add(short)
		rootSize = len(short)
		table := make([]byte, (len(shortFAT)*4+ss-1)/ss*ss)
		for i := range table {
			table[i] = 0xff
		}
		for i, next := range shortFAT {
			le.PutUint32(table[4*i:], uint32(next))
		}
		miniFirst, miniCount = add(table)
	}
	dir(0, "Root Entry", 5, rootFirst, rootSize)
	if msi {
		le.PutUint64(sectors[0][80:], 0x00000000000c1084)
		le.PutUint64(sectors[0][88:], 0x46000000000000c0)
	}
	nfat := 1
	for (len(sectors)+nfat+1)*4 > nfat*ss {
		nfat++
	}
	fatIDs := make([]int32, nfat)
	for i := range fatIDs {
		fatIDs[i] = int32(len(sectors))
		sectors = append(sectors, make([]byte, ss))
		fat = append(fat, -3)
	}
	difatID := int32(-2)
	if difat {
		difatID = int32(len(sectors))
		table := make([]byte, ss)
		for i := range table {
			table[i] = 0xff
		}
		for i, id := range fatIDs {
			le.PutUint32(table[4*i:], uint32(id))
		}
		le.PutUint32(table[ss-4:], 0xfffffffe)
		sectors = append(sectors, table)
		fat = append(fat, -4)
	}
	for i, id := range fatIDs {
		table := sectors[id]
		for j := range table {
			table[j] = 0xff
		}
		for j := 0; j < ss/4 && i*ss/4+j < len(fat); j++ {
			le.PutUint32(table[j*4:], uint32(fat[i*ss/4+j]))
		}
	}
	b := make([]byte, ss)
	copy(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	le.PutUint16(b[24:], 0x3e)
	le.PutUint16(b[26:], 3)
	le.PutUint16(b[28:], 0xfffe)
	shift := uint16(9)
	if ss == 4096 {
		shift = 12
		le.PutUint16(b[26:], 4)
	}
	le.PutUint16(b[30:], shift)
	le.PutUint16(b[32:], 6)
	le.PutUint32(b[44:], uint32(nfat))
	le.PutUint32(b[48:], 0)
	le.PutUint32(b[56:], 4096)
	le.PutUint32(b[60:], uint32(miniFirst))
	le.PutUint32(b[64:], uint32(miniCount))
	le.PutUint32(b[68:], uint32(difatID))
	if difat {
		le.PutUint32(b[72:], 1)
	}
	for i := 76; i < 512; i++ {
		b[i] = 0xff
	}
	if !difat {
		for i, id := range fatIDs {
			le.PutUint32(b[76+4*i:], uint32(id))
		}
	}
	for _, s := range sectors {
		b = append(b, s...)
	}
	return b
}

// Cases includes real chain layouts, summary properties, and damaged metadata.
// It deliberately puts familiar names outside directory records as decoys.
func Cases() map[string][]byte {
	app := property{18, 30, text("Microsoft Word")}
	info := summary(2, 0x0a06, property{1, 2, number(1252, 2)}, property{2, 30, text("A test document")}, app)
	e := entry{"\x05SummaryInformation", 2, info}
	cases := map[string][]byte{
		"summary-long":    compound(512, false, false, false, false, e),
		"summary-mini":    compound(512, true, false, false, false, e),
		"summary-v4":      compound(4096, true, false, false, false, e),
		"summary-far":     compound(512, false, false, true, false, e),
		"summary-difat":   compound(512, false, false, false, true, e),
		"msi-clsid":       compound(512, true, true, false, false, e),
		"empty-directory": compound(512, false, false, false, false),
		"decoy-word":      compound(512, false, false, false, false, entry{"notWord", 2, []byte("WordDocument Installer Root Entry")}),
		"hwp":             compound(512, true, false, false, false, entry{"FileHeader", 2, []byte("HWP Document File\x00\x05")}),
		"hwp-decoy":       compound(512, true, false, false, false, entry{"OtherHeader", 2, []byte("HWP Document File")}),
		"doc-summary":     compound(512, true, false, false, false, entry{"\x05DocumentSummaryInformation", 2, info}),
		"second-summary":  compound(512, true, false, false, false, entry{e.name, 2, []byte("broken")}, entry{"\x05DocumentSummaryInformation", 2, info}),
		"duplicate-summary": compound(512, true, false, false, false,
			e, entry{e.name, 2, summary(1, 0x0a04, property{18, 30, text("Microsoft Excel")})}),
	}
	for _, name := range []string{"EncryptedPackage", "EncryptedSummary", "mfbu_header", "Book", "Workbook", "WordDocument", "PowerPoint", "PowerPoint Document", "__properties_version1.0"} {
		cases["section-"+name] = compound(512, false, false, false, false, entry{name, 2, nil})
	}
	cases["section-outlook-storage"] = compound(512, false, false, false, false, entry{"__recip_version1.0_#00000000", 1, nil})
	cases["wrong-directory-type"] = compound(512, false, false, false, false, entry{"WordDocument", 1, nil})
	cases["section-priority"] = compound(512, false, false, false, false, entry{"Book", 2, nil}, entry{"WordDocument", 2, nil}, entry{"EncryptedSummary", 2, nil})
	for _, app := range []string{"unknown", "Microsoft Excel", "Microsoft PowerPoint", "Crystal Reports", "Advanced Installer", "InstallShield", "Microsoft Patch Compiler", "NAnt", "Windows Installer"} {
		cases["app-"+app] = compound(512, true, false, false, false, entry{e.name, 2, summary(2, 0x0106, property{18, 30, text(app)})})
	}
	cases["summary-name-fallback"] = compound(512, true, false, false, false, entry{e.name, 2, summary(0, 0x0201, property{1, 2, number(1200, 2)})}, entry{"Workbook", 2, nil})
	cases["summary-wide"] = compound(512, true, false, false, false, entry{e.name, 2, summary(1, 0x0a04, property{2, 31, append(number(12, 4), []byte{'W', 0, 'i', 0, 'd', 0, 'e', 0, '!', 0, 0, 0}...)})})
	cases["summary-numbers"] = compound(512, true, false, false, false, entry{e.name, 2, summary(2, 6,
		property{14, 3, number(0xfffffff9, 4)}, property{15, 19, number(0xffffffff, 4)},
		property{123, 4, number(uint64(math.Float32bits(1.25)), 4)}, property{124, 5, number(math.Float64bits(12.3456789), 8)},
		property{125, 1, nil}, property{17, 71, nil})})
	cases["summary-times"] = compound(512, true, false, false, false, entry{e.name, 2, summary(2, 6,
		property{10, 64, number(900610000000, 8)}, property{12, 64, number(0x01A5E403C2D59C00, 8)}, property{13, 64, number(0, 8)})})
	for _, date := range []string{"1900-02-28", "1977-04-23", "1996-10-15", "2000-02-29", "2024-03-01", "2026-08-14", "2026-11-01"} {
		d, _ := time.Parse("2006-01-02", date)
		ticks := uint64(d.Unix()+11644473600) * 10000000
		cases["time-"+date] = compound(512, true, false, false, false, entry{e.name, 2, summary(2, 6, property{12, 64, number(ticks, 8)})})
	}
	for _, n := range []float64{math.Inf(1), math.Inf(-1), math.NaN(), math.Copysign(0, -1), 1.23456789e20, 0.000000123456789} {
		cases["float-"+strconv.FormatFloat(n, 'g', -1, 64)] = compound(512, true, false, false, false, entry{e.name, 2, summary(2, 6, property{2, 5, number(math.Float64bits(n), 8)})})
	}
	cases["vector-string"] = compound(512, true, false, false, false, entry{e.name, 2, summary(2, 6, property{2, 0x101e, append(number(1, 4), text("vector")...)})})
	cases["empty-vector"] = compound(512, true, false, false, false, entry{e.name, 2, summary(2, 6, property{2, 0x101e, number(0, 4)})})
	for _, kind := range []uint32{0, 11, 20, 21, 0x1002, 0x2003, 0x4003, 0x8003, 0x123} {
		cases["unsupported-"+strconv.FormatUint(uint64(kind), 16)] = compound(512, true, false, false, false, entry{e.name, 2, summary(2, 6, property{2, kind, number(1, 8)})})
	}
	mutate := func(name, original string, offset int, value uint32) {
		b := append([]byte(nil), cases[original]...)
		le.PutUint32(b[offset:], value)
		cases[name] = b
	}
	mutate("bad-sat", "summary-mini", 76, 0x100000)
	mutate("bad-ssat", "summary-mini", 60, 0x100000)
	mutate("bad-directory", "summary-mini", 48, 0x100000)
	mutate("bad-root-stream", "summary-mini", 512+116, 0x100000)
	mutate("bad-summary-stream", "summary-mini", 512+128+116, 0x100000)
	mutate("bad-summary-length", "summary-mini", 1024+48, 0xffffffff)
	mutate("bad-summary-property", "summary-mini", 1024+60, 0xffffffff)
	mutate("ignored-sat-count", "summary-mini", 44, 0)
	mutate("ignored-ssat-count", "summary-mini", 64, 0)
	mutate("ignored-version", "summary-mini", 24, 0x0009003e)
	mutate("ignored-byteorder", "summary-mini", 28, 0x0009feff)
	mutate("big-endian-summary", "summary-mini", 1024, 0x0000feff)
	mutate("no-root-storage", "summary-mini", 512+64, 0)
	mutate("root-empty-size", "summary-mini", 512+120, 0)
	mutate("summary-zero-size", "summary-mini", 512+128+120, 0)
	mutate("summary-offset-small", "summary-mini", 1024+60, 4)
	mutate("summary-offset-equal-length", "summary-mini", 1024+60, uint32(len(info)-48))
	mutate("summary-properties-limit", "summary-mini", 1024+52, 0xffffffff)
	mutate("summary-count-ignored", "summary-mini", 1024+24, 0xffffffff)
	mutate("master-count-limit", "summary-mini", 72, 0xffffffff)
	mutate("bad-difat", "summary-difat", 68, 0x100000)
	mutate("negative-directory", "summary-mini", 48, 0xffffffff)
	mutate("end-directory", "summary-mini", 48, 0xfffffffe)
	mutate("header-shift-too-big", "summary-mini", 30, 0x00060015)
	for _, shift := range []uint32{0, 1, 2, 3, 6, 7, 8} {
		mutate("small-sector-"+strconv.FormatUint(uint64(shift), 10), "summary-mini", 30, 0x00060000|shift)
	}
	cases["header-truncated"] = cases["summary-mini"][:511]
	cases["truncated-sat"] = cases["summary-mini"][:len(cases["summary-mini"])-1]
	loop := append([]byte(nil), cases["summary-mini"]...)
	fatID := le.Uint32(loop[76:])
	le.PutUint32(loop[(fatID+1)*512:], 0)
	cases["directory-loop"] = loop
	return cases
}
