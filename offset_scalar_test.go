package libmagic

import (
	"encoding/binary"
	"testing"
)

func TestOffsetMasksWithoutReference(t *testing.T) {
	for _, flag := range []uint16{0, flagUnsigned} {
		for _, tc := range []struct {
			op   uint8
			mask uint64
			want uint64
		}{
			{opAnd, 2, 0}, {opOr, 2, 6}, {opXor, 2, 6},
			{opAdd, 2, 6}, {opSub, 2, 2}, {opMul, 2, 8},
			{opDiv, 2, 2}, {opMod, 3, 1}, {opInverse, 0, ^uint64(4)},
			{opAnd, 0, 4}, {opDiv, 0, 4},
		} {
			s := state{}
			m := entry{typ: typeOffset, flag: flag, maskOp: tc.op, numMask: tc.mask}
			// FILE_OFFSET is intrinsic, including beyond the input extent.
			if !s.copyValue(&m, []byte{90, 91}, 4, 4) || s.err != nil {
				t.Fatalf("flag %d op %d: intrinsic offset read failed: %v", flag, tc.op, s.err)
			}
			if s.value.u64 != tc.want || binary.LittleEndian.Uint64(s.value.raw[:8]) != tc.want {
				t.Fatalf("flag %d op %d: %x/%x, want %x", flag, tc.op, s.value.u64, s.value.raw[:8], tc.want)
			}
			s.offset = 4
			if next, ok := s.moffset(&m, 32); !ok || next != 4 {
				t.Fatalf("flag %d op %d: continuation follows %d/%v, want original offset 4", flag, tc.op, next, ok)
			}
		}
	}
}

func TestOffsetIndirectLiteralWithoutReference(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[4:], 12)
	for _, tc := range []struct {
		name string
		typ  uint8
		base int
		want int
	}{
		{"byte", typeByte, 0, 4},
		{"short", typeLEShort, 0, 4},
		{"long", typeLELong, 0, 4},
		{"quad", typeLEQuad, 0, 4},
		{"big endian", typeBELong, 0, 0x04000000},
		{"named base", typeLELong, 5, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := state{offset: 4}
			for i := range s.value.raw {
				s.value.raw[i] = 0xff
			}
			m := entry{typ: typeOffset, flag: flagIndir, inType: tc.typ, reln: 'x'}
			indir := 0
			if !s.mget(&m, data, data, tc.base, 1, flagBinTest, &indir, 0) || s.err != nil {
				t.Fatalf("intrinsic indirect offset failed: %v", s.err)
			}
			if s.offset != tc.want || s.value.u64 != uint64(tc.want) || binary.LittleEndian.Uint64(s.value.raw[:8]) != uint64(tc.want) {
				t.Fatalf("offset/value/raw = %d/%d/%x, want %d", s.offset, s.value.u64, s.value.raw[:8], tc.want)
			}
			for _, b := range s.value.raw[8:] {
				if b != 0 {
					t.Fatal("intrinsic copy retained file or previous union bytes")
				}
			}
		})
	}
}
