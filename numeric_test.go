package libmagic

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestFloatConversionWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeFloat, typeBEFloat, typeLEFloat, typeDouble, typeBEDouble, typeLEDouble} {
		for _, tc := range []struct {
			op   uint8
			mask uint64
			want float64
		}{
			{opAdd, 2, 5}, {opSub, 2, 1}, {opMul, 2, 6}, {opDiv, 2, 1.5},
			{opAnd, 2, 3}, {opOr, 2, 3}, {opXor, 2, 3}, {opMod, 2, 3},
			{opMul, 0, 3}, {opDiv, 0, 3}, {opInverse, 0, 3},
			{opMul | opInverse, 2, 6},
		} {
			m := entry{typ: typ, maskOp: tc.op, numMask: tc.mask}
			s := state{value: value{f32: 3, f64: 3}}
			if numericBits(typ) == 32 {
				s.value.u64 = uint64(math.Float32bits(3))
			} else {
				s.value.u64 = math.Float64bits(3)
			}
			s.applyMask(&m)
			got := s.value.f64
			bits := math.Float64bits(tc.want)
			if numericBits(typ) == 32 {
				got = float64(s.value.f32)
				bits = uint64(math.Float32bits(float32(tc.want)))
			}
			if got != tc.want || s.value.u64 != bits {
				t.Errorf("type %d op %d mask %d = %g/%x, want %g/%x", typ, tc.op, tc.mask, got, s.value.u64, tc.want, bits)
			}
		}
	}
	// cvt_float rounds the integer operand and each result to float.
	s := state{value: value{f32: 16777216}}
	s.applyMask(&entry{typ: typeFloat, maskOp: opAdd, numMask: 1})
	if s.value.f32 != 16777216 || s.value.u64 != uint64(math.Float32bits(16777216)) {
		t.Fatalf("single-precision addition = %g/%x", s.value.f32, s.value.u64)
	}
	s = state{value: value{}}
	s.applyMask(&entry{typ: typeFloat, maskOp: opAdd, numMask: 16777217})
	if s.value.f32 != 16777216 {
		t.Fatalf("single-precision operand = %g", s.value.f32)
	}
}

func TestIndirectUint32WithoutReference(t *testing.T) {
	for _, tc := range []struct {
		lhs    uint64
		op     uint8
		rhs    int32
		parent bool
		want   int
		ok     bool
	}{
		{0x80000006, opMul, 2, false, 12, true},
		{0xfffffffc, opAdd, 16, false, 12, true},
		{0x10000000c, opAdd, 0, false, 12, true},
		{0xfffffff8, opAdd, 0, true, 1, true},
		{0xfffffff7, opAdd, 0, true, 0, false},
		{0xfffffffa, opAdd, 0, false, 0xfffffffa, true},
	} {
		data := make([]byte, 36)
		binary.LittleEndian.PutUint64(data, tc.lhs)
		m := entry{inType: typeLEQuad, inOp: tc.op, inOffset: tc.rhs}
		s := state{levels: []level{{off: 9}}}
		if tc.parent {
			m.flag = flagIndirOffAdd
		}
		// mget copies the primary union first; final type bounds are
		// checked after readIndirect returns its uint32_t result.
		s.copyRaw(m.typ, data, 0, true)
		got, ok := s.readIndirect(&m, data, 0, 1)
		if got != tc.want || ok != tc.ok {
			t.Errorf("lhs %x op %d rhs %d parent %v = %d/%v, want %d/%v", tc.lhs, tc.op, tc.rhs, tc.parent, got, ok, tc.want, tc.ok)
		}
	}
}
