package libmagic

import (
	"encoding/binary"
	"testing"
)

func TestCompiledComparisonWidthWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeByte, typeLEShort, typeLELong} {
		bits := numericBits(typ)
		max := uint64(1)<<uint(bits) - 1
		s := state{value: value{u64: max}}
		m := entry{typ: typ, flag: flagUnsigned, reln: '=', quad: ^uint64(0)}
		if s.check(&m) {
			t.Fatalf("type %d truncated the compiled unsigned -1", typ)
		}
		m.flag = 0
		if !s.check(&m) {
			t.Fatalf("type %d did not sign-extend the input", typ)
		}
		s.value.u64, m.flag, m.quad = 0, flagUnsigned, max+1
		if s.check(&m) {
			t.Fatalf("type %d truncated the overflowing unsigned constant", typ)
		}
		m.reln = '<'
		if !s.check(&m) {
			t.Fatalf("type %d did not compare against the full constant", typ)
		}
	}
}

func TestTypedZeroMaskWithoutReference(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd}
	for _, typ := range []uint8{typeByte, typeBEShort, typeBELong} {
		for _, flag := range []uint16{0, flagUnsigned} {
			for _, op := range []uint8{opAnd, opMul, opDiv, opMod} {
				m := entry{typ: typ, flag: flag, maskOp: op, numMask: uint64(1) << uint(numericBits(typ)), lineno: 17}
				s := state{line: 17}
				ok := s.copyValue(&m, data, 0, 0)
				if op == opDiv || op == opMod {
					if ok || s.err == nil || s.err.Error() != "line 17: zerodivide in mconvert()" {
						t.Fatalf("type %d flag %d op %d: %v/%v", typ, flag, op, ok, s.err)
					}
					// mconvert changes byte order before the failed division.
					want := uint64(data[0])
					got := uint64(s.value.raw[0])
					if width(typ) == 2 {
						want = uint64(binary.BigEndian.Uint16(data))
						got = uint64(binary.LittleEndian.Uint16(s.value.raw[:2]))
					} else if width(typ) == 4 {
						want = uint64(binary.BigEndian.Uint32(data))
						got = uint64(binary.LittleEndian.Uint32(s.value.raw[:4]))
					}
					if got != want || s.value.raw[4] != data[4] {
						t.Fatalf("type %d failed conversion changed the union: %x, want %x", typ, s.value.raw[:8], want)
					}
				} else if !ok || s.err != nil || s.value.u64 != 0 {
					t.Fatalf("type %d flag %d op %d: %v/%v/%x, want zero", typ, flag, op, ok, s.err, s.value.u64)
				}
				// An original zero mask is skipped, unlike a narrowed zero.
				m.numMask = 0
				s = state{}
				if !s.copyValue(&m, data, 0, 0) || s.err != nil || s.value.u64 == 0 {
					t.Fatalf("type %d flag %d op %d did not skip an original zero mask", typ, flag, op)
				}
			}
		}
	}
}

func TestStringRelationsWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeString, typePString, typeBEStr16, typeLEStr16} {
		for _, flag := range []uint16{0, flagUnsigned} {
			s := state{}
			s.value.raw[0] = 'Z'
			m := entry{typ: typ, flag: flag, vallen: 1}
			m.value[0] = 'z'
			for _, tc := range []struct {
				op   byte
				want bool
			}{
				{'=', false}, {'!', true}, {'<', flag == 0},
				{'>', flag != 0}, {'&', true}, {'^', false}, {'x', true},
			} {
				m.reln = tc.op
				if got := s.check(&m); got != tc.want {
					t.Fatalf("type %d flag %d relation %c: %v, want %v", typ, flag, tc.op, got, tc.want)
				}
			}
			m.vallen, m.reln = 0, '='
			if !s.check(&m) {
				t.Fatalf("type %d flag %d compared bytes for an empty literal", typ, flag)
			}
		}
	}
}

func TestGUIDRelationsWithoutReference(t *testing.T) {
	for _, flag := range []uint16{0, flagUnsigned} {
		s := state{}
		s.value.raw[0] = 0xff
		m := entry{typ: typeGUID, flag: flag}
		m.guid[0] = 0x33
		for _, tc := range []struct {
			op   byte
			want bool
		}{
			{'=', false}, {'!', true}, {'<', flag == 0},
			{'>', flag != 0}, {'&', true}, {'^', false}, {'x', true},
		} {
			m.reln = tc.op
			if got := s.check(&m); got != tc.want {
				t.Fatalf("GUID flag %d relation %c: %v, want %v", flag, tc.op, got, tc.want)
			}
		}
	}
}
