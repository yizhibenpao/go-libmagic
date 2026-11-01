package libmagic

import "testing"

func TestIndirectTypesWithoutReference(t *testing.T) {
	valid := map[uint8]bool{
		typeByte: true, typeShort: true, typeLong: true,
		typeBEShort: true, typeBELong: true, typeLEShort: true,
		typeLELong: true, typeMELong: true, typeLEQuad: true,
		typeBEQuad: true, typeBEID3: true, typeLEID3: true,
	}
	data := make([]byte, 32)
	for typ := 0; typ < 256; typ++ {
		for _, rhs := range []uint8{0, opIndirect} {
			for _, signed := range []uint8{0, opSigned} {
				for _, flip := range []bool{false, true} {
					s := state{flip: flip}
					m := entry{inType: uint8(typ), inOffset: 8, inOp: opAdd | rhs | signed}
					before := s.value
					got, ok := s.readIndirect(&m, data, 4, 0)
					want := 8
					if rhs != 0 {
						want = 0
					}
					allowed := valid[flippedType(m.inType, flip)]
					if ok != allowed || ok && got != want || s.err != nil || s.value != before {
						t.Fatalf("type %d rhs %d signed %d flip %v: offset/ok/error = %d/%v/%v, want %d/%v; value unchanged %v", typ, rhs, signed, flip, got, ok, s.err, want, allowed, s.value == before)
					}
				}
			}
		}
	}
}
