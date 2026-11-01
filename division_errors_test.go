package libmagic

import (
	"strings"
	"testing"
)

func TestDivisionErrorsWithoutReference(t *testing.T) {
	for _, typ := range []uint8{
		typeByte, typeShort, typeBEShort, typeLEShort,
		typeLong, typeBELong, typeLELong, typeMELong,
		typeDate, typeBEDate, typeLEDate, typeMEDate,
		typeLDate, typeBELDate, typeLELDate, typeMELDate,
	} {
		for _, op := range []uint8{opDiv, opMod} {
			for _, line := range []uint32{0, 7} {
				for _, inverse := range []uint8{0, opInverse} {
					s := state{buf: &strings.Builder{}, line: line}
					s.buf.WriteString("root")
					s.value.u64, s.value.raw[0], s.value.n, s.value.text = 123, 0xab, 1, "before"
					before := s.value
					m := entry{typ: typ, numMask: uint64(1) << numericBits(typ), maskOp: op | inverse, lineno: 999}
					want := "line 7: zerodivide in mconvert()"
					if line == 0 {
						want = "root zerodivide in mconvert()"
					}
					if s.applyMask(&m) || s.err == nil || s.err.Error() != want {
						t.Fatalf("type %d op %d line %d inverse %d: error %v, want %q", typ, op, line, inverse, s.err, want)
					}
					if s.value != before || s.buf.String() != "root" {
						t.Fatalf("type %d op %d line %d inverse %d changed value/output", typ, op, line, inverse)
					}
				}
			}
		}
	}
}

func TestZeroDivisionMasksWithoutReference(t *testing.T) {
	for _, typ := range []uint8{
		typeByte, typeShort, typeBEShort, typeLEShort,
		typeLong, typeBELong, typeLELong, typeMELong,
		typeDate, typeBEDate, typeLEDate, typeMEDate,
		typeLDate, typeBELDate, typeLELDate, typeMELDate,
	} {
		for _, op := range []uint8{opDiv, opMod} {
			for _, inverse := range []uint8{0, opInverse} {
				s := state{buf: &strings.Builder{}, line: 7}
				s.buf.WriteString("root")
				s.value.u64 = 123
				m := entry{typ: typ, maskOp: op | inverse}
				want := uint64(123)
				if inverse != 0 {
					want = ^want
				}
				mask := uint64(1)<<numericBits(typ) - 1
				if !s.applyMask(&m) || s.err != nil || s.value.u64&mask != want&mask || s.buf.String() != "root" {
					t.Fatalf("type %d op %d inverse %d: value/error = %x/%v, want low bits %x", typ, op, inverse, s.value.u64, s.err, want&mask)
				}
			}
		}
	}
}
