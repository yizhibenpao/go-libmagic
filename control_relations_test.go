package libmagic

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestControlRelationsWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeDefault, typeClear} {
		for _, flag := range []uint16{0, flagUnsigned} {
			for _, input := range []uint64{0, 1, ^uint64(0), 0x123456789abcdef} {
				for _, op := range []byte{'x', '=', '!', '<', '>', '&', '^'} {
					s := state{buf: &strings.Builder{}}
					s.buf.WriteString("root")
					s.value.u64 = input
					binary.LittleEndian.PutUint64(s.value.raw[:8], input)
					before := s.value
					m := entry{typ: typ, flag: flag, reln: op, quad: ^input}
					binary.LittleEndian.PutUint64(m.value[:8], m.quad)
					want := op == 'x' || op == '=' || op == '&'
					if got := s.check(&m); got != want || s.err != nil || s.value != before || s.buf.String() != "root" {
						t.Fatalf("type %d flag %d input %x relation %c: result/error = %v/%v, want %v", typ, flag, input, op, got, s.err, want)
					}
				}
			}
		}
	}
}
