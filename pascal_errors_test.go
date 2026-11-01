package libmagic

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestPascalErrorOrderWithoutReference(t *testing.T) {
	data := []byte{2, 'C', 'D', 0}
	for bits := uint32(0); bits < 32; bits++ {
		for _, extra := range []uint32{0, pstringLenIncludesItself, stringTrim, stringBinTest | stringTextTest | stringIgnoreLower} {
			for _, offset := range []int{0, len(data), len(data) + 1} {
				flags := bits<<7 | extra
				s := &state{buf: &strings.Builder{}, line: 19}
				s.buf.WriteString("root")
				m := entry{typ: typePString, reln: 'x', vallen: 1, strFlags: flags}
				got := s.copyValue(&m, data, offset, offset)
				valid := bits == 1 || bits == 2 || bits == 4 || bits == 8 || bits == 16
				if offset != 0 {
					if got || s.err != nil || s.value.raw != [maxString]byte{} {
						t.Fatalf("bounds must precede length conversion: flags %d offset %d = %v/%v", flags, offset, got, s.err)
					}
				} else if !valid {
					want := fmt.Sprintf("root corrupt magic file (bad pascal string length %d)", bits<<7)
					if got || s.err == nil || s.err.Error() != want || !bytes.Equal(s.value.raw[:len(data)], data) {
						t.Fatalf("flags %d: copied %v error %v, want %q and the unconverted copy", flags, got, s.err, want)
					}
				} else if s.err != nil {
					t.Fatalf("valid length flags %d must not report corruption: %v", flags, s.err)
				}
			}
		}
	}
}
