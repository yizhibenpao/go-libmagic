package libmagic

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestFloatRelationErrorsWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeFloat, typeBEFloat, typeLEFloat, typeDouble, typeBEDouble, typeLEDouble} {
		for _, op := range []byte{'&', '^'} {
			for _, line := range []uint32{0, 37} {
				for _, prefix := range []string{"", "root"} {
					s := state{line: line, buf: &strings.Builder{}}
					s.buf.WriteString(prefix)
					s.value.f32, s.value.f64 = 1, 1
					before := s.value
					m := entry{typ: typ, reln: op, lineno: 99}
					kind := "float"
					if typ >= typeDouble {
						kind = "double"
					}
					want := fmt.Sprintf("cannot happen with %s: invalid relation `%c'", kind, op)
					if line != 0 {
						want = fmt.Sprintf("line %d: %s", line, want)
					} else if prefix != "" {
						want = prefix + " " + want
					}
					if s.check(&m) || s.err == nil || s.err.Error() != want || s.value != before || s.buf.String() != prefix {
						t.Fatalf("type %d relation %c line %d prefix %q: error = %v, want %q", typ, op, line, prefix, s.err, want)
					}
				}
			}
		}
	}
}

func TestFloatValidRelationsWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeFloat, typeBEFloat, typeLEFloat, typeDouble, typeBEDouble, typeLEDouble} {
		for _, pair := range [][2]float64{{1, 1}, {1, 2}, {2, 1}, {0, math.Copysign(0, -1)}, {math.Inf(1), 1}, {math.NaN(), 1}, {1, math.NaN()}} {
			for _, op := range []byte{'x', '!', '=', '<', '>'} {
				s := state{buf: &strings.Builder{}}
				s.value.f32, s.value.f64 = float32(pair[0]), pair[0]
				m := entry{typ: typ, reln: op}
				if typ < typeDouble {
					m.quad = uint64(math.Float32bits(float32(pair[1])))
				} else {
					m.quad = math.Float64bits(pair[1])
				}
				var want bool
				switch op {
				case 'x':
					want = true
				case '!':
					want = pair[0] != pair[1]
				case '=':
					want = pair[0] == pair[1]
				case '<':
					want = pair[0] < pair[1]
				case '>':
					want = pair[0] > pair[1]
				}
				if got := s.check(&m); got != want || s.err != nil {
					t.Fatalf("type %d relation %c pair %v: result/error = %v/%v, want %v", typ, op, pair, got, s.err, want)
				}
			}
		}
	}
}
