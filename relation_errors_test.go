package libmagic

import (
	"strings"
	"testing"
)

func TestRelationErrorsWithoutReference(t *testing.T) {
	valid := map[byte]bool{'x': true, '!': true, '=': false, '>': true, '<': false, '&': true, '^': false}
	for _, kind := range []string{"common", "float", "double"} {
		for op := 0; op < 256; op++ {
			for _, line := range []uint32{0, 7} {
				s := state{buf: &strings.Builder{}, line: line}
				s.buf.WriteString("root")
				s.value.u64, s.value.raw[0] = 123, 0xab
				before := s.value
				got := false
				if kind == "common" {
					got = s.rel(3, 1, byte(op), false)
				} else {
					got = s.cmpFloat(3, 1, byte(op), kind)
				}
				want, ok := valid[byte(op)]
				if kind != "common" && (op == '&' || op == '^') {
					ok = false
				}
				if ok {
					if got != want || s.err != nil {
						t.Fatalf("%s relation %d: result/error %v/%v, want %v", kind, op, got, s.err, want)
					}
				} else {
					prefix := "cannot happen"
					if kind != "common" {
						prefix += " with " + kind
					}
					message := prefix + ": invalid relation `"
					if op != 0 {
						message += string([]byte{byte(op), '\''})
					}
					if line == 0 {
						message = "root " + message
					} else {
						message = "line 7: " + message
					}
					if got || s.err == nil || s.err.Error() != message {
						t.Fatalf("%s relation %d line %d: result/error %v/%v, want bytes %q", kind, op, line, got, s.err, message)
					}
				}
				if s.value != before || s.buf.String() != "root" {
					t.Fatalf("%s relation %d changed the union or output", kind, op)
				}
			}
		}
	}
}

func TestValidRelationsWithoutReference(t *testing.T) {
	for _, pair := range [][2]int64{{0, 0}, {-1, 0}, {-1 << 63, 1<<63 - 1}, {3, 1}, {1, 3}} {
		v, l := pair[0], pair[1]
		for _, unsigned := range []bool{false, true} {
			less, greater := v < l, v > l
			if unsigned {
				less, greater = uint64(v) < uint64(l), uint64(v) > uint64(l)
			}
			for op, want := range map[byte]bool{
				'x': true, '!': v != l, '=': v == l, '>': greater, '<': less,
				'&': uint64(v)&uint64(l) == uint64(l), '^': uint64(v)&uint64(l) != uint64(l),
			} {
				s := state{buf: &strings.Builder{}, line: 7}
				if got := s.rel(v, l, op, unsigned); got != want || s.err != nil {
					t.Fatalf("values %d/%d unsigned %v relation %c: %v/%v, want %v", v, l, unsigned, op, got, s.err, want)
				}
			}
		}
	}
}

func TestRelationErrorOrderWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeSearch, typeRegex} {
		m := entry{typ: typ, reln: '?', vallen: 1}
		m.value[0] = 'B'
		if typ == typeRegex {
			m.re = compileRule(&m)
		}
		s := state{buf: &strings.Builder{}, line: 7, search: search{s: []byte("ABZ"), offset: 4, rmLen: 9}}
		if s.check(&m) || s.err == nil || s.err.Error() != "line 7: cannot happen: invalid relation `?'" {
			t.Fatalf("type %d: expected relation error, got %v", typ, s.err)
		}
		length := 2
		if typ == typeRegex {
			length = 1
		}
		if s.search.offset != 5 || s.search.rmLen != length {
			t.Fatalf("type %d: search work must precede relation error: offset %d length %d", typ, s.search.offset, s.search.rmLen)
		}
	}
	s := state{buf: &strings.Builder{}, line: 7}
	if s.regexMatch(&entry{typ: typeRegex, reln: '?'}) || s.err != nil {
		t.Fatal("a nil regex search region must bypass relation checking")
	}
}
