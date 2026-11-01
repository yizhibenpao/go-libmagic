package libmagic

import (
	"strings"
	"testing"
)

func TestUseOriginalViewWithoutReference(t *testing.T) {
	front := []byte{10, 20, 30, 40, 50, 60}
	active := []byte{2, 80, 90, 100, 110, 120}
	name := entry{typ: typeName}
	copy(name.value[:], "N")
	child := entry{contLevel: 1, typ: typeByte, reln: 'x', desc: "named=%u"}
	db := &Database{sets: []magicSet{{rules: []entry{name, child}, names: map[string]int{"N": 0}}}}
	for _, tc := range []struct {
		name      string
		offset    int
		indirect  bool
		activeLen int
		want      string
	}{
		{"direct", 2, false, len(active), "named=30"},
		{"pointer in active view", 0, true, len(active), "named=30"},
		{"active bounds", 3, false, 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			printed := false
			s := &state{db: db, offset: tc.offset, eoffset: 2, onEnd: true, buf: &strings.Builder{}, separator: &printed}
			use := entry{typ: typeUse, reln: '='}
			copy(use.value[:], "N")
			if tc.indirect {
				use.flag = flagIndir
				use.inType = typeByte
			}
			indir := 0
			ok := s.mget(&use, front, active[:tc.activeLen], 0, 1, flagBinTest, &indir, 0)
			if got := s.buf.String(); got != tc.want || ok != (tc.want != "") || s.err != nil {
				t.Fatalf("use = %q/%v/%v, want %q", got, ok, s.err, tc.want)
			}
			if !s.onEnd || s.eoffset != 2 {
				t.Fatal("name changed the parent's active end view")
			}
		})
	}
}
