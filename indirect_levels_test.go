package libmagic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndirectLevelsWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01CDEFGHIJ\x00\x01")
	for _, printed := range []bool{false, true} {
		root := entry{typ: typeString, flag: flagBinTest, reln: '=', vallen: 5}
		copy(root.value[:], "CDEFG")
		if printed {
			root.desc = "child"
		}
		rules := []entry{root}
		for depth := 1; depth <= 6; depth++ {
			rules = append(rules, entry{typ: typeByte, contLevel: uint16(depth), offset: int32(depth), reln: 'x'})
		}
		db := &Database{sets: []magicSet{{rules: rules, n0: len(rules)}}}
		// The child must return an expanded continuation slice, including
		// when it matched without producing a description or MIME.
		levels := make([]level, 2)
		levels[0].off, levels[1].off = 123, 456
		s := state{db: db, offset: 4, eoffset: 7, buf: &strings.Builder{}, levels: levels}
		indir := 0
		got := s.mget(&entry{typ: typeIndirect}, data, data, 0, 1, flagBinTest, &indir, 0)
		if s.err != nil || got != printed || s.offset != 4 || s.eoffset != 0 || len(s.levels) < 8 {
			t.Fatalf("printed %v: got=%v error=%v offset=%d end=%d levels=%+v", printed, got, s.err, s.offset, s.eoffset, s.levels)
		}
		if s.levels[0].off != 5 {
			t.Fatalf("printed %v: child root end = %d, want 5", printed, s.levels[0].off)
		}
		for depth := 1; depth <= 6; depth++ {
			if s.levels[depth].off != int32(depth+1) {
				t.Fatalf("printed %v: child level %d end = %d", printed, depth, s.levels[depth].off)
			}
		}
	}
}

func TestIndirectEndOffsetWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01CDEFGHIJ\x00\x01")
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, prefilled := range []bool{false, true} {
		root := entry{typ: typeString, flag: flagBinTest, reln: '=', vallen: 5, desc: "child"}
		copy(root.value[:], "CDEFG")
		db := &Database{sets: []magicSet{{rules: []entry{root, {typ: typeByte, contLevel: 1, flag: flagOffNegative, offset: 1, reln: 'x'}}, n0: 2}}}
		end := &tail{reader: f, size: int64(len(data)), regular: true}
		want := len(data) - 4 - 1
		if prefilled {
			end.done, end.buf = true, data
			want = len(data) - 1
		}
		s := state{db: db, offset: 4, eoffset: 4, onEnd: prefilled, tail: end, buf: &strings.Builder{}}
		indir := 0
		if !s.mget(&entry{typ: typeIndirect}, data, data, 0, 1, flagBinTest, &indir, 0) || s.err != nil {
			t.Fatalf("prefilled %v: indirect failed: %v", prefilled, s.err)
		}
		if s.offset != 4 || s.eoffset != want || s.onEnd != prefilled || s.tail != end || end.done != prefilled {
			t.Fatalf("prefilled %v: offset/end/view/tail = %d/%d/%v/%+v, want parent offset 4, child end %d, unchanged parent view", prefilled, s.offset, s.eoffset, s.onEnd, end, want)
		}
	}
}

func TestSkippedIndirectEndOffsetWithoutReference(t *testing.T) {
	root := entry{typ: typeString, flag: flagBinTest, strFlags: stringBinTest, reln: '=', vallen: 1}
	copy(root.value[:], "C")
	db := &Database{sets: []magicSet{{rules: []entry{root}, n0: 1}}}
	data := []byte("ABxxCDEFGHIJ\n")
	s := state{db: db, text: true, offset: 4, eoffset: 7, buf: &strings.Builder{}, levels: []level{{off: 9}}}
	indir := 0
	if s.mget(&entry{typ: typeIndirect}, data, data, 0, 1, flagBinTest, &indir, 0) || s.err != nil {
		t.Fatalf("binary-only child was not skipped: %v", s.err)
	}
	if s.offset != 4 || s.eoffset != 7 || s.levels[0].off != 9 {
		t.Fatalf("skipped child changed offsets: %d/%d/%d", s.offset, s.eoffset, s.levels[0].off)
	}
}
