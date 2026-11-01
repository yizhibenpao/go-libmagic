package libmagic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleLineOrderWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []entry
		text  bool
		want  uint32
	}{
		{"skipped top", []entry{{typ: typeString, flag: flagBinTest, strFlags: stringBinTest, lineno: 22}}, true, 91},
		{"failed top read", []entry{{typ: typeByte, flag: flagBinTest, offset: 50, reln: 'x', lineno: 22}}, false, 22},
		{"unreachable continuation", []entry{
			{typ: typeByte, flag: flagBinTest, reln: '=', quad: 'A', lineno: 10},
			{typ: typeByte, contLevel: 1, offset: 50, reln: 'x', lineno: 20},
			{typ: typeByte, contLevel: 2, reln: 'x', lineno: 30},
		}, false, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &Database{sets: []magicSet{{rules: tc.rules, n0: len(tc.rules)}}}
			s := state{db: db, set: &db.sets[0], line: 91, text: tc.text, buf: &strings.Builder{}}
			indir := 0
			s.soft([]byte("AB\x00\x01"), 0, flagBinTest, &indir, 0)
			if s.err != nil || s.line != tc.want {
				t.Fatalf("line/error = %d/%v, want %d", s.line, s.err, tc.want)
			}
		})
	}
}

func TestNamedHeaderRuleLineWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01CDEFGHIJ")
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	db := &Database{sets: []magicSet{{rules: []entry{
		{typ: typeName, flag: flagOffNegative, offset: 1, lineno: 1},
		{typ: typeByte, contLevel: 1, reln: 'x', lineno: 2},
	}, names: map[string]int{"N": 0}}}}
	for _, tc := range []struct {
		line   uint32
		prefix string
	}{
		{0, ""},
		{73, ""},
		{0, "root"},
		{73, "root"},
	} {
		separator := false
		s := state{db: db, offset: 4, line: tc.line, tail: &tail{reader: f, size: int64(len(data)), regular: true}, separator: &separator, buf: &strings.Builder{}}
		s.buf.WriteString(tc.prefix)
		use := entry{typ: typeUse, lineno: 99}
		copy(use.value[:], "N")
		indir := 0
		got := s.mget(&use, data, data, 0, 1, flagBinTest, &indir, 0)
		want := "non zero offset 4 at level 0"
		if tc.line != 0 {
			want = fmt.Sprintf("line %d: %s", tc.line, want)
		} else if tc.prefix != "" {
			want = tc.prefix + " " + want
		}
		if got || s.err == nil || s.err.Error() != want || s.line != tc.line {
			t.Fatalf("caller line %d, prefix %q: result/error/line = %v/%v/%d, want %q", tc.line, tc.prefix, got, s.err, s.line, want)
		}
	}
}

func TestCallRuleLineWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01")
	for _, name := range []string{"named", "indirect", "skipped indirect"} {
		t.Run(name, func(t *testing.T) {
			rules := []entry{
				{typ: typeByte, flag: flagBinTest, reln: 'x', lineno: 22},
				{typ: typeByte, contLevel: 1, offset: 50, reln: 'x', lineno: 33},
			}
			call := entry{typ: typeIndirect}
			want := uint32(33)
			if name == "named" {
				rules[0].typ = typeName
				call.typ = typeUse
				copy(call.value[:], "N")
			}
			if name == "skipped indirect" {
				rules[0].typ, rules[0].strFlags = typeString, stringBinTest
				want = 91
			}
			n0 := len(rules)
			if name == "named" {
				n0 = 0
			}
			db := &Database{sets: []magicSet{{rules: rules, n0: n0, names: map[string]int{"N": 0}}}}
			separator := false
			s := state{db: db, offset: 1, line: 91, text: name == "skipped indirect", separator: &separator, buf: &strings.Builder{}}
			indir := 0
			s.mget(&call, data, data, 0, 1, flagBinTest, &indir, 0)
			if s.err != nil || s.line != want {
				t.Fatalf("line/error = %d/%v, want %d", s.line, s.err, want)
			}
		})
	}
}
