package libmagic

import (
	"strings"
	"testing"
)

func TestNamedSearchContextWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01CDEFGHIJ")
	for _, tc := range []struct {
		name    string
		typ     uint8
		pattern string
		reln    byte
		want    int
	}{
		{"inherit", typeSearch, "Z", '!', 5},
		{"overwrite", typeRegex, "CDE", '=', 3},
		{"failed match clears", typeRegex, "Z", '=', 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := entry{typ: tc.typ, contLevel: 1, offset: 4, reln: tc.reln, vallen: uint8(len(tc.pattern)), strRange: 8}
			copy(rule.value[:], tc.pattern)
			db := &Database{sets: []magicSet{{rules: []entry{{typ: typeName}, rule}, names: map[string]int{"N": 0}}}}
			separator := false
			s := state{db: db, set: &db.sets[0], buf: &strings.Builder{}, separator: &separator, search: search{s: data[4:], offset: 4, rmLen: 5}}
			use := entry{typ: typeUse, reln: 'x'}
			copy(use.value[:], "N")
			indir := 0
			s.mget(&use, data, data, 0, 1, flagBinTest, &indir, 0)
			if s.err != nil || s.search.rmLen != tc.want || s.search.offset != 4 || string(s.search.s) != "CDEFGHIJ" {
				t.Fatalf("search = %+v, error %v; want length %d", s.search, s.err, tc.want)
			}
		})
	}
}

func TestIndirectSearchContextWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01CDEFGHIJ")
	for _, tc := range []struct {
		name    string
		typ     uint8
		pattern string
		reln    byte
		want    int
	}{
		{"inherit", typeSearch, "Z", '!', 5},
		{"overwrite", typeRegex, "CDE", '=', 3},
		{"failed match clears", typeRegex, "Z", '=', 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := entry{typ: tc.typ, contLevel: 1, reln: tc.reln, vallen: uint8(len(tc.pattern)), strRange: 8}
			copy(rule.value[:], tc.pattern)
			db := &Database{sets: []magicSet{{rules: []entry{{typ: typeByte, flag: flagBinTest, reln: 'x'}, rule}, n0: 2}}}
			s := state{db: db, set: &db.sets[0], offset: 4, buf: &strings.Builder{}, search: search{s: data[4:], offset: 4, rmLen: 5}}
			indir := 0
			s.mget(&entry{typ: typeIndirect, reln: 'x'}, data, data, 0, 1, flagBinTest, &indir, 0)
			if s.err != nil || s.search.rmLen != tc.want || s.search.offset != 0 || string(s.search.s) != "CDEFGHIJ" {
				t.Fatalf("search = %+v, error %v; want child length %d", s.search, s.err, tc.want)
			}
		})
	}
}

func TestSearchContextRequestIsolationWithoutReference(t *testing.T) {
	seed := entry{typ: typeRegex, contLevel: 1, offset: 4, reln: '=', vallen: 3, strRange: 8}
	copy(seed.value[:], "CDE")
	negative := entry{typ: typeSearch, contLevel: 1, offset: 4, reln: '!', vallen: 1, strRange: 4, desc: "tail=[%s]"}
	copy(negative.value[:], "Z")
	db := &Database{sets: []magicSet{
		{rules: []entry{{typ: typeByte, flag: flagBinTest, reln: '=', quad: 'A'}, seed}, n0: 2},
		{rules: []entry{{typ: typeByte, flag: flagBinTest, reln: 'x', desc: "root"}, negative}, n0: 2},
	}}
	for _, tc := range []struct {
		data string
		want string
	}{
		{"AB\x00\x01CDEFGHIJ", "root tail=[CDE]"},
		{"BB\x00\x01CDEFGHIJ", "root tail=[]"},
		{"AB\x00\x01CDEFGHIJ", "root tail=[CDE]"},
	} {
		got, err := db.Buffer([]byte(tc.data))
		if err != nil || got != tc.want {
			t.Fatalf("Buffer = %q/%v, want %q", got, err, tc.want)
		}
	}
}
