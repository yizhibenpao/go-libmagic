package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/mimeprobe"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMIMEProbeContracts(t *testing.T) {
	for _, tc := range mimeprobe.Cases() {
		t.Run(tc.Name, func(t *testing.T) {
			db := &Database{}
			for _, source := range tc.Sources {
				db.sets = append(db.sets, compileProbe(t, source).sets...)
			}
			if got, err := db.BufferMIMEType(tc.Data); err != nil || got != tc.MIME {
				t.Errorf("Buffer MIME = %q/%v, want %q", got, err, tc.MIME)
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			want := tc.MIME
			if tc.FileMIME != "" {
				want = tc.FileMIME
			}
			if got, err := db.FileMIMEType(path); err != nil || got != want {
				t.Errorf("File MIME = %q/%v, want %q", got, err, want)
			}
		})
	}
}

// No compiler or native reference is required for these regression checks.
func TestMIMEEmissionAndExpansion(t *testing.T) {
	for _, mode := range []string{"0", "1"} {
		prefix := "application/" + strings.Repeat("a", 59)
		s := &state{mime: true, elfFlag: mode, buf: &strings.Builder{}}
		printed := false
		if !s.emit(&entry{mime: prefix + "${x?a:b}"}, &printed) {
			t.Fatal("first annotation not emitted")
		}
		want := prefix + "b"
		if mode == "1" {
			want = prefix + "a"
		}
		if got := s.buf.String(); got != want {
			t.Errorf("mode %s: MIME %q, want %q", mode, got, want)
		}
	}
}

func TestFirstMIMEStopsMatch(t *testing.T) {
	root := entry{flag: flagBinTest, typ: typeString, reln: '=', vallen: 2, desc: "root", mime: "application/first"}
	copy(root.value[:], "AB")
	child := entry{contLevel: 1, offset: 2, typ: typeByte, reln: 'x', desc: "child", mime: "application/second"}
	db := &Database{sets: []magicSet{{rules: []entry{root, child}, n0: 2}}}
	if got, err := db.BufferMIMEType([]byte("AB\x00\x01")); err != nil || got != "application/first" {
		t.Fatalf("first MIME = %q/%v", got, err)
	}
}

func TestEmptyBufferMIMEDiffersFromEmptyFile(t *testing.T) {
	db := &Database{}
	if got, err := db.BufferMIMEType(nil); err != nil || got != "application/x-empty" {
		t.Fatalf("empty Buffer = %q/%v", got, err)
	}
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := db.FileMIMEType(path); err != nil || got != "inode/x-empty" {
		t.Fatalf("empty File = %q/%v", got, err)
	}
}
