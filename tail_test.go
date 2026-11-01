package libmagic

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailRawWindowWithoutReference(t *testing.T) {
	raw := []byte("AB\xe9DZ")
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, front := range [][]byte{raw, []byte("AB\xc3\xa9DZ"), []byte("DZ")} {
		s := &state{tail: &tail{reader: f, size: int64(len(raw)), regular: true}}
		got, ok := s.loadTail(front)
		n := len(front)
		if n > len(raw) {
			n = len(raw)
		}
		if !ok || !bytes.Equal(got, raw[len(raw)-n:]) {
			t.Errorf("front %x: tail = %x/%v", front, got, ok)
		}
	}
}

func TestTailSnapshotWithoutReference(t *testing.T) {
	raw := []byte("ABCDE")
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := &state{tail: &tail{reader: f, size: int64(len(raw)), regular: true}}
	got, ok := s.loadTail(raw)
	if !ok || string(got) != "ABCDE" {
		t.Fatalf("first tail = %q/%v", got, ok)
	}
	raw[0] = 'X'
	again, ok := s.loadTail(raw[:2])
	if !ok || string(again) != "ABCDE" {
		t.Fatalf("cached tail changed with front bytes/length: %q/%v", again, ok)
	}
}

func TestTailIndirectScopeWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01....XY.....................Z")
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	child := entry{flag: flagBinTest, typ: typeString, reln: '=', vallen: 2, desc: "child"}
	copy(child.value[:], "XY")
	negative := entry{contLevel: 1, flag: flagOffNegative, offset: 30, typ: typeByte, reln: 'x', desc: "tail"}
	db := &Database{sets: []magicSet{{rules: []entry{child, negative}, n0: 2}}}
	for _, warm := range []bool{false, true} {
		s := &state{db: db, offset: 8, buf: &strings.Builder{}, tail: &tail{reader: f, size: int64(len(data)), regular: true}}
		if warm {
			if _, ok := s.loadTail(data); !ok {
				t.Fatal("parent tail fill failed")
			}
		}
		indir := 0
		if !s.mget(&entry{typ: typeIndirect, reln: 'x'}, data, data, 0, 1, flagBinTest, &indir, 0) || s.err != nil {
			t.Fatalf("indirect failed: %v", s.err)
		}
		want := "child"
		if warm {
			want = "child tail"
		}
		if got := s.buf.String(); got != want || s.tail.done != warm {
			t.Errorf("warm %v: output %q, parent filled %v", warm, got, s.tail.done)
		}
		if got, ok := s.loadTail(data); !ok || !bytes.Equal(got, data) {
			t.Errorf("child fill leaked into parent: %x/%v", got, ok)
		}
	}
}
