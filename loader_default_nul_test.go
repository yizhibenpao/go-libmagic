package libmagic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNULTerminatedPathsUseCStringPrefix(t *testing.T) {
	db := testDB(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("plain text\n"), 0600); err != nil {
		t.Fatal(err)
	}
	withNUL := path + "\x00ignored"
	for _, mime := range []bool{false, true} {
		var clean, nul string
		var err error
		if mime {
			clean, err = db.FileMIMEType(path)
			if err == nil {
				nul, err = db.FileMIMEType(withNUL)
			}
		} else {
			clean, err = db.File(path)
			if err == nil {
				nul, err = db.File(withNUL)
			}
		}
		if err != nil {
			t.Fatalf("mime=%v: %v", mime, err)
		}
		if nul != clean {
			t.Fatalf("mime=%v: NUL path = %q, clean path = %q", mime, nul, clean)
		}
	}
	loaded, err := OpenDatabase(testMagicPath(t) + "\x00ignored")
	if err != nil {
		t.Fatal(err)
	}
	want, err := db.Buffer([]byte("plain text\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := loaded.Buffer([]byte("plain text\n"))
	if err != nil || got != want {
		t.Fatalf("NUL database path = %q/%v, want %q", got, err, want)
	}
}

func TestMagicmimeDefaultPathUsesMAGIC(t *testing.T) {
	Close()
	t.Cleanup(Close)
	t.Setenv("MAGIC", testMagicPath(t))
	if err := Open(""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, []byte("plain text\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := GetFiletype(path); err != nil {
		t.Fatal(err)
	}
	if _, err := GetMimetype(path); err != nil {
		t.Fatal(err)
	}
}
