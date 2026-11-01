package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/elfsample"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuiltinTextAndStructuredDetection(t *testing.T) {
	db := testDB(t)
	tests := []struct {
		name string
		data []byte
		desc string
		mime string
	}{
		{"json-object", []byte(`{"name":"asky"}`), "JSON data", "application/json"},
		{"json-array", []byte(`[1,2]`), "JSON data", "application/json"},
		{"json-scalar", []byte(`12`), "ASCII text, with no line terminators", "text/plain"},
		{"csv", []byte("a,b\n1,2\n3,4\n"), "CSV text", "text/csv"},
		{"utf8", []byte("你好\n"), "Unicode text, UTF-8 text", "text/plain"},
		{"sub", []byte{'a', 0x1a, 'b', '\n'}, "data", "application/octet-stream"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc, err := db.Buffer(tt.data)
			if err != nil {
				t.Fatal(err)
			}
			if desc != tt.desc {
				t.Fatalf("description = %q, want %q", desc, tt.desc)
			}
			mime, err := db.BufferMIMEType(tt.data)
			if err != nil {
				t.Fatal(err)
			}
			if mime != tt.mime {
				t.Fatalf("mime = %q, want %q", mime, tt.mime)
			}
		})
	}
}

func TestFilesystemMagicAndSymlinkHandles(t *testing.T) {
	db := testDB(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("hello\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := db.File(target); err != nil || got != "ASCII text" {
		t.Fatalf("regular file = %q, %v", got, err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got, err := db.File(link)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "symbolic link to ") {
		t.Fatalf("description symlink = %q", got)
	}
	mime, err := db.FileMIMEType(link)
	if err != nil {
		t.Fatal(err)
	}
	if mime != "text/plain" {
		t.Fatalf("mime symlink = %q", mime)
	}
}

func TestELFPIESelectionUsesDynamicFlag(t *testing.T) {
	cases := elfsample.Cases()
	for _, name := range []string{"shared", "pie", "static-pie", "flags-zero", "after-null", "second-dynamic"} {
		data := cases["64-le-"+name]
		for _, initial := range []bool{false, true} {
			_, execute, err := elfSupplement(data, bytes.NewReader(data), int64(len(data)), false, initial)
			want := name == "pie" || name == "static-pie" || name == "after-null"
			if err != nil || execute != want {
				t.Errorf("%s initial %v: execute %v, err %v", name, initial, execute, err)
			}
		}
		if suffix, _, err := elfSupplement(data, nil, 0, false, false); err != nil || suffix != "" {
			t.Errorf("Buffer %s: %q, %v", name, suffix, err)
		}
	}
}

func TestMagicmimeCompatibility(t *testing.T) {
	Close()
	t.Cleanup(Close)
	_, src, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	path := testMagicPath(t)
	if err := Open(path); err != nil {
		t.Fatal(err)
	}
	defer Close()
	if _, err := GetFiletype(filepath.Join(filepath.Dir(src), "magic.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := GetMimetype(filepath.Join(filepath.Dir(src), "magic.go")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("hello\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if got, err := GetFiletype(link); err != nil || !strings.HasPrefix(got, "symbolic link to ") {
		t.Fatalf("package description symlink = %q, %v", got, err)
	}
	if got, err := GetMimetype(link); err != nil || got != "text/plain" {
		t.Fatalf("package MIME symlink = %q, %v", got, err)
	}
	if err := Open(path); err == nil || err.Error() != "cannot open; magic mime db is already open" {
		t.Fatalf("second Open error = %v", err)
	}
}

func TestMagicmimeCompatibilityFailedOpenAndReopen(t *testing.T) {
	Close()
	t.Cleanup(Close)
	if err := Open(filepath.Join(t.TempDir(), "missing.mgc")); err == nil {
		t.Fatal("Open(missing) succeeded")
	}
	path := testMagicPath(t)
	if err := Open(path); err != nil {
		t.Fatalf("Open after failed Open = %v", err)
	}
	Close()
	if err := Open(path); err != nil {
		t.Fatalf("Open after Close = %v", err)
	}
}
