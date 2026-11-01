//go:build linux

package libmagic

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenDatabaseDirectorySkipsFIFO(t *testing.T) {
	data, err := os.ReadFile(testMagicPath(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "blocked.mgc")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.mgc"), data, 0600); err != nil {
		t.Fatal(err)
	}

	db, err := OpenDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Buffer([]byte("plain text\n"))
	if err != nil || got == "" {
		t.Fatalf("directory database = %q/%v", got, err)
	}
}
