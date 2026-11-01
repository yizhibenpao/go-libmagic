package libmagic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMagicPrefixRealFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, []byte("ABCDEFGH"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := readMagicPrefix(file, 4)
	if err != nil || string(first) != "ABCD" {
		t.Fatalf("first prefix=%q err=%v", first, err)
	}
	second, err := readMagicPrefix(file, 4)
	if err != nil || string(second) != "EFGH" {
		t.Fatalf("second prefix=%q err=%v", second, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readMagicPrefix(file, 4); err == nil {
		t.Fatal("closed file read unexpectedly succeeded")
	}
}
