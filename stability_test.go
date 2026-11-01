package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/cdfsample"
	"github.com/yizhibenpao/go-libmagic/internal/elfsample"
	"os"
	"path/filepath"
	"testing"
)

// Exercise the complete Buffer pipeline after adding the built-in parsers.
func FuzzBuffer(f *testing.F) {
	bin := filepath.Join("..", "build", "tool", "amd64", "local", "bin")
	path := os.Getenv("LIBMAGIC_PARITY_DB")
	if path == "" {
		path = filepath.Join(bin, "custom.mgc") + ":" + filepath.Join(bin, "magic.mgc")
	}
	db, err := OpenDatabase(path)
	if err != nil {
		f.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("hello\n"), []byte("你好\n"), []byte(`{"a":[1]}`), []byte("a,b\n1,2\n3,4\n")} {
		f.Add(data)
	}
	for _, data := range elfsample.Cases() {
		f.Add(data)
	}
	for _, data := range cdfsample.Cases() {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		db.Buffer(data)
		db.BufferMIMEType(data)
	})
}

func FuzzOpenBytes(f *testing.F) {
	path := filepath.Join("..", "build", "tool", "amd64", "local", "bin", "custom.mgc")
	data, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		if db, err := OpenBytes(data); err == nil {
			db.Buffer([]byte("hello\n"))
			db.BufferMIMEType([]byte("hello\n"))
		}
	})
}
