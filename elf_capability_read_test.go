package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/elfsample"
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func TestELFCapabilityUsesSequentialDescriptorRead(t *testing.T) {
	data := elfsample.Cases()["64-le-capabilities"]
	path := t.TempDir() + string(os.PathSeparator) + "capability"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, _, err := elfSupplement(data, file, int64(len(data)), false, false); err != nil {
		t.Fatal(err)
	}
	got, err := file.Seek(0, os.SEEK_CUR)
	if err != nil {
		t.Fatal(err)
	}
	shoff := binary.LittleEndian.Uint64(data[40:])
	capHeader := data[shoff+64 : shoff+128]
	want := int64(binary.LittleEndian.Uint64(capHeader[24:]) +
		binary.LittleEndian.Uint64(capHeader[32:]))
	if got != want {
		t.Fatalf("descriptor offset %d, want sequential capability end %d", got, want)
	}
}

func TestELFUnknownSizeSkipsRegularFileBounds(t *testing.T) {
	data := elfsample.Cases()["far-section-table"]
	known, _, err := elfSupplement(data, bytes.NewReader(data), int64(len(data)), false, false)
	if err != nil {
		t.Fatal(err)
	}
	unknown, _, err := elfSupplement(data, bytes.NewReader(data), elfSizeUnknown, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if unknown != known {
		t.Fatalf("unknown-size ELF %q, known-size ELF %q", unknown, known)
	}
	if strings.Contains(unknown, "too large section header offset") {
		t.Fatalf("unknown-size ELF applied a regular-file bound: %q", unknown)
	}
}
