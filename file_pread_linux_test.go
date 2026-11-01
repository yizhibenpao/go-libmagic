//go:build linux

package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMagicPreadRealFile(t *testing.T) {
	for _, c := range softprobe.PreadRawCases() {
		t.Run(c.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, []byte("ABCDEF\n"), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if c.Closed {
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			b := make([]byte, c.Count)
			n, err := readMagicAt(f, b, c.Offset)
			wantN := int(c.Want.Result)
			if wantN < 0 {
				wantN = 0
			}
			var wantErr error
			if c.Want.Errno != 0 {
				wantErr = syscall.Errno(c.Want.Errno)
			}
			if n != wantN || !errors.Is(err, wantErr) {
				t.Fatalf("n=%d err=%v, native %+v", n, err, c.Want)
			}
			if got := hex.EncodeToString(b[:n]); got != c.Want.Data {
				t.Fatalf("bytes %q, native %q", got, c.Want.Data)
			}
		})
	}
}
