package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/cdfsample"
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Compose the real classifier with a prefix/ReaderAt and the earlier fd size.
// This is not a fault-injected public File call or native Windows comparison.
func TestCDFSizeFrozenWithoutReference(t *testing.T) {
	dbPath := os.Getenv("LIBMAGIC_PARITY_DB")
	if dbPath == "" {
		bin := filepath.Dir(testMagicPath(t))
		dbPath = filepath.Join(bin, "custom.mgc") + ":" + filepath.Join(bin, "magic.mgc")
	}
	db, err := OpenDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	samples := cdfsample.Cases()
	empty := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, c := range softprobe.CDFSizeCases() {
		t.Run(c.Name, func(t *testing.T) {
			full := samples[c.Sample]
			initial := make([]byte, c.InitialSize)
			copy(initial, full)
			prefix := full
			if len(prefix) > fileBytesMax {
				prefix = prefix[:fileBytesMax]
			}
			for which, want := range c.Want {
				var value string
				var err error
				if which < 2 {
					if c.InitialSize == 0 {
						if which == 0 {
							value, err = db.File(empty)
						} else {
							value, err = db.FileMIMEType(empty)
						}
					} else {
						value, err = db.identifyBuffer(prefix, which == 1, "",
							bytes.NewReader(full), int64(c.InitialSize), false, true)
						value, err = magicResult(value, err)
					}
				} else if which == 2 {
					value, err = db.Buffer(initial)
				} else {
					value, err = db.BufferMIMEType(initial)
				}
				errText := ""
				if err != nil {
					errText = err.Error()
				}
				if value != want.Value || errText != want.Error || (err != nil) != want.Failed {
					t.Errorf("API %d %q/%v, native %+v", which, value, err, want)
				}
			}
		})
	}
}
