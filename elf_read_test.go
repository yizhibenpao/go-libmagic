package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Compose the actual classifier with the prefix snapshot, later file bytes
// and earlier size/mode. This is not a public File kernel-injection test.
func TestELFReadFrozenWithoutReference(t *testing.T) {
	dbPath := os.Getenv("LIBMAGIC_PARITY_DB")
	if dbPath == "" {
		bin := filepath.Dir(testMagicPath(t))
		dbPath = filepath.Join(bin, "custom.mgc") + ":" + filepath.Join(bin, "magic.mgc")
	}
	db, err := OpenDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range softprobe.ELFReadCases() {
		t.Run(c.Name, func(t *testing.T) {
			initial, err := hex.DecodeString(c.Data)
			if err != nil {
				t.Fatal(err)
			}
			after, err := hex.DecodeString(c.After)
			if err != nil {
				t.Fatal(err)
			}
			prefix := initial
			if c.Stage == "before" {
				prefix = after
			}
			for which, want := range c.Want {
				var value string
				var err error
				if which < 2 {
					value, err = db.identifyBuffer(prefix, which == 1, "",
						bytes.NewReader(after), int64(len(initial)), c.Mode&0111 != 0, true)
					value, err = magicResult(value, err)
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
