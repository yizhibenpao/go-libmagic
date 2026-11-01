package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSetBoundaryDecodeWithoutReference(t *testing.T) {
	for _, layout := range []struct {
		version uint32
		width   int
	}{{versionNo541, entrySize541}, {versionNo548, entrySize548}} {
		raw := make([]byte, 257*layout.width)
		binary.LittleEndian.PutUint32(raw[0:4], magicNo)
		binary.LittleEndian.PutUint32(raw[4:8], layout.version)
		for i := 0; i < 256; i++ {
			record := raw[(i+1)*layout.width : (i+2)*layout.width]
			record[6] = typeByte
			if i%2 == 0 {
				record[6] = typeName
				copy(record[32:], fmt.Sprintf("N%03d", i))
			}
		}
		for split := 0; split <= 256; split++ {
			binary.LittleEndian.PutUint32(raw[8:12], uint32(split))
			binary.LittleEndian.PutUint32(raw[12:16], uint32(256-split))
			db, err := OpenBytes(raw)
			if err != nil {
				t.Fatal(err)
			}
			set := &db.sets[0]
			if set.n0 != split || len(set.rules) != 256 {
				t.Fatalf("v%d split %d: count %d, records %d", layout.version, split, set.n0, len(set.rules))
			}
			for i := 0; i < 256; i++ {
				n, ok := set.names[fmt.Sprintf("N%03d", i)]
				want := i >= split && i%2 == 0
				if ok != want || ok && n != i {
					t.Fatalf("v%d split %d name %d: %d/%v, want %v", layout.version, split, i, n, ok, want)
				}
			}
		}
	}
}

func TestSoftSetBoundaryContracts(t *testing.T) {
	cases := softprobe.SetBoundaries()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			db := &Database{}
			for i, compiled := range tc.Compiled {
				raw := append([]byte(nil), compiled...)
				if i == 0 {
					binary.LittleEndian.PutUint32(raw[8:12], tc.Split)
					binary.LittleEndian.PutUint32(raw[12:16], uint32(len(raw)/entrySize541-1)-tc.Split)
				}
				one, err := OpenBytes(raw)
				if err != nil {
					t.Fatal(err)
				}
				db.sets = append(db.sets, one.sets...)
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, fromFile := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if fromFile {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					errText := ""
					if err != nil {
						errText = err.Error()
					}
					if got != want.Value || errText != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", fromFile, mime, got, errText, err != nil, want)
					}
				}
			}
		})
	}
}
