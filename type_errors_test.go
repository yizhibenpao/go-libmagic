package libmagic

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTypeErrorsWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01CDEFGH\x00\x01")
	for typ := 0; typ < 256; typ++ {
		if typ != 0 && typ < 53 && typ != 39 && typ != 40 && typ != 51 && typ != 52 {
			continue
		}
		raw := make([]byte, entrySize541)
		raw[4], raw[6] = 'x', byte(typ)
		binary.LittleEndian.PutUint32(raw[20:24], 999)
		m := decodeEntry(raw, false)
		if !m.version16 {
			t.Fatal("v16 provenance lost")
		}
		for _, off := range []int{0, len(data), len(data) + 8} {
			for _, line := range []uint32{0, 7} {
				for _, flip := range []bool{false, true} {
					s := state{buf: &strings.Builder{}, line: line, flip: flip}
					s.buf.WriteString("root")
					for i := range s.value.raw {
						s.value.raw[i] = 0xff
					}
					var wantRaw [maxString]byte
					n := 0
					if off < len(data) {
						n = copy(wantRaw[:], data[off:])
					}
					want := fmt.Sprintf("invalid type %d in mconvert()", typ)
					if line == 0 {
						want = "root " + want
					} else {
						want = "line 7: " + want
					}
					if s.copyValue(&m, data, off, off) || s.err == nil || s.err.Error() != want ||
						s.value.raw != wantRaw || s.value.n != n || s.buf.String() != "root" {
						t.Fatalf("type %d offset %d line %d flip %v: error %v, expected %q after raw copy", typ, off, line, flip, s.err, want)
					}
				}
			}
		}
	}
}

// These preserve existing v21 behavior; they are not FILE5_48 parity claims.
func TestTypeVersionControlsWithoutReference(t *testing.T) {
	for _, version := range []uint32{versionNo541, versionNo548} {
		size := entrySize541
		if version == versionNo548 {
			size = entrySize548
		}
		for _, typ := range []uint8{typeByte, typeMSDOSDate, typeLEMSDOSDate, typeBEMSDOSDate, typeMSDOSTime, typeLEMSDOSTime, typeBEMSDOSTime, typeOctal} {
			raw := make([]byte, size*4)
			binary.LittleEndian.PutUint32(raw[0:4], magicNo)
			binary.LittleEndian.PutUint32(raw[4:8], version)
			binary.LittleEndian.PutUint32(raw[8:12], 3)
			for i := 1; i <= 3; i++ {
				record := raw[i*size : (i+1)*size]
				if version == versionNo541 {
					record[0], record[2] = 1, flagBinTest
				} else {
					record[0], record[2] = flagBinTest, 1
				}
				record[4], record[6] = 'x', typeByte
				binary.LittleEndian.PutUint32(record[20:24], uint32(i))
			}
			root := raw[size : 2*size]
			if version == versionNo541 {
				root[0] = 0
			} else {
				root[2] = 0
			}
			root[4], root[5], root[6] = '=', 2, typeString
			binary.LittleEndian.PutUint32(root[28:32], stringBinTest)
			copy(root[32:], "AB")
			copy(root[160:], "root")
			scalar := raw[2*size : 3*size]
			scalar[6] = typ
			copy(scalar[160:], "unknown-type")
			copy(scalar[224:], "application/x-unknown")
			copy(raw[3*size+160:], "after")
			copy(raw[3*size+224:], "application/x-after")
			db, err := OpenBytes(raw)
			if err != nil {
				t.Fatal(err)
			}
			if db.sets[0].rules[1].version16 != (version == versionNo541) {
				t.Fatal("record version does not follow its database")
			}
			data := []byte("AB\x00\x01CDEFGH\x00\x01")
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					got, err := db.Buffer(data)
					if mime == 1 {
						got, err = db.BufferMIMEType(data)
					}
					if file {
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					if version == versionNo541 && typ != typeByte {
						want := fmt.Sprintf("line 2: invalid type %d in mconvert()", typ)
						if got != "" || err == nil || err.Error() != want {
							t.Fatalf("v%d type %d File %v MIME %d: %q/%v, want error %q", version, typ, file, mime, got, err, want)
						}
						continue
					}
					want := "root unknown-type after"
					if mime == 1 {
						want = "application/x-unknown"
					}
					if got != want || err != nil {
						t.Fatalf("v%d type %d File %v MIME %d: %q/%v, want %q", version, typ, file, mime, got, err, want)
					}
				}
			}
		}
	}
}
