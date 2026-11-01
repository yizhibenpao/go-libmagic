package libmagic

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestSoftModeFilterWithoutReference(t *testing.T) {
	// FILE5_41 file.h IS_STRING: octal was added only in the newer format.
	nativeStrings := map[uint8]bool{5: true, 13: true, 17: true, 18: true, 19: true, 20: true, 41: true, 45: true, 46: true}
	for typ := 0; typ < 256; typ++ {
		for _, v16 := range []bool{false, true} {
			for _, text := range []bool{false, true} {
				for _, flag := range []uint16{0, 32, 64, 96} {
					for _, flags := range []uint32{0, 32, 64, 96} {
						for _, mode := range []int{32, 64} {
							want := int(flag)&mode != mode
							if nativeStrings[uint8(typ)] || !v16 && typ == 61 {
								want = want || text && flags == 64 || !text && flags == 32
							}
							m := entry{typ: uint8(typ), version16: v16, flag: flag, strFlags: flags}
							if got := skipByMode(&m, text, mode); got != want {
								t.Fatalf("type %d v16 %v text %v flag %d flags %d mode %d: skip %v, want %v", typ, v16, text, flag, flags, mode, got, want)
							}
						}
					}
				}
			}
		}
	}
}

func TestDecodedOctalModeVersionWithoutReference(t *testing.T) {
	for _, version := range []uint32{versionNo541, versionNo548} {
		size := entrySize541
		if version == versionNo548 {
			size = entrySize548
		}
		for _, flags := range []uint32{0, 32, 64, 96} {
			raw := make([]byte, 2*size)
			binary.LittleEndian.PutUint32(raw[:4], magicNo)
			binary.LittleEndian.PutUint32(raw[4:8], version)
			binary.LittleEndian.PutUint32(raw[8:12], 1)
			m := raw[size:]
			if version == versionNo541 {
				m[2] = flagBinTest
			} else {
				m[0] = flagBinTest
			}
			m[4], m[6] = 'x', typeOctal
			binary.LittleEndian.PutUint32(m[20:24], 7)
			binary.LittleEndian.PutUint32(m[28:32], flags)
			copy(m[160:], "mode-target")
			copy(m[224:], "application/x-mode")
			db, err := OpenBytes(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, data := range [][]byte{[]byte("AB\x00\x01"), []byte("ABCD\n")} {
				text := data[2] != 0
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
						if version == versionNo541 {
							if got != "" || err == nil || err.Error() != "line 7: invalid type 61 in mconvert()" {
								t.Fatalf("v16 flags %d File %v MIME %d = %q/%v", flags, file, mime, got, err)
							}
							continue
						}
						want := "mode-target"
						if mime == 1 {
							want = "application/x-mode"
						}
						if text && flags == 64 || !text && flags == 32 {
							want = "data"
							if text {
								want = "ASCII text"
							}
							if mime == 1 {
								want = "application/octet-stream"
								if text {
									want = "text/plain"
								}
							}
						}
						if got != want || err != nil {
							t.Fatalf("v21 flags %d File %v MIME %d = %q/%v, want %q", flags, file, mime, got, err, want)
						}
					}
				}
			}
		}
	}
}
