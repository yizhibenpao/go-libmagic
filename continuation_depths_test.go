package libmagic

import (
	"encoding/binary"
	"testing"
)

func TestContinuationLevelDecodeWithoutReference(t *testing.T) {
	raw16 := make([]byte, entrySize541)
	raw21 := make([]byte, entrySize548)
	raw16[2], raw16[4], raw21[4] = flagBinTest, 'x', 'x'
	for n := 0; n <= 65535; n++ {
		binary.LittleEndian.PutUint16(raw16[0:2], uint16(n))
		m := decodeEntry(raw16, false)
		if int(m.contLevel) != n || m.flag != flagBinTest || !m.version16 || m.reln != 'x' {
			t.Fatalf("v16 level %d: %+v", n, m)
		}

		// v21 still has a one-byte level and a separate two-byte flag.
		// This preserves its decoder, not acceptance against native v21.
		binary.LittleEndian.PutUint16(raw21[0:2], uint16(n))
		raw21[2] = byte(n)
		m = decodeEntry(raw21, true)
		if int(m.contLevel) != n&255 || int(m.flag) != n || m.version16 || m.reln != 'x' {
			t.Fatalf("v21 flag %d: %+v", n, m)
		}
	}
}

func TestContinuationLevelLoadWithoutReference(t *testing.T) {
	for _, depth := range []uint16{0, 1, 254, 255, 256, 257, 511, 512, 1024, 32768, 65535} {
		raw := make([]byte, 2*entrySize541)
		binary.LittleEndian.PutUint32(raw[0:4], magicNo)
		binary.LittleEndian.PutUint32(raw[4:8], versionNo541)
		binary.LittleEndian.PutUint32(raw[8:12], 1)
		binary.LittleEndian.PutUint16(raw[entrySize541:entrySize541+2], depth)
		raw[entrySize541+2] = flagBinTest
		db, err := OpenBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		m := db.sets[0].rules[0]
		if m.contLevel != depth || m.flag != flagBinTest || !m.version16 {
			t.Fatalf("loaded level %d: %+v", depth, m)
		}
	}
}
