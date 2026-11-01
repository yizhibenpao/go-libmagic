package libmagic

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestELFErrorContinuesSoftmagicBeforeReturning(t *testing.T) {
	data := make([]byte, 256)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:18], 2)
	binary.LittleEndian.PutUint16(data[18:20], 62)
	binary.LittleEndian.PutUint64(data[40:48], 64)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[58:60], 64)
	binary.LittleEndian.PutUint16(data[60:62], 1)
	binary.LittleEndian.PutUint32(data[64+4:64+8], 7)
	binary.LittleEndian.PutUint64(data[64+24:64+32], 128)
	binary.LittleEndian.PutUint64(data[64+32:64+40], ^uint64(0))
	copy(data[252:], []byte("TAIL"))

	reader := &recordingReader{data: data}
	rule := entry{
		version16: true,
		flag:      flagBinTest | flagOffNegative,
		offset:    4,
		reln:      '=',
		vallen:    4,
		typ:       typeString,
		desc:      "tail",
	}
	copy(rule.value[:], "TAIL")
	db := &Database{sets: []magicSet{{rules: []entry{rule}, n0: 1}}}

	got, err := db.identifyBufferStat(data, false, "", reader, int64(len(data)), false, true, nil)
	if got != "" {
		t.Fatalf("description = %q, want empty on the earlier ELF error", got)
	}
	if err == nil || !strings.HasSuffix(err.Error(), "Cannot allocate memory for note (Cannot allocate memory)") {
		t.Fatalf("error = %v, want the FILE5_41 ELF error", err)
	}
	if !reader.saw(0) {
		t.Fatalf("softmagic did not continue to the tail view; reads = %v", reader.offsets)
	}
}

type recordingReader struct {
	data    []byte
	offsets []int64
}

func (r *recordingReader) ReadAt(p []byte, offset int64) (int, error) {
	r.offsets = append(r.offsets, offset)
	if offset < 0 || offset >= int64(len(r.data)) {
		return 0, errors.New("invalid offset")
	}
	n := copy(p, r.data[offset:])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *recordingReader) saw(offset int64) bool {
	return containsInt64(r.offsets, offset)
}

func containsInt64(values []int64, want int64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
