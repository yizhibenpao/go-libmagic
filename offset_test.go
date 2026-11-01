package libmagic

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOffsetCopyAndBoundsWithoutReference(t *testing.T) {
	data := make([]byte, 32)
	data[30], data[31] = 0x12, 0x34
	for _, tc := range []struct {
		typ       uint8
		off, base int
		ok        bool
		want      uint64
	}{
		{typeByte, 28, 8, true, 0},
		{typeByte, 33, 0, false, 0},
		{typeBELong, 0, 30, true, 0x12340000},
		{typeBEQuad, 33, 0, true, 0},
		{typeBEDouble, 33, 0, false, 0},
	} {
		s := &state{offset: tc.off}
		indir := 0
		got := s.mget(&entry{typ: tc.typ, reln: 'x'}, data, data, tc.base, 0, flagBinTest, &indir, 0)
		if got != tc.ok || got && s.value.u64 != tc.want {
			t.Errorf("type %d off %d base %d = %v/%x, want %v/%x", tc.typ, tc.off, tc.base, got, s.value.u64, tc.ok, tc.want)
		}
	}
}

func TestOffsetOperandBaseWithoutReference(t *testing.T) {
	data := make([]byte, 96)
	data[16], data[24], data[32], data[56] = 48, 8, 1, 90
	s := &state{offset: 8}
	m := &entry{typ: typeByte, flag: flagIndir, inType: typeByte, inOffset: 16, inOp: opAdd | opIndirect, reln: 'x'}
	indir := 0
	if !s.mget(m, data, data, 8, 1, flagBinTest, &indir, 0) || s.offset != 56 || s.value.u64 != 90 {
		t.Fatalf("indirect named read = offset %d, value %d", s.offset, s.value.u64)
	}
}

func TestOffsetWrapWithoutReference(t *testing.T) {
	data := make([]byte, 32)
	data[7] = 1
	s := &state{offset: 0xffffffff}
	indir := 0
	if !s.mget(&entry{typ: typeLEQuad, reln: 'x'}, data, data, 8, 0, flagBinTest, &indir, 0) || s.value.u64 != 1 {
		t.Fatalf("wrapped copy = %x", s.value.u64)
	}
	s.offset = 0xfffffffc
	if off, ok := s.moffset(&entry{typ: typeBEQuad}, 32); !ok || off != 4 {
		t.Fatalf("wrapped continuation = %d/%v", off, ok)
	}
	s.offset = 0x7fffffff
	if off, ok := s.moffset(&entry{typ: typeByte}, 32); ok {
		t.Fatalf("negative int32 continuation accepted: %d", off)
	}
}

func TestNegativeOffsetEndpointsWithoutReference(t *testing.T) {
	data := []byte("AB\x00\x01")
	m := &entry{typ: typeByte, offset: 1, flag: flagOffNegative, lineno: 17}
	s := &state{}
	if _, ok := s.setOffset(m, data, 0, 1); ok || s.err != nil {
		t.Fatal("Buffer supplied a regular-file end view")
	}
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s = &state{tail: &tail{reader: f, size: int64(len(data)), regular: true}, line: 17}
	if off, ok := s.setOffset(m, data, 0, 1); !ok || off != 3 {
		t.Fatalf("File end offset = %d/%v", off, ok)
	}
	if _, ok := s.setOffset(m, data, 8, 1); ok || s.err == nil || s.err.Error() != "line 17: non zero offset 8 at level 1" {
		t.Fatalf("named File end error = %v", s.err)
	}
	raw := make([]byte, entrySize541)
	binary.LittleEndian.PutUint32(raw[20:24], 17)
	if decodeEntry(raw, false).lineno != 17 {
		t.Fatal("compiled line number was not read from the existing field")
	}
}

func TestPrintOffsetFailureWithoutReference(t *testing.T) {
	for _, mime := range []bool{false, true} {
		s := &state{offset: 0xfffffff7, mime: mime, buf: &strings.Builder{}}
		printed := false
		got := s.emit(&entry{typ: typeBEQuad, desc: "hit", mime: "application/x-offset"}, &printed)
		if mime {
			if !got || s.err != nil || s.buf.String() != "application/x-offset" {
				t.Fatal("MIME did not stop before the printer return check")
			}
		} else if got || s.err == nil || s.err.Error() != "" {
			t.Fatalf("printer sentinel must be a non-nil empty-message error: %v", s.err)
		}
	}
}
