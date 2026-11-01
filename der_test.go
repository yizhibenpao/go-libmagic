package libmagic

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"testing"
)

func TestDERCopySearchContextWithoutReference(t *testing.T) {
	data := []byte("ABCD")
	for _, off := range []int{0, 2, 4, 5} {
		s := state{}
		s.search.rmLen = 3
		if !s.copyDER(data, off) {
			t.Fatal("DER region copy failed")
		}
		want := off
		if want > len(data) {
			want = len(data)
		}
		if s.search.rmLen != 3 || s.search.offset != want || !bytes.Equal(s.search.s, data[want:]) {
			t.Errorf("offset %d: region=%q offset=%d rm_len=%d", off, s.search.s, s.search.offset, s.search.rmLen)
		}
	}
}

// The digests come from unmodified FILE5_41 der.c function bodies.
// Parser callers test DER_BAD; the unused value of a failed Go parse is
// normalized to that sentinel. Cursor advancement is checked on failures too.
func writeDERProbe(h hash.Hash, v uint32, p int, ok bool) {
	if !ok {
		v = derBad
	}
	var b [8]byte
	binary.LittleEndian.PutUint32(b[:4], v)
	binary.LittleEndian.PutUint32(b[4:], uint32(p))
	h.Write(b[:])
}

func TestDERTagDigestWithoutReference(t *testing.T) {
	h := sha256.New()
	count := 0
	for tag := 0; tag < 256; tag++ {
		for n := 0; n < 9; n++ {
			for _, fill := range []byte{0, 127, 128, 255} {
				raw := make([]byte, 9)
				raw[0] = byte(tag)
				for i := 1; i < len(raw); i++ {
					raw[i] = fill
				}
				p := 0
				v, ok := derTag(raw[:n], &p)
				writeDERProbe(h, v, p, ok)
				count++
			}
		}
	}
	if count != 9216 || fmt.Sprintf("%x", h.Sum(nil)) != "8c3255619c3033d8658438bb6d443098c9978522ec91b0537bb511fd61f9e8b8" {
		t.Fatalf("%d tag parses: digest %x", count, h.Sum(nil))
	}
}

func TestDERLengthDigestWithoutReference(t *testing.T) {
	h := sha256.New()
	count := 0
	check := func(raw []byte) {
		p := 0
		v, ok := derLength(raw, &p)
		writeDERProbe(h, v, p, ok)
		count++
	}
	for first := 0; first < 256; first++ {
		for n := 0; n < 133; n++ {
			for _, fill := range []byte{0, 1, 128, 255} {
				raw := make([]byte, 132)
				raw[0] = byte(first)
				for i := 1; i < len(raw); i++ {
					raw[i] = fill
				}
				check(raw[:n])
			}
		}
	}
	for digits := 1; digits < 128; digits++ {
		for _, v := range []uint64{0, 1, 5, 1<<32 + 5} {
			if digits < 8 && v>>uint(8*digits) != 0 {
				continue
			}
			raw := make([]byte, 1+digits+6)
			raw[0] = byte(128 | digits)
			for i := 0; i < digits && i < 8; i++ {
				raw[digits-i] = byte(v >> uint(8*i))
			}
			for i := 1 + digits; i < len(raw); i++ {
				raw[i] = 'Z'
			}
			check(raw)
		}
	}
	if count != 136696 || fmt.Sprintf("%x", h.Sum(nil)) != "a9a70ae05303ba76b34f21d860affc966080431970ea433844ad5f82dc800376" {
		t.Fatalf("%d length parses: digest %x", count, h.Sum(nil))
	}
}

func TestDERDataDigestWithoutReference(t *testing.T) {
	h := sha256.New()
	count := 0
	sequence := make([]byte, 256)
	for i := range sequence {
		sequence[i] = byte(i)
	}
	patterns := [][]byte{[]byte("Cd\x80\xffEF"), sequence, []byte("\xff\x802401020304")}
	for _, tag := range []uint32{0, 2, 4, 6, 12, 19, 22, 23, 37, derBad} {
		for n := 0; n < 256; n++ {
			for _, pattern := range patterns {
				raw := make([]byte, n)
				for i := range raw {
					raw[i] = pattern[i%len(pattern)]
				}
				h.Write([]byte(derData(tag, raw, uint32(n))))
				h.Write([]byte{0})
				count++
			}
		}
	}
	if count != 7680 || fmt.Sprintf("%x", h.Sum(nil)) != "3340b70954fa9bd263f9679ffb2c4a179c6ae4f2242166645902abd1753b4130" {
		t.Fatalf("%d DER values: digest %x", count, h.Sum(nil))
	}
}
