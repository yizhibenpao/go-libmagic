package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/elfsample"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestELFQueryUsesModeOnly(t *testing.T) {
	for _, tc := range []struct {
		desc, flag, want string
		limit            int
	}{
		{"${x?pie:shared}", "1", "pie", 512},
		{"${x?pie:shared}", "3", "shared", 512},
		{"${x?pie:shared}", "", "shared", 512},
		{"${y?pie:shared}", "1", "${y?pie:shared}", 512},
		{"${x?a:b}${z?c:d}", "1", "${x?a:b}${z?c:d}", 512},
		{"${x?a:b:c}", "0", "b:c", 512},
		{"${x?abcd:efgh}", "1", "${x?abcd:efgh}", 4},
		{"${x?abcd:efgh}", "1", "abcd", 5},
	} {
		if got := expandQuery(tc.desc, tc.flag, tc.limit); got != tc.want {
			t.Errorf("%q/%q = %q, want %q", tc.desc, tc.flag, got, tc.want)
		}
	}
}

func TestELFCapabilitySizeCannotWrapLoop(t *testing.T) {
	data := elfsample.Cases()["64-le-capabilities"]
	shoff := binary.LittleEndian.Uint64(data[40:])
	binary.LittleEndian.PutUint64(data[shoff+64+32:], ^uint64(0))
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(data[1024+i*16:], uint64(9+i))
	}
	suffix, _, err := elfSupplement(data, bytes.NewReader(data), int64(len(data)), false, false)
	if err != nil || strings.Count(suffix, "unknown capability") != 4 {
		t.Fatalf("capability loop = %q / %v", suffix, err)
	}
}

func FuzzELF(f *testing.F) {
	for _, data := range elfsample.Cases() {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		elfSupplement(data, bytes.NewReader(data), int64(len(data)), false, false)
		elfSupplement(data, bytes.NewReader(data), int64(len(data)), true, true)
	})
}
