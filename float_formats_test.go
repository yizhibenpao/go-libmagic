package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestFloatFormatsWithoutReference(t *testing.T) {
	values, failures := 0, 0
	for _, tc := range softprobe.FloatFormatScalars() {
		m := entry{typ: typeFloat, desc: tc.Format}
		if tc.Wide {
			m.typ = typeDouble
		}
		if tc.Unsigned {
			m.flag = flagUnsigned
		}
		if tc.Error != "" {
			failures++
			m.version16 = true
			m.desc = "value=[" + tc.Format + "]"
			s := state{buf: new(strings.Builder), line: 2}
			s.buf.WriteString("root")
			s.value.u64 = tc.Bits
			printed := s.print(&m, true)
			if printed || s.err == nil || s.err.Error() != tc.Error {
				t.Errorf("wide %v %x %s: %v / %v, want %q", tc.Wide, tc.Bits, tc.Format, printed, s.err, tc.Error)
			}
		} else {
			values++
			if got := formatNumber(&m, tc.Bits); got != tc.Want {
				t.Errorf("wide %v %x %s: %q, want %q", tc.Wide, tc.Bits, tc.Format, got, tc.Want)
			}
		}
	}
	if values != 498 || failures != 204 {
		t.Fatalf("frozen checks: %d values / %d errors, want 498 / 204", values, failures)
	}
}

func TestFloatPrintfDigestWithoutReference(t *testing.T) {
	// Raw libc snprintf, C locale, FE_TONEAREST. This verifies the private
	// formatter, not acceptance by FILE5_41's public fmtcheck: public F/G
	// must fail, as separately frozen in the source/error contracts.
	formats := []string{"%e", "%E", "%f", "%F", "%g", "%G", "%.0g", "%.0f", "%.1g", "%.2e", "%.6f", "%.9g", "%.17g", "%.50g", "%012.3g", "%-12.3g", "%12.0F", "%.100f"}
	h := sha256.New()
	count := 0
	for _, width := range []int{32, 64} {
		values := []uint64{0, 0x80000000, 0x3f800000, 0xbf800000, 0x3fc00000, 0x7f7fffff, 1, 0x00800000, 0x7f800000, 0xff800000, 0x7fc00001, 0xffc00001, 0x7f800001, 0xff800001}
		typ := uint8(typeFloat)
		if width == 64 {
			values = []uint64{0, 0x8000000000000000, 0x3ff0000000000000, 0xbff0000000000000, 0x3ff8000000000000, 0x7fefffffffffffff, 1, 0x0010000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000001, 0xfff8000000000001, 0x7ff0000000000001, 0xfff0000000000001}
			typ = typeDouble
		}
		x := uint64(0x123456789abcdef)
		for i := 0; i < 4096; i++ {
			x ^= x >> 12
			x ^= x << 25
			x ^= x >> 27
			bits := x * 2685821657736338717
			if width == 32 {
				bits &= 0xffffffff
			}
			values = append(values, bits)
		}
		for _, bits := range values {
			for _, format := range formats {
				got := formatNumber(&entry{typ: typ, desc: format}, bits)
				fmt.Fprintf(h, "%d:%016x:%s:%s\n", width, bits, format, got)
				count++
			}
		}
	}
	if count != 147960 || fmt.Sprintf("%x", h.Sum(nil)) != "eb3cc3dec366079043c6e27e6c95a71b4852c3ec7cda0bcb62c4ba551cea5462" {
		t.Fatalf("%d raw printf checks: digest %x", count, h.Sum(nil))
	}
}
