package libmagic

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strconv"
	"testing"
)

func TestFlagFloatDigestWithoutReference(t *testing.T) {
	// Raw libc snprintf in C locale/FE_TONEAREST, independently frozen.
	// This is the private formatter contract, not public v16 acceptance:
	// F/G and apostrophe formats still have separate fmtcheck errors.
	formats := []string{"%+g", "% g", "%+ g", "% +g", "%+012.3g", "% 012.3g", "%-+012.3g", "%#g", "%#.0g", "%#.1g", "%#.3g", "%#.6g", "%#.17g", "%#.50g", "%#.0f", "%+#12.0f", "% #12.2e", "%+#.6E", "%#.0G", "%#.6G", "%+F", "% F"}
	h := sha256.New()
	count := 0
	for _, width := range []int{32, 64} {
		values := []uint64{0, 0x80000000, 0x3f800000, 0xbf800000, 0x3fc00000, 0x7f7fffff, 1, 0x00800000, 0x7f800000, 0xff800000, 0x7fc00001, 0xffc00001, 0x7f800001, 0xff800001}
		typ := uint8(typeFloat)
		if width == 64 {
			values = []uint64{0, 0x8000000000000000, 0x3ff0000000000000, 0xbff0000000000000, 0x3ff8000000000000, 0x7fefffffffffffff, 1, 0x0010000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000001, 0xfff8000000000001, 0x7ff0000000000001, 0xfff0000000000001}
			typ = typeDouble
		}
		for _, v := range []float64{0.0000999999, 0.9999999, 9.999999, 99.99999, 999.9999, 1000000} {
			if width == 32 {
				values = append(values, uint64(math.Float32bits(float32(v))))
			} else {
				values = append(values, math.Float64bits(v))
			}
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
			for _, f := range formats {
				m := entry{typ: typ, desc: f}
				h.Write([]byte(formatNumber(&m, bits)))
				h.Write([]byte{0})
				count++
			}
		}
	}
	if count != 181104 || fmt.Sprintf("%x", h.Sum(nil)) != "a58aa5eac2fed4fb0345a3ade3f5e02cba7a0f74aca1e218daf1a9ca7828b730" {
		t.Fatalf("%d raw printf values: digest %x", count, h.Sum(nil))
	}
}

func TestFlagTransitionsWithoutReference(t *testing.T) {
	// Actual snprintf results around every finite positive decimal power,
	// with both signs and two adjacent IEEE values in each direction.
	h := sha256.New()
	count := 0
	for _, width := range []int{32, 64} {
		last, typ := 38, uint8(typeFloat)
		if width == 64 {
			last, typ = 308, typeDouble
		}
		for exponent := 1; exponent <= last; exponent++ {
			v, err := strconv.ParseFloat("1e"+strconv.Itoa(exponent), width)
			if err != nil {
				t.Fatal(err)
			}
			center := math.Float64bits(v)
			if width == 32 {
				center = uint64(math.Float32bits(float32(v)))
			}
			for delta := -2; delta <= 2; delta++ {
				for _, negative := range []bool{false, true} {
					bits := uint64(int64(center) + int64(delta))
					if negative {
						bits |= uint64(1) << (width - 1)
					}
					p := strconv.Itoa(exponent)
					for _, f := range []string{"%#.0g", "%#.1g", "%#.3g", "%#.6g", "%#.17g", "%#." + p + "g", "%+#012." + p + "g", "% #." + p + "G"} {
						m := entry{typ: typ, desc: f}
						h.Write([]byte(formatNumber(&m, bits)))
						h.Write([]byte{0})
						count++
					}
				}
			}
		}
	}
	if count != 27680 || fmt.Sprintf("%x", h.Sum(nil)) != "95405366378a8689077cb48405b9ac730faa1865dbeb5b24b5e6f4af516883b7" {
		t.Fatalf("%d decimal-boundary values: digest %x", count, h.Sum(nil))
	}
}
