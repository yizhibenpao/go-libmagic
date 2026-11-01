package libmagic

import (
	"strconv"
	"testing"
)

func TestIntegerPromotionsWithoutReference(t *testing.T) {
	// All byte/short bit patterns, with signed and unsigned source types.
	// The expected values follow C integer promotion, not signExtend/hostNumber.
	for _, tc := range []struct {
		typ  uint8
		bits uint
	}{{typeByte, 8}, {typeShort, 16}} {
		for _, unsigned := range []bool{false, true} {
			for raw := uint64(0); raw < uint64(1)<<tc.bits; raw++ {
				n := int64(raw)
				if !unsigned && raw >= uint64(1)<<(tc.bits-1) {
					n -= int64(1) << tc.bits
				}
				for _, spec := range []byte{'d', 'i', 'u', 'x', 'X', 'o'} {
					m := entry{typ: tc.typ, desc: "value=[%" + string(spec) + "]"}
					if unsigned {
						m.flag = flagUnsigned
					}
					base := 10
					if spec == 'x' || spec == 'X' {
						base = 16
					}
					if spec == 'o' {
						base = 8
					}
					want := strconv.FormatUint(uint64(uint32(n)), base)
					if spec == 'd' || spec == 'i' {
						want = strconv.FormatInt(n, 10)
					}
					if spec == 'X' {
						b := []byte(want)
						for i, c := range b {
							if c >= 'a' && c <= 'f' {
								b[i] = c - 'a' + 'A'
							}
						}
						want = string(b)
					}
					want = "value=[" + want + "]"
					if got := expand(m.desc, formatNumber(&m, raw)); got != want {
						t.Fatalf("type %d unsigned %v raw %x spec %c: %q, want %q", tc.typ, unsigned, raw, spec, got, want)
					}
				}
			}
		}
	}
}

func TestIntegerFormatsNativeCasesWithoutReference(t *testing.T) {
	// Frozen real 5.41 results for long/quad signed formats and ll directives.
	for _, tc := range []struct {
		typ          uint8
		unsigned     bool
		raw          uint64
		format, want string
	}{
		{typeLong, false, 0, "value=[%d]", "value=[0]"},
		{typeLong, false, 1, "value=[%d]", "value=[1]"},
		{typeLong, false, 2147483647, "value=[%d]", "value=[2147483647]"},
		{typeLong, false, 2147483648, "value=[%d]", "value=[-2147483648]"},
		{typeLong, false, 4294967295, "value=[%d]", "value=[-1]"},
		{typeLong, false, 4294967294, "value=[%d]", "value=[-2]"},
		{typeLong, false, 0, "value=[%i]", "value=[0]"},
		{typeLong, false, 1, "value=[%i]", "value=[1]"},
		{typeLong, false, 2147483647, "value=[%i]", "value=[2147483647]"},
		{typeLong, false, 2147483648, "value=[%i]", "value=[-2147483648]"},
		{typeLong, false, 4294967295, "value=[%i]", "value=[-1]"},
		{typeLong, false, 4294967294, "value=[%i]", "value=[-2]"},
		{typeLong, false, 0, "value=[%u]", "value=[0]"},
		{typeLong, false, 1, "value=[%u]", "value=[1]"},
		{typeLong, false, 2147483647, "value=[%u]", "value=[2147483647]"},
		{typeLong, false, 2147483648, "value=[%u]", "value=[2147483648]"},
		{typeLong, false, 4294967295, "value=[%u]", "value=[4294967295]"},
		{typeLong, false, 4294967294, "value=[%u]", "value=[4294967294]"},
		{typeLong, false, 0, "value=[%x]", "value=[0]"},
		{typeLong, false, 1, "value=[%x]", "value=[1]"},
		{typeLong, false, 2147483647, "value=[%x]", "value=[7fffffff]"},
		{typeLong, false, 2147483648, "value=[%x]", "value=[80000000]"},
		{typeLong, false, 4294967295, "value=[%x]", "value=[ffffffff]"},
		{typeLong, false, 4294967294, "value=[%x]", "value=[fffffffe]"},
		{typeLong, false, 0, "value=[%X]", "value=[0]"},
		{typeLong, false, 1, "value=[%X]", "value=[1]"},
		{typeLong, false, 2147483647, "value=[%X]", "value=[7FFFFFFF]"},
		{typeLong, false, 2147483648, "value=[%X]", "value=[80000000]"},
		{typeLong, false, 4294967295, "value=[%X]", "value=[FFFFFFFF]"},
		{typeLong, false, 4294967294, "value=[%X]", "value=[FFFFFFFE]"},
		{typeLong, false, 0, "value=[%o]", "value=[0]"},
		{typeLong, false, 1, "value=[%o]", "value=[1]"},
		{typeLong, false, 2147483647, "value=[%o]", "value=[17777777777]"},
		{typeLong, false, 2147483648, "value=[%o]", "value=[20000000000]"},
		{typeLong, false, 4294967295, "value=[%o]", "value=[37777777777]"},
		{typeLong, false, 4294967294, "value=[%o]", "value=[37777777776]"},
		{typeLong, true, 0, "value=[%d]", "value=[0]"},
		{typeLong, true, 1, "value=[%d]", "value=[1]"},
		{typeLong, true, 2147483647, "value=[%d]", "value=[2147483647]"},
		{typeLong, true, 2147483648, "value=[%d]", "value=[-2147483648]"},
		{typeLong, true, 4294967295, "value=[%d]", "value=[-1]"},
		{typeLong, true, 4294967294, "value=[%d]", "value=[-2]"},
		{typeLong, true, 0, "value=[%i]", "value=[0]"},
		{typeLong, true, 1, "value=[%i]", "value=[1]"},
		{typeLong, true, 2147483647, "value=[%i]", "value=[2147483647]"},
		{typeLong, true, 2147483648, "value=[%i]", "value=[-2147483648]"},
		{typeLong, true, 4294967295, "value=[%i]", "value=[-1]"},
		{typeLong, true, 4294967294, "value=[%i]", "value=[-2]"},
		{typeLong, true, 0, "value=[%u]", "value=[0]"},
		{typeLong, true, 1, "value=[%u]", "value=[1]"},
		{typeLong, true, 2147483647, "value=[%u]", "value=[2147483647]"},
		{typeLong, true, 2147483648, "value=[%u]", "value=[2147483648]"},
		{typeLong, true, 4294967295, "value=[%u]", "value=[4294967295]"},
		{typeLong, true, 4294967294, "value=[%u]", "value=[4294967294]"},
		{typeLong, true, 0, "value=[%x]", "value=[0]"},
		{typeLong, true, 1, "value=[%x]", "value=[1]"},
		{typeLong, true, 2147483647, "value=[%x]", "value=[7fffffff]"},
		{typeLong, true, 2147483648, "value=[%x]", "value=[80000000]"},
		{typeLong, true, 4294967295, "value=[%x]", "value=[ffffffff]"},
		{typeLong, true, 4294967294, "value=[%x]", "value=[fffffffe]"},
		{typeLong, true, 0, "value=[%X]", "value=[0]"},
		{typeLong, true, 1, "value=[%X]", "value=[1]"},
		{typeLong, true, 2147483647, "value=[%X]", "value=[7FFFFFFF]"},
		{typeLong, true, 2147483648, "value=[%X]", "value=[80000000]"},
		{typeLong, true, 4294967295, "value=[%X]", "value=[FFFFFFFF]"},
		{typeLong, true, 4294967294, "value=[%X]", "value=[FFFFFFFE]"},
		{typeLong, true, 0, "value=[%o]", "value=[0]"},
		{typeLong, true, 1, "value=[%o]", "value=[1]"},
		{typeLong, true, 2147483647, "value=[%o]", "value=[17777777777]"},
		{typeLong, true, 2147483648, "value=[%o]", "value=[20000000000]"},
		{typeLong, true, 4294967295, "value=[%o]", "value=[37777777777]"},
		{typeLong, true, 4294967294, "value=[%o]", "value=[37777777776]"},
		{typeQuad, false, 0, "value=[%lld]", "value=[0]"},
		{typeQuad, false, 1, "value=[%lld]", "value=[1]"},
		{typeQuad, false, 9223372036854775807, "value=[%lld]", "value=[9223372036854775807]"},
		{typeQuad, false, 9223372036854775808, "value=[%lld]", "value=[-9223372036854775808]"},
		{typeQuad, false, 18446744073709551615, "value=[%lld]", "value=[-1]"},
		{typeQuad, false, 18446744073709551614, "value=[%lld]", "value=[-2]"},
		{typeQuad, false, 0, "value=[%lli]", "value=[0]"},
		{typeQuad, false, 1, "value=[%lli]", "value=[1]"},
		{typeQuad, false, 9223372036854775807, "value=[%lli]", "value=[9223372036854775807]"},
		{typeQuad, false, 9223372036854775808, "value=[%lli]", "value=[-9223372036854775808]"},
		{typeQuad, false, 18446744073709551615, "value=[%lli]", "value=[-1]"},
		{typeQuad, false, 18446744073709551614, "value=[%lli]", "value=[-2]"},
		{typeQuad, false, 0, "value=[%llu]", "value=[0]"},
		{typeQuad, false, 1, "value=[%llu]", "value=[1]"},
		{typeQuad, false, 9223372036854775807, "value=[%llu]", "value=[9223372036854775807]"},
		{typeQuad, false, 9223372036854775808, "value=[%llu]", "value=[9223372036854775808]"},
		{typeQuad, false, 18446744073709551615, "value=[%llu]", "value=[18446744073709551615]"},
		{typeQuad, false, 18446744073709551614, "value=[%llu]", "value=[18446744073709551614]"},
		{typeQuad, false, 0, "value=[%llx]", "value=[0]"},
		{typeQuad, false, 1, "value=[%llx]", "value=[1]"},
		{typeQuad, false, 9223372036854775807, "value=[%llx]", "value=[7fffffffffffffff]"},
		{typeQuad, false, 9223372036854775808, "value=[%llx]", "value=[8000000000000000]"},
		{typeQuad, false, 18446744073709551615, "value=[%llx]", "value=[ffffffffffffffff]"},
		{typeQuad, false, 18446744073709551614, "value=[%llx]", "value=[fffffffffffffffe]"},
		{typeQuad, false, 0, "value=[%llX]", "value=[0]"},
		{typeQuad, false, 1, "value=[%llX]", "value=[1]"},
		{typeQuad, false, 9223372036854775807, "value=[%llX]", "value=[7FFFFFFFFFFFFFFF]"},
		{typeQuad, false, 9223372036854775808, "value=[%llX]", "value=[8000000000000000]"},
		{typeQuad, false, 18446744073709551615, "value=[%llX]", "value=[FFFFFFFFFFFFFFFF]"},
		{typeQuad, false, 18446744073709551614, "value=[%llX]", "value=[FFFFFFFFFFFFFFFE]"},
		{typeQuad, false, 0, "value=[%llo]", "value=[0]"},
		{typeQuad, false, 1, "value=[%llo]", "value=[1]"},
		{typeQuad, false, 9223372036854775807, "value=[%llo]", "value=[777777777777777777777]"},
		{typeQuad, false, 9223372036854775808, "value=[%llo]", "value=[1000000000000000000000]"},
		{typeQuad, false, 18446744073709551615, "value=[%llo]", "value=[1777777777777777777777]"},
		{typeQuad, false, 18446744073709551614, "value=[%llo]", "value=[1777777777777777777776]"},
		{typeQuad, true, 0, "value=[%lld]", "value=[0]"},
		{typeQuad, true, 1, "value=[%lld]", "value=[1]"},
		{typeQuad, true, 9223372036854775807, "value=[%lld]", "value=[9223372036854775807]"},
		{typeQuad, true, 9223372036854775808, "value=[%lld]", "value=[-9223372036854775808]"},
		{typeQuad, true, 18446744073709551615, "value=[%lld]", "value=[-1]"},
		{typeQuad, true, 18446744073709551614, "value=[%lld]", "value=[-2]"},
		{typeQuad, true, 0, "value=[%lli]", "value=[0]"},
		{typeQuad, true, 1, "value=[%lli]", "value=[1]"},
		{typeQuad, true, 9223372036854775807, "value=[%lli]", "value=[9223372036854775807]"},
		{typeQuad, true, 9223372036854775808, "value=[%lli]", "value=[-9223372036854775808]"},
		{typeQuad, true, 18446744073709551615, "value=[%lli]", "value=[-1]"},
		{typeQuad, true, 18446744073709551614, "value=[%lli]", "value=[-2]"},
		{typeQuad, true, 0, "value=[%llu]", "value=[0]"},
		{typeQuad, true, 1, "value=[%llu]", "value=[1]"},
		{typeQuad, true, 9223372036854775807, "value=[%llu]", "value=[9223372036854775807]"},
		{typeQuad, true, 9223372036854775808, "value=[%llu]", "value=[9223372036854775808]"},
		{typeQuad, true, 18446744073709551615, "value=[%llu]", "value=[18446744073709551615]"},
		{typeQuad, true, 18446744073709551614, "value=[%llu]", "value=[18446744073709551614]"},
		{typeQuad, true, 0, "value=[%llx]", "value=[0]"},
		{typeQuad, true, 1, "value=[%llx]", "value=[1]"},
		{typeQuad, true, 9223372036854775807, "value=[%llx]", "value=[7fffffffffffffff]"},
		{typeQuad, true, 9223372036854775808, "value=[%llx]", "value=[8000000000000000]"},
		{typeQuad, true, 18446744073709551615, "value=[%llx]", "value=[ffffffffffffffff]"},
		{typeQuad, true, 18446744073709551614, "value=[%llx]", "value=[fffffffffffffffe]"},
		{typeQuad, true, 0, "value=[%llX]", "value=[0]"},
		{typeQuad, true, 1, "value=[%llX]", "value=[1]"},
		{typeQuad, true, 9223372036854775807, "value=[%llX]", "value=[7FFFFFFFFFFFFFFF]"},
		{typeQuad, true, 9223372036854775808, "value=[%llX]", "value=[8000000000000000]"},
		{typeQuad, true, 18446744073709551615, "value=[%llX]", "value=[FFFFFFFFFFFFFFFF]"},
		{typeQuad, true, 18446744073709551614, "value=[%llX]", "value=[FFFFFFFFFFFFFFFE]"},
		{typeQuad, true, 0, "value=[%llo]", "value=[0]"},
		{typeQuad, true, 1, "value=[%llo]", "value=[1]"},
		{typeQuad, true, 9223372036854775807, "value=[%llo]", "value=[777777777777777777777]"},
		{typeQuad, true, 9223372036854775808, "value=[%llo]", "value=[1000000000000000000000]"},
		{typeQuad, true, 18446744073709551615, "value=[%llo]", "value=[1777777777777777777777]"},
		{typeQuad, true, 18446744073709551614, "value=[%llo]", "value=[1777777777777777777776]"},
	} {
		m := entry{typ: tc.typ, desc: tc.format}
		if tc.unsigned {
			m.flag = flagUnsigned
		}
		if got := expand(m.desc, formatNumber(&m, tc.raw)); got != tc.want {
			t.Errorf("type %d unsigned %v raw %x format %q: %q, want %q", tc.typ, tc.unsigned, tc.raw, tc.format, got, tc.want)
		}
	}
}
