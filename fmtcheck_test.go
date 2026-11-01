package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestFmtcheckWithoutReference(t *testing.T) {
	// Frozen from the unmodified FILE5_41 fmtcheck.c compiled separately
	// under Linux/C locale. Raw printf acceptance is not this contract.
	formats := []string{"", "plain", "%%", "%%%%", "%%d", "%%%d", "%", "%d %d", "%d %%", "%% %s", "%d\x00%n", "\x00%n", "%*.*f", "%*d", "%.*g", "%d %s", "%d%*s", "%1$d", "%\\s", "%..s"}
	for c := 0; c < 256; c++ {
		formats = append(formats, "%"+string([]byte{byte(c)}))
	}
	for _, length := range []string{"", "h", "hh", "l", "ll", "q", "L", "j", "z", "t", "I", "I32", "I64"} {
		for _, spec := range []byte("diouxXnDOUeEfgFGaAcsp%m") {
			formats = append(formats, "%"+length+string(spec))
		}
	}
	for _, flags := range []string{"", "-", "+", " ", "#", "0", "-0", "#+", "'", "--"} {
		for _, width := range []string{"", "0", "12", "1024", "*"} {
			for _, precision := range []string{"", ".", ".0", ".2", ".*", "..2"} {
				formats = append(formats, "%"+flags+width+precision+"d")
			}
		}
	}
	alphabet := "%#0- +.*1239hlqLdiouxXeEfgGsncp"
	x := uint64(0x123456789abcdef)
	for i := 0; i < 2048; i++ {
		f := []byte{'%'}
		for j := 0; j < i%32; j++ {
			x ^= x >> 12
			x ^= x << 25
			x ^= x >> 27
			k := x * 2685821657736338717
			f = append(f, alphabet[k%uint64(len(alphabet))])
		}
		formats = append(formats, string(f))
	}
	defaults := []string{"%d", "%u", "%lld", "%llu", "%g", "%s", "%ld", "%n", "%*.*f", "%d %s", "%Lf", "%hn", "", "%p"}
	h := sha256.New()
	count, passed := 0, 0
	for _, actual := range formats {
		for _, expected := range defaults {
			ok := byte(0)
			if fmtMatches(actual, expected) {
				ok = 1
				passed++
			}
			h.Write([]byte{ok})
			count++
		}
	}
	if len(formats) != 2923 || count != 40922 || passed != 3083 || fmt.Sprintf("%x", h.Sum(nil)) != "539511d1e798eadab5de3ade69d02ad51400b07aa94f8efa44cadee8a3efaad3" {
		t.Fatalf("%d formats / %d checks / %d accepted: digest %x", len(formats), count, passed, h.Sum(nil))
	}
}

func TestNumericStringFormatWithoutReference(t *testing.T) {
	// Independently executed glibc regcomp/regexec, not Go regexp syntax.
	for _, desc := range []string{"%s", "%12.2s", "%012s", "%-12s", "%\\s", "%\\\\s", "%%s", "%d %s", "%..s", "%.s"} {
		if !numericStringFormat(desc) {
			t.Errorf("%q: want match", desc)
		}
	}
	for _, desc := range []string{"%+s", "%#s", "%1$s", "% s", "%12g", "\x00%s"} {
		if numericStringFormat(desc) {
			t.Errorf("%q: want no match", desc)
		}
	}
}

func TestFormatPrintWithoutReference(t *testing.T) {
	testFormatPrint(t, softprobe.FormatChecks(), 497)
}

func TestFlagPrintWithoutReference(t *testing.T) {
	testFormatPrint(t, softprobe.FormatFlags(), 1456)
}

func testFormatPrint(t *testing.T, cases []softprobe.FormatCheckCase, expected int) {
	t.Helper()
	count := 0
	for _, tc := range cases {
		if !tc.Patched || !strings.HasSuffix(tc.Name, "-continuation") || len(tc.Sources) != 1 {
			continue
		}
		switch tc.OriginalType {
		case typeByte, typeShort, typeBEShort, typeLEShort, typeLong, typeBELong, typeLELong, typeMELong,
			typeQuad, typeBEQuad, typeLEQuad, typeFloat, typeBEFloat, typeLEFloat, typeDouble, typeBEDouble, typeLEDouble:
		default:
			continue
		}
		fields := strings.Fields(strings.Split(tc.Sources[0], "\n")[1])
		off, err := strconv.Atoi(strings.TrimPrefix(fields[0], ">"))
		if err != nil {
			t.Fatal(err)
		}
		count++
		m := entry{version16: true, typ: tc.OriginalType, reln: 'x', desc: "value=[" + tc.Format + "]"}
		if strings.HasPrefix(fields[1], "u") {
			m.flag = flagUnsigned
		}
		s := state{buf: new(strings.Builder), line: 2, offset: off}
		s.buf.WriteString("root")
		if !s.copyValue(&m, tc.Data, off, off) {
			t.Fatalf("%s: copy value failed", tc.Name)
		}
		printed := s.print(&m, true)
		got, err := magicResult(s.buf.String(), s.err)
		want := tc.File[0]
		if want.Failed {
			if printed || s.err == nil || s.err.Error() != want.Error {
				t.Errorf("%s: %v / %v, want %q", tc.Name, printed, s.err, want.Error)
			}
		} else if !printed || err != nil || got != want.Value {
			t.Errorf("%s: %q / %v / %v, want %q", tc.Name, got, printed, err, want.Value)
		}
	}
	if count != expected {
		t.Fatalf("%d frozen numeric/error checks, want %d", count, expected)
	}
	t.Logf("%d independently frozen numeric/error checks", count)
}
