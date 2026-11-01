package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"errors"
	"strings"
	"testing"
)

func TestStringCharactersWithoutReference(t *testing.T) {
	characters, str := 0, 0
	for _, tc := range softprobe.StringCharacters() {
		var got string
		var err error
		switch {
		case strings.HasPrefix(tc.Name, "char-byte-"), strings.HasPrefix(tc.Name, "char-ubyte-"):
			fields := strings.Fields(strings.Split(tc.Sources[0], "\n")[1])
			m := entry{typ: typeByte, desc: fields[3]}
			if fields[1] == "ubyte" {
				m.flag = flagUnsigned
			}
			s := state{buf: new(strings.Builder), value: value{u64: uint64(tc.Data[8])}}
			s.buf.WriteString("root")
			printed := true
			s.emit(&m, &printed)
			got, err = magicResult(s.buf.String(), s.err)
			characters++
		case strings.HasPrefix(tc.Name, "string-string-"):
			fields := strings.Fields(strings.Split(tc.Sources[0], "\n")[1])
			got, err = magicResult("root "+expand(fields[3], printable(string(tc.Data[8:]))), nil)
			str++
		default:
			continue
		}
		if err != nil || got != tc.File[0].Value || got != tc.Buffer[0].Value {
			t.Errorf("%s: %q / %v, want %q / %q", tc.Name, got, err, tc.File[0].Value, tc.Buffer[0].Value)
		}
	}
	if characters != 668 || str != 36 {
		t.Fatalf("frozen private checks: characters %d, strings %d, want 668 / 36", characters, str)
	}
}

func TestCharacterBytesWithoutReference(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		m := entry{typ: typeByte, desc: "%c"}
		if unsigned {
			m.flag = flagUnsigned
		}
		for v := 0; v < 256; v++ {
			got := formatNumber(&m, uint64(v))
			if len(got) != 1 || got[0] != byte(v) {
				t.Fatalf("unsigned %v byte %d: %x, want one raw byte", unsigned, v, got)
			}
		}
	}
}

func TestMagicResultWithoutReference(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"", ""},
		{"ABC\\001", "ABC\\001"},
		{"A\x01B\x7f\xff", "A\\001B\\177\\377"},
		{"A\x00ignored", "A"},
		{"\xc3\xa9", "\\303\\251"},
		{strings.Repeat("\x01", 600), strings.Repeat("\\001", 600)},
	} {
		got, err := magicResult(tc.raw, nil)
		if err != nil || got != tc.want {
			t.Errorf("raw %x: %q / %v, want %q", tc.raw, got, err, tc.want)
		}
	}
	err := errors.New("native error")
	raw := "A\x01\x00B"
	got, gotErr := magicResult(raw, err)
	if got != raw || gotErr != err {
		t.Fatalf("error result changed: %q / %v", got, gotErr)
	}
}
