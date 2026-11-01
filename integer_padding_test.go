package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"encoding/binary"
	"strings"
	"testing"
)

func TestIntegerPaddingWithoutReference(t *testing.T) {
	// Frozen native outputs exercise the formatter even without file/WSL.
	n := 0
	for _, tc := range softprobe.IntegerPadding() {
		if !strings.HasPrefix(tc.Name, "scalar-") {
			continue
		}
		fields := strings.Fields(strings.Split(tc.Sources[0], "\n")[1])
		typ := fields[1]
		m := entry{desc: fields[3]}
		if strings.HasPrefix(typ, "u") {
			m.flag = flagUnsigned
			typ = typ[1:]
		}
		switch typ {
		case "byte":
			m.typ = typeByte
		case "long":
			m.typ = typeLong
		case "quad":
			m.typ = typeQuad
		default:
			t.Fatalf("%s: unexpected type %q", tc.Name, typ)
		}
		v := binary.LittleEndian.Uint64(tc.Data[8:16])
		got := "root " + expand(m.desc, formatNumber(&m, v))
		if got != tc.File[0].Value || got != tc.Buffer[0].Value {
			t.Errorf("%s: %q, want native %q / %q", tc.Name, got, tc.File[0].Value, tc.Buffer[0].Value)
		}
		n++
	}
	if n != 1728 {
		t.Fatalf("scalar contracts: %d, want 1728", n)
	}
}

func TestIntegerPaddingErrorsWithoutReference(t *testing.T) {
	for _, tc := range softprobe.IntegerPadding() {
		if !strings.HasPrefix(tc.Name, "boundary-") {
			continue
		}
		fields := strings.Fields(strings.Split(tc.Sources[0], "\n")[1])
		m := entry{typ: typeLong, desc: fields[3], mime: "application/x-padding"}
		s := state{buf: new(strings.Builder)}
		s.buf.WriteString("root")
		printed := true
		s.emit(&m, &printed)
		want := tc.File[0]
		if (s.err != nil) != want.Failed {
			t.Fatalf("%s: error %v, want failure %v", tc.Name, s.err, want.Failed)
		}
		if s.err != nil {
			if s.err.Error() != want.Error || s.buf.Len() != 0 {
				t.Errorf("%s: error %q, buffer %q, want %q / empty", tc.Name, s.err, s.buf.String(), want.Error)
			}
		} else if s.buf.String() != want.Value {
			t.Errorf("%s: output %q, want %q", tc.Name, s.buf.String(), want.Value)
		}
		mime := state{buf: new(strings.Builder), mime: true}
		if !mime.emit(&m, &printed) || mime.err != nil || mime.buf.String() != tc.File[1].Value {
			t.Errorf("%s: MIME %q / %v, want %q / nil", tc.Name, mime.buf.String(), mime.err, tc.File[1].Value)
		}
	}
	// Same accumulated length as the normal-source 1025-sibling native probe.
	s := state{buf: new(strings.Builder)}
	s.buf.WriteString(strings.Repeat("x", 4+1023*1024))
	printed := true
	m := entry{typ: typeLong, desc: "%1023d"}
	s.emit(&m, &printed)
	if s.err == nil || s.err.Error() != "Output buffer space exceeded 1023+1047557" || s.buf.Len() != 0 {
		t.Errorf("aggregate output: error %v, buffer length %d", s.err, s.buf.Len())
	}
}

func TestIntegerPaddingFormatGuard(t *testing.T) {
	for _, tc := range []struct{ format, want string }{
		{"%%1024d", ""},
		{"%#08.5llx", ""},
		{"%1023d", ""},
		{"%1024d", "field width too large: 1024"},
		{"%.1024d", "field width too large: 1024"},
		{"%8.1024d", "field precision too large: 1024"},
		{"%*d", "* not allowed in format"},
	} {
		if got := formatError(tc.format); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.format, got, tc.want)
		}
	}
}
