package libmagic

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodingPassBoundaries(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		kind encodingKind
	}{
		{"sub-is-binary", []byte("a\x1ab\n"), encodingBinary},
		{"initial-nuls-not-trimmed", []byte("ordinary text\n\000\000"), encodingBinary},
		{"limit", append(bytes.Repeat([]byte{'x'}, 65536), 0, 1), encodingASCII},
		{"utf8-partial", []byte("café \xe2\x82"), encodingUTF8},
		{"utf7", []byte("+/v8-ordinary text\n"), encodingUTF7},
		{"utf16-odd", []byte{0xff, 0xfe, 'A', 0, 'B'}, encodingUTF16LE},
		{"utf16-surrogate", []byte{0xff, 0xfe, 0, 0xd8, 'A', 0}, encodingUTF16LE},
		{"utf16-control", []byte{0xff, 0xfe, 'A', 0, 0, 0, 'B', 0}, encodingBinary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectEncoding(tt.data); got.kind != tt.kind {
				t.Fatalf("kind = %d (%s), want %d", got.kind, got.label, tt.kind)
			}
		})
	}
	if got := detectEncoding([]byte("café \xe2\x82")).normalized; string(got) != "café " {
		t.Fatalf("partial sequence was not ignored: %q", got)
	}
	if got := detectEncoding([]byte{0xff, 0xfe, 0, 0xd8, 'A', 0}).normalized; !bytes.Equal(got, []byte{0xed, 0xa0, 0x80, 'A'}) {
		t.Fatalf("5.41 UTF-16 code-unit encoding changed: %x", got)
	}
	for _, input := range [][]byte{
		{0xed, 0xa0, 0x80}, {0xf4, 0x90, 0x80, 0x80}, {0xf5, 0x80, 0x80, 0x80},
	} {
		if _, status := decodeTextUTF8(input); status != -1 {
			t.Errorf("invalid UTF-8 %x returned %d", input, status)
		}
	}
}

func TestTextPropertiesUseCharacterCounts(t *testing.T) {
	chars := make([]uint32, 302)
	for i := 0; i < 301; i++ {
		chars[i] = 'é'
	}
	chars[301] = '\n'
	if got := textProperties(chars, 603); got != ", with very long lines (301)" {
		t.Fatal(got)
	}
	mixed := []uint32{'\r', '\n', 'a', '\r', 'b', '\n', 0x85, 0x1b, '\b'}
	want := ", with CRLF, CR, LF, NEL line terminators, with escape sequences, with overstriking"
	if got := textProperties(mixed, len(mixed)); got != want {
		t.Fatalf("properties = %q, want %q", got, want)
	}
	if got := textProperties([]uint32{'a', '\r'}, fileBytesMax); got != ", with no line terminators" {
		t.Fatalf("truncated final CR: %q", got)
	}
}

func TestTextFallbackRetrimsAndReencodes(t *testing.T) {
	db := &Database{}
	desc, ok, err := db.textDescription(&tail{}, []byte("ordinary text\n\000\000"), false, false, "", "0", value{}, search{}, 0)
	if !ok || err != nil || desc != "ASCII text" {
		t.Fatalf("text fallback = %q, %v, %v", desc, ok, err)
	}
	data := append([]byte("é"), bytes.Repeat([]byte{'x'}, 65533)...)
	data = append(data, []byte("€\n")...)
	desc, ok, err = db.textDescription(&tail{}, data, false, true, "", "0", value{}, search{}, 0)
	if !ok || err != nil || !strings.HasSuffix(desc, "with very long lines (65534), with no line terminators") {
		t.Fatalf("cutoff = %q, %v, %v", desc, ok, err)
	}
}
