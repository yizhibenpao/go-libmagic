package libmagic

import "testing"

func TestFromOctUsesFILE541CLocaleWhitespace(t *testing.T) {
	want := fromOct([]byte("1234567 "))
	for _, leading := range []byte{'\t', '\n', '\v', '\f', '\r', ' '} {
		field := append([]byte{leading}, []byte("1234567")...)
		if got := fromOct(field); got != want {
			t.Errorf("leading %#02x: got %d, want %d", leading, got, want)
		}
	}
	for _, trailing := range []byte{'\t', '\n', '\v', '\f', '\r', ' '} {
		field := append([]byte("1234567"), trailing)
		if got := fromOct(field); got != want {
			t.Errorf("trailing %#02x: got %d, want %d", trailing, got, want)
		}
	}
	if got := fromOct(append([]byte("1234567"), 0xa0)); got != -1 {
		t.Fatalf("non-C-locale whitespace accepted: %d", got)
	}
}
