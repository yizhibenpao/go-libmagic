package libmagic

import (
	"strings"
	"testing"
)

func TestJSONProbeMatches541DetectorSemantics(t *testing.T) {
	for _, data := range []string{
		`{}`, `[]`, `[1]`, `[1,]`, `{"a":1,}`, `{} trailing bytes`,
		`[01]`, `{"a":-.2}`, `{"a":txxx}`, "{\"a\":\"\x01\"}",
	} {
		if desc, ok := jsonDescription([]byte(data)); !ok || desc != "JSON data" {
			t.Errorf("5.41 recognizes %q, got %q/%v", data, desc, ok)
		}
	}
	for _, data := range []string{
		`12`, `"text"`, `[ ]`, `[1, ]`, `{"a":"\q"}`, "{\"a\":\"\000\"}",
		`{"a":[1,`, strings.Repeat("[", 12) + "1" + strings.Repeat("]", 12),
	} {
		if _, ok := jsonDescription([]byte(data)); ok {
			t.Errorf("5.41 does not recognize %q as JSON", data)
		}
	}
}

func TestCSVProbeCountsLFRecords(t *testing.T) {
	for _, data := range []string{
		"a,b\n1,2\n3,4\n",
		"\"a\nb\",c\n1,2\n3,4\n",
		strings.Repeat("a,b\n", 10) + "bad,row,extra\n",
		"a,b\n1,2\n3,4\n\"unterminated",
	} {
		if desc, ok := csvDescription([]byte(data), true); !ok || desc != "CSV text" {
			t.Errorf("CSV = %q/%v for %q", desc, ok, data)
		}
		if _, ok := csvDescription([]byte(data), false); ok {
			t.Errorf("binary data must not enter CSV detection")
		}
	}
	for _, data := range []string{"a,b\n1,2\n3,4", "a,b\r1,2\r3,4\r", "a,b\n1,2,3\n4,5\n"} {
		if _, ok := csvDescription([]byte(data), true); ok {
			t.Errorf("not CSV: %q", data)
		}
	}
}
