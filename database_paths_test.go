package libmagic

import (
	"reflect"
	"runtime"
	"testing"
)

func TestSplitMagicPathWithoutReference(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"a:b", []string{"a", "b"}},
		{"a:b:c", []string{"a", "b", "c"}},
		{"/opt/a:b:/c", []string{"/opt/a", "b", "/c"}},
		{"a::b", []string{"a"}},
		{"a:b::c", []string{"a", "b"}},
		{"a:", []string{"a"}},
		{":a", []string{}},
		{"::a", []string{}},
		{":", []string{}},
		{"", []string{}},
	}
	if runtime.GOOS == "windows" {
		// Preserve the existing Go-only drive/colon-list compatibility.
		// Native Windows libmagic uses ';', outside the Linux parity target.
		cases = []struct {
			path string
			want []string
		}{
			{`C:\a.mgc:D:\b.mgc`, []string{`C:\a.mgc`, `D:\b.mgc`}},
			{`C:\a.mgc:magic.mgc`, []string{`C:\a.mgc`, `magic.mgc`}},
			{"/opt/a:b:/c", []string{"/opt/a", "b", "/c"}},
		}
	}
	for _, tc := range cases {
		if got := splitMagicPath(tc.path); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("split %q = %#v, want %#v", tc.path, got, tc.want)
		}
	}
}
