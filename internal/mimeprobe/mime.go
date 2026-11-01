// Package mimeprobe defines small source databases for MIME contract tests.
package mimeprobe

import (
	"fmt"
	"strings"
)

type Case struct {
	Name       string
	Sources    []string
	Data       []byte
	MIME       string
	FileMIME   string
	Executable string
}

func Cases() []Case {
	binary := []byte("ABCD\x00\x01\n")
	text := []byte("ABCD ordinary text\n")
	cases := []Case{
		{"top-first", []string{"0 string/b ABCD top\n!:mime application/x-first\n>4 byte x child\n!:mime application/x-second\n"}, binary, "application/x-first", "", ""},
		{"continuation-first", []string{"0 string/b ABCD top\n>4 byte x first\n!:mime application/x-first\n>5 byte x second\n!:mime application/x-second\n"}, binary, "application/x-first", "", ""},
		{"deep-first", []string{"0 string/b ABCD top\n>4 byte x child\n>>5 byte x deep\n!:mime application/x-deep\n>5 byte x later\n!:mime application/x-later\n"}, binary, "application/x-deep", "", ""},
		{"missed-continuation", []string{"0 string/b ABCD top\n>4 byte =2 missed\n!:mime application/x-missed\n>5 byte =1 selected\n!:mime application/x-selected\n"}, binary, "application/x-selected", "", ""},
		{"description-stops-group", []string{"0 string/b ABCD first\n!:strength +40\n0 string/b ABCD later\n!:mime application/x-later\n"}, binary, "application/octet-stream", "", ""},
		{"empty-description-continues", []string{"0 string/b ABCD\n!:strength +40\n0 string/b ABCD later\n!:mime application/x-later\n"}, binary, "application/x-later", "", ""},
		{"empty-parent-child-annotation", []string{"0 string/b ABCD\n>4 byte x child\n!:mime application/x-child\n"}, binary, "application/x-child", "", ""},
		{"missed-top", []string{"0 string/b ABCE missed\n!:strength +40\n!:mime application/x-missed\n0 string/b ABCD selected\n!:mime application/x-selected\n"}, binary, "application/x-selected", "", ""},
		{"named-annotation", []string{"0 name mime-child\n>0 string/b ABCD named\n!:mime application/x-named\n0 string/b ABCD root\n>0 use mime-child\n"}, binary, "application/x-named", "", ""},
		{"named-no-binary-root", []string{"0 name mime-child\n>0 string/b ABCD named\n!:mime application/x-named\n0 use mime-child\n"}, binary, "application/octet-stream", "", ""},
		{"second-database-after-description", []string{"0 string/b ABCD first\n0 string/b ABCD ignored\n!:mime application/x-ignored\n", "0 string/b ABCD second\n!:mime application/x-second\n"}, binary, "application/x-second", "", ""},
		{"first-database-annotation", []string{"0 string/b ABCD first\n!:mime application/x-first\n", "0 string/b ABCD second\n!:mime application/x-second\n"}, binary, "application/x-first", "", ""},
		{"second-database-after-miss", []string{"0 string/b ABCE missed\n!:mime application/x-missed\n", "0 string/b ABCD second\n!:mime application/x-second\n"}, binary, "application/x-second", "", ""},
		{"text-annotation", []string{"0 string/t ABCD text\n!:mime text/x-probe\n>4 byte x later\n!:mime text/x-later\n"}, text, "text/x-probe", "", ""},
		{"text-description-fallback", []string{"0 string/t ABCD description\n0 string/t ABCD later\n!:mime text/x-later\n"}, text, "text/plain", "", ""},
		{"binary-fallback", []string{"0 string/b ABCE missed\n"}, binary, "application/octet-stream", "", ""},
		{"ascii-fallback", []string{"0 string/t ABCE missed\n"}, text, "text/plain", "", ""},
		{"unicode-fallback", []string{"0 string/t ABCE missed\n"}, []byte("你好 ordinary text\n"), "text/plain", "", ""},
		{"empty-buffer", []string{"0 string/b ABCD unused\n"}, nil, "application/x-empty", "inode/x-empty", ""},
		{"one-byte", []string{"0 byte x ignored\n!:mime application/x-ignored\n"}, []byte{'A'}, "application/octet-stream", "", ""},
	}
	for _, q := range []struct {
		name, value, noexec, exec string
	}{
		{"mode", "application/x-${x?exec:data}", "application/x-data", "application/x-exec"},
		{"multiple", "application/${x?a:b}-${x?c:d}", "application/b-d", "application/a-c"},
		{"unknown-variable", "application/${z?a:b}", "application/${z?a:b}", ""},
		{"missing-colon", "application/${x?ab}", "application/${x?ab}", ""},
		{"missing-brace", "application/${x?a:b", "application/${x?a:b", ""},
		{"invalid-after-valid", "application/${x?a:b}-${z?c:d}", "application/${x?a:b}-${z?c:d}", ""},
		{"first-colon", "application/${x?a:b:c}", "application/b:c", "application/a"},
	} {
		cases = append(cases, Case{"query-" + q.name, []string{"0 string/b ABCD probe\n!:mime " + q.value + "\n"}, binary, q.noexec, "", q.exec})
	}
	for _, n := range []int{50, 51, 59} {
		prefix := "application/" + strings.Repeat("a", n)
		cases = append(cases, Case{
			Name:       fmt.Sprintf("long-query-%d", len(prefix)+1),
			Sources:    []string{"0 string/b ABCD probe\n!:mime " + prefix + "${x?a:b}\n"},
			Data:       binary,
			MIME:       prefix + "b",
			Executable: prefix + "a",
		})
	}
	return cases
}
