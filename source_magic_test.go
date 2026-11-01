package libmagic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSourceMagicFile(t *testing.T) {
	path := writeSourceMagic(t, "0 string/t HELLO root\n>5 byte =0x21 bang\n!:mime text/x-hello # trailing comment\n")
	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatalf("OpenDatabase(source) = %v", err)
	}
	if got, err := db.Buffer([]byte("HELLO!")); err != nil || got != "root bang" {
		t.Fatalf("Buffer(source) = %q, %v; want %q", got, err, "root bang")
	}
	if got, err := db.BufferMIMEType([]byte("HELLO!")); err != nil || got != "text/x-hello" {
		t.Fatalf("BufferMIMEType(source) = %q, %v; want %q", got, err, "text/x-hello")
	}
}

func TestSourceMagicMIMEAnnotationUsesCurrentRule(t *testing.T) {
	path := writeSourceMagic(t, "0 string/t ROOT root\n!:mime text/root\n>0 byte =0x52 child\n!:mime text/child\n")
	source, err := parseSourceMagicFile(path)
	if err != nil {
		t.Fatalf("parseSourceMagicFile(current MIME) = %v", err)
	}
	if len(source.regular) != 1 || len(source.regular[0].rules) != 2 {
		t.Fatalf("parsed rules = %#v, want one root and one continuation", source.regular)
	}
	if got := source.regular[0].rules[0].mime; got != "text/root" {
		t.Fatalf("root MIME annotation = %q, want %q", got, "text/root")
	}
	if got := source.regular[0].rules[1].mime; got != "text/child" {
		t.Fatalf("continuation MIME annotation = %q, want %q", got, "text/child")
	}
	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatalf("OpenDatabase(current MIME) = %v", err)
	}
	if got, err := db.BufferMIMEType([]byte("ROOT")); err != nil || got != "text/root" {
		t.Fatalf("runtime MIME selection = %q, %v; want %q", got, err, "text/root")
	}
}

func TestSourceMagicDuplicateMIMEAnnotation(t *testing.T) {
	path := writeSourceMagic(t, "0 string/t MIME first\n!:mime text/first\n!:mime text/second\n")
	if _, err := OpenDatabase(path); err == nil {
		t.Fatal("OpenDatabase(duplicate MIME) succeeded; want source diagnostic")
	}
}

func TestOpenSourceMagicDirectory(t *testing.T) {
	dir := t.TempDir()
	writeSourceMagicAt(t, filepath.Join(dir, "text"), "0 string/t HELLO source text\n!:mime text/x-source\n")
	writeSourceMagicAt(t, filepath.Join(dir, "empty"), "# comments only\n")
	if err := os.WriteFile(filepath.Join(dir, ".broken"), []byte("not a magic file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDatabase(dir)
	if err != nil {
		t.Fatalf("OpenDatabase(source directory) = %v", err)
	}
	if got, err := db.BufferMIMEType([]byte("HELLO\n")); err != nil || got != "text/x-source" {
		t.Fatalf("directory MIME = %q, %v; want %q", got, err, "text/x-source")
	}
}

func TestOpenSourceMagicDirectorySortsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeSourceMagicAt(t, filepath.Join(dir, "a"), "0 string A weak\n")
	writeSourceMagicAt(t, filepath.Join(dir, "b"), "0 string AB strong\n")
	db, err := OpenDatabase(dir)
	if err != nil {
		t.Fatalf("OpenDatabase(source order directory) = %v", err)
	}
	if got, err := db.Buffer([]byte("AB")); err != nil || got != "strong" {
		t.Fatalf("directory rule order = %q, %v; want %q", got, err, "strong")
	}
}

func TestOpenSourceMagicDirectoryCrossFileUse(t *testing.T) {
	dir := t.TempDir()
	writeSourceMagicAt(t, filepath.Join(dir, "a"), "0 name N\n>0 string/t MAGIC named\n")
	writeSourceMagicAt(t, filepath.Join(dir, "b"), "0 string/t MAGIC root\n>0 use N\n")
	db, err := OpenDatabase(dir)
	if err != nil {
		t.Fatalf("OpenDatabase(source use directory) = %v", err)
	}
	if got, err := db.Buffer([]byte("MAGIC")); err != nil || got != "root named, ASCII text, with no line terminators" {
		t.Fatalf("directory cross-file use = %q, %v; want %q", got, err, "root named, ASCII text, with no line terminators")
	}
}

func TestOpenMixedCompiledSourceDirectory(t *testing.T) {
	dir := t.TempDir()
	compiled, err := os.ReadFile(testMagicPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "magic.mgc"), compiled, 0600); err != nil {
		t.Fatal(err)
	}
	writeSourceMagicAt(t, filepath.Join(dir, "source"),
		"0 string MIXED_SOURCE mixed source\n!:mime application/x-mixed-source\n")
	if err := os.WriteFile(filepath.Join(dir, "helper"), []byte("not a magic database\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDatabase(dir)
	if err != nil {
		t.Fatalf("OpenDatabase(mixed directory) = %v", err)
	}
	if got, err := db.BufferMIMEType([]byte("MIXED_SOURCE")); err != nil || got != "application/x-mixed-source" {
		t.Fatalf("mixed directory MIME = %q, %v; want %q", got, err, "application/x-mixed-source")
	}
}

func TestOpenEmptySourceMagic(t *testing.T) {
	path := writeSourceMagic(t, "# comments only\n\n")
	if _, err := OpenDatabase(path); err != nil {
		t.Fatalf("OpenDatabase(empty source) = %v", err)
	}
}

func TestSourceMagicNameUse(t *testing.T) {
	path := writeSourceMagic(t, "0 name N\n>0 string/t MAGIC named\n0 string/t MAGIC root\n>0 use N\n")
	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatalf("OpenDatabase(name/use) = %v", err)
	}
	if got, err := db.Buffer([]byte("MAGIC")); err != nil || got != "root named, ASCII text, with no line terminators" {
		t.Fatalf("Buffer(name/use) = %q, %v; want %q", got, err, "root named, ASCII text, with no line terminators")
	}
}

func TestSourceMagicEscapesAndNumericMask(t *testing.T) {
	path := writeSourceMagic(t, "0 string/t A\\x42 root\n0 byte&0xf0 =0xa0 masked\n")
	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatalf("OpenDatabase(escapes) = %v", err)
	}
	if got, err := db.Buffer([]byte{0xa5, 'A', 'B'}); err != nil || got != "masked" {
		t.Fatalf("Buffer(mask) = %q, %v; want %q", got, err, "masked")
	}
	if got, err := db.Buffer([]byte("AB")); err != nil || got != "root, ASCII text, with no line terminators" {
		t.Fatalf("Buffer(escape) = %q, %v; want %q", got, err, "root, ASCII text, with no line terminators")
	}
}

func TestSourceMagicTrailingEscape(t *testing.T) {
	m, _, err := parseSourceRule("0 string A\\", 1)
	if err != nil {
		t.Fatalf("parseSourceRule(trailing escape) = %v", err)
	}
	if got := string(m.value[:m.vallen]); got != "A" {
		t.Fatalf("trailing escape value = %q, want %q", got, "A")
	}
}

func TestSourceMagicNumericHexAndSizeSuffix(t *testing.T) {
	path := writeSourceMagic(t, "0 byte =0x0c hex\n0 byte =10UL decimal\n")
	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatalf("OpenDatabase(numbers) = %v", err)
	}
	if got, err := db.Buffer([]byte{0x0c, 0}); err != nil || got != "hex" {
		t.Fatalf("hex source value = %q, %v; want %q", got, err, "hex")
	}
	if got, err := db.Buffer([]byte{10, 0}); err != nil || got != "decimal" {
		t.Fatalf("suffixed source value = %q, %v; want %q", got, err, "decimal")
	}
}

func TestSourceMagicStandardTypeAliases(t *testing.T) {
	tests := []struct {
		name     string
		typ      uint8
		unsigned bool
	}{
		{"d", typeLong, false},
		{"u", typeLong, true},
		{"dC", typeByte, false},
		{"uC", typeByte, true},
		{"d1", typeByte, false},
		{"u1", typeByte, true},
		{"dS", typeShort, false},
		{"uS", typeShort, true},
		{"d2", typeShort, false},
		{"u2", typeShort, true},
		{"dI", typeLong, false},
		{"uI", typeLong, true},
		{"dL", typeLong, false},
		{"uL", typeLong, true},
		{"d4", typeLong, false},
		{"u4", typeLong, true},
		{"dQ", typeQuad, false},
		{"uQ", typeQuad, true},
		{"d8", typeQuad, false},
		{"u8", typeQuad, true},
		{"s", typeString, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, err := parseSourceRule("0 "+tt.name+" x alias", 1)
			if err != nil {
				t.Fatalf("parseSourceRule(%q) = %v", tt.name, err)
			}
			if m.typ != tt.typ {
				t.Fatalf("type = %d, want %d", m.typ, tt.typ)
			}
			if got := m.flag&flagUnsigned != 0; got != tt.unsigned {
				t.Fatalf("unsigned = %v, want %v", got, tt.unsigned)
			}
		})
	}
}

func TestSourceMagicStringModifierSeparators(t *testing.T) {
	m, _, err := parseSourceRule(`0 string/c/t x alias`, 1)
	if err != nil {
		t.Fatalf("parseSourceRule(string/c/t) = %v", err)
	}
	if m.strFlags&(stringIgnoreLower|stringTextTest) != stringIgnoreLower|stringTextTest {
		t.Fatalf("string modifiers = %#x, want ignore-lower and text-test", m.strFlags)
	}
	m, _, err = parseSourceRule(`0 search/1/w #! x alias`, 1)
	if err != nil {
		t.Fatalf("parseSourceRule(search/1/w) = %v", err)
	}
	if m.strRange != 1 || m.strFlags&stringCompactOptionalWhitespace == 0 {
		t.Fatalf("search modifiers = range %d flags %#x, want range 1 and optional whitespace", m.strRange, m.strFlags)
	}
	m, _, err = parseSourceRule(`0 search/0x10 DATA x alias`, 1)
	if err != nil || m.strRange != 0x10 {
		t.Fatalf("parseSourceRule(search/0x10) = range %d, %v; want 16", m.strRange, err)
	}
}

func TestSourceMagicNoValueRelationAtEnd(t *testing.T) {
	m, _, err := parseSourceRule("0 clear x", 1)
	if err != nil {
		t.Fatalf("parseSourceRule(clear x) = %v", err)
	}
	if m.reln != 'x' {
		t.Fatalf("clear relation = %q, want x", m.reln)
	}
	if _, _, err := parseSourceRule("0 byte", 1); err == nil {
		t.Fatal("parseSourceRule(byte without value) succeeded")
	}
}

func TestSourceMagicNumericDivisionModifier(t *testing.T) {
	m, _, err := parseSourceRule("0 beqdate/1000 x seconds", 1)
	if err != nil {
		t.Fatalf("parseSourceRule(beqdate/1000) = %v", err)
	}
	if m.maskOp&opsMask != opDiv || m.numMask != 1000 {
		t.Fatalf("date division = op %#x mask %d, want divide/1000", m.maskOp, m.numMask)
	}
}

func TestSourceMagicStringModifierTypeChecks(t *testing.T) {
	for _, line := range []string{
		"0 string/B x invalid",
		"0 string/H x invalid",
		"0 string/h x invalid",
		"0 string/L x invalid",
		"0 string/J x invalid",
		"0 regex/B x invalid",
		"0 regex/W x invalid",
		"0 string/s x invalid",
		"0 bestring16/c x invalid",
	} {
		if _, _, err := parseSourceRule(line, 1); err == nil {
			t.Fatalf("parseSourceRule(%q) succeeded; want invalid modifier", line)
		}
	}
	if m, _, err := parseSourceRule(`0 regex/l x line-count`, 1); err != nil || m.strFlags&pstring4LE == 0 {
		t.Fatalf("regex/l = %#x, %v; want regex line-count modifier", m.strFlags, err)
	}
	if m, _, err := parseSourceRule(`0 pstring/B x pascal`, 1); err != nil || m.strFlags&pstring1BE == 0 {
		t.Fatalf("pstring/B = %#x, %v; want Pascal modifier", m.strFlags, err)
	}
}

func TestSourceMagicIndirectRelativeModifier(t *testing.T) {
	m, _, err := parseSourceRule("0 indirect/r =0 indirect", 1)
	if err != nil {
		t.Fatalf("parseSourceRule(indirect/r) = %v", err)
	}
	if m.strFlags&indirectRelative == 0 {
		t.Fatalf("indirect/r flags = %#x, want relative flag", m.strFlags)
	}
}

func TestSourceMagicIndirectOffsetLayout(t *testing.T) {
	m, _, err := parseSourceRule(">(14.s) uleshort x indirect", 1)
	if err != nil {
		t.Fatalf("parseSourceRule((14.s)) = %v", err)
	}
	if m.offset != 14 || m.inType != typeLEShort || m.inOffset != 0 {
		t.Fatalf("indirect layout = offset %d type %d in_offset %d", m.offset, m.inType, m.inOffset)
	}
}

func TestSourceMagicStrengthDiagnostics(t *testing.T) {
	for _, directive := range []string{
		"!:strength =10",
		"!:strength /0",
		"!:strength +1\n!:strength +2",
	} {
		t.Run(directive, func(t *testing.T) {
			path := writeSourceMagic(t, "0 byte x root\n"+directive+"\n")
			if _, err := OpenDatabase(path); err == nil {
				t.Fatalf("OpenDatabase(%q) succeeded; want source diagnostic", directive)
			}
		})
	}
	if _, err := OpenDatabase(writeSourceMagic(t, "0 name N\n!:strength +1\n")); err == nil {
		t.Fatal("name strength succeeded; want source diagnostic")
	}
	if _, err := OpenDatabase(writeSourceMagic(t, "0 byte x root\n!:strength + 15 # trailing comment\n")); err != nil {
		t.Fatalf("spaced strength failed: %v", err)
	}
}

func TestSourceMagicRegexStrengthUsesNonMagicLength(t *testing.T) {
	pattern := []byte(`a[0-9]*\.`)
	if got := sourceNonMagic(pattern); got != 3 {
		t.Fatalf("sourceNonMagic = %d, want 3", got)
	}
	if got := sourceNonMagic(nil); got != 1 {
		t.Fatalf("sourceNonMagic(empty) = %d, want 1", got)
	}
	group := sourceMagicGroup{rules: []entry{{
		typ:    typeRegex,
		reln:   '=',
		vallen: uint8(len(pattern)),
	}}}
	copy(group.rules[0].value[:], pattern)
	if got := sourceMagicStrength(group); got != 40 {
		t.Fatalf("regex source strength = %d, want 40", got)
	}
}

func TestSourceMagicStructureDiagnostics(t *testing.T) {
	for _, source := range []string{
		"0 &byte x invalid\n",
		"0 byte x root\n>0 name N\n",
	} {
		t.Run(source, func(t *testing.T) {
			if _, err := OpenDatabase(writeSourceMagic(t, source)); err == nil {
				t.Fatalf("OpenDatabase(%q) succeeded; want source diagnostic", source)
			}
		})
	}
}

func writeSourceMagic(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "magic")
	writeSourceMagicAt(t, path, source)
	return path
}

func writeSourceMagicAt(t *testing.T, path, source string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
}
