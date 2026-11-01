package libmagic

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func testMagicPath(t *testing.T) string {
	t.Helper()
	path := os.Getenv("LIBMAGIC_MGC")
	if path == "" {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("cannot locate test source")
		}
		path = filepath.Join(filepath.Dir(file), "..", "build", "tool", "amd64", "local", "bin", "magic.mgc")
	}
	return path
}

func testDB(t *testing.T) *Database {
	t.Helper()
	path := testMagicPath(t)
	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestRepresentativeFiles(t *testing.T) {
	db := testDB(t)
	fileBin, magic := reference541(t)
	dir := t.TempDir()
	samples := []struct {
		name string
		data []byte
	}{
		{"text.txt", []byte("Hello, this is plain text.\nSecond line.\n")},
		{"empty.bin", nil},
		{"sample.zip", []byte("PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00testPK\x01\x02" + string(make([]byte, 42)) + "\x04\x00\x00\x00testPK\x05\x06" + string(make([]byte, 18)))},
	}
	elf := make([]byte, 64)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	elf[16] = 2
	elf[18] = 62
	elf[20] = 1
	samples = append(samples, struct {
		name string
		data []byte
	}{"sample.elf", elf})

	pe := make([]byte, 128)
	pe[0], pe[1] = 'M', 'Z'
	pe[0x3c] = 0x40
	copy(pe[0x40:], []byte{'P', 'E', 0, 0})
	pe[0x44] = 0x64
	pe[0x45] = 0x86
	samples = append(samples, struct {
		name string
		data []byte
	}{"sample.exe", pe})

	for _, sample := range samples {
		path := filepath.Join(dir, sample.name)
		if err := os.WriteFile(path, sample.data, 0600); err != nil {
			t.Fatal(err)
		}
		wantDesc := file541(t, fileBin, magic, false, path)
		wantMIME := file541(t, fileBin, magic, true, path)
		t.Logf("file 5.41 %s = %q / %q", sample.name, wantDesc, wantMIME)

		got, err := db.File(path)
		if err != nil && len(sample.data) != 0 {
			t.Fatal(sample.name, err)
		}
		if got != wantDesc {
			t.Errorf("File %s = %q, file 5.41 = %q", sample.name, got, wantDesc)
		}
		mime, err := db.FileMIMEType(path)
		if err != nil && len(sample.data) != 0 {
			t.Fatal(err)
		}
		if mime != wantMIME {
			t.Errorf("FileMIMEType %s = %q, file 5.41 = %q", sample.name, mime, wantMIME)
		}
		bgot, err := db.Buffer(sample.data)
		if err != nil {
			t.Fatal(err)
		}
		if bgot != wantDesc {
			t.Errorf("Buffer %s = %q, file 5.41 = %q", sample.name, bgot, wantDesc)
		}
		bmime, err := db.BufferMIMEType(sample.data)
		if err != nil {
			t.Fatal(err)
		}
		wantBufferMIME := wantMIME
		if len(sample.data) == 0 {
			// Buffer has no stat-empty regular file for fsmagic to catch.
			wantBufferMIME = "application/x-empty"
		}
		if bmime != wantBufferMIME {
			t.Errorf("BufferMIMEType %s = %q, want %q", sample.name, bmime, wantBufferMIME)
		}
	}

	missing := filepath.Join(dir, "no-such-file")
	wantMissing := file541(t, fileBin, magic, false, missing)
	got, err := db.File(missing)
	if err != nil {
		t.Fatalf("description handle must report missing paths as text, not errors: %v", err)
	}
	// file 5.41 prints cannot open `path' (No such file or directory).
	// The reference runs under WSL, so its path and strerror differ from the
	// Windows open error. Both must still be the cannot-open result for this path.
	if !strings.HasPrefix(wantMissing, "cannot open `") || !strings.Contains(wantMissing, "No such file or directory") {
		t.Errorf("file 5.41 unreadable = %q", wantMissing)
	}
	if !strings.HasPrefix(got, "cannot open `"+missing+"' (") {
		t.Errorf("unreadable = %q, file 5.41 = %q", got, wantMissing)
	}
	t.Logf("unreadable go=%q", got)
	t.Logf("unreadable file 5.41=%q", wantMissing)
}

func TestTimezoneVersionChar(t *testing.T) {
	_, src, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	sample := filepath.Join("go-libmagic-test-fixture", "usr", "share", "zoneinfo", "Adelaide")
	if _, err := os.Stat(sample); err != nil {
		t.Skip(err)
	}
	root := filepath.Join(filepath.Dir(src), "..", "build", "tool", "arm64", "local", "bin")
	db, err := OpenDatabase(filepath.Join(root, "custom.mgc") + ":" + filepath.Join(root, "magic.mgc"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.File(sample)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "version 2") || strings.Contains(got, "version 50") {
		t.Fatalf("timezone = %q", got)
	}
}

func TestSignedCompare(t *testing.T) {
	db := compileProbe(t, "0 beshort >0x7fff signed-greater\n>0 byte x \\b, next\n0 beshort <0 signed-less\n>0 byte x \\b, next\n0 beshort =0xffd8 signed-equal\n")
	hi, err := db.Buffer([]byte{0xff, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if hi != "signed-less, next" {
		t.Fatalf("high = %q", hi)
	}
	lo, err := db.Buffer([]byte{0x00, 0xff})
	if err != nil {
		t.Fatal(err)
	}
	if lo != "data" {
		t.Fatalf("low = %q", lo)
	}
}

func TestPascalContinuation(t *testing.T) {
	db := compileProbe(t, "0 pstring/B x pascal %s\n>0 byte x \\b, next %d\n")
	got, err := db.Buffer([]byte{3, 'A', 'B', 'C', 'Z'})
	if err != nil {
		t.Fatal(err)
	}
	if got != "pascal ABC, next 3" {
		t.Fatalf("pascal = %q", got)
	}
}

func TestEmbeddedNULContinuation(t *testing.T) {
	db := compileProbe(t, "0 string x got %s\n>0 byte x \\b, next %d\n")
	got, err := db.Buffer([]byte{'A', 0, 'B', 'C'})
	if err != nil {
		t.Fatal(err)
	}
	// Print stops at NUL. WSL file reads the next byte as A (65).
	if got != "got A, next 65" {
		t.Fatalf("nul = %q", got)
	}
}

func TestByteStringHandling(t *testing.T) {
	// C isspace stops at NUL, so the NUL and the tail stay.
	if got := trimString(" \t\x00trail"); got != "\x00trail" {
		t.Fatalf("trim nul = %q", got)
	}
	if got := trimString("\u00a0A\u00a0"); got != "\u00a0A\u00a0" {
		t.Fatalf("trim nbsp = %q", got)
	}
	// 0xFF is one byte. C prints it as \377 and the next signed byte is -1.
	db := compileProbe(t, "0 string x got %s\n>0 byte x \\b, next %d\n")
	got, err := db.Buffer([]byte{0xff, 'Z'})
	if err != nil {
		t.Fatal(err)
	}
	if got != "got \\377Z, next -1" {
		t.Fatalf("byte = %q", got)
	}
}

func TestRegexRawByte(t *testing.T) {
	raw := []byte{0xff, 'A', 'Z'}
	if _, err := regexp.Compile("\xffA"); err == nil {
		t.Fatal("raw pattern accepted 0xFF")
	}
	s := &state{search: search{s: raw, offset: 4}}
	var m entry
	m.reln = '='
	copy(m.value[:], "\xffA")
	if !s.regexMatch(&m) {
		t.Fatal("converted search missed")
	}
	if s.search.offset != 4 || s.search.rmLen != 2 {
		t.Fatalf("span off=%d len=%d", s.search.offset, s.search.rmLen)
	}
	db := compileProbe(t, "0 regex \\377A match %s\n")
	got, err := db.Buffer([]byte{0x01, 'Z', 0xff, 'A', 'X'})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "\\377A") {
		t.Fatalf("regex file = %q", got)
	}
	// regexec stops at the initial NUL; the old fixture incorrectly expected
	// it to find the same raw bytes after that terminator.
	got, err = db.Buffer([]byte{0, 'Z', 0xff, 'A', 'X'})
	if err != nil || got != "data" {
		t.Fatalf("NUL-terminated regex file = %q/%v, want data", got, err)
	}
}

func TestFormatLayout(t *testing.T) {
	spec, width, prec, zero := formatLayout("%-11.96s")
	if spec != 's' || width != 11 || prec != 96 || zero {
		t.Fatalf("layout = %c %d %d %v", spec, width, prec, zero)
	}
	if got := clipPrecision(", %-11.96s", strings.Repeat("a", 100)); len(got) != 96 {
		t.Fatalf("clip len %d %q", len(got), got)
	}
}

func TestReleaseDescriptionFormats(t *testing.T) {
	_, src, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	base := "go-libmagic-test-fixture"
	samples := []struct {
		path string
		want string
	}{
		{`default\easymesh\plugin\poe24000mesh.bin`, "gzip compressed data, last modified: Mon Apr 17 04:55:23 2023, from Unix, original size modulo 2^32 1280000"},
		{`default\easymesh\agentdb.icons.tar`, "POSIX tar archive (GNU)"},
		{`home\httpd\ui\assets\packages\cupertino_icons\assets\CupertinoIcons.ttf`, "TrueType Font data, 12 tables, 1st \"OS/2\", 7 names, Microsoft, language 0x409, Version 1.08FontForge 2.0 : CupertinoIcons : 15-4-2024RegularCupertinoIcons\\001"},
		{`home\httpd\ui\assets\fonts\MyFlutterApp.ttf`, `TrueType Font data, 11 tables, 1st "GSUB", 18 names, Macintosh, Copyright (C) 2026 by original authors @ fluttericon.com, fontello.comMyFlutterAppRegularMyFlutt`},
	}
	var (
		db  *Database
		err error
	)
	for _, sample := range samples {
		path := filepath.Join(base, sample.path)
		if _, err := os.Stat(path); err != nil {
			t.Skip(err)
		}
		if db == nil {
			root := filepath.Join(filepath.Dir(src), "..", "build", "tool", "arm64", "local", "bin")
			db, err = OpenDatabase(filepath.Join(root, "custom.mgc") + ":" + filepath.Join(root, "magic.mgc"))
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := db.File(path)
		if err != nil {
			t.Fatal(sample.path, err)
		}
		if got != sample.want {
			t.Errorf("%s = %q, want %q", sample.path, got, sample.want)
		}
	}
}

func TestOpenCompiledDirectory(t *testing.T) {
	dir := t.TempDir()
	mgc := testMagicPath(t)
	data, err := os.ReadFile(mgc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "magic.mgc"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"),
		[]byte("0 string/t MIXED source\n!:mime text/x-mixed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Buffer([]byte("Hello, this is plain text.\nSecond line.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "ASCII text" {
		t.Fatalf("directory load = %q", got)
	}
	if got, err := db.BufferMIMEType([]byte("MIXED")); err != nil || got != "text/x-mixed" {
		t.Fatalf("mixed source MIME = %q, %v", got, err)
	}
}

func TestOpenReleaseVersion16(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "build", "tool", "arm64", "local", "bin"))
	_, src, _, ok := runtime.Caller(0)
	if ok {
		root = filepath.Join(filepath.Dir(src), "..", "build", "tool", "arm64", "local", "bin")
	}
	custom := filepath.Join(root, "custom.mgc")
	magic := filepath.Join(root, "magic.mgc")
	if _, err := os.Stat(custom); err != nil {
		t.Skip(err)
	}
	db, err := OpenDatabase(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.sets) != 2 {
		t.Fatalf("directory loaded %d databases", len(db.sets))
	}
	listed, err := OpenDatabase(custom + ":" + magic)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.sets) != 2 {
		t.Fatalf("list loaded %d databases", len(listed.sets))
	}
	got, err := db.Buffer([]byte("# CAR archive header"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "SAPCAR archive (legacy version)" {
		t.Fatalf("custom.mgc = %q", got)
	}
	got, err = db.Buffer([]byte("PK\x05\x06" + string(make([]byte, 18))))
	if err != nil {
		t.Fatal(err)
	}
	if got != "Zip archive data (empty)" {
		t.Fatalf("magic.mgc zip = %q", got)
	}
}

// reference541 requires the scanner's FILE5_41 reference, on Linux directly
// or through WSL on Windows. Only unavailable optional references are skipped.
func reference541(t *testing.T) (bin, magic string) {
	t.Helper()
	bin = os.Getenv("LIBMAGIC_FILE")
	if bin == "" {
		bin = "file"
	}
	magic = testMagicPath(t)
	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("wsl"); err != nil {
			t.Skip("WSL reference unavailable:", err)
		}
	}
	cmd := referenceCommand(bin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "file-5.41\n") && !strings.HasPrefix(string(out), "file-5.41\r\n") {
		if os.Getenv("LIBMAGIC_FILE") != "" {
			t.Fatalf("explicit FILE5_41 reference invalid: %v\n%s", err, out)
		}
		t.Skipf("optional FILE5_41 reference unavailable: %v\n%s", err, out)
	}
	return bin, magic
}

func referenceCommand(bin string, args ...string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("wsl", append([]string{"-e", bin}, args...)...)
	}
	return exec.Command(bin, args...)
}

func file541(t *testing.T, bin, magic string, mime bool, target string) string {
	t.Helper()
	args := []string{"-m", wslPath(magic), "-b"}
	if mime {
		args = append(args, "--mime-type")
	}
	args = append(args, wslPath(target))
	cmd := referenceCommand(bin, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimRight(string(bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))), "\n")
	if err != nil {
		t.Fatalf("file 5.41 %s: %v\n%s", target, err, text)
	}
	return text
}

// Compile in the test's own directory; never read somebody's stale /tmp
// probe and never write generated .mgc files to the repository.
func compileProbe(t *testing.T, source string) *Database {
	t.Helper()
	bin, _ := reference541(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.magic")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := referenceCommand(bin, "-C", "-m", wslPath(path))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile FILE5_41 probe: %v\n%s", err, out)
	}
	compiled, err := os.ReadFile(path + ".mgc")
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) < 8 || compiled[4] != 16 || compiled[5] != 0 || compiled[6] != 0 || compiled[7] != 0 {
		t.Fatal("probe compiler did not produce a little-endian v16 database")
	}
	db, err := OpenBytes(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func wslPath(path string) string {
	if len(path) >= 2 && path[1] == ':' {
		drive := strings.ToLower(path[:1])
		rest := strings.ReplaceAll(path[2:], "\\", "/")
		return "/mnt/" + drive + rest
	}
	return strings.ReplaceAll(path, "\\", "/")
}
