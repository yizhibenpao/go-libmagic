package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/cdfsample"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCDFStructureAndProperties(t *testing.T) {
	const base = "Composite Document File V2 Document"
	const summary = base + ", Little Endian, Os: Windows, Version 6.10"
	const properties = ", Code page: 1252, Title: A test document, Name of Creating Application: Microsoft Word"
	cases := cdfsample.Cases()
	wants := map[string][2]string{
		"summary-long":         {summary + properties, "application/msword"},
		"summary-mini":         {summary + properties, "application/msword"},
		"summary-v4":           {summary + properties, "application/msword"},
		"summary-difat":        {summary + properties, "application/msword"},
		"msi-clsid":            {summary + ", MSI Installer" + properties, "application/x-msi"},
		"ignored-version":      {summary + properties, "application/msword"},
		"ignored-byteorder":    {summary + properties, "application/msword"},
		"bad-sat":              {base + ", Can't read SAT", "application/CDFV2"},
		"bad-ssat":             {base + ", Can't read SSAT", "application/CDFV2"},
		"bad-directory":        {base + ", Can't read directory", "application/CDFV2"},
		"bad-root-stream":      {base + ", Cannot read short stream", "application/CDFV2"},
		"decoy-word":           {base + ", Cannot read section info", "application/CDFV2"},
		"section-priority":     {"CDFV2 Encrypted", "application/encrypted"},
		"section-WordDocument": {"CDFV2 Microsoft Word", "application/msword"},
		"hwp":                  {"Hangul (Korean) Word Processor File 5.x", "application/x-hwp"},
	}
	for name, want := range wants {
		t.Run(name, func(t *testing.T) {
			for i, mime := range []bool{false, true} {
				got, ok := cdfDescription(cases[name], nil, mime)
				if !ok || got != want[i] {
					t.Errorf("mime=%v = %q/%v, want %q", mime, got, ok, want[i])
				}
			}
		})
	}
	for _, name := range []string{"header-truncated", "header-shift-too-big"} {
		if _, ok := cdfDescription(cases[name], nil, false); ok {
			t.Errorf("%s must fall through to softmagic", name)
		}
	}
}

func TestCDFReadBeyondPrefix(t *testing.T) {
	data := cdfsample.Cases()["summary-far"]
	prefix := data[:fileBytesMax]
	want, _ := cdfDescription(data, nil, false)
	got, ok := cdfDescription(prefix, bytes.NewReader(data), false)
	if !ok || got != want {
		t.Fatalf("ReaderAt = %q/%v, want %q", got, ok, want)
	}
	got, ok = cdfDescription(prefix, nil, false)
	if !ok || got != "Composite Document File V2 Document, Can't read SAT" {
		t.Fatalf("prefix-only buffer = %q/%v", got, ok)
	}
	db := testDB(t)
	path := filepath.Join(t.TempDir(), "far.cdf")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := db.File(path); err != nil || got != want {
		t.Errorf("File = %q/%v, want %q", got, err, want)
	}
}

func TestCDFTime541(t *testing.T) {
	if got := cdfTime(0x01A5E403C2D59C00); got != "Sun Apr 24 01:30:00 1977" {
		t.Errorf("libmagic 5.41 observed timestamp = %q", got)
	}
	if got := cdfTime(900610000000); got != "1d+01:01:01" {
		t.Errorf("elapsed = %q", got)
	}
}

func FuzzCDF(f *testing.F) {
	for _, data := range cdfsample.Cases() {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cdfDescription(data, nil, false)
		cdfDescription(data, nil, true)
	})
}
