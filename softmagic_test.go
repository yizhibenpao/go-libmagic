package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSoftBoundsContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Bounds())
}

func TestSoftNumericContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Numeric())
}

func TestDERContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.DER())
}

func TestFloatFormatsContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.FloatFormats())
}

func TestCalendarTimesContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.CalendarTimes())
}

func TestStringCharactersContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.StringCharacters())
}

func TestIntegerPaddingContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.IntegerPadding())
}

func TestIntegerFormatsContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.IntegerFormats())
}

func TestSoftValueUnionContracts(t *testing.T) {
	testSoftContracts(t, softprobe.ValueUnion())
}

func TestSoftConditionalContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.Conditionals())
}

func TestSoftOffsetContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.Offsets())
}

func TestSoftTailContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.TailViews())
}

func TestSoftUseViewsContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.UseViews())
}

func TestSoftScalarChecksContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.ScalarChecks())
}

func TestSoftOffsetScalarContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.OffsetScalars())
}

func TestSoftSearchContextContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.SearchContexts())
}

func TestSoftIndirectLevelsContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.IndirectLevels())
}

func TestSoftContinuationDepthContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.ContinuationDepths())
}

func TestSoftRuleLineContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.RuleLines())
}

func TestSoftUnsupportedScalarContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.UnsupportedScalars())
}

func TestSoftRegexErrorsContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.RegexErrors())
}

func TestSoftFloatRelationsContracts(t *testing.T) {
	testSoftOffsetContracts(t, softprobe.FloatRelations())
}

func TestSoftPascalErrorContracts(t *testing.T) {
	for _, tc := range softprobe.PascalErrors() {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			patched := 0
			for i := range db.sets {
				for j := range db.sets[i].rules {
					m := &db.sets[i].rules[j]
					if m.mime == "application/x-pascal-target" {
						if m.typ != typePString || m.strFlags != tc.OriginalFlags {
							t.Fatal("unexpected source type or string flags")
						}
						m.strFlags = tc.Flags
						m.numMask = uint64(m.strRange) | uint64(tc.Flags)<<32
						patched++
					}
				}
			}
			if patched != 1 {
				t.Fatal("expected exactly one Pascal record")
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func TestSoftModeContracts(t *testing.T) {
	for _, tc := range softprobe.Modes() {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			patched := 0
			for i := range db.sets {
				for j := range db.sets[i].rules {
					m := &db.sets[i].rules[j]
					if m.desc == "mode-target" {
						if m.typ != tc.OriginalType || m.strFlags != tc.OriginalFlags {
							t.Fatal("unexpected source type or string flags")
						}
						m.typ, m.strFlags = tc.Type, tc.Flags
						m.numMask = uint64(m.strRange) | uint64(tc.Flags)<<32
						patched++
					}
				}
			}
			if patched != 1 {
				t.Fatal("expected exactly one mode record")
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func TestSoftIndirectTypeContracts(t *testing.T) {
	for _, tc := range softprobe.IndirectTypes() {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			patched := 0
			for i := range db.sets {
				for j := range db.sets[i].rules {
					m := &db.sets[i].rules[j]
					if m.desc == "pointer-target" {
						if m.inType != tc.OriginalType {
							t.Fatal("unexpected source indirect type")
						}
						m.inType = tc.Type
						patched++
					}
				}
			}
			if patched != 1 {
				t.Fatal("expected exactly one indirect record")
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func TestSoftDivisionErrorContracts(t *testing.T) {
	for _, tc := range softprobe.DivisionErrors() {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			patched := 0
			for i := range db.sets {
				for j := range db.sets[i].rules {
					m := &db.sets[i].rules[j]
					if m.desc == "conversion-target" {
						if m.typ != tc.Type || m.numMask != 1 {
							t.Fatal("unexpected source type/mask")
						}
						m.numMask = tc.Mask
						if tc.ZeroLine {
							m.lineno = 0
						}
						patched++
					}
				}
			}
			if patched != 1 {
				t.Fatal("expected exactly one conversion record")
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func TestSoftRelationErrorContracts(t *testing.T) {
	for _, tc := range softprobe.RelationErrors() {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			patched := 0
			for i := range db.sets {
				for j := range db.sets[i].rules {
					m := &db.sets[i].rules[j]
					if m.desc == "relation-target" {
						if m.typ != tc.OriginalType || m.reln != tc.OriginalRelation {
							t.Fatal("unexpected source type/relation")
						}
						m.reln = tc.Relation
						if tc.ZeroLine {
							m.lineno = 0
						}
						patched++
					}
				}
			}
			if patched != 1 {
				t.Fatal("expected exactly one relation record")
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func TestSoftTypeErrorContracts(t *testing.T) {
	for _, tc := range softprobe.TypeErrors() {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			patched := 0
			for i := range db.sets {
				for j := range db.sets[i].rules {
					m := &db.sets[i].rules[j]
					if m.desc == "unknown-type" {
						if m.typ != typeByte {
							t.Fatal("unexpected source type")
						}
						m.typ = tc.Type
						if tc.ZeroLine {
							m.lineno = 0
						}
						patched++
					}
				}
			}
			if patched != 1 {
				t.Fatal("expected exactly one type record")
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func TestSoftControlRelationsContracts(t *testing.T) {
	for _, tc := range softprobe.ControlRelations() {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			patched := 0
			for i := range db.sets {
				for j := range db.sets[i].rules {
					m := &db.sets[i].rules[j]
					if m.desc == tc.Marker && (m.typ == typeDefault || m.typ == typeClear) {
						if m.reln != 'x' || m.quad != 0 {
							t.Fatal("unexpected source control relation/value")
						}
						m.reln, m.quad = tc.Relation, tc.Quad
						binary.LittleEndian.PutUint64(m.value[:8], tc.Quad)
						patched++
					}
				}
			}
			if patched != 1 {
				t.Fatal("expected exactly one control record")
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func TestSoftString16FlagsContracts(t *testing.T) {
	for _, tc := range softprobe.String16Flags() {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			patched := 0
			for i := range db.sets {
				for j := range db.sets[i].rules {
					m := &db.sets[i].rules[j]
					if m.desc == "str16=[%s]" && (m.typ == typeBEStr16 || m.typ == typeLEStr16) {
						if m.strFlags != 0 {
							t.Fatal("source unexpectedly compiled nonzero string16 flags")
						}
						m.strFlags = tc.Flags
						patched++
					}
				}
			}
			if patched != 1 {
				t.Fatal("expected exactly one string16 record")
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}

func testSoftOffsetContracts(t *testing.T, cases []softprobe.OffsetCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, fromFile := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if fromFile {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					errText := ""
					if err != nil {
						errText = err.Error()
					}
					if got != want.Value || errText != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", fromFile, mime, got, errText, err != nil, want)
					}
				}
			}
		})
	}
}

func TestSoftIndirectContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Indirect())
}

func TestSoftUseContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Use())
}

func TestSoftIndirectCountsContracts(t *testing.T) {
	testSoftContracts(t, softprobe.IndirectCounts())
}

func TestSoftMoffsetContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Moffset())
}

func TestSoftID3Contracts(t *testing.T) {
	testSoftContracts(t, softprobe.ID3())
}

func TestSoftDefaultClearContracts(t *testing.T) {
	testSoftContracts(t, softprobe.DefaultClear())
}

func TestSoftRegexContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Regex())
}

func TestSoftRegexEscapesContracts(t *testing.T) {
	testSoftContracts(t, softprobe.RegexEscapes())
}

func TestSoftRegexExtensionsContracts(t *testing.T) {
	testSoftContracts(t, softprobe.RegexExtensions())
}

func TestSoftRegexRepeatsContracts(t *testing.T) {
	testSoftContracts(t, softprobe.RegexRepeats())
}

func TestSoftRegexFoldRangesContracts(t *testing.T) {
	testSoftContracts(t, softprobe.RegexFoldRanges())
}

func TestSoftRegexBoundedCapturesContracts(t *testing.T) {
	testSoftContracts(t, softprobe.RegexBoundedCaptures())
}

func TestSoftRegexPruneContracts(t *testing.T) {
	testSoftContracts(t, softprobe.RegexPrune())
}

func TestSoftPascalContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Pascal())
}

func TestSoftPrintableContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Printable())
}

func TestSoftSearchContracts(t *testing.T) {
	testSoftContracts(t, softprobe.Search())
}

func TestSoftSearchFileEOFContract(t *testing.T) {
	// File has zeroed SLOP bytes in FILE5_41 magic.c. The reference's
	// Buffer full-word check can read beyond its declared input length.
	db := compileProbe(t, "0 string/b AB root\n>4 search/2/f A hit=[%s]\n!:mime application/x-search\n")
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, []byte("AB\x00\x01A"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := db.File(path); err != nil || got != "root hit=[A]" {
		t.Errorf("File = %q/%v", got, err)
	}
	if got, err := db.FileMIMEType(path); err != nil || got != "application/x-search" {
		t.Errorf("File MIME = %q/%v", got, err)
	}
}

func softDatabase(t *testing.T, sources []string) *Database {
	t.Helper()
	db := &Database{}
	for _, source := range sources {
		db.sets = append(db.sets, compileProbe(t, source).sets...)
	}
	return db
}

func testSoftContracts(t *testing.T, cases []softprobe.Case) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, fromFile := range []bool{false, true} {
				desc, err := db.Buffer(tc.Data)
				if fromFile {
					desc, err = db.File(path)
				}
				if err != nil || desc != tc.Desc {
					t.Errorf("File %v description = %q/%v, want %q", fromFile, desc, err, tc.Desc)
				}
				mime, err := db.BufferMIMEType(tc.Data)
				if fromFile {
					mime, err = db.FileMIMEType(path)
				}
				if err != nil || mime != tc.MIME {
					t.Errorf("File %v MIME = %q/%v, want %q", fromFile, mime, err, tc.MIME)
				}
			}
		})
	}
}

func TestSoftUseFailures(t *testing.T) {
	testSoftFailures(t, softprobe.UseFailures())
}

func TestSoftIndirectCountFailures(t *testing.T) {
	testSoftFailures(t, softprobe.IndirectCountFailures())
}

func testSoftFailures(t *testing.T, cases []softprobe.Failure) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, fromFile := range []bool{false, true} {
				for _, mime := range []bool{false, true} {
					got, err := db.Buffer(tc.Data)
					want, wantErr := tc.Desc, tc.DescErr
					if fromFile {
						got, err = db.File(path)
					}
					if mime {
						want, wantErr = tc.MIME, tc.MIMEErr
						got, err = db.BufferMIMEType(tc.Data)
						if fromFile {
							got, err = db.FileMIMEType(path)
						}
					}
					gotErr := ""
					if err != nil {
						gotErr = err.Error()
					}
					if got != want || gotErr != wantErr {
						t.Errorf("File %v MIME %v: %q/%q, want %q/%q", fromFile, mime, got, gotErr, want, wantErr)
					}
				}
			}
		})
	}
}

func TestStringExtentAllowsEmptyAtEOF(t *testing.T) {
	for _, typ := range []uint8{typeString, typePString, typeSearch} {
		for _, off := range []int{-1, 0, 2, 3} {
			s := &state{}
			m := entry{typ: typ, reln: 'x'}
			if typ == typePString {
				m.strFlags = pstring1BE
			}
			got := s.copyValue(&m, []byte{0, 0}, off, off)
			if want := off >= 0 && off <= 2; got != want {
				t.Errorf("type %d offset %d: got %v, want %v", typ, off, got, want)
			}
		}
	}
}

func TestMoffsetWithoutReference(t *testing.T) {
	s := &state{offset: 2}
	for _, typ := range []uint8{typeQWDate, typeLEQWDate, typeBEQWDate, typeQDate, typeLEQDate, typeBEQDate} {
		want := 10
		if typ == typeQWDate || typ == typeLEQWDate || typ == typeBEQWDate {
			want = 0
		}
		if got, ok := s.moffset(&entry{typ: typ}, 12); !ok || got != want {
			t.Errorf("type %d: offset %d/%v, want %d/true", typ, got, ok, want)
		}
	}
	for _, off := range []int{-7, 11, 12} {
		s.offset = off
		if got, ok := s.moffset(&entry{typ: typeByte}, 12); ok != (off == 11) || ok && got != 12 {
			t.Errorf("byte offset %d: %d/%v", off, got, ok)
		}
	}
	first := entry{flag: flagBinTest, typ: typeString, reln: '!', offset: 10, vallen: 2, desc: "first"}
	second := entry{flag: flagBinTest, typ: typeString, reln: '=', vallen: 2, desc: "second", mime: "application/x-second"}
	copy(first.value[:], "AB")
	copy(second.value[:], "AB")
	skipped := entry{contLevel: 1, typ: typeByte, reln: 'x', desc: "skipped"}
	db := &Database{sets: []magicSet{{rules: []entry{first, skipped, second}, n0: 3}}}
	data := []byte("AB\x00\x01")
	if got, err := db.Buffer(data); err != nil || got != "firstsecond" {
		t.Errorf("failed top offset: %q/%v", got, err)
	}
	if got, err := db.BufferMIMEType(data); err != nil || got != "application/x-second" {
		t.Errorf("failed top offset MIME: %q/%v", got, err)
	}
}

func TestID3OffsetWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeBEID3, typeLEID3} {
		var order binary.ByteOrder = binary.BigEndian
		if typ == typeLEID3 {
			order = binary.LittleEndian
		}
		if got := flippedType(typ, true); got != typ {
			t.Errorf("ID3 type %d flipped to %d", typ, got)
		}
		for _, raw := range []uint32{0x100, 0x80808180} {
			data := make([]byte, 600)
			order.PutUint32(data[4:], raw)
			order.PutUint32(data[8:], 0x100)
			for _, flip := range []bool{false, true} {
				s := &state{flip: flip}
				for _, indirectRHS := range []bool{false, true} {
					m := &entry{inType: typ, inOp: opSigned}
					want := 128
					if indirectRHS {
						m.inOffset, m.inOp = 4, opSigned|opAdd|opIndirect
						want = 384
					}
					s.copyRaw(m.typ, data, 4, true)
					got, ok := s.readIndirect(m, data, 4, 0)
					if !ok || got != want {
						t.Errorf("type %d raw %#x flip %v RHS %v: %d/%v, want %d", typ, raw, flip, indirectRHS, got, ok, want)
					}
				}
			}
		}
	}
	if flippedType(typeBELong, true) != typeLELong || flippedType(typeLELong, true) != typeBELong {
		t.Fatal("ordinary long types no longer flip")
	}
}

func TestDefaultClearLiteralWithoutReference(t *testing.T) {
	for _, typ := range []uint8{typeDefault, typeClear} {
		for _, desc := range []string{softprobe.LiteralPercentDescription, "${x?yes:no}", "${x?yes:\\bno}"} {
			for _, flag := range []uint16{0, flagNoSpace} {
				for _, executable := range []string{"0", "1"} {
					s := &state{buf: &strings.Builder{}, elfFlag: executable, value: value{u64: 42}}
					s.buf.WriteString("root")
					s.print(&entry{typ: typ, desc: desc, flag: flag}, true)
					want := "root"
					if flag == 0 {
						want += " "
					}
					want += desc
					if got := s.buf.String(); got != want {
						t.Errorf("type %d flag %d executable %s: %q, want %q", typ, flag, executable, got, want)
					}
				}
			}
		}
	}
}

// These entries mirror the compiled description/cross-library probes without
// requiring a compiler or native reference.
func TestIndirectWithoutReference(t *testing.T) {
	root := entry{flag: flagBinTest, typ: typeString, reln: '=', vallen: 2, desc: "root"}
	copy(root.value[:], "AB")
	indirect := entry{contLevel: 1, typ: typeIndirect, reln: 'x', offset: 4, desc: "off=%u:"}
	child := entry{flag: flagBinTest, typ: typeString, reln: '=', vallen: 2, desc: "child", mime: "application/x-child"}
	copy(child.value[:], "CD")
	for _, separate := range []bool{false, true} {
		db := &Database{sets: []magicSet{{rules: []entry{root, indirect, child}, n0: 3}}}
		if separate {
			db.sets = []magicSet{{rules: []entry{root, indirect}, n0: 2}, {rules: []entry{child}, n0: 1}}
		}
		data := []byte("AB\x00\x01CD\x00\x01")
		if got, err := db.Buffer(data); err != nil || got != "rootoff=4:child " {
			t.Errorf("separate %v: description %q/%v", separate, got, err)
		}
		if got, err := db.BufferMIMEType(data); err != nil || got != "application/x-child" {
			t.Errorf("separate %v: MIME %q/%v", separate, got, err)
		}
		if got, _ := db.Trace(data); got != "rootoff=4:child " {
			t.Errorf("separate %v: trace description %q", separate, got)
		}
	}
}

func TestIndirectCounterWithoutReference(t *testing.T) {
	root := entry{flag: flagBinTest, typ: typeString, reln: '=', vallen: 2, desc: "root"}
	copy(root.value[:], "AB")
	step := entry{contLevel: 1, typ: typeIndirect, reln: 'x', offset: 4, desc: "X"}
	leaf := entry{flag: flagBinTest, typ: typeString, reln: '=', vallen: 2, desc: "child", mime: "application/x-child"}
	copy(leaf.value[:], "CD")
	data := []byte("AB\x00\x01CD\x00\x01")
	for _, count := range []int{49, 50} {
		rules := []entry{root}
		for i := 0; i < count; i++ {
			rules = append(rules, step)
		}
		db := &Database{sets: []magicSet{{rules: append(rules, leaf), n0: len(rules) + 1}}}
		// Reusing a Database must not carry a previous request's counter.
		for request := 0; request < 2; request++ {
			for _, mime := range []bool{false, true} {
				got, err := db.Buffer(data)
				want := "root" + strings.Repeat("Xchild ", count)
				if mime {
					got, err = db.BufferMIMEType(data)
					want = strings.Repeat("application/x-child", count)
				}
				if count == 50 {
					if got != "" || err == nil || err.Error() != "indirect count (50) exceeded" {
						t.Errorf("request %d MIME %v: %q/%v, want indirect limit error", request, mime, got, err)
					}
				} else if err != nil || got != want {
					t.Errorf("request %d MIME %v: %q/%v, want %q", request, mime, got, err, want)
				}
			}
		}
	}
}

func TestUseWithoutReference(t *testing.T) {
	root := entry{flag: flagBinTest, typ: typeString, reln: '=', vallen: 2, desc: "root"}
	copy(root.value[:], "AB")
	use := entry{contLevel: 1, typ: typeUse, reln: '='}
	copy(use.value[:], "N")
	name := entry{typ: typeName, reln: '='}
	copy(name.value[:], "N")
	child := root
	child.contLevel, child.desc, child.mime = 1, "child", "application/x-child"
	data := []byte("AB\x00\x01")
	for _, nospace := range []bool{false, true} {
		want := "root child"
		if nospace {
			use.flag = flagNoSpace
			want = "rootchild"
		}
		db := &Database{sets: []magicSet{{rules: []entry{root, use}, n0: 2}, {rules: []entry{name, child}, names: map[string]int{"N": 0}}}}
		if got, err := db.Buffer(data); err != nil || got != want {
			t.Errorf("NOSPACE %v: %q/%v, want %q", nospace, got, err, want)
		}
		if got, err := db.BufferMIMEType(data); err != nil || got != "application/x-child" {
			t.Errorf("NOSPACE %v: MIME %q/%v", nospace, got, err)
		}
		if got, _ := db.Trace(data); got != want {
			t.Errorf("NOSPACE %v: trace %q, want %q", nospace, got, want)
		}
	}
	for _, recursive := range []bool{false, true} {
		db := &Database{sets: []magicSet{{rules: []entry{root, use}, n0: 2}}}
		want := "root cannot find entry `N'"
		if recursive {
			db.sets = append(db.sets, magicSet{rules: []entry{name, use}, names: map[string]int{"N": 0}})
			want = "root name use count (50) exceeded"
		}
		if got, err := db.Buffer(data); got != "" || err == nil || err.Error() != want {
			t.Errorf("recursive %v: %q/%v, want empty/%q", recursive, got, err, want)
		}
	}
}

func TestMatchLevelResetKeepsOffset(t *testing.T) {
	s := &state{levels: []level{{off: 13, gotMatch: true, lastMatch: true}}}
	s.checkLevel(0)
	if got := s.levels[0]; got.off != 13 || got.gotMatch || got.lastMatch {
		t.Fatalf("level flags/offset after reset = %+v", got)
	}
	s.checkLevel(3)
	if len(s.levels) != 4 || s.levels[0].off != 13 {
		t.Fatal("new level reset changed another level")
	}
}

func TestFormatCheckContracts(t *testing.T) {
	testFormatCheckContracts(t, softprobe.FormatChecks())
}

func TestFormatFlagsContracts(t *testing.T) {
	testFormatCheckContracts(t, softprobe.FormatFlags())
}

func testFormatCheckContracts(t *testing.T, cases []softprobe.FormatCheckCase) {
	if os.Getenv("LIBMAGIC_TEST_FORMAT_CHECK") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
		cmd.Env = append(os.Environ(), "LIBMAGIC_TEST_FORMAT_CHECK=1", "TZ=UTC")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if testing.Verbose() {
			t.Logf("%s", out)
		}
		return
	}
	// Isolated test process only. Windows does not read Unix TZ for time.Local.
	time.Local = time.UTC
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			db := softDatabase(t, tc.Sources)
			if tc.Patched {
				patched := 0
				for i := range db.sets {
					for j := range db.sets[i].rules {
						m := &db.sets[i].rules[j]
						if m.desc == "fmtcheck-target" {
							if m.typ != tc.OriginalType {
								t.Fatal("unexpected source type")
							}
							m.desc = "value=[" + tc.Format + "]"
							if tc.ZeroLine {
								m.lineno = 0
							}
							patched++
						}
					}
				}
				if patched != 1 {
					t.Fatal("expected exactly one description field")
				}
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, tc.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := tc.Buffer[mime]
					got, err := db.Buffer(tc.Data)
					if mime == 1 {
						got, err = db.BufferMIMEType(tc.Data)
					}
					if file {
						want = tc.File[mime]
						got, err = db.File(path)
						if mime == 1 {
							got, err = db.FileMIMEType(path)
						}
					}
					text := ""
					if err != nil {
						text = err.Error()
					}
					if got != want.Value || text != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%q/failed=%v, want %+v", file, mime, got, text, err != nil, want)
					}
				}
			}
		})
	}
}
