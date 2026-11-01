/*
 * Copyright (c) Ian F. Darwin 1986-1995.
 * Software written by Ian F. Darwin and others;
 * maintained 1995-present by Christos Zoulas and others.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
// Package libmagic identifies file contents the way file 5.48 does.
//
// The matching behavior is translated from upstream file tag FILE5_48
// (https://github.com/file/file, commit eb754ace19fed5481d8142426543100a2d6bae4e).
// Databases are the compiled magic files produced by that release
// (magic number 0xF11E041C, version 21). Identification stays in Go.
package libmagic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	magicNo      = 0xF11E041C
	versionNo548 = 21
	entrySize548 = 432
	versionNo541 = 16
	entrySize541 = 376
	magicSets    = 2

	maxString = 128
	maxDesc   = 64
	maxMIME   = 80

	fileBytesMax = 1024 * 1024
	indirMax     = 50
	nameMax      = 50

	flagIndir       = 0x01
	flagOffAdd      = 0x02
	flagIndirOffAdd = 0x04
	flagUnsigned    = 0x08
	flagNoSpace     = 0x10
	flagBinTest     = 0x20
	flagTextTest    = 0x40
	flagOffNegative = 0x80
	flagOffPositive = 0x100

	stringCompactWhitespace         = 1 << 0
	stringCompactOptionalWhitespace = 1 << 1
	stringIgnoreLower               = 1 << 2
	stringIgnoreUpper               = 1 << 3
	regexOffsetStart                = 1 << 4
	stringTextTest                  = 1 << 5
	stringBinTest                   = 1 << 6
	pstring1BE                      = 1 << 7
	pstring2BE                      = 1 << 8
	pstring2LE                      = 1 << 9
	pstring4BE                      = 1 << 10
	pstring4LE                      = 1 << 11
	pstringLenIncludesItself        = 1 << 12
	stringTrim                      = 1 << 13
	stringFullWord                  = 1 << 14
	indirectRelative                = 1 << 0

	pstringLen = pstring1BE | pstring2BE | pstring2LE | pstring4BE | pstring4LE
	regexMax   = 8192

	opAnd = 0
	opOr  = 1
	opXor = 2
	opAdd = 3
	opSub = 4
	opMul = 5
	opDiv = 6
	opMod = 7

	opSigned   = 0x20
	opInverse  = 0x40
	opIndirect = 0x80
	opsMask    = 0x07
	condNone   = 0
	condIf     = 1
	condElif   = 2
	condElse   = 3

	typeInvalid     = 0
	typeByte        = 1
	typeShort       = 2
	typeDefault     = 3
	typeLong        = 4
	typeString      = 5
	typeDate        = 6
	typeBEShort     = 7
	typeBELong      = 8
	typeBEDate      = 9
	typeLEShort     = 10
	typeLELong      = 11
	typeLEDate      = 12
	typePString     = 13
	typeLDate       = 14
	typeBELDate     = 15
	typeLELDate     = 16
	typeRegex       = 17
	typeBEStr16     = 18
	typeLEStr16     = 19
	typeSearch      = 20
	typeMEDate      = 21
	typeMELDate     = 22
	typeMELong      = 23
	typeQuad        = 24
	typeLEQuad      = 25
	typeBEQuad      = 26
	typeQDate       = 27
	typeLEQDate     = 28
	typeBEQDate     = 29
	typeQLDate      = 30
	typeLEQLDate    = 31
	typeBEQLDate    = 32
	typeFloat       = 33
	typeBEFloat     = 34
	typeLEFloat     = 35
	typeDouble      = 36
	typeBEDouble    = 37
	typeLEDouble    = 38
	typeBEID3       = 39
	typeLEID3       = 40
	typeIndirect    = 41
	typeQWDate      = 42
	typeLEQWDate    = 43
	typeBEQWDate    = 44
	typeName        = 45
	typeUse         = 46
	typeClear       = 47
	typeDER         = 48
	typeGUID        = 49
	typeOffset      = 50
	typeBEVarint    = 51
	typeLEVarint    = 52
	typeMSDOSDate   = 55
	typeLEMSDOSDate = 56
	typeBEMSDOSDate = 57
	typeMSDOSTime   = 58
	typeLEMSDOSTime = 59
	typeBEMSDOSTime = 60
	typeOctal       = 61
)

// Database is one or more loaded magic databases.
// A file 5.48 database uses version 21. A file 5.41 release database uses version 16.
type Database struct {
	sets []magicSet
}

type magicSet struct {
	rules []entry
	n0    int
	names map[string]int
}

type entry struct {
	flag      uint16
	version16 bool
	contLevel uint16
	reln      byte
	vallen    uint8
	typ       uint8
	inType    uint8
	inOp      uint8
	maskOp    uint8
	cond      uint8
	offset    int32
	inOffset  int32
	lineno    uint32
	numMask   uint64
	strRange  uint32
	strFlags  uint32
	value     [maxString]byte
	quad      uint64
	guid      [16]byte
	desc      string
	mime      string
	re        *magicRegex
}

// OpenDatabase reads one compiled .mgc file or a source magic file. A directory
// loads all of its visible regular compiled and source magic files.
// Like FILE5_41 apprentice.c, a Linux colon list ends at its first empty
// component, tries each preceding path, and succeeds if any database loads.
// A non-directory path without the ".mgc" suffix resolves to path + ".mgc".
func OpenDatabase(path string) (*Database, error) {
	return openDatabasePath(cStringPath(path))
}

func openDatabasePath(path string) (*Database, error) {
	db := &Database{}
	var firstError error
	for _, part := range splitMagicPath(path) {
		info, statErr := os.Stat(part)
		err := statErr
		var one *Database
		if err == nil && info.IsDir() {
			one, err = openDir(part)
		} else {
			name := part
			if runtime.GOOS != "windows" && len(name) < len(".mgc") && strings.HasSuffix(".mgc", name) {
				// FILE5_41 mkdbname treats a bare partial suffix
				// ("c", "gc", "mgc") as the name ".mgc".
				name = ".mgc"
			} else if !strings.HasSuffix(name, ".mgc") {
				name += ".mgc"
			}
			one, err = openCompiledDatabase(name)
			if (one == nil || err != nil) && statErr == nil && info.Mode().IsRegular() &&
				!strings.EqualFold(filepath.Ext(part), ".mgc") {
				candidate, sourceErr := sourceMagicCandidate(part)
				if sourceErr != nil {
					one, err = nil, sourceErr
				} else if candidate {
					one, err = openSourceDatabase(part)
				} else {
					one, err = nil, nil
				}
			}
			if err != nil && firstError == nil {
				firstError = err
			}
		}
		if err != nil {
			continue
		}
		if one == nil {
			continue
		}
		db.sets = append(db.sets, one.sets...)
	}
	if len(db.sets) == 0 {
		if firstError != nil {
			return nil, firstError
		}
		return nil, errors.New("could not find any valid magic files!")
	}
	return db, nil
}

func openCompiledDatabase(name string) (*Database, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, compiledDatabaseOpenError(name, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat `%s' (%s)", name, systemError(err))
	}
	if info.Size() < 8 {
		return nil, fmt.Errorf("file `%s' is too small", name)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading (%s)", systemError(err))
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("error reading")
	}

	set, err := decodeDatabaseFile(data, name)
	if err != nil {
		return nil, err
	}
	return &Database{sets: []magicSet{set}}, nil
}

func compiledDatabaseOpenError(name string, err error) error {
	if os.IsNotExist(err) {
		// FILE5_41 treats an unavailable compiled path as a candidate
		// that can be skipped in a colon list. A later valid path may
		// still load.
		return nil
	}
	return fmt.Errorf("cannot read magic file `%s' (%s)", name, systemError(err))
}

func openDefaultDatabase() (*Database, error) {
	return openDatabasePath(defaultMagicPath())
}

func defaultMagicPath() string {
	if magic, ok := os.LookupEnv("MAGIC"); ok {
		return cStringPath(magic)
	}
	if runtime.GOOS == "windows" {
		return "magic.mgc"
	}
	const systemMagic = "/etc/magic"
	home, ok := os.LookupEnv("HOME")
	if !ok {
		return systemMagic
	}
	homeCompiled := home + "/.magic.mgc"
	if _, err := os.Stat(homeCompiled); err == nil {
		return homeCompiled + ":" + systemMagic
	}
	homeMagic := home + "/.magic"
	if info, err := os.Stat(homeMagic); err == nil {
		if info.IsDir() {
			nested := homeMagic + "/magic.mgc"
			f, err := os.Open(nested)
			if err != nil {
				return systemMagic
			}
			_ = f.Close()
			return nested + ":" + systemMagic
		}
		return homeMagic + ":" + systemMagic
	}
	return systemMagic
}

// splitMagicPath splits the colon list used by the scanner on Linux.
// Only the Go Windows compatibility path preserves drive letters.
func splitMagicPath(path string) []string {
	if runtime.GOOS != "windows" {
		parts := strings.Split(path, ":")
		for i, part := range parts {
			if part == "" {
				return parts[:i]
			}
		}
		return parts
	}
	if len(path) < 2 || !isDrive(path[0]) || path[1] != ':' {
		var out []string
		for _, part := range strings.Split(path, ":") {
			if part != "" {
				out = append(out, part)
			}
		}
		if len(out) == 0 {
			return []string{path}
		}
		return out
	}
	parts := strings.Split(path, ":")
	if len(parts) == 1 {
		return parts
	}
	var out []string
	for i := 0; i < len(parts); i++ {
		if len(parts[i]) == 1 && isDrive(parts[i][0]) && i+1 < len(parts) {
			out = append(out, parts[i]+":"+parts[i+1])
			i++
			continue
		}
		if parts[i] != "" {
			out = append(out, parts[i])
		}
	}
	if len(out) == 0 {
		return []string{path}
	}
	return out
}

func isDrive(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func openDir(path string) (*Database, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var names []string
	hasCompiled := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		full := filepath.Join(path, entry.Name())
		info, err := os.Stat(full)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		names = append(names, entry.Name())
		if strings.EqualFold(filepath.Ext(entry.Name()), ".mgc") {
			hasCompiled = true
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("libmagic: no magic files in %s", path)
	}
	db := &Database{}
	var compiledNames, sourceNames []string
	for _, name := range names {
		if strings.EqualFold(filepath.Ext(name), ".mgc") {
			compiledNames = append(compiledNames, name)
		} else {
			sourceNames = append(sourceNames, name)
		}
	}

	for _, name := range compiledNames {
		one, err := openCompiledDatabase(filepath.Join(path, name))
		if err != nil {
			return nil, fmt.Errorf("libmagic: %s: %w", name, err)
		}
		db.sets = append(db.sets, one.sets...)
	}
	if len(sourceNames) != 0 {
		paths := make([]string, 0, len(sourceNames))
		for _, name := range sourceNames {
			paths = append(paths, filepath.Join(path, name))
		}
		set, loaded, err := openSourceDirectory(paths, hasCompiled)
		if err != nil {
			return nil, err
		}
		if loaded {
			db.sets = append(db.sets, set)
		}
	}
	if len(db.sets) == 0 {
		return nil, errors.New("could not find any valid magic files!")
	}
	return db, nil
}

// OpenBytes reads one compiled magic database from memory.
// Version 21 is the file 5.48 layout. Version 16 is the file 5.41 release layout.
func OpenBytes(data []byte) (*Database, error) {
	set, err := decodeDatabase(data)
	if err != nil {
		return nil, err
	}
	return &Database{sets: []magicSet{set}}, nil
}

func decodeDatabase(data []byte) (magicSet, error) {
	return decodeDatabaseNamed(data, "buffer", true)
}

func decodeDatabaseFile(data []byte, name string) (magicSet, error) {
	return decodeDatabaseNamed(data, name, false)
}

func decodeDatabaseNamed(data []byte, name string, buffer bool) (magicSet, error) {
	prefix := ""
	if buffer {
		prefix = "libmagic: "
	}
	if len(data) < 16 {
		if !buffer {
			return magicSet{}, fmt.Errorf("file `%s' is too small", name)
		}
		return magicSet{}, fmt.Errorf("libmagic: database is too short")
	}
	if binary.LittleEndian.Uint32(data[0:4]) != magicNo {
		return magicSet{}, fmt.Errorf("%sbad magic in `%s'", prefix, name)
	}
	version := binary.LittleEndian.Uint32(data[4:8])
	width, flagFirst, err := entryLayout(version)
	if err != nil {
		return magicSet{}, fmt.Errorf("%sFile 5.41 supports only version 16 magic files. `%s' is version %d", prefix, name, version)
	}
	if len(data)%width != 0 {
		return magicSet{}, fmt.Errorf("%sSize of `%s' %d is not a multiple of %d", prefix, name, len(data), width)
	}
	n0 := int(binary.LittleEndian.Uint32(data[8:12]))
	n1 := int(binary.LittleEndian.Uint32(data[12:16]))
	if n0 < 0 || n1 < 0 || n0+n1+1 != len(data)/width {
		return magicSet{}, fmt.Errorf("%sInconsistent entries in `%s' %d != %d", prefix, name, len(data)/width, n0+n1+1)
	}
	set := magicSet{rules: make([]entry, n0+n1), n0: n0, names: map[string]int{}}
	for i := 0; i < n0+n1; i++ {
		set.rules[i] = decodeEntry(data[(i+1)*width:(i+2)*width], flagFirst)
		if set.rules[i].typ == typeRegex {
			set.rules[i].re = compileRule(&set.rules[i])
		}
		if i >= n0 && set.rules[i].typ == typeName {
			name := cString(set.rules[i].value[:])
			if _, ok := set.names[name]; !ok {
				set.names[name] = i
			}
		}
	}
	return set, nil
}

func entryLayout(version uint32) (width int, flagFirst bool, err error) {
	switch version {
	case versionNo548:
		return entrySize548, true, nil
	case versionNo541:
		return entrySize541, false, nil
	default:
		return 0, false, fmt.Errorf("libmagic: database version %d, want %d or %d", version, versionNo541, versionNo548)
	}
}

func decodeEntry(b []byte, flagFirst bool) entry {
	e := entry{version16: !flagFirst}
	if flagFirst {
		e.flag = binary.LittleEndian.Uint16(b[0:2])
		e.contLevel = uint16(b[2])
	} else {
		e.contLevel = binary.LittleEndian.Uint16(b[0:2])
		e.flag = uint16(b[2])
	}
	e.reln = b[4]
	e.vallen = b[5]
	e.typ = b[6]
	e.inType = b[7]
	e.inOp = b[8]
	e.maskOp = b[9]
	e.cond = b[10]
	e.offset = int32(binary.LittleEndian.Uint32(b[12:16]))
	e.inOffset = int32(binary.LittleEndian.Uint32(b[16:20]))
	e.lineno = binary.LittleEndian.Uint32(b[20:24])
	e.numMask = binary.LittleEndian.Uint64(b[24:32])
	e.strRange = binary.LittleEndian.Uint32(b[24:28])
	e.strFlags = binary.LittleEndian.Uint32(b[28:32])
	copy(e.value[:], b[32:32+maxString])
	e.quad = binary.LittleEndian.Uint64(b[32:40])
	copy(e.guid[:], b[32:48])
	e.desc = cString(b[160 : 160+maxDesc])
	if len(b) >= 224+maxMIME {
		e.mime = cString(b[224 : 224+maxMIME])
	}
	return e
}

func cString(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		i = len(b)
	}
	return string(b[:i])
}

// cLen is strlen. Go's len counts bytes after an embedded NUL; C stops.
func cLen(s string) int {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return i
	}
	return len(s)
}

func cStringPath(path string) string {
	return path[:cLen(path)]
}

// File returns the textual description of path, matching file -b.
func (db *Database) File(path string) (string, error) {
	return magicResult(db.identify(cStringPath(path), nil, false, true))
}

// FileMIMEType returns the MIME type of path, matching file -b --mime-type.
func (db *Database) FileMIMEType(path string) (string, error) {
	return magicResult(db.identify(cStringPath(path), nil, true, true))
}

// Buffer returns the textual description of data, matching file -b.
func (db *Database) Buffer(data []byte) (string, error) {
	return magicResult(db.identify("", data, false, false))
}

// BufferMIMEType returns the MIME type of data, matching file -b --mime-type.
func (db *Database) BufferMIMEType(data []byte) (string, error) {
	return magicResult(db.identify("", data, true, false))
}

func (db *Database) identify(path string, data []byte, mime, fromFile bool) (string, error) {
	prefix := ""
	execute := false
	var reader io.ReaderAt
	var sourceSize int64
	sourceRegular := false
	var statErr error
	if fromFile {
		probe, special, err := probePath(path, mime)
		if err != nil {
			return special, err
		}
		if special != "" {
			return special, nil
		}
		prefix = probe.prefix
		f, err := openForMagic(probe.path)
		if err != nil {
			// FILE5_41 magic.c reports unreadable_info even in MIME mode
			// when open fails but stat succeeds; this is not MAGIC_ERROR.
			if info, statErr := os.Stat(path); statErr == nil {
				return withPrefix(prefix, unreadableDescription(path, info)), nil
			}
			return withPrefix(prefix, ""), nil
		}
		defer f.Close()
		reader = f
		var info os.FileInfo
		data, info, err, statErr = readMagicFileState(f)
		if err != nil && len(data) == 0 {
			return "", fmt.Errorf("cannot read `%s' (%s)", path, systemError(err))
		}
		if info != nil {
			sourceSize = info.Size()
			execute = info.Mode().Perm()&0111 != 0
			sourceRegular = info.Mode().IsRegular()
		}
		if elfPrefix(data) && sourceSize == 0 {
			// FILE5_41 file_tryelf performs its own fstat when the
			// buffer snapshot has a zero size, including after a
			// successful initial stat.
			info, statErr = f.Stat()
			if statErr != nil {
				sourceSize, execute, sourceRegular = 0, false, false
			} else {
				sourceSize = info.Size()
				execute = info.Mode().Perm()&0111 != 0
				sourceRegular = info.Mode().IsRegular()
			}
		}
	}
	result, err := db.identifyBufferStat(data, mime, prefix, reader, sourceSize, execute, sourceRegular, statErr)
	if err != nil {
		return result, err
	}
	if !mime {
		result = withPrefix(prefix, result)
	}
	return result, nil
}

func elfPrefix(data []byte) bool {
	return len(data) > 5 && data[0] == 0x7f &&
		(data[1] == 'E' || data[1] == 'O') && data[2] == 'L' && data[3] == 'F'
}

func (db *Database) identifyBuffer(data []byte, mime bool, prefix string, reader io.ReaderAt, sourceSize int64, execute, sourceRegular bool) (string, error) {
	return db.identifyBufferStat(data, mime, prefix, reader, sourceSize, execute, sourceRegular, nil)
}

func (db *Database) identifyBufferStat(data []byte, mime bool, prefix string, reader io.ReaderAt, sourceSize int64, execute, sourceRegular bool, statErr error) (string, error) {
	if len(data) == 0 {
		if mime {
			// fsmagic already handled a stat-empty regular file. An
			// empty buffer (or an empty read) uses file_default instead.
			return "application/x-empty", nil
		}
		return "empty", nil
	}
	if len(data) == 1 {
		if mime {
			return "application/octet-stream", nil
		}
		return "very short file (no magic)", nil
	}
	encoding := detectEncoding(data)
	text := encoding.text
	if !mime {
		if desc, ok := tarDescription(data); ok {
			return desc, nil
		}
	} else if tarMIME(data) {
		return "application/x-tar", nil
	}
	if desc, ok := jsonDescription(data); ok {
		if mime {
			return "application/json", nil
		}
		return desc, nil
	}
	if desc, ok := csvDescription(data, text); ok {
		if mime {
			return "text/csv", nil
		}
		return desc, nil
	}
	if result, ok := cdfDescription(data, reader, mime); ok {
		return result, nil
	}
	elfSize := sourceSize
	if elfSize == 0 && !sourceRegular {
		// file_tryelf uses SIZE_UNKNOWN for a non-regular descriptor whose
		// stat size is zero. A regular ELF with a zero stat is handled by
		// the native fstat retry before this point.
		elfSize = elfSizeUnknown
	}
	elf, execute, elfErr := elfSupplementStatus(data, reader, elfSize, mime, execute, statErr)
	if elfErr != nil {
		// FILE5_41 keeps the ELF error pending, then still runs softmagic
		// and text checks before returning the first error. The later
		// descriptions are not exposed when that error wins.
		elf = ""
	}
	finish := func(result string, err error) (string, error) {
		if elfErr != nil {
			return "", elfErr
		}
		return result, err
	}
	elfFlag := "0"
	if execute {
		elfFlag = "1"
	}
	end := &tail{reader: reader, size: sourceSize, regular: sourceRegular}
	indir := 0
	previous := value{}
	previousSearch := search{}
	var previousLine uint32
	for i := range db.sets {
		st := &state{db: db, set: &db.sets[i], value: previous, search: previousSearch, line: previousLine, mime: mime, text: text, buf: &strings.Builder{}, tail: end, elfFlag: elfFlag}
		matched := st.soft(data, 0, flagBinTest, &indir, 0)
		previous = st.value
		previousSearch = st.search
		previousLine = st.line
		if st.err != nil {
			return finish("", st.err)
		}
		if matched {
			return finish(st.buf.String()+elf, nil)
		}
	}
	if desc, ok, err := db.textDescription(end, data, mime, text, prefix, elfFlag, previous, previousSearch, previousLine); ok || err != nil {
		return finish(desc, err)
	}
	if mime {
		return finish("application/octet-stream", nil)
	}
	return finish("data", nil)
}

type level struct {
	off       int32
	gotMatch  bool
	lastMatch bool
}

type search struct {
	s      []byte
	offset int
	rmLen  int
}

type state struct {
	db        *Database
	set       *magicSet
	separator *bool
	returnval bool
	found     bool
	err       error
	mime      bool
	text      bool
	buf       *strings.Builder
	levels    []level
	value     value
	search    search
	line      uint32
	offset    int
	eoffset   int
	trace     *[]string
	setIndex  int
	flip      bool
	tail      *tail
	onEnd     bool
	elfFlag   string
}

type value struct {
	raw  [maxString]byte
	n    int
	u64  uint64
	f32  float32
	f64  float64
	text string
}

// tarDescription matches file 5.41's builtin tar check, which runs before magic rules.
func tarDescription(data []byte) (string, bool) {
	kind := tarKind(data)
	switch kind {
	case 1:
		return "tar archive", true
	case 2:
		return "POSIX tar archive", true
	case 3:
		return "POSIX tar archive (GNU)", true
	default:
		return "", false
	}
}

func tarMIME(data []byte) bool {
	k := tarKind(data)
	return k >= 1 && k <= 3
}

func tarKind(data []byte) int {
	if len(data) < 512 {
		return 0
	}
	sum := 0
	for _, b := range data[:512] {
		sum += int(b)
	}
	for _, b := range data[148:156] {
		sum -= int(b)
	}
	sum += ' ' * 8
	rec := fromOct(data[148:156])
	if sum != rec {
		return 0
	}
	if bytes.Equal(data[257:265], []byte("ustar  \x00")) {
		return 3
	}
	if bytes.Equal(data[257:263], []byte("ustar\x00")) {
		return 2
	}
	return 1
}

func fromOct(field []byte) int {
	i := 0
	for i < len(field) && tarSpace(field[i]) {
		i++
	}
	if i == len(field) {
		return -1
	}
	value := 0
	for i < len(field) && field[i] >= '0' && field[i] <= '7' {
		value = value<<3 | int(field[i]-'0')
		i++
	}
	if i < len(field) && field[i] != 0 && !tarSpace(field[i]) {
		return -1
	}
	return value
}

func tarSpace(b byte) bool {
	return b == ' ' || b >= '\t' && b <= '\r'
}

func (s *state) soft(data []byte, offset int, mode int, indir *int, names int) bool {
	s.returnval = false
	s.found = false
	return s.match(s.set.rules, 0, s.set.n0, data, offset, mode, indir, names)
}

func (s *state) match(rules []entry, start, n int, data []byte, base int, mode int, indir *int, names int) bool {
	if n > len(rules)-start {
		n = len(rules) - start
	}
	cont := 0
	if s.separator == nil {
		separator := s.buf.Len() > 0
		s.separator = &separator
	}
	s.checkLevel(0)
	var read []byte
	var readBase int
nextGroup:
	for i := 0; i < n; i++ {
		m := &rules[start+i]
		ruleIndex := start + i
		if m.typ != typeName && skipByMode(m, s.text, mode) {
			for i+1 < n && rules[start+i+1].contLevel != 0 {
				i++
			}
			cont = 0
			continue
		}
		off, ok := s.setOffset(m, data, base, cont)
		if !ok {
			if s.err != nil {
				return false
			}
			for i+1 < n && rules[start+i+1].contLevel != 0 {
				i++
			}
			cont = 0
			continue
		}
		s.offset = int(uint32(off))
		s.line = m.lineno
		read, readBase = s.readBuf(data, base)
		got := s.mget(m, data, read, readBase, cont, mode, indir, names)
		if s.err != nil {
			return false
		}
		if got && m.typ == typeIndirect {
			s.found = true
			s.returnval = true
		}
		flush := false
		if !got {
			flush = m.reln != '!'
		} else if m.typ == typeUse {
			if !s.check(m) {
				flush = true
			}
		} else if m.typ != typeIndirect && m.typ != typeName {
			if !s.check(m) {
				flush = true
			}
		}
		if s.err != nil {
			return false
		}
		if flush {
			if s.trace != nil && m.contLevel == 0 && (m.typ == typeBEShort || m.typ == typeBELong || m.typ == typeLELong) && m.desc != "" {
				s.note(m, ruleIndex, "top-num-fail")
			}
			for i+1 < n && rules[start+i+1].contLevel != 0 {
				i++
			}
			cont = 0
			continue
		}
		if m.desc != "" {
			s.found = true
		}
		topPrinted := false // Top-level messages never prepend a separator.
		emitted := s.emit(m, &topPrinted)
		if s.err != nil {
			return false
		}
		if emitted {
			s.found = true
			s.returnval = true
			*s.separator = true
			s.note(m, ruleIndex, "top-hit")
		}
		// A MIME annotation ends the search immediately. A description
		// alone stops this rule group only AFTER its continuations, and
		// does not count as printed MIME (FILE5_41 match returnval).
		if s.mime && emitted {
			return true
		}
		next, okOff := s.moffset(m, len(read))
		if !okOff {
			// file 5.41 flushes continuations but keeps text already printed.
			for i+1 < n && rules[start+i+1].contLevel != 0 {
				i++
			}
			cont = 0
			continue
		}
		s.ensureLevel(cont)
		s.levels[cont].off = int32(next)
		s.levels[cont].gotMatch = true
		s.levels[cont].lastMatch = true
		cont++
		s.checkLevel(cont)
		for i+1 < n && rules[start+i+1].contLevel != 0 {
			i++
			m = &rules[start+i]
			s.line = m.lineno
			if cont < int(m.contLevel) {
				continue
			}
			if cont > int(m.contLevel) {
				cont = int(m.contLevel)
			}
			off, ok = s.setOffset(m, data, base, cont)
			if !ok {
				if s.err != nil {
					return false
				}
				for i+1 < n && rules[start+i+1].contLevel != 0 {
					i++
				}
				cont = 0
				continue nextGroup
			}
			if m.flag&flagOffAdd != 0 {
				if cont == 0 {
					return false
				}
				off += int(s.levels[cont-1].off)
			}
			s.offset = int(uint32(off))
			read, readBase = s.readBuf(data, base)
			if m.cond == condElse || m.cond == condElif {
				s.ensureLevel(cont)
				if s.levels[cont].lastMatch {
					continue
				}
			}
			got = s.mget(m, data, read, readBase, cont, mode, indir, names)
			if s.err != nil {
				return false
			}
			if got && m.typ == typeIndirect {
				s.found = true
				s.returnval = true
			}
			if !got && m.reln != '!' {
				continue
			}
			okCheck := !got || s.check(m)
			if s.err != nil {
				return false
			}
			s.ensureLevel(cont)
			s.levels[cont].lastMatch = okCheck
			if !okCheck {
				continue
			}
			if m.typ == typeClear {
				s.levels[cont].gotMatch = false
			} else if s.levels[cont].gotMatch && m.typ == typeDefault {
				continue
			} else {
				s.levels[cont].gotMatch = true
			}
			if m.desc != "" {
				s.found = true
			}
			emitted = s.emit(m, s.separator)
			if s.err != nil {
				return false
			}
			if emitted {
				s.found = true
				s.returnval = true
				*s.separator = true
				s.note(m, start+i, "cont-hit")
			}
			if s.mime && emitted {
				return true
			}

			next, okOff = s.moffset(m, len(read))
			if !okOff {
				cont--
				if cont < 0 {
					cont = 0
				}
			} else {
				s.levels[cont].off = int32(next)
			}
			cont++
			// file 5.41 clears the next level before a deeper continuation.
			// A default rule then runs only when nothing at that level matched.
			s.checkLevel(cont)
		}
		if s.found {
			return s.returnval
		}
		cont = 0
	}
	return s.returnval
}

func (s *state) emit(m *entry, printed *bool) bool {
	if s.mime {
		if m.mime != "" {
			s.buf.WriteString(expandQuery(m.mime, s.elfFlag, 1024))
			return true
		}
		return false
	}
	if m.desc == "" {
		return false
	}
	if !s.print(m, *printed) {
		if s.err == nil {
			s.err = errors.New("")
		}
		return false
	}
	*printed = true
	return true
}

func (s *state) levelsMatch() bool {
	for _, lv := range s.levels {
		if lv.gotMatch {
			return s.buf.Len() > 0
		}
	}
	return false
}

func (s *state) ensureLevel(n int) {
	for len(s.levels) <= n {
		s.levels = append(s.levels, level{})
	}
}

func (s *state) checkLevel(n int) {
	s.ensureLevel(n)
	s.levels[n].gotMatch = false
	s.levels[n].lastMatch = false
}

func skipByMode(m *entry, text bool, mode int) bool {
	if isStringType(m.typ) && !(m.version16 && m.typ == typeOctal) {
		flt := m.strFlags & (stringBinTest | stringTextTest)
		if text && flt == stringBinTest {
			return true
		}
		if !text && flt == stringTextTest {
			return true
		}
	}
	return int(m.flag)&mode != mode
}

func isStringType(t uint8) bool {
	switch t {
	case typeString, typePString, typeBEStr16, typeLEStr16, typeRegex, typeSearch, typeIndirect, typeName, typeUse, typeOctal:
		return true
	default:
		return false
	}
}

func (s *state) setOffset(m *entry, data []byte, base, cont int) (int, bool) {
	if m.flag&flagOffNegative != 0 {
		if cont > 0 && m.flag&(flagOffAdd|flagIndirOffAdd) != 0 {
			s.onEnd = false
			s.eoffset = 0
			return -int(m.offset), true
		}
		// file 5.41 rejects a negative offset when this match itself
		// started away from the beginning of the buffer.
		view, ok := s.loadTail(data)
		if !ok {
			return 0, false
		}
		if base != 0 {
			s.magerror(fmt.Sprintf("non zero offset %d at level %d", base, cont))
			return 0, false
		}
		if m.offset < 0 || int(m.offset) > len(view) {
			return 0, false
		}
		s.onEnd = true
		s.eoffset = len(view) - int(m.offset)
		return s.eoffset, true
	}
	if m.flag&flagOffPositive != 0 || cont == 0 {
		s.onEnd = false
		s.eoffset = 0
		return int(m.offset), true
	}
	return s.eoffset + int(m.offset), true
}

// readBuf returns the bytes and match base for the current rule.
// A negative offset keeps later continuations on the end copy, and their
// match base is the start of that copy.
func (s *state) readBuf(front []byte, base int) ([]byte, int) {
	if !s.onEnd {
		return front, base
	}
	view, ok := s.loadTail(front)
	if !ok {
		return nil, 0
	}
	return view, 0
}

func (s *state) mget(m *entry, front, data []byte, base, cont, mode int, indir *int, names int) bool {
	if *indir >= indirMax {
		s.fail(fmt.Sprintf("indirect count (%d) exceeded", *indir))
		return false
	}
	if names >= nameMax {
		s.fail(fmt.Sprintf("name use count (%d) exceeded", names))
		return false
	}
	off := s.offset
	if off < 0 {
		return false
	}
	// The pointer is read at the match base. file 5.41 then reads the
	// value at the indirect result. A named rule starts at that result
	// plus the current match base, so JPEG segments keep walking forward.
	fileOff := int(uint32(off + base))
	if m.flag&flagIndir != 0 {
		s.copyRaw(m.typ, data, fileOff, true)
		nv, ok := s.readIndirect(m, data, off, cont)
		if !ok {
			return false
		}
		s.offset = nv
		fileOff = nv
	}
	if m.typ == typeIndirect || m.typ == typeUse || m.typ == typeName {
		copyOff := fileOff
		if m.flag&flagIndir != 0 {
			copyOff = s.offset
		}
		s.copyRaw(m.typ, data, copyOff, false)
	}
	switch m.typ {
	case typeIndirect:
		fileOff = s.offset
		if m.strFlags&indirectRelative != 0 {
			fileOff = int(uint32(fileOff) + uint32(base))
		}
		if fileOff <= 0 || fileOff > len(data) {
			return false
		}
		*indir += 1
		// FILE_INDIRECT copies struct buffer, including any already filled tail.
		// A first fill in the child does not populate the parent's end view.
		end := &tail{}
		if s.tail != nil {
			*end = *s.tail
		}
		sub := &state{db: s.db, value: s.value, search: s.search, line: s.line, levels: s.levels, eoffset: s.eoffset, separator: s.separator, mime: s.mime, text: s.text, buf: &strings.Builder{}, tail: end, elfFlag: s.elfFlag, trace: s.trace}
		for i := range s.db.sets {
			sub.set = &s.db.sets[i]
			sub.setIndex = i
			matched := sub.soft(data[fileOff:], 0, flagBinTest, indir, names)
			s.value = sub.value
			s.search = sub.search
			s.line = sub.line
			s.levels = sub.levels
			s.eoffset = sub.eoffset
			if matched {
				if !s.mime && m.desc != "" {
					if m.version16 {
						// mget's indirect prefix has its own F() call,
						// after the child has updated the current line.
						if !s.checkNativeFormat(m.desc, "%u", 1841) {
							return false
						}
						if msg := formatError(m.desc); msg != "" {
							s.buf.Reset()
							s.err = fmt.Errorf("Bad magic format `%s' (%s)", m.desc, msg)
							return false
						}
						number := entry{version16: true, typ: typeLong, flag: flagUnsigned, desc: m.desc}
						if !s.appendFormatted(expand(m.desc, formatNumber(&number, uint64(fileOff)))) {
							return false
						}
					} else {
						s.buf.WriteString(expand(m.desc, fmt.Sprintf("%d", fileOff)))
					}
				}
				if m.version16 {
					return s.appendFormatted(sub.buf.String())
				}
				s.buf.WriteString(sub.buf.String())
				return true
			}
			if sub.err != nil {
				s.err = sub.err
				return false
			}
		}
		return false
	case typeUse:
		if s.offset > len(data) {
			return false
		}
		name := cString(m.value[:])
		flip := s.flip
		if strings.HasPrefix(name, "^") {
			name = name[1:]
			flip = !flip
		}
		idx, setIndex := -1, 0
		var set *magicSet
		for i := range s.db.sets {
			if n, ok := s.db.sets[i].names[name]; ok {
				idx, setIndex, set = n, i, &s.db.sets[i]
				break
			}
		}
		if idx < 0 {
			s.fail(fmt.Sprintf("cannot find entry `%s'", name))
			return false
		}
		end := idx + 1
		for end < len(set.rules) && set.rules[end].contLevel != 0 {
			end++
		}
		names++
		savedLevels := append([]level(nil), s.levels...)
		savedOffset := s.offset
		savedEOffset := s.eoffset
		savedSeparator := *s.separator
		if m.flag&flagNoSpace != 0 {
			*s.separator = false
		}
		out := &state{db: s.db, set: set, value: s.value, search: s.search, line: s.line, separator: s.separator, returnval: s.returnval, mime: s.mime, text: s.text, buf: s.buf, levels: append([]level(nil), s.levels...), flip: flip, trace: s.trace, setIndex: setIndex, tail: s.tail, elfFlag: s.elfFlag}
		// FILE_USE passes the original buffer, not mget's current end view.
		ok := out.match(set.rules, idx, end-idx, front, s.offset+base, mode, indir, names)
		if !ok {
			*s.separator = savedSeparator
		}
		s.returnval = out.returnval
		s.found = s.found || out.found
		s.err = out.err
		s.offset = savedOffset
		s.eoffset = savedEOffset
		s.levels = savedLevels
		s.value = out.value
		s.search = out.search
		s.line = out.line
		if out.found {
			s.value.u64 = 1
		} else {
			s.value.u64 = 0
		}
		binary.LittleEndian.PutUint64(s.value.raw[:8], s.value.u64)
		return ok
	case typeName:
		if !s.mime {
			s.buf.WriteString(m.desc)
		}
		return true
	case typeDER:
		return s.copyDER(data, fileOff)
	default:
		return s.copyValue(m, data, fileOff, s.offset)
	}
}

func (s *state) fail(message string) {
	if s.buf.Len() != 0 {
		message = s.buf.String() + " " + message
	}
	s.err = errors.New(message)
}

func (s *state) magerror(message string) {
	if s.line == 0 {
		s.fail(message)
		return
	}
	s.err = fmt.Errorf("line %d: %s", s.line, message)
}

func (s *state) readIndirect(m *entry, data []byte, off, cont int) (int, bool) {
	// (offset.s+N) reads a number at offset and adds the constant N.
	// FILE_OPINDIRECT reads that constant from the file instead.
	// A named rule entered as ^name flips the endianness of this read.
	inType := flippedType(m.inType, s.flip)
	// mcopy already read the primary union at offset+base. Bounds and
	// an indirect RHS use the local offset in the original buffer.
	need := width(inType)
	if off < 0 || off > len(data) || need > len(data)-off {
		return 0, false
	}
	lhs, ok := s.readAt(inType, s.value.raw[:], 0, m.inOp&opSigned != 0)
	if !ok {
		return 0, false
	}
	if inType == typeBEID3 || inType == typeLEID3 {
		// Only the primary offset is syncsafe; an indirect RHS stays raw.
		v := uint32(lhs)
		lhs = int64((v & 0x7f) | ((v >> 8 & 0x7f) << 7) | ((v >> 16 & 0x7f) << 14) | ((v >> 24 & 0x7f) << 21))
	}
	rhs := int64(m.inOffset)
	if m.inOp&opIndirect != 0 {
		v, ok := s.readAt(inType, data, off+int(m.inOffset), m.inOp&opSigned != 0)
		if !ok {
			return 0, false
		}
		rhs = v
	}
	out := lhs
	if rhs != 0 {
		switch m.inOp & opsMask {
		case opAnd:
			out = lhs & rhs
		case opOr:
			out = lhs | rhs
		case opXor:
			out = lhs ^ rhs
		case opAdd:
			out = lhs + rhs
		case opSub:
			out = lhs - rhs
		case opMul:
			out = lhs * rhs
		case opDiv:
			if rhs == 0 {
				return 0, false
			}
			out = lhs / rhs
		case opMod:
			if rhs == 0 {
				return 0, false
			}
			out = lhs % rhs
		}
	}
	if m.inOp&opInverse != 0 {
		out = ^out
	}
	// FILE5_41 do_ops returns uint32_t before INDIROFFADD and bounds checks.
	offset := uint32(out)
	if m.flag&flagIndirOffAdd != 0 {
		if cont == 0 {
			return 0, false
		}
		offset += uint32(s.levels[cont-1].off)
		if offset == 0 {
			return 0, false
		}
	}
	return int(offset), true
}

func (s *state) readAt(typ uint8, data []byte, off int, signed bool) (int64, bool) {
	if off < 0 || off >= len(data) {
		return 0, false
	}
	need := width(typ)
	if need > 0 && off+need > len(data) {
		return 0, false
	}
	p := data[off:]
	var u uint64
	switch typ {
	case typeByte:
		u = uint64(p[0])
		if signed {
			return int64(int8(p[0])), true
		}
	case typeShort:
		u = uint64(binary.LittleEndian.Uint16(p))
	case typeBEShort:
		u = uint64(binary.BigEndian.Uint16(p))
	case typeLEShort:
		u = uint64(binary.LittleEndian.Uint16(p))
	case typeLong:
		u = uint64(binary.LittleEndian.Uint32(p))
	case typeBELong, typeBEID3:
		u = uint64(binary.BigEndian.Uint32(p))
	case typeLELong, typeLEID3:
		u = uint64(binary.LittleEndian.Uint32(p))
	case typeMELong:
		u = uint64(uint32(p[1])<<24 | uint32(p[0])<<16 | uint32(p[3])<<8 | uint32(p[2]))
	case typeBEQuad:
		u = binary.BigEndian.Uint64(p)
	case typeLEQuad:
		u = binary.LittleEndian.Uint64(p)
	default:
		return 0, false
	}
	if signed && need == 2 {
		return int64(int16(u)), true
	}
	if signed && need == 4 {
		return int64(int32(u)), true
	}
	return int64(u), true
}

func width(t uint8) int {
	switch t {
	case typeByte:
		return 1
	case typeShort, typeBEShort, typeLEShort, typeMSDOSDate, typeLEMSDOSDate, typeBEMSDOSDate, typeMSDOSTime, typeLEMSDOSTime, typeBEMSDOSTime:
		return 2
	case typeLong, typeBELong, typeLELong, typeMELong, typeDate, typeBEDate, typeLEDate, typeMEDate, typeLDate, typeBELDate, typeLELDate, typeMELDate, typeFloat, typeBEFloat, typeLEFloat, typeBEID3, typeLEID3:
		return 4
	case typeQuad, typeBEQuad, typeLEQuad, typeDouble, typeBEDouble, typeLEDouble, typeQDate, typeBEQDate, typeLEQDate, typeQLDate, typeBEQLDate, typeLEQLDate, typeQWDate, typeBEQWDate, typeLEQWDate:
		return 8
	case typeGUID:
		return 16
	default:
		return 0
	}
}

// copyRaw is the value-union part of FILE5_41 mcopy. Regex/search/DER
// only update their separate search region. A 16-bit string writes decoded
// bytes in place, including NULs; its unfilled tail is the preceding value.
func (s *state) copyRaw(typ uint8, data []byte, off int, indirect bool) {
	if !indirect && (typ == typeSearch || typ == typeRegex || typ == typeDER) {
		return
	}
	var raw [maxString]byte
	n := 0
	switch {
	case !indirect && (typ == typeBEStr16 || typ == typeLEStr16) && off >= 0 && off < len(data):
		raw = s.value.raw
		src := off
		if typ == typeBEStr16 {
			src++
		}
		for dst := 0; src < len(data) && dst < maxString-1; src, dst = src+2, dst+1 {
			c := data[src]
			if c == 0 && ((typ == typeBEStr16 && data[src-1] != 0) || (typ == typeLEStr16 && src+1 < len(data) && data[src+1] != 0)) {
				c = ' '
			}
			raw[dst] = c
		}
		raw[maxString-1] = 0
		n = maxString
	case typ == typeOffset:
		binary.LittleEndian.PutUint64(raw[:8], uint64(off))
		n = 8
	default:
		if off >= 0 && off < len(data) {
			n = copy(raw[:], data[off:])
		}
	}
	s.value = value{raw: raw, n: n, u64: binary.LittleEndian.Uint64(raw[:8]), f32: math.Float32frombits(binary.LittleEndian.Uint32(raw[:4])), f64: math.Float64frombits(binary.LittleEndian.Uint64(raw[:8]))}
}

// copyOff is mcopy's uint32(offset+base); off is mget's local offset.
func (s *state) copyValue(m *entry, data []byte, copyOff, off int) bool {
	s.copyRaw(m.typ, data, copyOff, false)
	if off < 0 {
		return false
	}
	if m.typ == typeInvalid || m.typ == typeBEID3 || m.typ == typeLEID3 ||
		m.typ == typeBEVarint || m.typ == typeLEVarint ||
		m.typ > typeOctal || m.version16 && m.typ > typeLEVarint {
		// FILE5_41 mconvert rejects unknown types after copying the union,
		// even beyond EOF. Types added in v21 remain supported only there.
		s.magerror(fmt.Sprintf("invalid type %d in mconvert()", m.typ))
		return false
	}
	if m.typ == typeSearch {
		// mcopy runs before the extent check, including failed '!' reads.
		// FILE_SEARCH does not reset rm_len when copying a new region.
		start := copyOff
		if start > len(data) {
			start = len(data)
		}
		s.search.s = data[start:]
		s.search.offset = start
	}
	// FILE5_41 checks the declared extent even for relation 'x'.
	// A zero-length value at EOF is allowed; past EOF is not.
	if m.typ == typeString || m.typ == typePString || m.typ == typeSearch {
		if off > len(data) || int(m.vallen) > len(data)-off {
			return false
		}
	}
	switch m.typ {
	case typeSearch:
		return true
	case typeRegex:
		s.copyRegex(m, data, copyOff)
		return off <= len(data)
	case typeDefault, typeClear, typeName, typeUse:
		return true
	case typeOffset:
		if !s.applyMask(m) {
			return false
		}
		binary.LittleEndian.PutUint64(s.value.raw[:8], s.value.u64)
		return true
	}
	w := width(m.typ)
	if w == 0 {
		n := int(m.vallen)
		if m.typ == typeString || m.typ == typePString || m.typ == typeOctal {
			if n == 0 {
				n = 1
			}
		}
		if m.typ != typeString && m.typ != typePString && m.typ != typeBEStr16 && m.typ != typeLEStr16 && (off >= len(data) || (n > 0 && off+n > len(data) && m.typ != typeRegex)) {
			return m.reln == 'x'
		}
		switch m.typ {
		case typePString:
			if _, ok := pascalLengthSize(m.strFlags); !ok {
				s.fail(fmt.Sprintf("corrupt magic file (bad pascal string length %d)", m.strFlags&pstringLen))
				return false
			}
			// mcopy pads the entire value union before mconvert shifts
			// and clips the Pascal body. Missing bytes are not a failure.
			body, ok := pascalBody(m, s.value.raw[:])
			if !ok {
				return false
			}
			s.value.n = copy(s.value.raw[:], body)
			s.value.raw[s.value.n] = 0
			s.value.text = cString(s.value.raw[:s.value.n])
		case typeBEStr16, typeLEStr16:
			s.value.text = string(s.value.raw[:])
		default:
			// Keep bytes after an embedded NUL. Comparison reads them.
			// Printing and continuation length stop at the first NUL.
			if m.typ == typeString {
				s.value.raw[maxString-1] = 0
			}
			s.value.text = string(s.value.raw[:s.value.n])
		}
		return true
	}
	switch m.typ {
	case typeQuad, typeBEQuad, typeLEQuad, typeQDate, typeBEQDate, typeLEQDate, typeQLDate, typeBEQLDate, typeLEQLDate, typeQWDate, typeBEQWDate, typeLEQWDate:
		// FILE5_41 mget has no extent test for these padded quad types.
	default:
		if off > len(data) || w > len(data)-off {
			return false
		}
	}
	p := s.value.raw[:]
	typ := flippedType(m.typ, s.flip)
	switch typ {
	case typeByte:
		s.value.u64 = uint64(p[0])
	case typeShort, typeLEShort, typeMSDOSDate, typeLEMSDOSDate, typeMSDOSTime, typeLEMSDOSTime:
		s.value.u64 = uint64(binary.LittleEndian.Uint16(p))
	case typeBEShort, typeBEMSDOSDate, typeBEMSDOSTime:
		s.value.u64 = uint64(binary.BigEndian.Uint16(p))
	case typeLong, typeLELong, typeDate, typeLEDate, typeLDate, typeLELDate:
		s.value.u64 = uint64(binary.LittleEndian.Uint32(p))
	case typeBELong, typeBEDate, typeBELDate:
		s.value.u64 = uint64(binary.BigEndian.Uint32(p))
	case typeMELong, typeMEDate, typeMELDate:
		s.value.u64 = uint64(uint32(p[1])<<24 | uint32(p[0])<<16 | uint32(p[3])<<8 | uint32(p[2]))
	case typeQuad, typeLEQuad, typeQDate, typeLEQDate, typeQLDate, typeLEQLDate, typeQWDate, typeLEQWDate:
		s.value.u64 = binary.LittleEndian.Uint64(p)
	case typeBEQuad, typeBEQDate, typeBEQLDate, typeBEQWDate:
		s.value.u64 = binary.BigEndian.Uint64(p)
	case typeFloat, typeLEFloat:
		s.value.u64 = uint64(binary.LittleEndian.Uint32(p))
		s.value.f32 = math.Float32frombits(uint32(s.value.u64))
	case typeBEFloat:
		s.value.u64 = uint64(binary.BigEndian.Uint32(p))
		s.value.f32 = math.Float32frombits(uint32(s.value.u64))
	case typeDouble, typeLEDouble:
		s.value.u64 = binary.LittleEndian.Uint64(p)
		s.value.f64 = math.Float64frombits(s.value.u64)
	case typeBEDouble:
		s.value.u64 = binary.BigEndian.Uint64(p)
		s.value.f64 = math.Float64frombits(s.value.u64)
	case typeGUID:
		copy(s.value.raw[:16], p[:16])
		s.value.n = 16
	default:
		return false
	}
	converted := s.applyMask(m)
	switch w {
	case 1:
		s.value.raw[0] = byte(s.value.u64)
	case 2:
		binary.LittleEndian.PutUint16(s.value.raw[:2], uint16(s.value.u64))
	case 4:
		binary.LittleEndian.PutUint32(s.value.raw[:4], uint32(s.value.u64))
	case 8:
		binary.LittleEndian.PutUint64(s.value.raw[:8], s.value.u64)
	}
	return converted
}

func (s *state) applyMask(m *entry) bool {
	if m.numMask == 0 && m.maskOp&opInverse == 0 {
		return true
	}
	switch m.typ {
	case typeFloat, typeBEFloat, typeLEFloat:
		// cvt_float/cvt_double convert the integer mask to the value's
		// precision. Bitwise operations and inverse do not apply.
		if m.numMask != 0 {
			mask := float32(m.numMask)
			switch m.maskOp & opsMask {
			case opAdd:
				s.value.f32 += mask
			case opSub:
				s.value.f32 -= mask
			case opMul:
				s.value.f32 *= mask
			case opDiv:
				s.value.f32 /= mask
			}
		}
		s.value.u64 = uint64(math.Float32bits(s.value.f32))
		return true
	case typeDouble, typeBEDouble, typeLEDouble:
		if m.numMask != 0 {
			mask := float64(m.numMask)
			switch m.maskOp & opsMask {
			case opAdd:
				s.value.f64 += mask
			case opSub:
				s.value.f64 -= mask
			case opMul:
				s.value.f64 *= mask
			case opDiv:
				s.value.f64 /= mask
			}
		}
		s.value.u64 = math.Float64bits(s.value.f64)
		return true
	case typeString, typePString, typeSearch, typeRegex, typeGUID:
		return true
	}
	bits := numericBits(m.typ)
	s.value.u64 = hostNumber(s.value.u64, bits)
	numMask := hostNumber(m.numMask, bits)
	// The mask is applied to the low bits. Sign extension happens later,
	// when the value is printed or compared.
	v := s.value.u64
	// DO_CVT tests the original mask before narrowing its operand.
	if m.numMask != 0 {
		switch m.maskOp & opsMask {
		case opAnd:
			v &= numMask
		case opOr:
			v |= numMask
		case opXor:
			v ^= numMask
		case opAdd:
			v += numMask
		case opSub:
			v -= numMask
		case opMul:
			v *= numMask
		case opDiv, opMod:
			if numMask == 0 {
				s.magerror("zerodivide in mconvert()")
				return false
			}
			if m.maskOp&opsMask == opDiv {
				v /= numMask
			} else {
				v %= numMask
			}
		}
	}
	if m.maskOp&opInverse != 0 {
		v = ^v
	}
	s.value.u64 = v
	return true
}

func (s *state) check(m *entry) bool {
	switch m.typ {
	case typeDefault, typeClear:
		return s.rel(0, 0, m.reln, m.flag&flagUnsigned != 0)
	case typeName, typeIndirect:
		return true
	case typeUse:
		return s.value.u64 != 0
	case typeDER:
		return s.derMatch(m)
	case typeString, typePString, typeOctal, typeBEStr16, typeLEStr16:
		n := int(m.vallen)
		if n > maxString {
			n = maxString
		}
		flags := m.strFlags
		if m.typ == typeBEStr16 || m.typ == typeLEStr16 {
			// FILE5_41 file_strncmp16 ignores flags, not the output
			// and mode consumers of the same stored field.
			flags = 0
		}
		cmp := fileStrncmp(m.value[:n], s.value.raw[:], n, flags)
		return s.rel(int64(cmp), 0, m.reln, m.flag&flagUnsigned != 0)
	case typeSearch:
		return s.searchMatch(m)
	case typeRegex:
		return s.regexMatch(m)
	case typeFloat, typeBEFloat, typeLEFloat:
		return s.cmpFloat(float64(s.value.f32), float64(math.Float32frombits(uint32(m.quad))), m.reln, "float")
	case typeDouble, typeBEDouble, typeLEDouble:
		return s.cmpFloat(s.value.f64, math.Float64frombits(m.quad), m.reln, "double")
	case typeGUID:
		cmp := bytes.Compare(m.guid[:], s.value.raw[:16])
		return s.rel(int64(cmp), 0, m.reln, m.flag&flagUnsigned != 0)
	default:
		bits := numericBits(m.typ)
		got := hostNumber(s.value.u64, bits)
		want := m.quad
		if m.flag&flagUnsigned == 0 {
			return s.rel(signExtend(got, bits), int64(want), m.reln, false)
		}
		return s.rel(int64(got), int64(want), m.reln, true)
	}
}

// hostNumber reads the low byte, short, or long from the value union.
// The compiled comparison constant remains a full 64-bit value; signed
// constants were already sign-extended by apprentice when compiled.
func hostNumber(v uint64, bits int) uint64 {
	if bits <= 0 || bits >= 64 {
		return v
	}
	return v & (uint64(1)<<uint(bits) - 1)
}

// flippedType swaps big-endian and little-endian numeric types.
// file(1) does this when a named rule is invoked as ^name.
func flippedType(t uint8, flip bool) uint8 {
	if !flip {
		return t
	}
	switch t {
	case typeBEShort:
		return typeLEShort
	case typeLEShort:
		return typeBEShort
	case typeBELong:
		return typeLELong
	case typeLELong:
		return typeBELong
	case typeBEDate:
		return typeLEDate
	case typeLEDate:
		return typeBEDate
	case typeBELDate:
		return typeLELDate
	case typeLELDate:
		return typeBELDate
	case typeBEQuad:
		return typeLEQuad
	case typeLEQuad:
		return typeBEQuad
	case typeBEQDate:
		return typeLEQDate
	case typeLEQDate:
		return typeBEQDate
	case typeBEQLDate:
		return typeLEQLDate
	case typeLEQLDate:
		return typeBEQLDate
	case typeBEQWDate:
		return typeLEQWDate
	case typeLEQWDate:
		return typeBEQWDate
	case typeBEFloat:
		return typeLEFloat
	case typeLEFloat:
		return typeBEFloat
	case typeBEDouble:
		return typeLEDouble
	case typeLEDouble:
		return typeBEDouble
	default:
		return t
	}
}

func numericBits(t uint8) int {
	switch width(t) {
	case 1:
		return 8
	case 2:
		return 16
	case 4:
		return 32
	default:
		return 64
	}
}

func signExtend(v uint64, bits int) int64 {
	if bits >= 64 {
		return int64(v)
	}
	shift := 64 - bits
	return int64(v<<shift) >> shift
}

func maskedExpected(m *entry) uint64 {
	return m.quad
}

func (s *state) rel(v, l int64, op byte, unsigned bool) bool {
	switch op {
	case 'x':
		return true
	case '!':
		return v != l
	case '=':
		return v == l
	case '>':
		if unsigned {
			return uint64(v) > uint64(l)
		}
		return v > l
	case '<':
		if unsigned {
			return uint64(v) < uint64(l)
		}
		return v < l
	case '&':
		return uint64(v)&uint64(l) == uint64(l)
	case '^':
		return uint64(v)&uint64(l) != uint64(l)
	default:
		s.magerror("cannot happen: invalid relation `" + cString([]byte{op, '\''}))
		return false
	}
}

func (s *state) cmpFloat(v, l float64, op byte, typ string) bool {
	switch op {
	case 'x':
		return true
	case '!':
		return v != l
	case '=':
		return v == l
	case '>':
		return v > l
	case '<':
		return v < l
	default:
		s.magerror(fmt.Sprintf("cannot happen with %s: invalid relation `", typ) + cString([]byte{op, '\''}))
		return false
	}
}

func fileStrncmp(a, b []byte, n int, flags uint32) int {
	if flags == 0 {
		for i := 0; i < n; i++ {
			if i >= len(b) {
				return 1
			}
			if b[i] != a[i] {
				return int(b[i]) - int(a[i])
			}
		}
		return 0
	}
	bi := 0
	for i := 0; i < n; i++ {
		if bi >= len(b) {
			return 1
		}
		av := a[i]
		switch {
		case flags&stringIgnoreLower != 0 && av >= 'a' && av <= 'z':
			if lower(b[bi]) != av {
				return int(lower(b[bi])) - int(av)
			}
			bi++
		case flags&stringIgnoreUpper != 0 && av >= 'A' && av <= 'Z':
			if upper(b[bi]) != av {
				return int(upper(b[bi])) - int(av)
			}
			bi++
		case flags&stringCompactWhitespace != 0 && isSpace(av):
			if !isSpace(b[bi]) {
				return 1
			}
			bi++
			if i+1 == n || !isSpace(a[i+1]) {
				for bi < len(b) && isSpace(b[bi]) {
					bi++
				}
			}
		case flags&stringCompactOptionalWhitespace != 0 && isSpace(av):
			for bi < len(b) && isSpace(b[bi]) {
				bi++
			}
		default:
			if b[bi] != av {
				return int(b[bi]) - int(av)
			}
			bi++
		}
	}
	if flags&stringFullWord != 0 && bi < len(b) && b[bi] != 0 && !isSpace(b[bi]) {
		return 1
	}
	return 0
}

func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func upper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - ('a' - 'A')
	}
	return b
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

func (s *state) searchMatch(m *entry) bool {
	n := int(m.vallen)
	if n > len(m.value) {
		n = len(m.value)
	}
	found, cmp := -1, 0
	if n > 0 && m.strFlags == 0 {
		// The reference's memmem range includes a match starting at
		// str_range; its flagged comparison loop excludes that start.
		limit := len(s.search.s)
		if m.strRange > 0 && int(m.strRange)+n < limit {
			limit = int(m.strRange) + n
		}
		found = bytes.Index(s.search.s[:limit], m.value[:n])
		if found < 0 {
			cmp = 1
		}
	} else {
		for i := 0; m.strRange == 0 || i < int(m.strRange); i++ {
			if i+n > len(s.search.s) {
				cmp = 1
				break
			}
			cmp = fileStrncmp(m.value[:n], s.search.s[i:], n, m.strFlags)
			if cmp == 0 {
				found = i
				break
			}
		}
	}
	if found >= 0 {
		s.search.offset += found
		s.search.rmLen = len(s.search.s) - found
	}
	return s.rel(int64(cmp), 0, m.reln, m.flag&flagUnsigned != 0)
}

func (s *state) copyRegex(m *entry, data []byte, off int) bool {
	if off > len(data) {
		s.search.s = nil
		// mcopy clears the region, retaining the previous offset/length;
		// mget then fails the read, so a '!' continuation still matches.
		return false
	}
	region := data[off:]
	bytecnt := int(m.strRange)
	// BIT(11) is REGEX_LINE_COUNT. The same bit is PSTRING_4_LE on pascal strings.
	if m.strFlags&pstring4LE != 0 {
		bytecnt *= 80
	}
	if bytecnt == 0 || bytecnt > len(region) {
		bytecnt = len(region)
	}
	if bytecnt > regexMax {
		bytecnt = regexMax
	}
	last := bytecnt
	if m.strFlags&pstring4LE != 0 {
		lines := int(m.strRange)
		i := 0
		for lines > 0 && i < bytecnt {
			// FILE5_41 looks for LF first, using CR only if no LF exists.
			pos := bytes.IndexByte(region[i:bytecnt], '\n')
			if pos < 0 {
				pos = bytes.IndexByte(region[i:bytecnt], '\r')
			}
			if pos < 0 {
				break
			}
			pos += i
			if pos+1 < bytecnt && region[pos] == '\r' && region[pos+1] == '\n' {
				pos++
			}
			if pos+1 < bytecnt && region[pos] == '\n' {
				pos++
			}
			last = pos
			i = pos + 1
			lines--
		}
		if lines > 0 {
			last = bytecnt
		}
	}
	s.search.s = region[:last]
	s.search.offset = off
	s.search.rmLen = 0
	return true
}

func (s *state) regexMatch(m *entry) bool {
	if s.search.s == nil {
		return false
	}
	re := m.re
	if re == nil {
		pattern := cString(m.value[:])
		fold := m.strFlags&(stringIgnoreLower|stringIgnoreUpper) != 0
		if code := regexErrorCode(pattern, fold); code != 0 {
			s.magerror(fmt.Sprintf("regex error %d for `%s', (%s)", code, pattern, regexErrorMessages[code]))
			return false
		}
		re = compileRule(m)
		if re == nil {
			return false
		}
	}
	// Each file byte becomes one code point before the regexp runs.
	// The returned indexes are then converted back to file bytes.
	region := s.search.s
	if len(region) > 0 {
		// magiccheck copies the selected region and replaces its last byte
		// with NUL before regexec. Earlier NULs also terminate the search.
		region = region[:len(region)-1]
	}
	if end := bytes.IndexByte(region, 0); end >= 0 {
		region = region[:end]
	}
	text, off := bytesAsRunes(region)
	loc := re.FindStringIndex(text)
	if loc == nil {
		return s.rel(1, 0, m.reln, m.flag&flagUnsigned != 0)
	}
	start := byteIndex(off, loc[0])
	end := byteIndex(off, loc[1])
	s.search.offset += start
	s.search.rmLen = end - start
	if start > 0 && start <= len(s.search.s) {
		s.search.s = s.search.s[start:]
	}
	return s.rel(0, 0, m.reln, m.flag&flagUnsigned != 0)
}

func compileRule(m *entry) *magicRegex {
	pat := cString(m.value[:])
	fold := m.strFlags&(stringIgnoreLower|stringIgnoreUpper) != 0
	if regexErrorCode(pat, fold) != 0 {
		return nil
	}
	// The pattern is stored as raw bytes. Convert it the same way as the
	// file bytes so both sides use one code point per byte.
	pat, _ = bytesAsRunes([]byte(pat))
	tree, ops, err := parseRegex(pat, fold)
	if err != nil {
		return nil
	}
	return buildRegex(tree, ops, fold)
}

// bytesAsRunes copies convertutf8: one source byte becomes one rune.
// A raw 0xFF is then the character U+00FF, so a regexp can match it.
func bytesAsRunes(src []byte) (string, []int) {
	off := make([]int, len(src))
	var b strings.Builder
	b.Grow(len(src) * 2)
	for i, c := range src {
		off[i] = b.Len()
		b.WriteRune(rune(c))
	}
	return b.String(), off
}

func byteIndex(off []int, idx int) int {
	i := sort.Search(len(off), func(i int) bool { return off[i] >= idx })
	if i < len(off) && off[i] == idx {
		return i
	}
	if i == len(off) {
		return len(off)
	}
	return i
}

func (s *state) moffset(m *entry, nbytes int) (int, bool) {
	var o int
	switch m.typ {
	case typeByte:
		o = s.offset + 1
	case typeShort, typeBEShort, typeLEShort, typeMSDOSDate, typeLEMSDOSDate, typeBEMSDOSDate, typeMSDOSTime, typeLEMSDOSTime, typeBEMSDOSTime:
		o = s.offset + 2
	case typeLong, typeBELong, typeLELong, typeMELong, typeDate, typeBEDate, typeLEDate, typeMEDate, typeLDate, typeBELDate, typeLELDate, typeMELDate, typeFloat, typeBEFloat, typeLEFloat:
		o = s.offset + 4
	case typeQuad, typeBEQuad, typeLEQuad, typeDouble, typeBEDouble, typeLEDouble, typeQDate, typeBEQDate, typeLEQDate, typeQLDate, typeBEQLDate, typeLEQLDate:
		o = s.offset + 8
	case typeString, typePString, typeBEStr16, typeLEStr16, typeOctal:
		if m.reln == '=' || m.reln == '!' {
			o = s.offset + int(m.vallen)
		} else {
			text := s.value.text
			if n := cLen(text); n < len(text) {
				text = text[:n]
			}
			if len(m.value) == 0 || m.value[0] == 0 {
				if i := strings.IndexAny(text, "\r\n"); i >= 0 {
					s.value.raw[i] = 0
					s.value.text = string(s.value.raw[:s.value.n])
					text = text[:i]
				}
			}
			o = s.offset + len(text)
			if m.typ == typePString {
				n, ok := pascalLengthSize(m.strFlags)
				if !ok {
					return 0, false
				}
				o += n
			}
		}
	case typeSearch:
		vlen := int(m.vallen)
		if m.strFlags&regexOffsetStart != 0 {
			vlen = 0
		}
		o = s.search.offset + vlen
	case typeRegex:
		vlen := s.search.rmLen
		if m.strFlags&regexOffsetStart != 0 {
			vlen = 0
		}
		o = s.search.offset + vlen
	case typeOffset, typeUse, typeIndirect, typeClear, typeDefault:
		o = s.offset
	case typeDER:
		next, ok := s.derOffset(m, nbytes)
		if !ok {
			return 0, false
		}
		o = next
	case typeGUID:
		o = s.offset + 16
	default:
		// file 5.41 stores offset 0 and still accepts the match.
		// Name, varint, ID3, and QWDATE rules take this path.
		o = 0
	}
	o = int(int32(o))
	if o < 0 || o > nbytes {
		return 0, false
	}
	return o, true
}

func (s *state) print(m *entry, printed bool) bool {
	// mprint returns its end as int32_t. Only -1 is an error sentinel,
	// even when no error message was recorded by the native handle.
	end := s.offset
	if w := width(m.typ); w > 0 && m.typ != typeGUID {
		end += w
	}
	switch m.typ {
	case typeOffset:
		end += 8
	case typeString, typePString, typeBEStr16, typeLEStr16:
		if m.reln == '=' || m.reln == '!' {
			end += int(m.vallen)
		} else {
			end += cLen(s.value.text)
			if m.typ == typePString {
				n, ok := pascalLengthSize(m.strFlags)
				if !ok {
					return false
				}
				end += n
			}
		}
	case typeSearch:
		end = s.search.offset
		if m.strFlags&regexOffsetStart == 0 {
			end += int(m.vallen)
		}
	case typeRegex:
		end = s.search.offset
		if m.strFlags&regexOffsetStart == 0 {
			end += s.search.rmLen
		}
	}
	if m.typ == typeDefault || m.typ == typeClear {
		// FILE5_41 prints m->desc, not the expanded/formatted description.
		if printed && m.flag&flagNoSpace == 0 {
			s.buf.WriteByte(' ')
		}
		s.buf.WriteString(m.desc)
		return int32(end) != -1
	}
	desc := expandQuery(m.desc, s.elfFlag, 512)
	if strings.HasPrefix(desc, "\\b") {
		desc = desc[2:]
	} else if printed && m.flag&flagNoSpace == 0 {
		s.buf.WriteByte(' ')
	}
	asString := false
	if m.version16 {
		def, line, numericString := nativePrintFormat(m, desc)
		asString = numericString
		if def != "" && !s.checkNativeFormat(desc, def, line) {
			return false
		}
	}
	if m.typ != typeIndirect && m.typ != typeUse && m.typ != typeName {
		if msg := formatError(desc); msg != "" {
			s.buf.Reset()
			s.err = fmt.Errorf("Bad magic format `%s' (%s)", desc, msg)
			return false
		}
	}
	switch m.typ {
	case typeIndirect, typeUse, typeName:
		// mget already printed the recursive or named output.
		desc = ""
	case typeString, typePString, typeBEStr16, typeLEStr16:
		text := s.value.text
		if m.reln == '=' || m.reln == '!' {
			text = cString(m.value[:])
		} else {
			if n := cLen(text); n < len(text) {
				text = text[:n]
			}
			// file 5.41 writes a NUL at the first CR or LF when the
			// expected string is empty. Bytes after that are not printed.
			if len(m.value) == 0 || m.value[0] == 0 {
				if i := strings.IndexAny(text, "\r\n"); i >= 0 {
					s.value.raw[i] = 0
					s.value.text = string(s.value.raw[:s.value.n])
					text = text[:i]
				}
			}
			if m.strFlags&stringTrim != 0 {
				// file_strtrim advances past leading whitespace but writes
				// only one NUL after the last non-whitespace union byte.
				end := len(text)
				for end > 0 && isSpace(text[end-1]) {
					end--
				}
				s.value.raw[end] = 0
				s.value.text = string(s.value.raw[:s.value.n])
				text = trimString(text)
			}
		}
		desc = expand(desc, printable(clipPrecision(m.desc, text)))
	case typeDER:
		text := s.value.text
		if m.version16 {
			// DER tag/length-only matches leave ms_value untouched.
			// mprint prints that union, not der_data's decoded value.
			desc = expand(desc, printable(string(s.value.raw[:])))
			break
		}
		if m.strFlags&stringTrim != 0 {
			text = trimString(text)
		}
		desc = expand(desc, printable(clipPrecision(m.desc, text)))
	case typeDate, typeBEDate, typeLEDate, typeMEDate, typeQDate, typeBEQDate, typeLEQDate:
		desc = expand(desc, formatTimeFlags(s.value.u64, timeUTC))
	case typeLDate, typeBELDate, typeLELDate, typeMELDate, typeQLDate, typeBEQLDate, typeLEQLDate:
		desc = expand(desc, formatTimeFlags(s.value.u64, timeLocal))
	case typeQWDate, typeBEQWDate, typeLEQWDate:
		desc = expand(desc, formatTimeFlags(s.value.u64, timeWindows))
	case typeGUID:
		desc = expand(desc, formatGUID(s.value.raw[:16]))
	case typeSearch, typeRegex:
		n := s.search.rmLen
		if n > len(s.search.s) {
			n = len(s.search.s)
		}
		start := 0
		if s.search.offset < len(s.search.s) {
			// rm starts at the match within the original search slice after offset update.
		}
		text := ""
		if n > 0 && n <= len(s.search.s) {
			text = cString(s.search.s[:n])
		}
		if m.strFlags&stringTrim != 0 {
			text = trimString(text)
		}
		desc = expand(desc, printable(text))
		_ = start
	default:
		number := *m
		if asString {
			// check_fmt first renders a number into buf[128], then passes
			// that unpadded string to the description's %s conversion.
			number.desc = "%d"
			if m.flag&flagUnsigned != 0 {
				number.desc = "%u"
			}
			switch m.typ {
			case typeFloat, typeBEFloat, typeLEFloat, typeDouble, typeBEDouble, typeLEDouble:
				number.desc = "%g"
			}
		}
		desc = expand(desc, formatNumber(&number, s.value.u64))
	}
	if !s.appendFormatted(desc) {
		return false
	}
	return int32(end) != -1
}

func (s *state) appendFormatted(desc string) bool {
	if len(desc) > 1024 || len(desc)+s.buf.Len() > 1024*1024 {
		n := s.buf.Len()
		s.buf.Reset()
		s.err = fmt.Errorf("Output buffer space exceeded %d+%d", len(desc), n)
		return false
	}
	// file_vprintf appends through "%s%s"; a formatted NUL cannot
	// hide the descriptions appended by subsequent rules.
	s.buf.WriteString(desc[:cLen(desc)])
	return true
}

// FILE5_41 varexpand tests mode & 0111, not the value being formatted.
// Invalid variables or output overflow leave the entire original unchanged.
func expandQuery(desc, val string, limit int) string {
	original := desc
	var out strings.Builder
	for {
		start := strings.Index(desc, "${")
		if start < 0 {
			if out.Len()+len(desc) >= limit {
				return original
			}
			out.WriteString(desc)
			return out.String()
		}
		out.WriteString(desc[:start])
		body := desc[start+2:]
		if len(body) < 2 || body[0] != 'x' || body[1] != '?' {
			return original
		}
		colon := strings.IndexByte(body[2:], ':')
		if colon < 0 {
			return original
		}
		colon += 2
		end := strings.IndexByte(body[colon+1:], '}')
		if end < 0 {
			return original
		}
		end += colon + 1
		pick := body[colon+1 : end]
		if val == "1" {
			pick = body[2:colon]
		}
		if out.Len()+len(pick) >= limit {
			return original
		}
		out.WriteString(pick)
		desc = body[end+1:]
	}
}

func formatTime(v uint64) string {
	return formatTimeFlags(v, timeUTC)
}

const (
	timeUTC     = 0
	timeLocal   = 1
	timeWindows = 2
)

func formatTimeFlags(v uint64, flags int) string {
	if flags&timeWindows != 0 {
		sec, ok := cdfMktime(cdfCivilFromTimestamp(int64(v)))
		if !ok {
			return "*Invalid time*"
		}
		t := time.Unix(sec, 0).UTC()
		if year := t.Year(); year < -999 || year > 9999 {
			return "*Invalid time*"
		}
		return t.Format("Mon Jan _2 15:04:05 2006")
	}
	sec := int64(v)
	t := time.Unix(sec, 0)
	if flags&timeLocal != 0 {
		t = t.Local()
	} else {
		t = t.UTC()
	}
	// FILE5_41 uses asctime_r's 26-byte buffer and an unpadded %d year.
	year := t.Year()
	if year < -999 || year > 9999 {
		return "*Invalid time*"
	}
	return t.Format("Mon Jan _2 15:04:05 ") + fmt.Sprint(year)
}

func clipPrecision(desc, val string) string {
	if formatSpec(desc) != 's' {
		return val
	}
	n := formatPrecision(desc)
	if n >= 0 && len(val) > n {
		return val[:n]
	}
	return val
}

func formatPrecision(desc string) int {
	_, _, prec, _ := formatLayout(desc)
	return prec
}

func formatNumber(m *entry, v uint64) string {
	o := parseFormat(m.desc)
	spec, prec := o.spec, o.prec
	v = hostNumber(v, numericBits(m.typ))
	signed := int64(v)
	if m.flag&flagUnsigned == 0 {
		signed = signExtend(v, numericBits(m.typ))
	}
	// PRINTER promotes byte/short arguments to int; the format then
	// interprets the promoted 32-bit value, independently of UNSIGNED.
	if numericBits(m.typ) < 64 {
		v = uint64(uint32(signed))
	}
	if m.version16 && o.short {
		v = uint64(uint16(v))
		if spec == 'd' || spec == 'i' {
			v = uint64(int64(int16(v)))
		}
	}
	var text string
	switch spec {
	case 'd', 'i':
		if numericBits(m.typ) == 64 {
			text = fmt.Sprintf("%d", int64(v))
		} else {
			text = fmt.Sprintf("%d", int32(v))
		}
	case 'c':
		text = string([]byte{byte(v)})
	case 'x':
		text = fmt.Sprintf("%x", v)
	case 'X':
		text = fmt.Sprintf("%X", v)
	case 'o':
		text = fmt.Sprintf("%o", v)
	case 'u':
		text = fmt.Sprintf("%d", v)
	case 'e', 'E', 'f', 'F', 'g', 'G':
		return formatFloatBits(o, v, numericBits(m.typ) == 64)
	default:
		if m.flag&flagUnsigned != 0 {
			text = fmt.Sprintf("%d", v)
		} else {
			text = fmt.Sprintf("%d", signed)
		}
	}
	if strings.ContainsRune("diuoxX", rune(spec)) && prec >= 0 {
		sign := ""
		if strings.HasPrefix(text, "-") {
			sign, text = text[:1], text[1:]
		}
		if prec == 0 && text == "0" {
			text = ""
		}
		if prec > len(text) {
			text = strings.Repeat("0", prec-len(text)) + text
		}
		text = sign + text
		o.zero = false // Integer precision takes precedence over width's 0 flag.
	}
	if (spec == 'd' || spec == 'i') && o.sign != 0 && !strings.HasPrefix(text, "-") {
		// Signed conversions keep their sign even when %.0d prints no digits.
		text = string(o.sign) + text
	}
	if o.alt {
		switch spec {
		case 'x':
			if v != 0 {
				text = "0x" + text
			}
		case 'X':
			if v != 0 {
				text = "0X" + text
			}
		case 'o':
			if !strings.HasPrefix(text, "0") {
				text = "0" + text
			}
		}
	}
	return applyWidth(text, o)
}

func formatFloatBits(o formatOptions, bits uint64, wide bool) string {
	var fv float64
	if wide {
		fv = math.Float64frombits(bits)
	} else {
		fv = float64(math.Float32frombits(uint32(bits)))
	}
	var text string
	if math.IsNaN(fv) || math.IsInf(fv, 0) {
		text = "inf"
		if math.IsNaN(fv) {
			text = "nan"
		}
		if o.spec >= 'A' && o.spec <= 'Z' {
			text = strings.ToUpper(text)
		}
		if math.Signbit(fv) {
			text = "-" + text
		}
		o.zero = false // C pads infinities and NaNs with spaces, not zeroes.
	} else {
		prec := o.prec
		if prec < 0 {
			prec = 6
		}
		flag := ""
		if o.alt {
			flag = "#"
		}
		text = fmt.Sprintf("%"+flag+"."+fmt.Sprint(prec)+string(o.spec), fv)
		if o.alt && (o.spec == 'g' || o.spec == 'G') {
			digits := prec
			if digits == 0 {
				digits = 1
			}
			if i := strings.IndexAny(text, "eE"); i >= 0 {
				exponent, _ := strconv.Atoi(text[i+1:])
				if exponent == digits && math.Abs(fv) < math.Pow10(digits) {
					// glibc keeps the pre-rounding fractional minimum
					// when %g carries from fixed to exponent notation.
					text = strings.TrimRight(text[:i], "0") + text[i:]
				}
			}
		}
	}
	if o.sign != 0 && !strings.HasPrefix(text, "-") {
		text = string(o.sign) + text
	}
	return applyWidth(text, o)
}

func formatSpec(desc string) byte {
	spec, _, _, _ := formatLayout(desc)
	return spec
}

func expand(desc, val string) string {
	if !strings.Contains(desc, "%") {
		return desc
	}
	var b strings.Builder
	for i := 0; i < len(desc); i++ {
		if desc[i] != '%' {
			b.WriteByte(desc[i])
			continue
		}
		if i+1 < len(desc) && desc[i+1] == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		j := i + 1
		for j < len(desc) && strings.ContainsRune("#0.'+- ", rune(desc[j])) {
			j++
		}
		for j < len(desc) && desc[j] >= '0' && desc[j] <= '9' {
			j++
		}
		if j < len(desc) && desc[j] == '.' {
			j++
			for j < len(desc) && desc[j] >= '0' && desc[j] <= '9' {
				j++
			}
		}
		for j < len(desc) && strings.ContainsRune("hqljztL", rune(desc[j])) {
			j++
		}
		if j >= len(desc) {
			break
		}
		spec := desc[j]
		switch spec {
		case 's':
			b.WriteString(formatString(desc[i:j+1], val))
		case 'u', 'd', 'x', 'X', 'o', 'c', 'i':
			b.WriteString(val)
		default:
			b.WriteString(val)
		}
		i = j
	}
	return b.String()
}

func printable(s string) string {
	const printableMax = 511 // FILE5_41 mprint's 512-byte sbuf, including NUL.
	var b strings.Builder
	n := 0
	for i := 0; i < len(s) && n < printableMax; i++ {
		c := s[i]
		if c == 0 {
			break
		}
		if c >= 32 && c < 127 {
			b.WriteByte(c)
			n++
			continue
		}
		if n+4 > printableMax {
			break
		}
		fmt.Fprintf(&b, "\\%03o", c)
		n += 4
	}
	return b.String()
}

// textChars matches file 5.41 encoding.c.
// 0 never appears in text, 1 is plain ASCII, 2 is ISO-8859, 3 is extended.
var textChars = [256]byte{
	0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
	3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
}

// looksText reports whether soft-magic should treat the buffer as text.
// file 5.41 returns true for ASCII, UTF-8, UTF-16, UTF-32, Latin-1,
// extended ASCII, and EBCDIC. Encoding names stay out of scope; only the
// boolean that selects STRING_TEXTTEST versus STRING_BINTEST is needed.
func looksText(buf []byte) bool {
	return detectEncoding(buf).text
}

// looksEBCDIC applies the file 5.41 table without copying the buffer.
func looksEBCDIC(buf []byte) bool {
	ascii, latin := true, true
	for _, c := range buf {
		v := byte(0)
		if int(c) < len(ebcdicToASCII) {
			v = ebcdicToASCII[c]
		}
		if textChars[v] != 1 {
			ascii = false
			if textChars[v] != 2 {
				return false
			}
		}
		if !ascii && !latin {
			return false
		}
	}
	return ascii || latin
}

func looksASCII(buf []byte) bool {
	for _, c := range buf {
		if textChars[c] != 1 {
			return false
		}
	}
	return true
}

func looksLatin1(buf []byte) bool {
	for _, c := range buf {
		if textChars[c] != 1 && textChars[c] != 2 {
			return false
		}
	}
	return true
}

func looksExtended(buf []byte) bool {
	for _, c := range buf {
		if textChars[c] == 0 {
			return false
		}
	}
	return true
}

func looksUTF8(buf []byte) bool {
	return validUTF8(buf)
}

func looksUCS16(buf []byte) bool {
	if len(buf) < 2 {
		return false
	}
	be := buf[0] == 0xfe && buf[1] == 0xff
	le := buf[0] == 0xff && buf[1] == 0xfe
	if !be && !le {
		return false
	}
	for i := 2; i+1 < len(buf); i += 2 {
		var c uint16
		if be {
			c = uint16(buf[i])<<8 | uint16(buf[i+1])
		} else {
			c = uint16(buf[i]) | uint16(buf[i+1])<<8
		}
		if c == 0xfffe || (c < 128 && textChars[c] != 1) {
			return false
		}
	}
	return true
}

func looksUCS32(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	be := buf[0] == 0 && buf[1] == 0 && buf[2] == 0xfe && buf[3] == 0xff
	le := buf[0] == 0xff && buf[1] == 0xfe && buf[2] == 0 && buf[3] == 0
	if !be && !le {
		return false
	}
	for i := 4; i+3 < len(buf); i += 4 {
		var c uint32
		if be {
			c = uint32(buf[i])<<24 | uint32(buf[i+1])<<16 | uint32(buf[i+2])<<8 | uint32(buf[i+3])
		} else {
			c = uint32(buf[i]) | uint32(buf[i+1])<<8 | uint32(buf[i+2])<<16 | uint32(buf[i+3])<<24
		}
		if c == 0xfffe || (c < 128 && textChars[c] != 1) {
			return false
		}
	}
	return true
}

func fromEBCDIC(buf []byte) []byte {
	out := make([]byte, len(buf))
	for i, c := range buf {
		if int(c) < len(ebcdicToASCII) {
			out[i] = ebcdicToASCII[c]
		}
	}
	return out
}

// ebcdicToASCII is the file 5.41 translation used only to decide text-ness.
var ebcdicToASCII = []byte{
	0, 1, 2, 3, 156, 9, 134, 127, 151, 141, 142, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 157, 133, 8, 135, 24, 25, 146, 143, 28, 29, 30, 31,
	128, 129, 130, 131, 132, 10, 23, 27, 136, 137, 138, 139, 140, 5, 6, 7,
	144, 145, 22, 147, 148, 149, 150, 4, 152, 153, 154, 155, 20, 21, 158, 26,
	' ', 160, 161, 162, 163, 164, 165, 166, 167, 168, 213, '.', '<', '(', '+', '|',
	'&', 169, 170, 171, 172, 173, 174, 175, 176, 177, '!', '$', '*', ')', ';', '~',
	'-', '/', 178, 179, 180, 181, 182, 183, 184, 185, 203, ',', '%', '_', '>', '?',
	186, 187, 188, 189, 190, 191, 192, 193, 194, '`', ':', '#', '@', '\'', '=', '"',
	195, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 196, 197, 198, 199, 200, 201,
	202, 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '^', 204, 205, 206, 207, 208,
	209, 229, 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 210, 211, 212, '[', 214, 215,
	216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, ']', 230, 231,
	'{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 232, 233, 234, 235, 236, 237,
	'}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 238, 239, 240, 241, 242, 243,
	'\\', 159, 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 244, 245, 246, 247, 248, 249,
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 250, 251, 252, 253, 254, 255,
}
