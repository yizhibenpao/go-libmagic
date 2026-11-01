package libmagic

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type sourceMagicGroup struct {
	rules    []entry
	factorOp byte
	factor   uint8
	order    int
}

type sourceMagicFile struct {
	regular []sourceMagicGroup
	named   []sourceMagicGroup
}

type sourceTypeSpec struct {
	name string
	typ  uint8
}

var sourceTypes = []sourceTypeSpec{
	{"bestring16", typeBEStr16},
	{"lestring16", typeLEStr16},
	{"bevarint", typeBEVarint},
	{"levarint", typeLEVarint},
	{"beqwdate", typeBEQWDate},
	{"leqwdate", typeLEQWDate},
	{"beqldate", typeBEQLDate},
	{"leqldate", typeLEQLDate},
	{"beqdate", typeBEQDate},
	{"leqdate", typeLEQDate},
	{"beldate", typeBELDate},
	{"leldate", typeLELDate},
	{"bedate", typeBEDate},
	{"ledate", typeLEDate},
	{"belong", typeBELong},
	{"lelong", typeLELong},
	{"beshort", typeBEShort},
	{"leshort", typeLEShort},
	{"bedouble", typeBEDouble},
	{"ledouble", typeLEDouble},
	{"befloat", typeBEFloat},
	{"lefloat", typeLEFloat},
	{"bequad", typeBEQuad},
	{"lequad", typeLEQuad},
	{"beid3", typeBEID3},
	{"leid3", typeLEID3},
	{"meldate", typeMELDate},
	{"medate", typeMEDate},
	{"melong", typeMELong},
	{"qldate", typeQLDate},
	{"qdate", typeQDate},
	{"qwdate", typeQWDate},
	{"ldate", typeLDate},
	{"pstring", typePString},
	{"indirect", typeIndirect},
	{"default", typeDefault},
	{"byte", typeByte},
	{"double", typeDouble},
	{"float", typeFloat},
	{"short", typeShort},
	{"long", typeLong},
	{"string", typeString},
	{"regex", typeRegex},
	{"search", typeSearch},
	{"quad", typeQuad},
	{"date", typeDate},
	{"name", typeName},
	{"use", typeUse},
	{"clear", typeClear},
	{"der", typeDER},
	{"guid", typeGUID},
	{"offset", typeOffset},
}

func openSourceDatabase(name string) (*Database, error) {
	source, err := parseSourceMagicFile(name)
	if err != nil {
		return nil, err
	}
	set, err := sourceMagicSet(source)
	if err != nil {
		return nil, err
	}
	return &Database{sets: []magicSet{set}}, nil
}

func sourceMagicCandidate(name string) (bool, error) {
	file, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer file.Close()

	buf := make([]byte, 4096)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}
	return !bytes.Contains(buf[:n], []byte{0}), nil
}

func openSourceDirectory(paths []string, tolerateErrors bool) (magicSet, bool, error) {
	var merged sourceMagicFile
	order := 0
	loaded := false
	for _, path := range paths {
		source, err := parseSourceMagicFile(path)
		if err != nil {
			if tolerateErrors {
				continue
			}
			return magicSet{}, false, err
		}
		loaded = true
		for _, group := range source.regular {
			group.order = order
			order++
			merged.regular = append(merged.regular, group)
		}
		for _, group := range source.named {
			group.order = order
			order++
			merged.named = append(merged.named, group)
		}
	}
	if !loaded {
		return magicSet{}, false, nil
	}
	set, err := sourceMagicSet(merged)
	if err != nil {
		return magicSet{}, false, err
	}
	return set, true, nil
}

func parseSourceMagicFile(name string) (sourceMagicFile, error) {
	file, err := os.Open(name)
	if err != nil {
		return sourceMagicFile{}, fmt.Errorf("cannot read magic file `%s' (%s)", name, systemError(err))
	}
	defer file.Close()

	var result sourceMagicFile
	var current *sourceMagicGroup
	order := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "!:") {
			if current == nil {
				return sourceMagicFile{}, fmt.Errorf("%s:%d: directive without current magic entry", name, lineNo)
			}
			if err := parseSourceDirective(current, line[2:]); err != nil {
				return sourceMagicFile{}, fmt.Errorf("%s:%d: %w", name, lineNo, err)
			}
			continue
		}
		rule, level, err := parseSourceRule(line, lineNo)
		if err != nil {
			return sourceMagicFile{}, fmt.Errorf("%s:%d: %w", name, lineNo, err)
		}
		if level == 0 {
			group := sourceMagicGroup{rules: []entry{rule}, order: order}
			order++
			if rule.typ == typeName {
				result.named = append(result.named, group)
				current = &result.named[len(result.named)-1]
			} else {
				result.regular = append(result.regular, group)
				current = &result.regular[len(result.regular)-1]
			}
			continue
		}
		if current == nil {
			return sourceMagicFile{}, fmt.Errorf("continuation without a top-level entry")
		}
		if level > int(current.rules[len(current.rules)-1].contLevel)+1 {
			return sourceMagicFile{}, fmt.Errorf("continuation level %d is more than one larger than %d", level, current.rules[len(current.rules)-1].contLevel)
		}
		rule.contLevel = uint16(level)
		current.rules = append(current.rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return sourceMagicFile{}, fmt.Errorf("error reading (%s)", systemError(err))
	}
	return result, nil
}

func parseSourceDirective(group *sourceMagicGroup, directive string) error {
	fields := strings.Fields(directive)
	if len(fields) == 0 {
		return fmt.Errorf("empty !: directive")
	}
	for i, field := range fields {
		if strings.HasPrefix(field, "#") {
			fields = fields[:i]
			break
		}
	}
	if len(fields) == 0 {
		return fmt.Errorf("empty !: directive")
	}
	switch fields[0] {
	case "mime":
		if len(fields) < 2 {
			return fmt.Errorf("bad !:mime directive")
		}
		rule := &group.rules[len(group.rules)-1]
		if rule.mime != "" {
			return fmt.Errorf("current entry already has a MIME type")
		}
		rule.mime = fields[1]
	case "strength":
		if len(fields) < 2 || len(fields) > 3 {
			return fmt.Errorf("bad !:strength directive")
		}
		if group.factorOp != 0 {
			return fmt.Errorf("duplicate !:strength directive")
		}
		if group.rules[0].typ == typeName {
			return fmt.Errorf("!:strength is not supported for name entries")
		}
		operator := fields[1]
		valueText := ""
		if len(fields) == 3 {
			if len(operator) != 1 {
				return fmt.Errorf("bad !:strength directive")
			}
			valueText = fields[2]
		} else {
			if len(operator) < 2 {
				return fmt.Errorf("bad !:strength directive")
			}
			valueText = operator[1:]
		}
		switch operator[0] {
		case '+', '-', '*', '/':
			group.factorOp = operator[0]
		default:
			return fmt.Errorf("bad !:strength operator %q", operator)
		}
		value, err := strconv.ParseUint(valueText, 0, 8)
		if err != nil {
			return fmt.Errorf("bad !:strength value %q", valueText)
		}
		if group.factorOp == '/' && value == 0 {
			return fmt.Errorf("bad !:strength value %q", valueText)
		}
		group.factor = uint8(value)
	case "apple", "ext":
		// These fields are not consumed by the Go runtime.
	default:
		return fmt.Errorf("unknown !:%s directive", fields[0])
	}
	return nil
}

func parseSourceRule(line string, lineNo int) (entry, int, error) {
	var m entry
	m.version16 = true
	m.lineno = uint32(lineNo)
	m.reln = '='
	i := 0
	for i < len(line) && line[i] == '>' {
		i++
	}
	level := i
	if i < len(line) && line[i] == '&' {
		m.flag |= flagOffAdd
		i++
	}
	if i < len(line) && line[i] == '(' {
		m.flag |= flagIndir
		i++
		if i < len(line) && line[i] == '&' {
			m.flag = (m.flag &^ flagOffAdd) | flagIndirOffAdd
			i++
		}
		if i < len(line) && line[i] == '-' {
			m.flag |= flagOffNegative
		}
		value, next, err := sourceInteger(line, i)
		if err != nil {
			return entry{}, 0, fmt.Errorf("invalid offset")
		}
		m.offset = int32(value)
		i = next
		i, err = parseSourceIndirect(line, i, &m)
		if err != nil {
			return entry{}, 0, err
		}
	} else {
		if i < len(line) && line[i] == '-' {
			m.flag |= flagOffNegative
		}
		value, next, err := sourceInteger(line, i)
		if err != nil {
			return entry{}, 0, fmt.Errorf("invalid offset")
		}
		m.offset = int32(value)
		i = next
	}
	i = sourceSpace(line, i)
	if i < len(line) {
		switch {
		case strings.HasPrefix(line[i:], "if ") || strings.HasPrefix(line[i:], "if\t"):
			m.cond = condIf
			i += 2
		case strings.HasPrefix(line[i:], "elif ") || strings.HasPrefix(line[i:], "elif\t"):
			m.cond = condElif
			i += 4
		case strings.HasPrefix(line[i:], "else ") || strings.HasPrefix(line[i:], "else\t"):
			m.cond = condElse
			i += 4
		}
		i = sourceSpace(line, i)
	}

	typ, next, unsigned, err := sourceType(line, i)
	if err != nil {
		return entry{}, 0, err
	}
	m.typ = typ
	i = next
	if unsigned {
		m.flag |= flagUnsigned
	}
	if level == 0 && m.flag&(flagOffAdd|flagIndirOffAdd) != 0 {
		return entry{}, 0, fmt.Errorf("relative offset at level 0")
	}
	if level != 0 && m.typ == typeName {
		return entry{}, 0, fmt.Errorf("name entries can only be declared at top level")
	}
	if m.typ == typePString {
		m.strFlags = pstring1BE
	}
	if i < len(line) && line[i] == '~' {
		if !isSourceStringType(m.typ) {
			m.maskOp |= opInverse
		}
		i++
	}
	if i < len(line) && line[i] == '/' && m.typ == typeIndirect {
		next, err = parseSourceIndirectModifier(line, i+1, &m)
		if err != nil {
			return entry{}, 0, err
		}
		i = next
	} else if i < len(line) && line[i] == '/' && isSourceStringType(m.typ) {
		next, err = parseSourceStringModifier(line, i+1, &m)
		if err != nil {
			return entry{}, 0, err
		}
		i = next
	} else if i < len(line) && isSourceOperator(line[i]) {
		if isSourceStringType(m.typ) {
			return entry{}, 0, fmt.Errorf("numeric operator on string type")
		}
		op, ok := sourceOperator(line[i])
		if !ok {
			return entry{}, 0, fmt.Errorf("invalid operator")
		}
		m.maskOp = op
		i++
		mask, next, err := sourceInteger(line, i)
		if err != nil {
			return entry{}, 0, fmt.Errorf("invalid numeric mask")
		}
		m.numMask = uint64(mask)
		if m.flag&flagUnsigned == 0 {
			m.numMask = uint64(signExtend(m.numMask, numericBits(m.typ)))
		}
		i = next
	}
	i = sourceSpace(line, i)
	if i < len(line) && strings.ContainsRune("><&^=!", rune(line[i])) {
		m.reln = line[i]
		i++
		if i < len(line) && line[i] == '=' {
			i++
		}
	} else if i >= len(line) || line[i] != 'x' ||
		(i+1 < len(line) && !sourceSpaceOrEnd(line, i+1)) {
		m.reln = '='
	} else {
		m.reln = 'x'
		i++
	}
	i = sourceSpace(line, i)
	if m.reln != 'x' {
		next, err = parseSourceValue(line, i, &m)
		if err != nil {
			return entry{}, 0, err
		}
		i = next
	}
	i = sourceSpace(line, i)
	if i < len(line) && line[i] == '\\' && i+1 < len(line) && line[i+1] == 'b' {
		m.flag |= flagNoSpace
		i += 2
	} else if i < len(line) && line[i] == '\b' {
		m.flag |= flagNoSpace
		i++
	}
	m.desc = line[sourceSpace(line, i):]
	return m, level, nil
}

func parseSourceIndirect(line string, i int, m *entry) (int, error) {
	m.inType = typeLong
	m.inOffset = 0
	m.inOp = 0
	if i < len(line) && (line[i] == '.' || line[i] == ',') {
		if line[i] == ',' {
			m.inOp |= opSigned
		}
		i++
		switch line[i] {
		case 'l':
			m.inType = typeLELong
		case 'L':
			m.inType = typeBELong
		case 'm':
			m.inType = typeMELong
		case 'h', 's':
			m.inType = typeLEShort
		case 'H', 'S':
			m.inType = typeBEShort
		case 'c', 'b', 'C', 'B':
			m.inType = typeByte
		case 'e', 'f', 'g':
			m.inType = typeLEDouble
		case 'E', 'F', 'G':
			m.inType = typeBEDouble
		case 'i':
			m.inType = typeLEID3
		case 'I':
			m.inType = typeBEID3
		case 'q':
			m.inType = typeLEQuad
		case 'Q':
			m.inType = typeBEQuad
		default:
			return i, fmt.Errorf("invalid indirect offset type")
		}
		i++
	}
	if i < len(line) && line[i] == '~' {
		m.inOp |= opInverse
		i++
	}
	if i < len(line) {
		if op, ok := sourceOperator(line[i]); ok {
			m.inOp |= op
			i++
		}
	}
	if i < len(line) && line[i] == '(' {
		m.inOp |= opIndirect
		i++
	}
	if i < len(line) && (line[i] == '-' || line[i] >= '0' && line[i] <= '9') {
		value, next, err := sourceInteger(line, i)
		if err != nil {
			return i, fmt.Errorf("invalid indirect offset")
		}
		m.inOffset = int32(value)
		i = next
	}
	if i >= len(line) || line[i] != ')' {
		return i, fmt.Errorf("missing ')' in indirect offset")
	}
	i++
	if m.inOp&opIndirect != 0 {
		if i >= len(line) || line[i] != ')' {
			return i, fmt.Errorf("missing ')' in indirect offset")
		}
		i++
	}
	return i, nil
}

func parseSourceIndirectModifier(line string, i int, m *entry) (int, error) {
	for i < len(line) && !sourceSpaceByte(line[i]) {
		if line[i] != 'r' {
			return i, fmt.Errorf("invalid indirect modifier %q", line[i])
		}
		m.strFlags |= indirectRelative
		i++
	}
	return i, nil
}

func sourceType(line string, i int) (uint8, int, bool, error) {
	if typ, next, ok := sourceTypeSpecAt(line, i); ok {
		return typ, next, false, nil
	}
	start := i
	if i < len(line) && line[i] == 'u' {
		if typ, next, ok := sourceTypeSpecAt(line, i+1); ok {
			return typ, next, true, nil
		}
	}
	if typ, next, standardUnsigned, ok := sourceStandardIntegerType(line, i); ok {
		return typ, next, standardUnsigned, nil
	}
	if i < len(line) && line[i] == 's' &&
		(i+1 == len(line) || !isSourceAlpha(line[i+1])) {
		return typeString, i + 1, false, nil
	}
	return typeInvalid, start, false, fmt.Errorf("invalid type")
}

func sourceTypeSpecAt(line string, i int) (uint8, int, bool) {
	for _, item := range sourceTypes {
		if !strings.HasPrefix(line[i:], item.name) {
			continue
		}
		next := i + len(item.name)
		if next < len(line) && isSourceAlpha(line[next]) {
			continue
		}
		return item.typ, next, true
	}
	return typeInvalid, i, false
}

func sourceStandardIntegerType(line string, i int) (uint8, int, bool, bool) {
	if i >= len(line) || (line[i] != 'd' && line[i] != 'u') {
		return typeInvalid, i, false, false
	}
	unsigned := line[i] == 'u'
	next := i + 1
	if next == len(line) || !isSourceAlpha(line[next]) &&
		(line[next] < '0' || line[next] > '9') {
		return typeLong, next, unsigned, true
	}
	if isSourceAlpha(line[next]) {
		var typ uint8
		switch line[next] {
		case 'C':
			typ = typeByte
		case 'S':
			typ = typeShort
		case 'I', 'L':
			typ = typeLong
		case 'Q':
			typ = typeQuad
		default:
			return typeInvalid, i, false, false
		}
		return typ, next + 1, unsigned, true
	}
	if line[next] < '0' || line[next] > '9' ||
		next+1 < len(line) && line[next+1] >= '0' && line[next+1] <= '9' {
		return typeInvalid, i, false, false
	}
	var typ uint8
	switch line[next] {
	case '1':
		typ = typeByte
	case '2':
		typ = typeShort
	case '4':
		typ = typeLong
	case '8':
		typ = typeQuad
	default:
		return typeInvalid, i, false, false
	}
	return typ, next + 1, unsigned, true
}

func parseSourceStringModifier(line string, i int, m *entry) (int, error) {
	for i < len(line) && !sourceSpaceByte(line[i]) {
		switch line[i] {
		case 'W':
			if m.typ == typeRegex || m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= stringCompactWhitespace
		case 'w':
			if m.typ == typeRegex || m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= stringCompactOptionalWhitespace
		case 'c':
			if m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= stringIgnoreLower
		case 'C':
			if m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= stringIgnoreUpper
		case 's':
			if m.typ == typeString || m.typ == typePString ||
				m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= regexOffsetStart
		case 'b':
			if m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= stringBinTest
		case 't':
			if m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= stringTextTest
		case 'T':
			if m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= stringTrim
		case 'f':
			if m.typ == typeBEStr16 || m.typ == typeLEStr16 {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= stringFullWord
		case 'B':
			if m.typ != typePString {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags = (m.strFlags &^ pstringLen) | pstring1BE
		case 'H':
			if m.typ != typePString {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags = (m.strFlags &^ pstringLen) | pstring2BE
		case 'h':
			if m.typ != typePString {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags = (m.strFlags &^ pstringLen) | pstring2LE
		case 'L':
			if m.typ != typePString {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags = (m.strFlags &^ pstringLen) | pstring4BE
		case 'l':
			if m.typ != typePString && m.typ != typeRegex {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags = (m.strFlags &^ pstringLen) | pstring4LE
		case 'J':
			if m.typ != typePString {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			m.strFlags |= pstringLenIncludesItself
		default:
			if line[i] < '0' || line[i] > '9' {
				return i, fmt.Errorf("invalid string modifier %q", line[i])
			}
			start := i
			if i+1 < len(line) && line[i] == '0' &&
				(line[i+1] == 'x' || line[i+1] == 'X') {
				i += 2
				for i < len(line) && isSourceHex(line[i]) {
					i++
				}
			} else {
				for i < len(line) && line[i] >= '0' && line[i] <= '9' {
					i++
				}
			}
			value, err := strconv.ParseUint(line[start:i], 0, 32)
			if err != nil || value == 0 {
				return i, fmt.Errorf("invalid string range")
			}
			m.strRange = uint32(value)
			if i < len(line) && line[i] == '/' && i+1 < len(line) &&
				!sourceSpaceByte(line[i+1]) {
				i++
			}
			continue
		}
		if i+2 < len(line) && line[i+1] == '/' && !sourceSpaceByte(line[i+2]) {
			i++
		}
		i++
	}
	return i, nil
}

func parseSourceValue(line string, i int, m *entry) (int, error) {
	if isSourceStringType(m.typ) || m.typ == typeName || m.typ == typeUse || m.typ == typeDER {
		token, next := sourceToken(line, i)
		decoded := decodeMagicString(token)
		if len(decoded) > maxString {
			return i, fmt.Errorf("string value too long")
		}
		copy(m.value[:], decoded)
		m.vallen = uint8(len(decoded))
		if m.typ == typePString {
			n, ok := pascalLengthSize(m.strFlags)
			if !ok || len(decoded)+n > maxString {
				return i, fmt.Errorf("invalid pascal string length")
			}
			m.vallen += uint8(n)
		}
		return next, nil
	}
	if m.typ == typeFloat || m.typ == typeBEFloat || m.typ == typeLEFloat {
		token, next := sourceToken(line, i)
		value, err := strconv.ParseFloat(token, 32)
		if err != nil {
			return i, fmt.Errorf("invalid float value")
		}
		m.quad = uint64(math.Float32bits(float32(value)))
		return next, nil
	}
	if m.typ == typeDouble || m.typ == typeBEDouble || m.typ == typeLEDouble {
		token, next := sourceToken(line, i)
		value, err := strconv.ParseFloat(token, 64)
		if err != nil {
			return i, fmt.Errorf("invalid double value")
		}
		m.quad = math.Float64bits(value)
		return next, nil
	}
	if m.typ == typeGUID {
		token, next := sourceToken(line, i)
		guid, err := parseSourceGUID(token)
		if err != nil {
			return i, err
		}
		m.guid = guid
		return next, nil
	}
	value, next, err := sourceInteger(line, i)
	if err != nil {
		return i, fmt.Errorf("invalid numeric value")
	}
	m.quad = uint64(value)
	if m.flag&flagUnsigned == 0 {
		m.quad = uint64(signExtend(m.quad, numericBits(m.typ)))
	}
	return next, nil
}

func sourceMagicSet(source sourceMagicFile) (magicSet, error) {
	for i := range source.regular {
		for j := range source.regular[i].rules {
			sourceSetTestType(&source.regular[i].rules[0], &source.regular[i].rules[j])
		}
	}
	sortSourceGroups(source.regular)
	sortSourceGroups(source.named)
	var set magicSet
	set.names = make(map[string]int)
	for _, group := range source.regular {
		if err := prepareSourceRules(group.rules); err != nil {
			return magicSet{}, err
		}
		set.rules = append(set.rules, group.rules...)
	}
	set.n0 = len(set.rules)
	for _, group := range source.named {
		if err := prepareSourceRules(group.rules); err != nil {
			return magicSet{}, err
		}
		start := len(set.rules)
		set.rules = append(set.rules, group.rules...)
		name := cString(group.rules[0].value[:])
		if name != "" {
			set.names[name] = start
		}
	}
	return set, nil
}

func sourceSetTestType(root, m *entry) {
	switch m.typ {
	case typeByte, typeShort, typeLong, typeDate, typeBEShort, typeBELong,
		typeBEDate, typeLEShort, typeLELong, typeLEDate, typeLDate,
		typeBELDate, typeLELDate, typeMEDate, typeMELDate, typeMELong,
		typeQuad, typeLEQuad, typeBEQuad, typeQDate, typeLEQDate,
		typeBEQDate, typeQLDate, typeLEQLDate, typeBEQLDate, typeQWDate,
		typeLEQWDate, typeBEQWDate, typeFloat, typeBEFloat, typeLEFloat,
		typeDouble, typeBEDouble, typeLEDouble, typeBEVarint, typeLEVarint,
		typeDER, typeGUID, typeOffset:
		root.flag |= flagBinTest
	case typeString, typePString, typeBEStr16, typeLEStr16:
		if root.strFlags&stringTextTest != 0 {
			root.flag |= flagTextTest
		} else {
			root.flag |= flagBinTest
		}
	case typeRegex, typeSearch:
		if root.strFlags&stringBinTest != 0 {
			root.flag |= flagBinTest
		}
		if root.strFlags&stringTextTest != 0 {
			root.flag |= flagTextTest
		}
		if root.flag&(flagBinTest|flagTextTest) == 0 {
			if utf8.Valid(m.value[:m.vallen]) {
				root.flag |= flagTextTest
			} else {
				root.flag |= flagBinTest
			}
		}
	}
}

func prepareSourceRules(rules []entry) error {
	for i := range rules {
		if rules[i].typ == typeRegex {
			rules[i].re = compileRule(&rules[i])
			if rules[i].re == nil {
				return fmt.Errorf("invalid regular expression at line %d", rules[i].lineno)
			}
		}
	}
	return nil
}

func sortSourceGroups(groups []sourceMagicGroup) {
	sort.SliceStable(groups, func(i, j int) bool {
		left := sourceMagicStrength(groups[i])
		right := sourceMagicStrength(groups[j])
		if left == right {
			return groups[i].order < groups[j].order
		}
		return left > right
	})
}

func sourceMagicStrength(group sourceMagicGroup) int {
	if len(group.rules) == 0 {
		return 0
	}
	m := group.rules[0]
	if m.typ == typeDefault {
		return 0
	}
	value := 20
	switch {
	case m.typ == typeString || m.typ == typePString:
		value += int(m.vallen) * 10
	case m.typ == typeBEStr16 || m.typ == typeLEStr16:
		value += int(m.vallen) * 5
	case m.typ == typeSearch:
		if m.vallen != 0 {
			value += int(m.vallen) * maxInt(10/int(m.vallen), 1)
		}
	case m.typ == typeRegex:
		length := sourceNonMagic(m.value[:m.vallen])
		value += length * maxInt(10/length, 1)
	case m.typ == typeDER:
		value += 10
	case m.typ == typeBEVarint || m.typ == typeLEVarint:
		value += 8 * 10
	default:
		value += width(m.typ) * 10
	}
	switch m.reln {
	case 'x', '!':
		value = 0
	case '=':
		value += 10
	case '>', '<':
		value -= 20
	case '^', '&':
		value -= 10
	}
	switch group.factorOp {
	case '+':
		value += int(group.factor)
	case '-':
		value -= int(group.factor)
	case '*':
		value *= int(group.factor)
	case '/':
		if group.factor != 0 {
			value /= int(group.factor)
		}
	}
	if value <= 0 {
		value = 1
	}
	if m.desc == "" {
		value++
	}
	return value
}

func sourceNonMagic(pattern []byte) int {
	length := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			if i+1 < len(pattern) {
				i++
			}
			length++
		case '?', '*', '.', '+', '^', '$':
			continue
		case '[':
			for i < len(pattern) && pattern[i] != ']' {
				i++
			}
			if i < len(pattern) && pattern[i] == ']' {
				i--
			}
		case '{':
			for i < len(pattern) && pattern[i] != '}' {
				i++
			}
		default:
			length++
		}
	}
	if length == 0 {
		return 1
	}
	return length
}

func sourceInteger(line string, i int) (int64, int, error) {
	start := i
	if i < len(line) && (line[i] == '+' || line[i] == '-') {
		i++
	}
	if i+2 <= len(line) && i < len(line) && line[i] == '0' && i+1 < len(line) && (line[i+1] == 'x' || line[i+1] == 'X') {
		i += 2
		for i < len(line) && isSourceHex(line[i]) {
			i++
		}
	} else {
		for i < len(line) && line[i] >= '0' && line[i] <= '9' {
			i++
		}
	}
	for i < len(line) && strings.ContainsRune("uUlLsSbBcC", rune(line[i])) {
		i++
	}
	if i == start || (i == start+1 && (line[start] == '+' || line[start] == '-')) {
		return 0, start, fmt.Errorf("number expected")
	}
	token := line[start:i]
	if token == "" || token == "+" || token == "-" {
		return 0, start, fmt.Errorf("number expected")
	}
	value, err := strconv.ParseInt(token, 0, 64)
	if err != nil {
		trimmed := token
		for len(trimmed) > 0 && strings.ContainsRune("uUlLsSbBcC", rune(trimmed[len(trimmed)-1])) {
			trimmed = trimmed[:len(trimmed)-1]
			if trimmed == "" || trimmed == "+" || trimmed == "-" {
				break
			}
			if value, err = strconv.ParseInt(trimmed, 0, 64); err == nil {
				return value, i, nil
			}
		}
	} else {
		return value, i, nil
	}
	unsigned, unsignedErr := strconv.ParseUint(strings.TrimPrefix(token, "+"), 0, 64)
	if unsignedErr != nil {
		trimmed := token
		for len(trimmed) > 0 && strings.ContainsRune("uUlLsSbBcC", rune(trimmed[len(trimmed)-1])) {
			trimmed = trimmed[:len(trimmed)-1]
			if trimmed == "" || trimmed == "+" || trimmed == "-" {
				break
			}
			unsigned, unsignedErr = strconv.ParseUint(strings.TrimPrefix(trimmed, "+"), 0, 64)
			if unsignedErr == nil {
				return int64(unsigned), i, nil
			}
		}
	}
	if unsignedErr != nil {
		return 0, start, err
	}
	return int64(unsigned), i, nil
}

func sourceToken(line string, i int) (string, int) {
	start := i
	for i < len(line) {
		if sourceSpaceByte(line[i]) {
			break
		}
		if line[i] == '\\' && i+1 < len(line) {
			i += 2
			continue
		}
		i++
	}
	return line[start:i], i
}

func decodeMagicString(token string) []byte {
	var out []byte
	for i := 0; i < len(token); i++ {
		if token[i] != '\\' {
			out = append(out, token[i])
			continue
		}
		if i+1 >= len(token) {
			break
		}
		i++
		switch token[i] {
		case 'a':
			out = append(out, '\a')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, '\v')
		case 'x':
			value := byte('x')
			if i+1 < len(token) && isSourceHex(token[i+1]) {
				value = sourceHexValue(token[i+1])
				i++
				if i+1 < len(token) && isSourceHex(token[i+1]) {
					value = value<<4 | sourceHexValue(token[i+1])
					i++
				}
			}
			out = append(out, value)
		default:
			if token[i] >= '0' && token[i] <= '7' {
				value := byte(token[i] - '0')
				for n := 0; n < 2 && i+1 < len(token) && token[i+1] >= '0' && token[i+1] <= '7'; n++ {
					i++
					value = value<<3 | (token[i] - '0')
				}
				out = append(out, value)
			} else {
				out = append(out, token[i])
			}
		}
	}
	return out
}

func parseSourceGUID(token string) ([16]byte, error) {
	var result [16]byte
	hex := strings.ReplaceAll(token, "-", "")
	if len(hex) != 32 {
		return result, fmt.Errorf("invalid GUID %q", token)
	}
	raw := make([]byte, 16)
	for i := range raw {
		value, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return result, fmt.Errorf("invalid GUID %q", token)
		}
		raw[i] = byte(value)
	}
	binary.LittleEndian.PutUint32(result[0:4], binary.BigEndian.Uint32(raw[0:4]))
	binary.LittleEndian.PutUint16(result[4:6], binary.BigEndian.Uint16(raw[4:6]))
	binary.LittleEndian.PutUint16(result[6:8], binary.BigEndian.Uint16(raw[6:8]))
	copy(result[8:], raw[8:])
	return result, nil
}

func sourceOperator(b byte) (uint8, bool) {
	switch b {
	case '&':
		return opAnd, true
	case '|':
		return opOr, true
	case '^':
		return opXor, true
	case '+':
		return opAdd, true
	case '-':
		return opSub, true
	case '*':
		return opMul, true
	case '/':
		return opDiv, true
	case '%':
		return opMod, true
	default:
		return 0, false
	}
}

func isSourceOperator(b byte) bool {
	_, ok := sourceOperator(b)
	return ok
}

func isSourceStringType(typ uint8) bool {
	switch typ {
	case typeString, typePString, typeBEStr16, typeLEStr16, typeRegex, typeSearch, typeName, typeUse, typeDER:
		return true
	default:
		return false
	}
}

func sourceSpace(s string, i int) int {
	for i < len(s) && sourceSpaceByte(s[i]) {
		i++
	}
	return i
}

func sourceSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\v' || b == '\f' || b == '\r'
}

func sourceSpaceOrEnd(s string, i int) bool {
	return i >= len(s) || sourceSpaceByte(s[i])
}

func isSourceAlpha(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isSourceHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

func sourceHexValue(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
