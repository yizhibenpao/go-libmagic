package libmagic

import (
	"fmt"
	"strings"
)

// Trace reports which compiled rules write a description for data.
func (db *Database) Trace(data []byte) (string, []string) {
	if len(data) == 0 {
		return "empty", nil
	}
	var hits []string
	text := looksText(data)
	indir := 0
	for si := range db.sets {
		st := &state{db: db, set: &db.sets[si], text: text, buf: &strings.Builder{}, trace: &hits, setIndex: si}
		if st.soft(data, 0, flagBinTest, &indir, 0) {
			return st.buf.String(), hits
		}
	}
	return "data", hits
}

func (s *state) note(m *entry, idx int, why string) {
	if s.trace == nil {
		return
	}
	line := fmt.Sprintf("set=%d i=%d L=%d typ=%d rel=%q off=%d flag=%#x mask=%#x op=%d val=%#x quad=%#x %s desc=%q",
		s.setIndex, idx, m.contLevel, m.typ, string(m.reln), m.offset, m.flag, m.numMask, m.maskOp, s.value.u64, m.quad, why, m.desc)
	*s.trace = append(*s.trace, line)
}
