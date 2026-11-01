package libmagic

import (
	"regexp/syntax"
	"sort"
)

// expandRegexRepeats follows GNU parse_dup_op: optional copies precede
// the last copy, so duplicated capture-node order is preserved.
func expandRegexRepeats(r *syntax.Regexp) *syntax.Regexp {
	for i, sub := range r.Sub {
		r.Sub[i] = expandRegexRepeats(sub)
	}
	if r.Op != syntax.OpRepeat {
		return r
	}
	child := r.Sub[0]
	var pieces []*syntax.Regexp
	for i := 0; i < r.Min; i++ {
		pieces = append(pieces, child)
	}
	if r.Max != r.Min {
		var suffix *syntax.Regexp
		if r.Max < 0 {
			suffix = &syntax.Regexp{Op: syntax.OpStar, Sub: []*syntax.Regexp{child}}
		} else {
			suffix = &syntax.Regexp{Op: syntax.OpQuest, Sub: []*syntax.Regexp{child}}
			for i := r.Min + 2; i <= r.Max; i++ {
				suffix = &syntax.Regexp{Op: syntax.OpQuest, Sub: []*syntax.Regexp{
					{Op: syntax.OpConcat, Sub: []*syntax.Regexp{suffix, child}},
				}}
			}
		}
		pieces = append(pieces, suffix)
	}
	switch len(pieces) {
	case 0:
		return &syntax.Regexp{Op: syntax.OpEmptyMatch}
	case 1:
		return pieces[0]
	default:
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: pieces}
	}
}

type regexBackrefNode struct {
	pc  uint32
	pos int
}

type regexBackrefValue struct {
	lo, hi int
	id     int
}

type regexBackrefMatch struct {
	vm      *regexVM
	data    []rune
	states  []map[uint32]bool
	refs    map[regexBackrefNode][]regexBackrefValue
	opens   []regexBackrefNode
	known   map[regexBackrefNode]bool
	entries int
	lasts   map[regexBackrefNode][]regexBackrefNode
}

// matchBackrefsAt follows the forward state log, first-close lookup and
// boundary-limited arrival checks in GNU get_subexp. Initial nullable
// references follow create_initial_state, independently of runtime cache.
// Forward halts are then validated by prune_impossible_nodes-style sifting.
func (vm *regexVM) matchBackrefsAt(data []rune, start int) int {
	m := regexBackrefMatch{
		lasts: make(map[regexBackrefNode][]regexBackrefNode),
		vm:    vm, data: data, states: make([]map[uint32]bool, len(data)+1),
		refs: make(map[regexBackrefNode][]regexBackrefValue), known: make(map[regexBackrefNode]bool),
	}
	m.add(regexBackrefNode{uint32(vm.prog.Start), start})
	for {
		before := len(m.states[start])
		for pc := range m.states[start] {
			inst := &vm.prog.Inst[pc]
			op, ok := vm.ops[inst.Arg>>1]
			if inst.Op != syntax.InstCapture || inst.Arg&1 != 0 || !ok || op.kind < '1' || op.kind > '9' {
				continue
			}
			for close := range m.states[start] {
				end := &vm.prog.Inst[close]
				if end.Op == syntax.InstCapture && end.Arg == op.target*2+1 {
					m.add(regexBackrefNode{inst.Out, start})
					break
				}
			}
		}
		if before == len(m.states[start]) {
			break
		}
	}
	best := -1
	for pos := start; pos <= len(data); pos++ {
		for {
			var pcs []int
			for pc := range m.states[pos] {
				pcs = append(pcs, int(pc))
			}
			sort.Ints(pcs)
			for _, p := range pcs {
				pc := uint32(p)
				inst := &vm.prog.Inst[pc]
				group := inst.Arg >> 1
				key := regexBackrefNode{pc, pos}
				if inst.Op == syntax.InstCapture && inst.Arg&1 == 0 && !m.known[key] {
					if _, ok := vm.captures[group]; ok {
						m.opens = append(m.opens, key)
						m.known[key] = true
					}
				}
			}
			before := len(m.states[pos])
			for _, p := range pcs {
				pc := uint32(p)
				inst := &vm.prog.Inst[pc]
				op, ok := vm.ops[inst.Arg>>1]
				if inst.Op != syntax.InstCapture || inst.Arg&1 != 0 || !ok || op.kind < '1' || op.kind > '9' {
					continue
				}
				key := regexBackrefNode{pc, pos}
				m.reference(key, op.target)
				for _, next := range m.next(key) {
					m.add(next)
				}
			}
			if len(m.states[pos]) == before {
				break
			}
		}
		for pc := range m.states[pos] {
			inst := &vm.prog.Inst[pc]
			if inst.Op == syntax.InstMatch {
				best = pos
			}
			switch inst.Op {
			case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
				for _, next := range m.next(regexBackrefNode{pc, pos}) {
					m.add(next)
				}
			}
		}
	}
	return m.prune(start, best)
}

func (m *regexBackrefMatch) add(first regexBackrefNode) {
	todo := []regexBackrefNode{first}
	for len(todo) > 0 {
		n := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if m.states[n.pos] == nil {
			m.states[n.pos] = make(map[uint32]bool)
		}
		if m.states[n.pos][n.pc] {
			continue
		}
		m.states[n.pos][n.pc] = true
		inst := &m.vm.prog.Inst[n.pc]
		switch inst.Op {
		case syntax.InstMatch, syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			continue
		case syntax.InstCapture:
			if op, ok := m.vm.ops[inst.Arg>>1]; ok && inst.Arg&1 == 0 && op.kind >= '1' && op.kind <= '9' {
				continue
			}
		}
		todo = append(todo, m.next(n)...)
	}
}

func (m *regexBackrefMatch) next(n regexBackrefNode) []regexBackrefNode {
	inst := &m.vm.prog.Inst[n.pc]
	to := regexBackrefNode{inst.Out, n.pos}
	switch inst.Op {
	case syntax.InstFail, syntax.InstMatch:
		return nil
	case syntax.InstAlt, syntax.InstAltMatch:
		return []regexBackrefNode{to, {inst.Arg, n.pos}}
	case syntax.InstCapture:
		if op, ok := m.vm.ops[inst.Arg>>1]; ok && inst.Arg&1 == 0 {
			before, after := regexContext(m.data, n.pos)
			switch op.kind {
			case '<':
				if syntax.IsWordChar(before) || !syntax.IsWordChar(after) {
					return nil
				}
			case '>':
				if !syntax.IsWordChar(before) || syntax.IsWordChar(after) {
					return nil
				}
			default:
				var out []regexBackrefNode
				for _, ref := range m.refs[n] {
					out = append(out, regexBackrefNode{inst.Out, n.pos + ref.hi - ref.lo})
				}
				return out
			}
		}
	case syntax.InstEmptyWidth:
		before, after := regexContext(m.data, n.pos)
		if syntax.EmptyOp(inst.Arg)&^syntax.EmptyOpContext(before, after) != 0 {
			return nil
		}
	case syntax.InstRune, syntax.InstRune1:
		if n.pos >= len(m.data) || !inst.MatchRune(m.data[n.pos]) {
			return nil
		}
		to.pos++
	case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
		if n.pos >= len(m.data) || inst.Op == syntax.InstRuneAnyNotNL && m.data[n.pos] == '\n' {
			return nil
		}
		to.pos++
	}
	return []regexBackrefNode{to}
}

func (m *regexBackrefMatch) reference(n regexBackrefNode, group uint32) {
	if len(m.refs[n]) != 0 {
		return
	}
	for _, open := range m.opens {
		if m.vm.prog.Inst[open.pc].Arg>>1 != group {
			continue
		}
		from, offset := open.pos, n.pos
		compatible := true
		for _, last := range m.lasts[open] {
			for from < last.pos {
				if offset >= len(m.data) {
					compatible = false
					break
				}
				a, b := m.data[from], m.data[offset]
				if m.vm.fold {
					a, b = regexUpper(a), regexUpper(b)
				}
				if a != b {
					compatible = false
					break
				}
				from++
				offset++
			}
			if !compatible {
				break
			}
			if m.arrive(last, n, group, false) {
				m.cacheReference(n, open.pos, last.pos)
			}
		}
		if !compatible {
			continue
		}
		if len(m.lasts[open]) != 0 {
			from++
		}
		for hi := from; hi <= n.pos; hi++ {
			if hi > open.pos {
				if offset >= len(m.data) {
					break
				}
				a, b := m.data[hi-1], m.data[offset]
				offset++
				if m.vm.fold {
					a, b = regexUpper(a), regexUpper(b)
				}
				if a != b {
					break
				}
			}
			close := uint32(0)
			for pc := range m.states[hi] {
				inst := &m.vm.prog.Inst[pc]
				if inst.Op == syntax.InstCapture && inst.Arg == group*2+1 && (close == 0 || pc < close) {
					close = pc
				}
			}
			if close == 0 {
				continue
			}
			last := regexBackrefNode{close, hi}
			if !m.arrive(open, last, group, true) {
				continue
			}
			m.lasts[open] = append(m.lasts[open], last)
			if m.arrive(last, n, group, false) {
				m.cacheReference(n, open.pos, hi)
			}
		}
	}
}

func (m *regexBackrefMatch) cacheReference(n regexBackrefNode, lo, hi int) {
	m.refs[n] = append(m.refs[n], regexBackrefValue{lo: lo, hi: hi, id: m.entries})
	m.entries++
}

func (m *regexBackrefMatch) arrive(first, last regexBackrefNode, group uint32, stopClose bool) bool {
	s := regexSift{m: m, closures: make(map[regexBackrefNode][]uint32)}
	pending := make([]map[uint32]bool, last.pos+1)
	pending[first.pos] = map[uint32]bool{first.pc: true}
	for pos := first.pos; pos <= last.pos; pos++ {
		nodes := m.arrivalClosure(&s, pending[pos], pos, group, stopClose)
		for {
			before := len(nodes)
			for ref, values := range m.refs {
				if ref.pos != pos || !nodes[ref.pc] {
					continue
				}
				for _, value := range values {
					to := regexBackrefNode{m.vm.prog.Inst[ref.pc].Out, pos + value.hi - value.lo}
					if to.pos > last.pos {
						continue
					}
					if to.pos == pos {
						for pc := range m.arrivalClosure(&s, map[uint32]bool{to.pc: true}, pos, group, stopClose) {
							nodes[pc] = true
						}
					} else {
						if pending[to.pos] == nil {
							pending[to.pos] = make(map[uint32]bool)
						}
						pending[to.pos][to.pc] = true
					}
				}
			}
			if len(nodes) == before {
				break
			}
		}
		if pos == last.pos {
			return nodes[last.pc]
		}
		for pc := range nodes {
			switch m.vm.prog.Inst[pc].Op {
			case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
				for _, to := range m.next(regexBackrefNode{pc, pos}) {
					if to.pos > last.pos {
						continue
					}
					if pending[to.pos] == nil {
						pending[to.pos] = make(map[uint32]bool)
					}
					pending[to.pos][to.pc] = true
				}
			}
		}
	}
	return false
}

// check_arrival_expand_ecl_sub follows edests even for a backreference.
// The incremental closure is used only when its ordinary closure includes
// the excluded capture boundary; it differs from a cached reference jump.
func (m *regexBackrefMatch) arrivalClosure(s *regexSift, seeds map[uint32]bool, pos int, group uint32, stopClose bool) map[uint32]bool {
	nodes := make(map[uint32]bool)
	for seed := range seeds {
		closure := s.closure(regexBackrefNode{seed, pos})
		stop := false
		for _, pc := range closure {
			inst := &m.vm.prog.Inst[pc]
			if inst.Op == syntax.InstCapture && inst.Arg>>1 == group && (inst.Arg&1 != 0) == stopClose {
				stop = true
				break
			}
		}
		if !stop {
			for _, pc := range closure {
				nodes[pc] = true
			}
			continue
		}
		todo := []uint32{seed}
		for len(todo) > 0 {
			pc := todo[len(todo)-1]
			todo = todo[:len(todo)-1]
			if nodes[pc] {
				continue
			}
			inst := &m.vm.prog.Inst[pc]
			if inst.Op == syntax.InstCapture && inst.Arg>>1 == group && (inst.Arg&1 != 0) == stopClose {
				if stopClose {
					nodes[pc] = true
				}
				continue
			}
			nodes[pc] = true
			switch inst.Op {
			case syntax.InstCapture:
				if s.isReference(pc) {
					todo = append(todo, inst.Out)
					continue
				}
				fallthrough
			case syntax.InstNop, syntax.InstAlt, syntax.InstAltMatch, syntax.InstEmptyWidth:
				for _, to := range m.next(regexBackrefNode{pc, pos}) {
					todo = append(todo, to.pc)
				}
			}
		}
	}
	return nodes
}
