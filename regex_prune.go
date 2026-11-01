package libmagic

import (
	"regexp/syntax"
	"sort"
)

type regexSiftLimit struct {
	node  regexBackrefNode
	value regexBackrefValue
}

type regexSift struct {
	m             *regexBackrefMatch
	start         int
	maxJump       int
	epsDead       map[int]map[uint32]bool
	kept, limited []map[uint32]bool
	closures      map[regexBackrefNode][]uint32
}

// prune follows prune_impossible_nodes: a forward halt is only a candidate.
// Try longest halts first and retain paths satisfying every cached capture.
func (m *regexBackrefMatch) prune(start, end int) int {
	s := regexSift{m: m, start: start, closures: make(map[regexBackrefNode][]uint32), epsDead: make(map[int]map[uint32]bool)}
	for _, values := range m.refs {
		for _, v := range values {
			if n := v.hi - v.lo; n > s.maxJump {
				s.maxJump = n
			}
		}
	}
	for ; end >= start; end-- {
		for _, pc := range regexSortedPCs(m.states[end]) {
			if m.vm.prog.Inst[pc].Op != syntax.InstMatch {
				continue
			}
			s.kept = make([]map[uint32]bool, end+1)
			s.limited = make([]map[uint32]bool, end+1)
			s.backward(regexBackrefNode{pc, end}, nil)
			if len(s.kept[start]) > 0 || len(s.limited[start]) > 0 {
				return end
			}
		}
	}
	return -1
}

func regexSortedPCs(nodes map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(nodes))
	for pc := range nodes {
		out = append(out, pc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *regexSift) isReference(pc uint32) bool {
	inst := &s.m.vm.prog.Inst[pc]
	op, ok := s.m.vm.ops[inst.Arg>>1]
	return inst.Op == syntax.InstCapture && inst.Arg&1 == 0 && ok && op.kind >= '1' && op.kind <= '9'
}

// Epsilon closures stop at backreferences, including nullable ones. Those
// transitions are considered separately using the forward candidate cache.
func (s *regexSift) closure(n regexBackrefNode) []uint32 {
	if pcs, ok := s.closures[n]; ok {
		return pcs
	}
	seen := make(map[uint32]bool)
	todo := []regexBackrefNode{n}
	for len(todo) > 0 {
		cur := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[cur.pc] {
			continue
		}
		seen[cur.pc] = true
		switch s.m.vm.prog.Inst[cur.pc].Op {
		case syntax.InstNop, syntax.InstAlt, syntax.InstAltMatch, syntax.InstCapture, syntax.InstEmptyWidth:
			if !s.isReference(cur.pc) {
				todo = append(todo, s.m.next(cur)...)
			}
		}
	}
	pcs := regexSortedPCs(seen)
	s.closures[n] = pcs
	return pcs
}

func regexContains(pcs []uint32, pc uint32) bool {
	i := sort.Search(len(pcs), func(i int) bool { return pcs[i] >= pc })
	return i < len(pcs) && pcs[i] == pc
}

func (s *regexSift) expand(dest map[uint32]bool, pos int) {
	for pc := range s.m.states[pos] {
		for _, to := range s.closure(regexBackrefNode{pc, pos}) {
			if dest[to] {
				dest[pc] = true
				break
			}
		}
	}
}

// backward shares the sifted array with nested reference contexts, as GNU
// sift_states_bkref does; successful limited prefixes are merged separately.
func (s *regexSift) backward(last regexBackrefNode, limits []regexSiftLimit) {
	nulls := 0
	for pos := last.pos; pos >= s.start; pos-- {
		if pos < last.pos {
			if len(s.kept[pos+1]) == 0 {
				nulls++
			} else {
				nulls = 0
			}
			if nulls > s.maxJump {
				for i := s.start; i <= pos; i++ {
					s.kept[i] = nil
				}
				return
			}
		}
		dest := make(map[uint32]bool)
		if pos == last.pos {
			dest[last.pc] = true
		} else {
			for pc := range s.m.states[pos] {
				switch s.m.vm.prog.Inst[pc].Op {
				case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
					from := regexBackrefNode{pc, pos}
					for _, to := range s.m.next(from) {
						if to.pos <= last.pos && s.kept[to.pos][to.pc] && !s.crosses(limits, to, from) {
							dest[pc] = true
						}
					}
				}
			}
		}
		s.expand(dest, pos)
		s.limitNodes(dest, pos, limits)
		s.kept[pos] = dest
		for _, pc := range regexSortedPCs(s.m.states[pos]) {
			from := regexBackrefNode{pc, pos}
			if from == last || !s.isReference(pc) {
				continue
			}
			for _, value := range s.m.refs[from] {
				to := regexBackrefNode{s.m.vm.prog.Inst[pc].Out, pos + value.hi - value.lo}
				if to.pos > last.pos || !s.kept[to.pos][to.pc] || s.crosses(limits, from, to) {
					continue
				}
				saved := s.kept[pos]
				nextLimits := append([]regexSiftLimit(nil), limits...)
				have := false
				for _, lim := range limits {
					if lim.value.id == value.id {
						have = true
						break
					}
				}
				if !have {
					nextLimits = append(nextLimits, regexSiftLimit{from, value})
				}
				sort.Slice(nextLimits, func(i, j int) bool { return nextLimits[i].value.id < nextLimits[j].value.id })
				s.backward(from, nextLimits)
				for i := s.start; i <= pos; i++ {
					if len(s.kept[i]) == 0 {
						continue
					}
					if s.limited[i] == nil {
						s.limited[i] = make(map[uint32]bool)
					}
					for node := range s.kept[i] {
						s.limited[i][node] = true
					}
				}
				s.kept[pos] = saved
			}
		}
	}
}

func (s *regexSift) crosses(limits []regexSiftLimit, from, to regexBackrefNode) bool {
	for _, lim := range limits {
		group := s.m.vm.ops[s.m.vm.prog.Inst[lim.node.pc].Arg>>1].target
		if s.position(lim.value, group, from) != s.position(lim.value, group, to) {
			return true
		}
	}
	return false
}

func (s *regexSift) position(value regexBackrefValue, group uint32, n regexBackrefNode) int {
	if n.pos < value.lo {
		return -1
	}
	if n.pos > value.hi {
		return 1
	}
	boundaries := 0
	if n.pos == value.lo {
		boundaries |= 1
	}
	if n.pos == value.hi {
		boundaries |= 2
	}
	if boundaries == 0 {
		return 0
	}
	return s.boundary(group, n, boundaries, make(map[uint32]bool))
}

func (s *regexSift) boundary(group uint32, n regexBackrefNode, boundaries int, active map[uint32]bool) int {
	active[n.pc] = true
	defer delete(active, n.pc)
	for _, pc := range s.closure(n) {
		inst := &s.m.vm.prog.Inst[pc]
		if s.isReference(pc) {
			for _, value := range s.m.refs[regexBackrefNode{pc, n.pos}] {
				if value.lo != value.hi || s.epsDead[value.id][group] {
					continue
				}
				next := regexBackrefNode{inst.Out, n.pos}
				if next.pc == n.pc {
					if boundaries&1 != 0 {
						return -1
					}
					return 0
				}
				at := 0
				if boundaries&2 != 0 {
					at = 1
				}
				if !active[next.pc] {
					at = s.boundary(group, next, boundaries, active)
				}
				if at == -1 || at == 0 && boundaries&2 != 0 {
					return at
				}
				if s.epsDead[value.id] == nil {
					s.epsDead[value.id] = make(map[uint32]bool)
				}
				s.epsDead[value.id][group] = true
			}
		} else if inst.Op == syntax.InstCapture && inst.Arg>>1 == group {
			if inst.Arg&1 == 0 && boundaries&1 != 0 {
				return -1
			}
			if inst.Arg&1 != 0 && boundaries&2 != 0 {
				return 0
			}
		}
	}
	if boundaries&2 != 0 {
		return 1
	}
	return 0
}

func (s *regexSift) removeSources(dest map[uint32]bool, node uint32, pos int) {
	inv := make(map[uint32]bool)
	for i := range s.m.vm.prog.Inst {
		pc := uint32(i)
		if regexContains(s.closure(regexBackrefNode{pc, pos}), node) {
			inv[pc] = true
		}
	}
	except := make(map[uint32]bool)
	for pc := range inv {
		if pc == node {
			continue
		}
		inst := &s.m.vm.prog.Inst[pc]
		switch inst.Op {
		case syntax.InstNop, syntax.InstAlt, syntax.InstAltMatch, syntax.InstCapture, syntax.InstEmptyWidth:
			if s.isReference(pc) {
				continue
			}
			for _, to := range s.m.next(regexBackrefNode{pc, pos}) {
				if !inv[to.pc] && dest[to.pc] {
					for candidate := range s.m.states[pos] {
						if regexContains(s.closure(regexBackrefNode{candidate, pos}), pc) {
							except[candidate] = true
						}
					}
				}
			}
		}
	}
	for pc := range inv {
		if !except[pc] {
			delete(dest, pc)
		}
	}
}

func (s *regexSift) limitNodes(dest map[uint32]bool, pos int, limits []regexSiftLimit) {
	for _, lim := range limits {
		if pos <= lim.value.lo || pos > lim.node.pos {
			continue
		}
		group := s.m.vm.ops[s.m.vm.prog.Inst[lim.node.pc].Arg>>1].target
		if pos == lim.value.hi {
			var open, close uint32
			for _, pc := range regexSortedPCs(dest) {
				inst := &s.m.vm.prog.Inst[pc]
				if inst.Op == syntax.InstCapture && inst.Arg>>1 == group {
					if inst.Arg&1 == 0 {
						open = pc
					} else {
						close = pc
					}
				}
			}
			if open != 0 {
				s.removeSources(dest, open, pos)
			}
			if close != 0 {
				nodes := regexSortedPCs(dest)
				for i := 0; i < len(nodes); i++ {
					pc := nodes[i]
					if !regexContains(s.closure(regexBackrefNode{pc, pos}), close) && !regexContains(s.closure(regexBackrefNode{close, pos}), pc) {
						s.removeSources(dest, pc, pos)
						nodes = regexSortedPCs(dest)
						i--
					}
				}
			}
		} else {
			nodes := regexSortedPCs(dest)
			for i := 0; i < len(nodes); i++ {
				pc := nodes[i]
				inst := &s.m.vm.prog.Inst[pc]
				if inst.Op == syntax.InstCapture && inst.Arg>>1 == group {
					s.removeSources(dest, pc, pos)
					nodes = regexSortedPCs(dest)
				}
			}
		}
	}
}
