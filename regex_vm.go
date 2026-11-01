package libmagic

import (
	"regexp"
	"regexp/syntax"
	"unicode/utf8"
)

type regexOp struct {
	kind   rune
	target uint32
}

// Ordinary rules keep regexp's leftmost-longest engine. GNU word directions,
// backreferences and counts beyond Go's parser use syntax programs directly.
type magicRegex struct {
	standard *regexp.Regexp
	extended *regexVM
}

type regexVM struct {
	prog      *syntax.Prog
	ops       map[uint32]regexOp
	captures  map[uint32]bool
	fold      bool
	prefixLen int
}

func buildRegex(tree *syntax.Regexp, ops map[uint32]regexOp, fold bool) *magicRegex {
	if len(ops) == 0 {
		re, err := regexp.Compile(tree.String())
		if err == nil {
			re.Longest()
			return &magicRegex{standard: re}
		}
		// A valid GNU count may exceed Go's parsing limit. The tree
		// already has the source-checked count; do not parse it again.
	}
	vm := &regexVM{ops: ops, captures: make(map[uint32]bool), fold: fold}
	for _, op := range ops {
		if op.kind < '1' || op.kind > '9' {
			continue
		}
		if op.target == 0 {
			return nil // GNU requires a previously closed capture.
		}
		vm.captures[op.target] = true
	}
	prog, err := syntax.Compile(expandRegexRepeats(tree).Simplify())
	if err != nil {
		return nil
	}
	vm.prog = prog
	if len(ops) == 0 {
		// A literal prefix cannot fit at later starts. Only use Prog's
		// prefix without GNU markers: its Capture instructions otherwise
		// represent consuming backreferences, not ordinary empty captures.
		prefix, _ := prog.Prefix()
		vm.prefixLen = utf8.RuneCountInString(prefix)
	}
	return &magicRegex{extended: vm}
}

func (r *magicRegex) FindStringIndex(text string) []int {
	if r.standard != nil {
		return r.standard.FindStringIndex(text)
	}
	data := []rune(text)
	offsets := make([]int, 0, len(data)+1)
	for i := range text {
		offsets = append(offsets, i)
	}
	offsets = append(offsets, len(text))
	for start := 0; start <= len(data)-r.extended.prefixLen; start++ {
		var end int
		if len(r.extended.captures) > 0 {
			end = r.extended.matchBackrefsAt(data, start)
		} else {
			end = r.extended.matchAt(data, start)
		}
		if end >= 0 {
			return []int{offsets[start], offsets[end]}
		}
	}
	return nil
}

type regexVMState struct {
	pc  uint32
	pos int
}

func (vm *regexVM) matchAt(data []rune, start int) int {
	initial := regexVMState{pc: uint32(vm.prog.Start), pos: start}
	stack := []regexVMState{initial}
	// This path has no backreferences; PC/position stops zero-width
	// assertion cycles without imposing a different matching limit.
	seen := make(map[regexVMState]bool)
	best := -1
	for len(stack) > 0 {
		state := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[state] {
			continue
		}
		seen[state] = true
		inst := &vm.prog.Inst[state.pc]
		next := state
		next.pc = inst.Out
		switch inst.Op {
		case syntax.InstFail:
			continue
		case syntax.InstMatch:
			if state.pos > best {
				best = state.pos
			}
		case syntax.InstNop:
			stack = append(stack, next)
		case syntax.InstAlt, syntax.InstAltMatch:
			other := state
			other.pc = inst.Arg
			stack = append(stack, other, next)
		case syntax.InstCapture:
			group := inst.Arg >> 1
			if op, ok := vm.ops[group]; ok {
				if inst.Arg&1 == 0 {
					before, after := regexContext(data, state.pos)
					switch op.kind {
					case '<':
						if syntax.IsWordChar(before) || !syntax.IsWordChar(after) {
							continue
						}
					case '>':
						if !syntax.IsWordChar(before) || syntax.IsWordChar(after) {
							continue
						}
					}
				}
			}
			stack = append(stack, next)
		case syntax.InstEmptyWidth:
			before, after := regexContext(data, state.pos)
			context := syntax.EmptyOpContext(before, after)
			if syntax.EmptyOp(inst.Arg)&^context == 0 {
				stack = append(stack, next)
			}
		case syntax.InstRune, syntax.InstRune1:
			if state.pos < len(data) && inst.MatchRune(data[state.pos]) {
				next.pos++
				stack = append(stack, next)
			}
		case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			if state.pos < len(data) && (inst.Op == syntax.InstRuneAny || data[state.pos] != '\n') {
				next.pos++
				stack = append(stack, next)
			}
		}
	}
	return best
}

func regexContext(data []rune, pos int) (before, after rune) {
	before, after = -1, -1
	if pos > 0 {
		before = data[pos-1]
	}
	if pos < len(data) {
		after = data[pos]
	}
	return before, after
}

func regexUpper(c rune) rune {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}
