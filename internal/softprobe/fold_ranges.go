package softprobe

// RegexFoldRanges preserves C-locale uppercase-before-range behavior.
func RegexFoldRanges() []Case {
	data := []byte("AB\x00\x01[]^_`!09ABCDXYZabcdxyz{~\xffZ")
	var cases []Case
	for _, p := range []struct{ name, check, plain, folded string }{
		{"range-0", "[A-z]+", "root hit=[[]^_`]", "root hit=[ABCDXYZabcdxyz]"},
		{"range-1", "[^A-z]+", "root hit=[!09]", "root hit=[[]^_`!09]"},
		{"range-2", "[A-c]+", "root hit=[[]^_`]", "root hit=[ABC]"},
		{"range-3", "[^A-c]+", "root hit=[!09]", "root hit=[[]^_`!09]"},
		{"range-4", "[B-y]+", "root hit=[[]^_`]", "root hit=[BCDXY]"},
		{"range-5", "[^B-y]+", "root hit=[!09A]", "root hit=[[]^_`!09A]"},
		{"range-6", "[a-{]+", "root hit=[abcdxyz{]", "root hit=[[]^_`]"},
		{"range-7", "[^a-{]+", "root hit=[[]^_`!09ABCDXYZ]", "root hit=[!09]"},
		{"range-8", "[[.A.]-[.z.]]+", "root hit=[[]^_`]", "root hit=[ABCDXYZabcdxyz]"},
		{"range-9", "[[:digit:]A-z]+", "root hit=[[]^_`]", "root hit=[09ABCDXYZabcdxyz]"},
		{"range-10", "[^[:digit:]A-z]+", "root hit=[!]", "root hit=[[]^_`!]"},
		{"range-11", "[A-z\\\\]+", "root hit=[[]^_`]", "root hit=[ABCDXYZabcdxyz]"},
		{"range-12", "[A-\\377]+", "root hit=[[]^_`]", "root hit=[[]^_`]"},
		{"range-13", "[a-~]+", "root hit=[abcdxyz{~]", "root hit=[[]^_`]"},
	} {
		for _, flag := range []string{"", "/c", "/C"} {
			name, desc := p.name+"-plain", p.plain
			if flag != "" {
				name, desc = p.name+"-"+flag[1:], p.folded
			}
			source := "0 string/b AB root\n>4 regex" + flag + " " + p.check + " hit=[%s]\n!:mime application/x-audit\n"
			cases = append(cases, Case{name, []string{source}, data, desc, "application/x-audit"})
		}
	}
	return cases
}
