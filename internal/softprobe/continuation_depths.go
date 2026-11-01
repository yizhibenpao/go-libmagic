package softprobe

import (
	"fmt"
	"strings"
)

// ContinuationDepths freezes FILE5_41 normal-source continuation boundaries.
// Context outcomes were measured at every listed depth, not inferred from Go.
func ContinuationDepths() []OffsetCase {
	contexts := []struct {
		name         string
		file, buffer [2]OffsetResult
	}{
		{"plain", [2]OffsetResult{{"root deep after", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"root deep after", "", false}, {"application/x-deep", "", false}}},
		{"named", [2]OffsetResult{{"rootnamed- deep after", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"rootnamed- deep after", "", false}, {"application/x-deep", "", false}}},
		{"flipped", [2]OffsetResult{{"rootnamed- deep after", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"rootnamed- deep after", "", false}, {"application/x-deep", "", false}}},
		{"crosslib", [2]OffsetResult{{"rootnamed- deep after", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"rootnamed- deep after", "", false}, {"application/x-deep", "", false}}},
		{"indirect", [2]OffsetResult{{"rootwrapperchild deep after ", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"rootwrapperchild deep after ", "", false}, {"application/x-deep", "", false}}},
		{"early-mime", [2]OffsetResult{{"root deep after", "", false}, {"application/x-root", "", false}}, [2]OffsetResult{{"root deep after", "", false}, {"application/x-root", "", false}}},
		{"parent-miss", [2]OffsetResult{{"root after", "", false}, {"application/octet-stream", "", false}}, [2]OffsetResult{{"root after", "", false}, {"application/octet-stream", "", false}}},
		{"relative", [2]OffsetResult{{"root deep after", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"root deep after", "", false}, {"application/x-deep", "", false}}},
		{"default-clear", [2]OffsetResult{{"root deep again after", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"root deep again after", "", false}, {"application/x-deep", "", false}}},
		{"conditional", [2]OffsetResult{{"root deep after", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"root deep after", "", false}, {"application/x-deep", "", false}}},
		{"use-error", [2]OffsetResult{{"", "root cannot find entry `absent'", true}, {"", "cannot find entry `absent'", true}}, [2]OffsetResult{{"", "root cannot find entry `absent'", true}, {"", "cannot find entry `absent'", true}}},
		{"tail", [2]OffsetResult{{"root deep", "", false}, {"application/x-deep", "", false}}, [2]OffsetResult{{"root", "", false}, {"application/octet-stream", "", false}}},
	}
	var cases []OffsetCase
	for _, depth := range []int{1, 254, 255, 256, 257, 300, 511, 512, 513, 1024} {
		for _, context := range contexts {
			sources, data := continuationDepthSource(depth, context.name)
			cases = append(cases, OffsetCase{fmt.Sprintf("%s-%d", context.name, depth), sources, data, context.file, context.buffer})
		}
	}
	return cases
}

func continuationDepthSource(depth int, context string) ([]string, []byte) {
	var chain strings.Builder
	for i := 1; i < depth; i++ {
		test := "=65"
		if context == "parent-miss" && i == depth-1 {
			test = "=0"
		}
		fmt.Fprintf(&chain, "%s0 byte %s\n", strings.Repeat(">", i), test)
	}
	terminal := "0 byte =65 deep\n"
	switch context {
	case "parent-miss":
		if depth == 1 {
			terminal = "0 byte =0 deep\n"
		}
	case "relative":
		terminal = "&0 byte =66 deep\n"
	case "default-clear":
		terminal = "0 default x deep\n"
	case "conditional":
		terminal = "0 if byte =0 absent\n" + strings.Repeat(">", depth) + "0 else byte =65 deep\n"
	case "use-error":
		terminal = "0 use absent deep\n"
	case "tail":
		terminal = "-1 byte =1 deep\n"
	}
	chain.WriteString(strings.Repeat(">", depth) + terminal + "!:mime application/x-deep\n")
	if context == "default-clear" {
		chain.WriteString(strings.Repeat(">", depth) + "0 clear x\n" + strings.Repeat(">", depth) + "0 default x again\n")
	}
	chain.WriteString(">1 byte =66 after\n")
	root := "0 string/b AB root\n"
	data := []byte("AB\x00\x01")
	switch context {
	case "named", "flipped", "crosslib":
		name := "0 name N named-\n" + chain.String()
		use := "N"
		if context == "flipped" {
			use = "^N"
		}
		caller := root + ">0 use " + use + "\n"
		if context == "crosslib" {
			return []string{name, caller}, data
		}
		return []string{name + caller}, data
	case "indirect":
		return []string{"0 string/b ZZ root\n>2 indirect x wrapper\n0 string/b AB child\n" + chain.String()}, []byte("ZZAB\x00\x01")
	case "early-mime":
		root += "!:mime application/x-root\n"
	case "relative":
		root = "0 byte =65 root\n"
	}
	return []string{root + chain.String()}, data
}
