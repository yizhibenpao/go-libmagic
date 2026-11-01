package softprobe

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type FDStatCase struct {
	Name    string          `json:"name"`
	Data    string          `json:"data"`
	OldMode uint32          `json:"old_mode"`
	NewMode uint32          `json:"new_mode"`
	NewSize int64           `json:"new_size"`
	Want    [4]OffsetResult `json:"want"`
}

// FDStatCases uses synthetic ELF bytes, never patched compiled magic.
func FDStatCases() []FDStatCase {
	want := [72][4]OffsetResult{
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}, {Value: "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-object", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-sharedlib, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, stripped", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
		{{Value: "setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), no program header, too large section header offset 400", Error: "", Failed: false}, {Value: "application/x-pie-executable, no program header", Error: "", Failed: false}, {Value: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", Error: "", Failed: false}, {Value: "application/x-sharedlib", Error: "", Failed: false}},
	}
	var out []FDStatCase
	for _, bits := range []int{32, 64} {
		for _, typ := range []uint16{1, 3} {
			for _, m := range [][2]uint32{{0644, 0644}, {0755, 0755}, {0644, 0755}, {0755, 0644}, {04755, 0644}, {04644, 0755}} {
				for _, sizes := range [][2]int{{512, 512}, {128, 512}, {512, 128}} {
					b := make([]byte, sizes[0])
					copy(b, "\x7fELF")
					b[4], b[5], b[6] = 2, 1, 1
					binary.LittleEndian.PutUint16(b[16:], typ)
					binary.LittleEndian.PutUint32(b[20:], 1)
					if bits == 32 {
						b[4] = 1
						binary.LittleEndian.PutUint16(b[18:], 3)
						binary.LittleEndian.PutUint32(b[32:], 64)
						for i, v := range []uint16{52, 32, 0, 40, 1, 0} {
							binary.LittleEndian.PutUint16(b[40+i*2:], v)
						}
						binary.LittleEndian.PutUint32(b[68:], 7)
						binary.LittleEndian.PutUint32(b[80:], 400)
						binary.LittleEndian.PutUint32(b[84:], 16)
					} else {
						binary.LittleEndian.PutUint16(b[18:], 62)
						binary.LittleEndian.PutUint64(b[40:], 64)
						for i, v := range []uint16{64, 56, 0, 64, 1, 0} {
							binary.LittleEndian.PutUint16(b[52+i*2:], v)
						}
						binary.LittleEndian.PutUint32(b[68:], 7)
						binary.LittleEndian.PutUint64(b[88:], 400)
						binary.LittleEndian.PutUint64(b[96:], 16)
					}
					out = append(out, FDStatCase{Name: fmt.Sprintf("elf%d-t%d-%o-%o-%d-%d", bits, typ, m[0], m[1], sizes[0], sizes[1]), Data: hex.EncodeToString(b), OldMode: m[0], NewMode: m[1], NewSize: int64(sizes[1]), Want: want[len(out)]})
				}
			}
		}
	}
	return out
}

type FDStatFlowCase struct {
	FirstFail, SecondFail, ReadFail, Mutate bool
	OldMode, NewMode                        uint32
	OldSize, NewSize                        int64
	Called, Failed                          bool
	StatCalls, ReadCalls                    int
	Mode                                    uint32
	Size                                    int64
	Requested                               int
	Events                                  string
}

// FDStatFlows freezes C stat/read/buffer_init order, not kernel fault injection.
func FDStatFlows() []FDStatFlowCase {
	return []FDStatFlowCase{
		{false, false, false, false, 420, 493, 128, 512, true, false, 1, 1, 33188, 128, 1048576, "SR"},
		{false, false, false, false, 420, 493, 512, 128, true, false, 1, 1, 33188, 512, 1048576, "SR"},
		{false, false, false, false, 493, 420, 128, 512, true, false, 1, 1, 33261, 128, 1048576, "SR"},
		{false, false, false, false, 493, 420, 512, 128, true, false, 1, 1, 33261, 512, 1048576, "SR"},
		{false, false, false, true, 420, 493, 128, 512, true, false, 1, 1, 33188, 128, 1048576, "SR"},
		{false, false, false, true, 420, 493, 512, 128, true, false, 1, 1, 33188, 512, 1048576, "SR"},
		{false, false, false, true, 493, 420, 128, 512, true, false, 1, 1, 33261, 128, 1048576, "SR"},
		{false, false, false, true, 493, 420, 512, 128, true, false, 1, 1, 33261, 512, 1048576, "SR"},
		{true, false, false, false, 420, 493, 128, 512, true, false, 2, 1, 33188, 128, 1048576, "SRS"},
		{true, false, false, false, 420, 493, 512, 128, true, false, 2, 1, 33188, 512, 1048576, "SRS"},
		{true, false, false, false, 493, 420, 128, 512, true, false, 2, 1, 33261, 128, 1048576, "SRS"},
		{true, false, false, false, 493, 420, 512, 128, true, false, 2, 1, 33261, 512, 1048576, "SRS"},
		{true, false, false, true, 420, 493, 128, 512, true, false, 2, 1, 33261, 512, 1048576, "SRS"},
		{true, false, false, true, 420, 493, 512, 128, true, false, 2, 1, 33261, 128, 1048576, "SRS"},
		{true, false, false, true, 493, 420, 128, 512, true, false, 2, 1, 33188, 512, 1048576, "SRS"},
		{true, false, false, true, 493, 420, 512, 128, true, false, 2, 1, 33188, 128, 1048576, "SRS"},
		{true, true, false, false, 420, 493, 128, 512, true, false, 2, 1, 0, 0, 1048576, "SRS"},
		{true, true, false, false, 420, 493, 512, 128, true, false, 2, 1, 0, 0, 1048576, "SRS"},
		{true, true, false, false, 493, 420, 128, 512, true, false, 2, 1, 0, 0, 1048576, "SRS"},
		{true, true, false, false, 493, 420, 512, 128, true, false, 2, 1, 0, 0, 1048576, "SRS"},
		{true, true, false, true, 420, 493, 128, 512, true, false, 2, 1, 0, 0, 1048576, "SRS"},
		{true, true, false, true, 420, 493, 512, 128, true, false, 2, 1, 0, 0, 1048576, "SRS"},
		{true, true, false, true, 493, 420, 128, 512, true, false, 2, 1, 0, 0, 1048576, "SRS"},
		{true, true, false, true, 493, 420, 512, 128, true, false, 2, 1, 0, 0, 1048576, "SRS"},
		{false, false, true, false, 420, 493, 128, 512, false, true, 1, 1, 0, 0, 1048576, "SR"},
		{false, false, true, false, 420, 493, 512, 128, false, true, 1, 1, 0, 0, 1048576, "SR"},
		{false, false, true, false, 493, 420, 128, 512, false, true, 1, 1, 0, 0, 1048576, "SR"},
		{false, false, true, false, 493, 420, 512, 128, false, true, 1, 1, 0, 0, 1048576, "SR"},
		{true, false, true, false, 420, 493, 128, 512, false, true, 1, 1, 0, 0, 1048576, "SR"},
		{true, false, true, false, 420, 493, 512, 128, false, true, 1, 1, 0, 0, 1048576, "SR"},
		{true, false, true, false, 493, 420, 128, 512, false, true, 1, 1, 0, 0, 1048576, "SR"},
		{true, false, true, false, 493, 420, 512, 128, false, true, 1, 1, 0, 0, 1048576, "SR"},
	}
}
