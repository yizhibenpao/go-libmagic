package softprobe

import (
	"github.com/yizhibenpao/go-libmagic/internal/cdfsample"
	"encoding/binary"
)

type PreadCall struct {
	Count    int   `json:"count"`
	Offset   int64 `json:"offset"`
	Result   int64 `json:"result"`
	Errno    int   `json:"errno"`
	Injected bool  `json:"injected"`
}
type PreadFileCase struct {
	Name, Sample, DB string
	Fault            int
	Want             [4]OffsetResult
	Calls            [2][]PreadCall
}
type PreadRawResult struct {
	Result int64  `json:"result"`
	Errno  int    `json:"errno"`
	Data   string `json:"data"`
}
type PreadRawCase struct {
	Name   string
	Count  int
	Offset int64
	Closed bool
	Want   PreadRawResult
}

// Normal FILE5_41 compiler outputs, independently compiled twice without patches.
func PreadDatabases() map[string]TailFileDatabase {
	return map[string]TailFileDatabase{
		"tail": {Sources: []string{"-1 byte =0x5a tail\n!:mime application/x-tail-once\n"}, Compiled: []string{"1c041ef11000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0003d0001000000000001000000000000000100000000000000000000005a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007461696c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006170706c69636174696f6e2f782d7461696c2d6f6e6365000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}},
		"elf":  {Sources: []string{"0 string \\177ELF elf\n!:mime application/x-elf-once\n"}, Compiled: []string{"1c041ef1100000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020003d0405000000000000000000000000000100000000000000000000007f454c4600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000656c66000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006170706c69636174696f6e2f782d656c662d6f6e636500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}},
	}
}

// These real file bytes are cross-checked with the independent native input hashes.
func PreadFileSamples() map[string][]byte {
	tail := make([]byte, 1536)
	for i := range tail {
		tail[i] = 0xaa
	}
	tail[len(tail)-1] = 0x5a
	elf := make([]byte, 512)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(elf[16:], 2)
	le.PutUint16(elf[18:], 62)
	le.PutUint32(elf[20:], 1)
	le.PutUint64(elf[32:], 64)
	le.PutUint16(elf[52:], 64)
	le.PutUint16(elf[54:], 56)
	le.PutUint16(elf[56:], 1)
	le.PutUint16(elf[58:], 64)
	le.PutUint32(elf[64:], 1)
	le.PutUint64(elf[72:], 256)
	le.PutUint64(elf[96:], 32)
	le.PutUint64(elf[104:], 32)
	le.PutUint64(elf[112:], 4)
	return map[string][]byte{"tail": tail, "elf": elf, "cdf": cdfsample.Cases()["summary-far"]}
}

// Public File/Buffer in both modes, with one target-fd fault at the syscall boundary.
// SETREGS injects only an error, never bytes, classification or a positive read result.
func PreadFileCases() []PreadFileCase {
	return []PreadFileCase{
		{Name: "tail-base", Sample: "tail", DB: "tail", Fault: 0, Want: [4]OffsetResult{{Value: "tail", Error: "", Failed: false}, {Value: "application/x-tail-once", Error: "", Failed: false}, {Value: "ISO-8859 text, with very long lines (1536), with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 1536, Offset: 0, Result: 1536, Errno: 0, Injected: false}}, {{Count: 1536, Offset: 0, Result: 1536, Errno: 0, Injected: false}}}},
		{Name: "tail-EINTR", Sample: "tail", DB: "tail", Fault: 4, Want: [4]OffsetResult{{Value: "ISO-8859 text, with very long lines (1536), with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}, {Value: "ISO-8859 text, with very long lines (1536), with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 1536, Offset: 0, Result: -4, Errno: 4, Injected: true}}, {{Count: 1536, Offset: 0, Result: -4, Errno: 4, Injected: true}}}},
		{Name: "tail-EAGAIN", Sample: "tail", DB: "tail", Fault: 11, Want: [4]OffsetResult{{Value: "ISO-8859 text, with very long lines (1536), with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}, {Value: "ISO-8859 text, with very long lines (1536), with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 1536, Offset: 0, Result: -11, Errno: 11, Injected: true}}, {{Count: 1536, Offset: 0, Result: -11, Errno: 11, Injected: true}}}},
		{Name: "tail-EIO", Sample: "tail", DB: "tail", Fault: 5, Want: [4]OffsetResult{{Value: "ISO-8859 text, with very long lines (1536), with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}, {Value: "ISO-8859 text, with very long lines (1536), with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 1536, Offset: 0, Result: -5, Errno: 5, Injected: true}}, {{Count: 1536, Offset: 0, Result: -5, Errno: 5, Injected: true}}}},
		{Name: "elf-base", Sample: "elf", DB: "elf", Fault: 0, Want: [4]OffsetResult{{Value: "elf, statically linked, no section header", Error: "", Failed: false}, {Value: "application/x-elf-once", Error: "", Failed: false}, {Value: "elf", Error: "", Failed: false}, {Value: "application/x-elf-once", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 56, Offset: 64, Result: 56, Errno: 0, Injected: false}}, {{Count: 56, Offset: 64, Result: 56, Errno: 0, Injected: false}}}},
		{Name: "elf-EINTR", Sample: "elf", DB: "elf", Fault: 4, Want: [4]OffsetResult{{Value: "elf, can't read elf program headers at 64, no section header", Error: "", Failed: false}, {Value: "application/x-elf-once, can't read elf program headers at 64", Error: "", Failed: false}, {Value: "elf", Error: "", Failed: false}, {Value: "application/x-elf-once", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 56, Offset: 64, Result: -4, Errno: 4, Injected: true}}, {{Count: 56, Offset: 64, Result: -4, Errno: 4, Injected: true}}}},
		{Name: "elf-EAGAIN", Sample: "elf", DB: "elf", Fault: 11, Want: [4]OffsetResult{{Value: "elf, can't read elf program headers at 64, no section header", Error: "", Failed: false}, {Value: "application/x-elf-once, can't read elf program headers at 64", Error: "", Failed: false}, {Value: "elf", Error: "", Failed: false}, {Value: "application/x-elf-once", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 56, Offset: 64, Result: -11, Errno: 11, Injected: true}}, {{Count: 56, Offset: 64, Result: -11, Errno: 11, Injected: true}}}},
		{Name: "elf-EIO", Sample: "elf", DB: "elf", Fault: 5, Want: [4]OffsetResult{{Value: "elf, can't read elf program headers at 64, no section header", Error: "", Failed: false}, {Value: "application/x-elf-once, can't read elf program headers at 64", Error: "", Failed: false}, {Value: "elf", Error: "", Failed: false}, {Value: "application/x-elf-once", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 56, Offset: 64, Result: -5, Errno: 5, Injected: true}}, {{Count: 56, Offset: 64, Result: -5, Errno: 5, Injected: true}}}},
		{Name: "cdf-base", Sample: "cdf", DB: "elf", Fault: 0, Want: [4]OffsetResult{{Value: "Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.10, Code page: 1252, Title: A test document, Name of Creating Application: Microsoft Word", Error: "", Failed: false}, {Value: "application/msword", Error: "", Failed: false}, {Value: "Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.10, Code page: 1252, Title: A test document, Name of Creating Application: Microsoft Word", Error: "", Failed: false}, {Value: "application/msword", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 512, Offset: 1079808, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1080320, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1080832, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1081344, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1081856, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1082368, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1082880, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1083392, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1083904, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1084416, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1084928, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1085440, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1085952, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1086464, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1086976, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1087488, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1088000, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1075712, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1076224, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1076736, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1077248, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1077760, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1078272, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1078784, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1079296, Result: 512, Errno: 0, Injected: false}}, {{Count: 512, Offset: 1079808, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1080320, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1080832, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1081344, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1081856, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1082368, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1082880, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1083392, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1083904, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1084416, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1084928, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1085440, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1085952, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1086464, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1086976, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1087488, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1088000, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1075712, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1076224, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1076736, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1077248, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1077760, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1078272, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1078784, Result: 512, Errno: 0, Injected: false}, {Count: 512, Offset: 1079296, Result: 512, Errno: 0, Injected: false}}}},
		{Name: "cdf-EINTR", Sample: "cdf", DB: "elf", Fault: 4, Want: [4]OffsetResult{{Value: "Composite Document File V2 Document, Can't read SAT", Error: "", Failed: false}, {Value: "application/CDFV2", Error: "", Failed: false}, {Value: "Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.10, Code page: 1252, Title: A test document, Name of Creating Application: Microsoft Word", Error: "", Failed: false}, {Value: "application/msword", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 512, Offset: 1079808, Result: -4, Errno: 4, Injected: true}}, {{Count: 512, Offset: 1079808, Result: -4, Errno: 4, Injected: true}}}},
		{Name: "cdf-EAGAIN", Sample: "cdf", DB: "elf", Fault: 11, Want: [4]OffsetResult{{Value: "Composite Document File V2 Document, Can't read SAT", Error: "", Failed: false}, {Value: "application/CDFV2", Error: "", Failed: false}, {Value: "Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.10, Code page: 1252, Title: A test document, Name of Creating Application: Microsoft Word", Error: "", Failed: false}, {Value: "application/msword", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 512, Offset: 1079808, Result: -11, Errno: 11, Injected: true}}, {{Count: 512, Offset: 1079808, Result: -11, Errno: 11, Injected: true}}}},
		{Name: "cdf-EIO", Sample: "cdf", DB: "elf", Fault: 5, Want: [4]OffsetResult{{Value: "Composite Document File V2 Document, Can't read SAT", Error: "", Failed: false}, {Value: "application/CDFV2", Error: "", Failed: false}, {Value: "Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.10, Code page: 1252, Title: A test document, Name of Creating Application: Microsoft Word", Error: "", Failed: false}, {Value: "application/msword", Error: "", Failed: false}}, Calls: [2][]PreadCall{{{Count: 512, Offset: 1079808, Result: -5, Errno: 5, Injected: true}}, {{Count: 512, Offset: 1079808, Result: -5, Errno: 5, Injected: true}}}},
	}
}

// Actual Linux libc pread results; Go represents a failed read by n=0 plus errno.
func PreadRawCases() []PreadRawCase {
	return []PreadRawCase{
		{Name: "full", Count: 3, Offset: 0, Closed: false, Want: PreadRawResult{Result: 3, Errno: 0, Data: "414243"}},
		{Name: "short", Count: 8, Offset: 0, Closed: false, Want: PreadRawResult{Result: 7, Errno: 0, Data: "4142434445460a"}},
		{Name: "partial-end", Count: 8, Offset: 3, Closed: false, Want: PreadRawResult{Result: 4, Errno: 0, Data: "4445460a"}},
		{Name: "eof", Count: 8, Offset: 7, Closed: false, Want: PreadRawResult{Result: 0, Errno: 0, Data: ""}},
		{Name: "past-eof", Count: 8, Offset: 99, Closed: false, Want: PreadRawResult{Result: 0, Errno: 0, Data: ""}},
		{Name: "zero", Count: 0, Offset: 0, Closed: false, Want: PreadRawResult{Result: 0, Errno: 0, Data: ""}},
		{Name: "negative", Count: 1, Offset: -1, Closed: false, Want: PreadRawResult{Result: -1, Errno: 22, Data: ""}},
		{Name: "zero-negative", Count: 0, Offset: -1, Closed: false, Want: PreadRawResult{Result: -1, Errno: 22, Data: ""}},
		{Name: "closed", Count: 1, Offset: 0, Closed: true, Want: PreadRawResult{Result: -1, Errno: 9, Data: ""}},
		{Name: "closed-zero", Count: 0, Offset: 0, Closed: true, Want: PreadRawResult{Result: -1, Errno: 9, Data: ""}},
	}
}
