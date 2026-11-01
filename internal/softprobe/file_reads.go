package softprobe

// One normal FILE5_41 source, independently compiled twice without warnings.
// The hex fixture is the unmodified compiler output; no header/field patches.
const FileReadSource = "0 string/b ABCDEF complete read\n!:mime application/x-read-complete\n0 string/b ABCD prefix read\n!:mime application/x-read-prefix\n1048575 string/b X last prefix byte\n!:mime application/x-read-last\n1048576 string/b LIMIT beyond prefix\n!:mime application/x-read-past\n-4 string/b TAIL tail read\n!:mime application/x-read-tail\n"
const FileReadDatabaseSHA256 = "a77f271324cdcdb20f6818c638ca3a599d99bc14cf8c639d73a23369f2645eec"
const FileReadDatabaseHex = "1c041ef1100000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020003d0605000000000000000000000000000100000000000000400000004142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000636f6d706c65746520726561640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006170706c69636174696f6e2f782d726561642d636f6d706c6574650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020003d0505000000000000001000000000000700000000000000400000004c494d49540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006265796f6e64207072656669780000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006170706c69636174696f6e2f782d726561642d70617374000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020003d0405000000000000000000000000000300000000000000400000004142434400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000707265666978207265616400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006170706c69636174696f6e2f782d726561642d707265666978000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0003d0405000000000004000000000000000900000000000000400000005441494c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007461696c2072656164000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006170706c69636174696f6e2f782d726561642d7461696c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020003d01050000000000ffff0f000000000005000000000000004000000058000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c6173742070726566697820627974650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006170706c69636174696f6e2f782d726561642d6c617374000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

func FileReads() []OffsetCase {
	specs := []struct {
		name, kind   string
		size         int
		file, buffer [2]OffsetResult
	}{
		{"prefix-0", "prefix", 0, [2]OffsetResult{{"empty", "", false}, {"inode/x-empty", "", false}}, [2]OffsetResult{{"empty", "", false}, {"application/x-empty", "", false}}},
		{"prefix-1", "prefix", 1, [2]OffsetResult{{"very short file (no magic)", "", false}, {"application/octet-stream", "", false}}, [2]OffsetResult{{"very short file (no magic)", "", false}, {"application/octet-stream", "", false}}},
		{"prefix-2", "prefix", 2, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}},
		{"prefix-3", "prefix", 3, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}},
		{"prefix-4", "prefix", 4, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}},
		{"prefix-5", "prefix", 5, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}},
		{"prefix-6", "prefix", 6, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}, [2]OffsetResult{{"ASCII text, with no line terminators", "", false}, {"text/plain", "", false}}},
		{"prefix-7", "prefix", 7, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-15", "prefix", 15, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-127", "prefix", 127, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-128", "prefix", 128, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-512", "prefix", 512, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-4096", "prefix", 4096, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-8192", "prefix", 8192, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-65536", "prefix", 65536, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-1048575", "prefix", 1048575, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-1048576", "prefix", 1048576, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"prefix-1048577", "prefix", 1048577, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
		{"last-1048576", "last", 1048576, [2]OffsetResult{{"last prefix byte", "", false}, {"application/x-read-last", "", false}}, [2]OffsetResult{{"last prefix byte", "", false}, {"application/x-read-last", "", false}}},
		{"last-outside-1048577", "last-outside", 1048577, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}},
		{"past-1048581", "past", 1048581, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}, [2]OffsetResult{{"beyond prefix", "", false}, {"application/x-read-past", "", false}}},
		{"past-truncated-1048580", "past-truncated", 1048580, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}},
		{"tail-1052672", "tail", 1052672, [2]OffsetResult{{"tail read", "", false}, {"application/x-read-tail", "", false}}, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}},
		{"tail-4096", "tail", 4096, [2]OffsetResult{{"tail read", "", false}, {"application/x-read-tail", "", false}}, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}},
		{"plain-1052672", "plain", 1052672, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}},
		{"both-1052672", "both", 1052672, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}, [2]OffsetResult{{"complete read", "", false}, {"application/x-read-complete", "", false}}},
	}
	var out []OffsetCase
	for _, c := range specs {
		data := make([]byte, c.size)
		if c.kind == "prefix" || c.kind == "both" {
			copy(data, "ABCDEF")
		}
		switch c.kind {
		case "last":
			data[1048575] = 'X'
		case "last-outside":
			data[1048576] = 'X'
		case "past", "past-truncated":
			copy(data[1048576:], "LIMIT")
		}
		if c.kind == "tail" || c.kind == "both" {
			copy(data[len(data)-4:], "TAIL")
		}
		out = append(out, OffsetCase{Name: c.name, Sources: []string{FileReadSource},
			Data: data, File: c.file, Buffer: c.buffer})
	}
	return out
}

// CDFReadPrefixCase preserves native File with a controlled prefix read
// and native Buffer without a descriptor. The File reference reads the rest
// through pread; the initial prefix is not treated as the whole file.
type CDFReadPrefixCase struct {
	Prefix       int
	File, Buffer [2]OffsetResult
}

const CDFReadDataSHA256 = "9360e263f68969472af3791d7316d78d72a196016a0626a2724025c1be69360c"

func CDFReadPrefixes() []CDFReadPrefixCase {
	return []CDFReadPrefixCase{
		{0, [2]OffsetResult{{"empty", "", false}, {"application/x-empty", "", false}}, [2]OffsetResult{{"empty", "", false}, {"application/x-empty", "", false}}},
		{1, [2]OffsetResult{{"very short file (no magic)", "", false}, {"application/octet-stream", "", false}}, [2]OffsetResult{{"very short file (no magic)", "", false}, {"application/octet-stream", "", false}}},
		{2, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"ISO-8859 text, with no line terminators", "", false}, {"text/plain", "", false}}},
		{3, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}},
		{4, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}},
		{7, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"data", "", false}, {"application/octet-stream", "", false}}},
		{8, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"OLE 2 Compound Document", "", false}, {"application/octet-stream", "", false}}},
		{15, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"OLE 2 Compound Document", "", false}, {"application/octet-stream", "", false}}},
		{16, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"OLE 2 Compound Document", "", false}, {"application/octet-stream", "", false}}},
		{127, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"OLE 2 Compound Document, v3.62, SecID 0x0, Mini FAT start sector 0x2", "", false}, {"application/octet-stream", "", false}}},
		{128, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"OLE 2 Compound Document, v3.62, SecID 0x0, Mini FAT start sector 0x2", "", false}, {"application/octet-stream", "", false}}},
		{511, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"OLE 2 Compound Document, v3.62, SecID 0x0, Mini FAT start sector 0x2", "", false}, {"application/octet-stream", "", false}}},
		{512, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}},
		{513, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}},
		{1024, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}, [2]OffsetResult{{"Composite Document File V2 Document, Can't read SAT", "", false}, {"application/CDFV2", "", false}}},
	}
}
