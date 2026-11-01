package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/cdfsample"
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func frozenReadDatabase(t *testing.T) *Database {
	t.Helper()
	data, err := hex.DecodeString(softprobe.FileReadDatabaseHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != softprobe.FileReadDatabaseSHA256 {
		t.Fatalf("compiled fixture SHA256 %s", got)
	}
	db, err := OpenBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

type prefixScript struct {
	data                   []byte
	first                  int
	firstError, afterError bool
	err                    error
	requests               []int
}

func (r *prefixScript) Read(p []byte) (int, error) {
	r.requests = append(r.requests, len(p))
	first := len(r.requests) == 1
	if first && r.firstError || !first && r.afterError {
		return 0, r.err
	}
	n := len(r.data)
	if first && n > r.first {
		n = r.first
	}
	if n > len(p) {
		n = len(p)
	}
	if n == 0 {
		return 0, io.EOF
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestReadPrefixSourceContractWithoutReference(t *testing.T) {
	db := frozenReadDatabase(t)
	cases := []struct {
		name                                       string
		size, first, firstError, afterError, count int
		failed                                     bool
		hash                                       string
		buffer                                     [2]softprobe.OffsetResult
	}{
		{"eof-0", 0, 0, 0, 0, 0, false, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [2]softprobe.OffsetResult{{Value: "empty", Error: "", Failed: false}, {Value: "application/x-empty", Error: "", Failed: false}}},
		{"eof-1", 1, 1, 0, 0, 1, false, "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd", [2]softprobe.OffsetResult{{Value: "very short file (no magic)", Error: "", Failed: false}, {Value: "application/octet-stream", Error: "", Failed: false}}},
		{"eof-2", 2, 2, 0, 0, 2, false, "38164fbd17603d73f696b8b4d72664d735bb6a7c88577687fd2ae33fd6964153", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"eof-3", 3, 3, 0, 0, 3, false, "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"eof-4", 4, 4, 0, 0, 4, false, "e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"eof-5", 5, 5, 0, 0, 5, false, "f0393febe8baaa55e32f7be2a7cc180bf34e52137d99e056c817a9c07b8f239a", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"eof-6", 6, 6, 0, 0, 6, false, "e9c0f8b575cbfcb42ab3b78ecc87efa3b011d9a5d10b09fa4e96f240bf6a82f5", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"eof-7", 7, 7, 0, 0, 7, false, "74d4c6cac11b95c241112d29afaf2cc19e7becb1634b6383954225f735912a26", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-15", 15, 15, 0, 0, 15, false, "15a27a669483a8e431a3f8823fc047a83a0feee6cc365e38c296baf63f037326", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-127", 127, 127, 0, 0, 127, false, "f11aadb0dd7cb4a90a1d48dfc7dd2250ae9f028da861ee452bde2a4580b4c7c7", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-128", 128, 128, 0, 0, 128, false, "35c3a4bab19f0b39338c0086339e05c0a91de71b439ede6a691b85a44e723dad", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-512", 512, 512, 0, 0, 512, false, "b679086e6757dfe8a9657a5533d498ba7d9b7f09a92a005eb7e6efa4d2a62bbf", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-4096", 4096, 4096, 0, 0, 4096, false, "dda9383d4b71f15a104b4d479ac11f9773b626a6d7c6677ae6160cfc199fc823", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-8192", 8192, 8192, 0, 0, 8192, false, "ae87e4b83915a47afbf9c2631ceb2a449f733a9ac44727db6d078b03ebc2e770", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-65536", 65536, 65536, 0, 0, 65536, false, "3b9e6cda9e1cb96ed80c7c50932994f5f91c394f4522c0a80e870000c522373e", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-1048575", 1048575, 1048575, 0, 0, 1048575, false, "13beead58b61d0de8bc4b7ee7c3a2cb993c452ff3f5e0e77edd3b977ff3f2d80", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-1048576", 1048576, 1048576, 0, 0, 1048576, false, "535dce34a1f7180a38c63611014050dc7298a35b09432fe3f4ff6894e3d195e5", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"eof-1048577", 1048577, 1048577, 0, 0, 1048576, false, "535dce34a1f7180a38c63611014050dc7298a35b09432fe3f4ff6894e3d195e5", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-1", 64, 1, 0, 0, 1, false, "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd", [2]softprobe.OffsetResult{{Value: "very short file (no magic)", Error: "", Failed: false}, {Value: "application/octet-stream", Error: "", Failed: false}}},
		{"short-2", 64, 2, 0, 0, 2, false, "38164fbd17603d73f696b8b4d72664d735bb6a7c88577687fd2ae33fd6964153", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"short-3", 64, 3, 0, 0, 3, false, "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"short-4", 64, 4, 0, 0, 4, false, "e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"short-5", 64, 5, 0, 0, 5, false, "f0393febe8baaa55e32f7be2a7cc180bf34e52137d99e056c817a9c07b8f239a", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"short-6", 64, 6, 0, 0, 6, false, "e9c0f8b575cbfcb42ab3b78ecc87efa3b011d9a5d10b09fa4e96f240bf6a82f5", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"short-7", 64, 7, 0, 0, 7, false, "74d4c6cac11b95c241112d29afaf2cc19e7becb1634b6383954225f735912a26", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-15", 64, 15, 0, 0, 15, false, "15a27a669483a8e431a3f8823fc047a83a0feee6cc365e38c296baf63f037326", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-127", 134, 127, 0, 0, 127, false, "f11aadb0dd7cb4a90a1d48dfc7dd2250ae9f028da861ee452bde2a4580b4c7c7", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-128", 135, 128, 0, 0, 128, false, "35c3a4bab19f0b39338c0086339e05c0a91de71b439ede6a691b85a44e723dad", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-4096", 4103, 4096, 0, 0, 4096, false, "dda9383d4b71f15a104b4d479ac11f9773b626a6d7c6677ae6160cfc199fc823", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-8192", 8199, 8192, 0, 0, 8192, false, "ae87e4b83915a47afbf9c2631ceb2a449f733a9ac44727db6d078b03ebc2e770", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-65535", 65542, 65535, 0, 0, 65535, false, "d48a3d0816c6fc716142e16908da3e82e552205991fa3450b303001e54120762", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-65536", 65543, 65536, 0, 0, 65536, false, "3b9e6cda9e1cb96ed80c7c50932994f5f91c394f4522c0a80e870000c522373e", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"short-1048575", 1048582, 1048575, 0, 0, 1048575, false, "13beead58b61d0de8bc4b7ee7c3a2cb993c452ff3f5e0e77edd3b977ff3f2d80", [2]softprobe.OffsetResult{{Value: "complete read", Error: "", Failed: false}, {Value: "application/x-read-complete", Error: "", Failed: false}}},
		{"error-4", 64, 0, 4, 0, 0, true, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [2]softprobe.OffsetResult{{Value: "", Error: "", Failed: false}, {Value: "", Error: "", Failed: false}}},
		{"error-5", 64, 0, 5, 0, 0, true, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [2]softprobe.OffsetResult{{Value: "", Error: "", Failed: false}, {Value: "", Error: "", Failed: false}}},
		{"error-9", 64, 0, 9, 0, 0, true, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [2]softprobe.OffsetResult{{Value: "", Error: "", Failed: false}, {Value: "", Error: "", Failed: false}}},
		{"error-11", 64, 0, 11, 0, 0, true, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [2]softprobe.OffsetResult{{Value: "", Error: "", Failed: false}, {Value: "", Error: "", Failed: false}}},
		{"error-13", 64, 0, 13, 0, 0, true, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [2]softprobe.OffsetResult{{Value: "", Error: "", Failed: false}, {Value: "", Error: "", Failed: false}}},
		{"short-before-error-4", 64, 4, 0, 4, 4, false, "e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"short-before-error-5", 64, 4, 0, 5, 4, false, "e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
		{"short-before-error-11", 64, 4, 0, 11, 4, false, "e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677", [2]softprobe.OffsetResult{{Value: "ASCII text, with no line terminators", Error: "", Failed: false}, {Value: "text/plain", Error: "", Failed: false}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := make([]byte, c.size)
			copy(data, "ABCDEF")
			readErr := errors.New("scripted read failure")
			r := &prefixScript{data: data, first: c.first,
				firstError: c.firstError != 0, afterError: c.afterError != 0, err: readErr}
			got, err := readMagicPrefix(r, fileBytesMax)
			if len(r.requests) != 1 || r.requests[0] != fileBytesMax {
				t.Errorf("read requests %v, native [%d]", r.requests, fileBytesMax)
			}
			if len(got) != c.count || fmt.Sprintf("%x", sha256.Sum256(got)) != c.hash {
				t.Errorf("prefix length/hash %d/%x, native %d/%s", len(got), sha256.Sum256(got), c.count, c.hash)
			}
			if (err != nil) != c.failed || err != nil && err != readErr {
				t.Errorf("read error %v, native failed=%v", err, c.failed)
			}
			if c.failed {
				return
			}
			for mime := 0; mime < 2; mime++ {
				var value string
				var err error
				if mime == 0 {
					value, err = db.Buffer(got)
				} else {
					value, err = db.BufferMIMEType(got)
				}
				want := c.buffer[mime]
				errText := ""
				if err != nil {
					errText = err.Error()
				}
				if value != want.Value || errText != want.Error || (err != nil) != want.Failed {
					t.Errorf("Buffer MIME %d = %q/%v, native %+v", mime, value, err, want)
				}
			}
		})
	}
}

func TestFileReadFrozenContractsWithoutReference(t *testing.T) {
	db := frozenReadDatabase(t)
	hashes := map[string]string{
		"prefix-0":               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"prefix-1":               "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
		"prefix-2":               "38164fbd17603d73f696b8b4d72664d735bb6a7c88577687fd2ae33fd6964153",
		"prefix-3":               "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78",
		"prefix-4":               "e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677",
		"prefix-5":               "f0393febe8baaa55e32f7be2a7cc180bf34e52137d99e056c817a9c07b8f239a",
		"prefix-6":               "e9c0f8b575cbfcb42ab3b78ecc87efa3b011d9a5d10b09fa4e96f240bf6a82f5",
		"prefix-7":               "74d4c6cac11b95c241112d29afaf2cc19e7becb1634b6383954225f735912a26",
		"prefix-15":              "15a27a669483a8e431a3f8823fc047a83a0feee6cc365e38c296baf63f037326",
		"prefix-127":             "f11aadb0dd7cb4a90a1d48dfc7dd2250ae9f028da861ee452bde2a4580b4c7c7",
		"prefix-128":             "35c3a4bab19f0b39338c0086339e05c0a91de71b439ede6a691b85a44e723dad",
		"prefix-512":             "b679086e6757dfe8a9657a5533d498ba7d9b7f09a92a005eb7e6efa4d2a62bbf",
		"prefix-4096":            "dda9383d4b71f15a104b4d479ac11f9773b626a6d7c6677ae6160cfc199fc823",
		"prefix-8192":            "ae87e4b83915a47afbf9c2631ceb2a449f733a9ac44727db6d078b03ebc2e770",
		"prefix-65536":           "3b9e6cda9e1cb96ed80c7c50932994f5f91c394f4522c0a80e870000c522373e",
		"prefix-1048575":         "13beead58b61d0de8bc4b7ee7c3a2cb993c452ff3f5e0e77edd3b977ff3f2d80",
		"prefix-1048576":         "535dce34a1f7180a38c63611014050dc7298a35b09432fe3f4ff6894e3d195e5",
		"prefix-1048577":         "a07839df60c30bad32af605ee465f52344fa0d2e1aff6c72c575f5b7029883b4",
		"last-1048576":           "5638de4a4c5977dc1260491dbfefc6a2de3c29f3b6501ac59e067836dd65b3c3",
		"last-outside-1048577":   "de854820bc71a49dccf958c5ffd13793ea62fc94b1b72b32a7be8d731812b830",
		"past-1048581":           "fbc81e4144374de5645466bd0f25b39fbd95354e7d2a2806246f9dde3e5652dd",
		"past-truncated-1048580": "075e87ee2b17f32eb277491df65289a8caeeeebc79264bf2b1b35a5e1b98300e",
		"tail-1052672":           "a1cb00066883faacdddb4c38875f2777503ab54a9ff501b8fedd814a819dcfdb",
		"tail-4096":              "8d370bc2c5db8fa9343a37581f68680e2fe2838771ae132a1f5b13163b2b28c4",
		"plain-1052672":          "aca99948e23c6b16b752867285930253e5d614a236eb23fe5b7d8d71984a31f4",
		"both-1052672":           "bb226761e8d81611d015b3362649d565f80ad4c972d1907e381f28c6bc5511a5",
	}
	cases := softprobe.FileReads()
	if len(cases) != len(hashes) {
		t.Fatalf("cases=%d hashes=%d", len(cases), len(hashes))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if got := fmt.Sprintf("%x", sha256.Sum256(c.Data)); got != hashes[c.Name] {
				t.Fatalf("sample SHA256=%s, native %s", got, hashes[c.Name])
			}
			path := filepath.Join(t.TempDir(), "sample")
			if err := os.WriteFile(path, c.Data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, fromFile := range []bool{false, true} {
				for mime := 0; mime < 2; mime++ {
					want := c.Buffer[mime]
					var value string
					var err error
					if fromFile {
						want = c.File[mime]
						if mime == 0 {
							value, err = db.File(path)
						} else {
							value, err = db.FileMIMEType(path)
						}
					} else if mime == 0 {
						value, err = db.Buffer(c.Data)
					} else {
						value, err = db.BufferMIMEType(c.Data)
					}
					errText := ""
					if err != nil {
						errText = err.Error()
					}
					if value != want.Value || errText != want.Error || (err != nil) != want.Failed {
						t.Errorf("File %v MIME %d = %q/%v, native %+v", fromFile, mime, value, err, want)
					}
				}
			}
		})
	}
}

func TestCDFShortPrefixFrozenContractsWithoutReference(t *testing.T) {
	dbPath := os.Getenv("LIBMAGIC_PARITY_DB")
	if dbPath == "" {
		bin := filepath.Dir(testMagicPath(t))
		dbPath = filepath.Join(bin, "custom.mgc") + ":" + filepath.Join(bin, "magic.mgc")
	}
	db, err := OpenDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	data := cdfsample.Cases()["bad-sat"]
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != softprobe.CDFReadDataSHA256 {
		t.Fatalf("CDF data SHA256 %s, native %s", got, softprobe.CDFReadDataSHA256)
	}
	path := filepath.Join(t.TempDir(), "bad-sat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, c := range softprobe.CDFReadPrefixes() {
		t.Run(fmt.Sprintf("prefix-%d", c.Prefix), func(t *testing.T) {
			script := &prefixScript{data: data, first: c.Prefix}
			prefix, err := readMagicPrefix(script, fileBytesMax)
			if err != nil || len(prefix) != c.Prefix || len(script.requests) != 1 || script.requests[0] != fileBytesMax {
				t.Fatalf("prefix len=%d err=%v requests=%v", len(prefix), err, script.requests)
			}
			for _, source := range []struct {
				name   string
				reader io.ReaderAt
			}{{"buffer", nil}, {"memory-fd", bytes.NewReader(data)}, {"real-fd", f}} {
				for mime := 0; mime < 2; mime++ {
					want := c.Buffer[mime]
					var value string
					var err error
					if source.reader != nil {
						want = c.File[mime]
						value, err = magicResult(db.identifyBuffer(prefix, mime == 1, "", source.reader, int64(len(data)), false, true))
					} else if mime == 0 {
						value, err = db.Buffer(prefix)
					} else {
						value, err = db.BufferMIMEType(prefix)
					}
					errText := ""
					if err != nil {
						errText = err.Error()
					}
					if value != want.Value || errText != want.Error || (err != nil) != want.Failed {
						t.Errorf("%s MIME %d = %q/%v, native %+v", source.name, mime, value, err, want)
					}
				}
			}
		})
	}
}
