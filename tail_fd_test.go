package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

type tailFillReader struct {
	ret      int
	supplied int
	calls    []softprobe.TailFillRead
}

func (r *tailFillReader) ReadAt(b []byte, off int64) (int, error) {
	n := r.ret
	if off < 0 || n < 0 {
		r.supplied = 0
		r.calls = append(r.calls, softprobe.TailFillRead{Count: len(b), Offset: off, Result: -1})
		return 0, os.ErrInvalid
	}
	if n > len(b) {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		b[i] = byte('A' + i)
	}
	r.supplied = n
	r.calls = append(r.calls, softprobe.TailFillRead{Count: len(b), Offset: off, Result: n})
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

// The unchanged buffer.c probe supplies the fd status and scripted pread.
// Compare its window/cache/requests and supplied bytes, never C heap garbage.
func TestTailFillFrozenWithoutReference(t *testing.T) {
	for _, c := range softprobe.TailFillCases() {
		t.Run(c.Name, func(t *testing.T) {
			reader := &tailFillReader{ret: c.Ret}
			s := &state{tail: &tail{reader: reader, size: c.Size, regular: c.Regular}}
			front := c.Front
			for i, want := range c.Want {
				b, ok := s.loadTail(make([]byte, front))
				got := softprobe.TailFillResult{OK: ok, Length: len(b), Done: s.tail.done,
					Calls: append([]softprobe.TailFillRead{}, reader.calls...)}
				if ok {
					got.Supplied = string(b[:reader.supplied])
				}
				a, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				w, err := json.Marshal(want)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(a, w) {
					t.Errorf("fill %d: %s, C %s", i, a, w)
				}
				if front == 4 {
					front = 8
				} else {
					front = 4
				}
				if i != 0 || c.Ret < 0 {
					reader.ret = 8
				} else {
					reader.ret = -1
				}
			}
		})
	}
}

// Compose the actual classifier with the prefix, opened-fd contents and old
// regular-file status. This is not public File kernel-failure injection.
func TestTailFileFrozenWithoutReference(t *testing.T) {
	dbs := map[string]*Database{}
	for name, fixture := range softprobe.TailFileDatabases() {
		db := &Database{}
		for _, h := range fixture.Compiled {
			raw, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			one, err := OpenBytes(raw)
			if err != nil {
				t.Fatal(err)
			}
			db.sets = append(db.sets, one.sets...)
		}
		dbs[name] = db
	}
	for _, c := range softprobe.TailFileCases() {
		t.Run(c.Name, func(t *testing.T) {
			initial, err := hex.DecodeString(c.Data)
			if err != nil {
				t.Fatal(err)
			}
			after, err := hex.DecodeString(c.After)
			if err != nil {
				t.Fatal(err)
			}
			prefix, fdBytes := initial, after
			if c.Stage == "before" {
				prefix = after
			}
			if c.Operation == "replace" || c.Operation == "remove" {
				fdBytes = initial
			}
			if len(prefix) > fileBytesMax {
				prefix = prefix[:fileBytesMax]
			}
			var reader io.ReaderAt = bytes.NewReader(fdBytes)
			if c.Operation == "close" {
				f, err := os.CreateTemp(t.TempDir(), "closed")
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				reader = f
			}
			db := dbs[c.DB]
			for which, want := range c.Want {
				var value string
				var err error
				switch which {
				case 0, 1:
					value, err = magicResult(db.identifyBuffer(prefix, which == 1, "",
						reader, int64(len(initial)), false, true))
				case 2:
					value, err = db.Buffer(initial)
				case 3:
					value, err = db.BufferMIMEType(initial)
				}
				text := ""
				if err != nil {
					text = err.Error()
				}
				if value != want.Value || text != want.Error || (err != nil) != want.Failed {
					t.Errorf("API %d %q/%v, native %+v", which, value, err, want)
				}
			}
		})
	}
}
