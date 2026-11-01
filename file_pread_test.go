package libmagic

import (
	"errors"
	"io"
	"testing"
)

type magicAtScript struct {
	n, calls int
	err      error
	offset   int64
}

func (r *magicAtScript) ReadAt(b []byte, off int64) (int, error) {
	r.calls++
	r.offset = off
	copy(b, "ABCD")
	return r.n, r.err
}

func TestMagicAtReaderContract(t *testing.T) {
	failed := errors.New("read failed")
	for _, c := range []struct {
		name         string
		count, n     int
		err, wantErr error
	}{
		{name: "full", count: 4, n: 4},
		{name: "short", count: 4, n: 2, err: io.EOF},
		{name: "eof", count: 4, err: io.EOF},
		{name: "zero", count: 0},
		{name: "full-eof", count: 4, n: 4, err: io.EOF},
		{name: "error", count: 4, err: failed, wantErr: failed},
		{name: "partial-error", count: 4, n: 2, err: failed, wantErr: failed},
		{name: "zero-eof", count: 0, err: io.EOF},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &magicAtScript{n: c.n, err: c.err}
			n, err := readMagicAt(r, make([]byte, c.count), 17)
			if n != c.n || !errors.Is(err, c.wantErr) || r.calls != 1 || r.offset != 17 {
				t.Fatalf("got n=%d err=%v calls=%d offset=%d", n, err, r.calls, r.offset)
			}
		})
	}
}
