package libmagic

import (
	"bytes"
	"errors"
	"testing"
)

func TestELFStatRetryFailureBecomesBadRead(t *testing.T) {
	data := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}
	err := errors.New("bad file descriptor")
	_, got := (&Database{}).identifyBufferStat(data, false, "", bytes.NewReader(data), 0, false, false, err)
	if got == nil || got.Error() != "error reading (Bad file descriptor)" {
		t.Fatalf("error %v, want FILE5_41 bad-read text", got)
	}
}
