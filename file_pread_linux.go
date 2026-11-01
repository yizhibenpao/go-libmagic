//go:build linux

package libmagic

import (
	"io"
	"os"
	"syscall"
)

// FILE5_41 buffer.c, cdf.c and readelf.c use one pread, without filling a
// short result or retrying EINTR. RawControl keeps the same fd reference
// protection as os.File's Pread, without introducing read locks or polling.
func readMagicAt(reader io.ReaderAt, b []byte, offset int64) (n int, err error) {
	file, ok := reader.(*os.File)
	if !ok {
		n, err = reader.ReadAt(b, offset)
		if err == io.EOF {
			err = nil
		}
		return n, err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}
	controlErr := raw.Control(func(fd uintptr) {
		n, err = syscall.Pread(int(fd), b, offset)
	})
	if controlErr != nil {
		// RawControl's fd reference acquisition fails only on a closed file.
		return 0, syscall.EBADF
	}
	if err != nil {
		n = 0
	}
	return n, err
}
