//go:build linux

package libmagic

import (
	"io"
	"os"
	"syscall"
)

// FILE5_41 magic.c calls read once for the ordinary-file prefix. RawControl
// preserves os.File's descriptor lifetime protection without Read's EINTR
// retry behavior.
func readMagicPrefixOnce(reader io.Reader, buf []byte) (n int, err error) {
	file, ok := reader.(*os.File)
	if !ok {
		return reader.Read(buf)
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}
	controlErr := raw.Control(func(fd uintptr) {
		n, err = syscall.Read(int(fd), buf)
	})
	if controlErr != nil {
		return 0, syscall.EBADF
	}
	return n, err
}
