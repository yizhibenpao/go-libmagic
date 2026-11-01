//go:build linux

package libmagic

import (
	"fmt"
	"os"
	"syscall"
)

func deviceSuffix(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	dev := uint64(stat.Rdev)
	major := (dev >> 8 & 0xfff) | (dev >> 32 & 0xfffff000)
	minor := (dev & 0xff) | (dev >> 12 & 0xffffff00)
	return fmt.Sprintf(" (%d/%d)", major, minor)
}

func pathAccessible(path string, mode uint32) bool {
	return syscall.Access(path, mode) == nil
}

func openForMagic(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
