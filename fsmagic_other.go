//go:build !linux

package libmagic

import "os"

// Runtime parity targets Linux; other platforms retain ordinary file support.
func deviceSuffix(info os.FileInfo) string { return "" }

func pathAccessible(path string, mode uint32) bool {
	info, err := os.Stat(path)
	return err == nil && uint32(info.Mode().Perm())&(mode*0111) != 0
}

func openForMagic(path string) (*os.File, error) { return os.Open(path) }
