//go:build !linux

package libmagic

import "io"

func readMagicPrefixOnce(reader io.Reader, buf []byte) (int, error) {
	return reader.Read(buf)
}
