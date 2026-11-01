//go:build !linux

package libmagic

import "io"

// Preserve the existing non-Linux reader behavior; native single-pread
// equivalence is verified only against the Linux FILE5_41 reference.
func readMagicAt(reader io.ReaderAt, b []byte, offset int64) (int, error) {
	n, err := reader.ReadAt(b, offset)
	if err == io.EOF {
		err = nil
	}
	return n, err
}
