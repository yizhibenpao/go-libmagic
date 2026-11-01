package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type frozenFileInfo struct {
	mode os.FileMode
	size int64
}

func (s frozenFileInfo) Name() string       { return "sample" }
func (s frozenFileInfo) Size() int64        { return s.size }
func (s frozenFileInfo) Mode() os.FileMode  { return s.mode }
func (s frozenFileInfo) ModTime() time.Time { return time.Time{} }
func (s frozenFileInfo) IsDir() bool        { return false }
func (s frozenFileInfo) Sys() interface{}   { return nil }

type scriptedStatFile struct {
	c      softprobe.FDStatFlowCase
	err    error
	phase  bool
	stats  int
	events string
}

func (s *scriptedStatFile) Stat() (os.FileInfo, error) {
	s.events += "S"
	s.stats++
	if s.stats == 1 && s.c.FirstFail || s.stats == 2 && s.c.SecondFail {
		return nil, s.err
	}
	mode, size := s.c.OldMode, s.c.OldSize
	if s.phase {
		mode, size = s.c.NewMode, s.c.NewSize
	}
	return frozenFileInfo{mode: os.FileMode(mode), size: size}, nil
}

func (s *scriptedStatFile) Read(p []byte) (int, error) {
	s.events += "R"
	if len(p) != s.c.Requested {
		return 0, fmt.Errorf("read budget %d, native %d", len(p), s.c.Requested)
	}
	if s.c.ReadFail {
		return 0, s.err
	}
	if s.c.Mutate {
		s.phase = true
	}
	return copy(p, "ABCD"), nil
}

func TestFDStatFlowWithoutReference(t *testing.T) {
	for i, c := range softprobe.FDStatFlows() {
		t.Run(fmt.Sprintf("flow-%d", i), func(t *testing.T) {
			script := &scriptedStatFile{c: c, err: errors.New("scripted I/O failure")}
			data, info, err := readMagicFile(script)
			if script.events != c.Events || script.stats != c.StatCalls {
				t.Errorf("events %q/%d, native %q/%d", script.events, script.stats, c.Events, c.StatCalls)
			}
			if (err != nil) != c.Failed || err != nil && err != script.err {
				t.Errorf("error %v, native failed=%v", err, c.Failed)
			}
			if !c.Called {
				if len(data) != 0 {
					t.Errorf("failed prefix %q", data)
				}
				return
			}
			if string(data) != "ABCD" {
				t.Errorf("prefix %q", data)
			}
			if c.Mode == 0 {
				if info != nil {
					t.Errorf("both stats failed, got info %+v", info)
				}
			} else if info == nil || info.Size() != c.Size || uint32(info.Mode().Perm()) != c.Mode&0777 {
				t.Errorf("info %+v, native mode=%o size=%d", info, c.Mode, c.Size)
			}
		})
	}
}

type frozenStatReader struct {
	*bytes.Reader
	info os.FileInfo
}

func (s frozenStatReader) Stat() (os.FileInfo, error) { return s.info, nil }

func frozenPosixMode(mode uint32) os.FileMode {
	m := os.FileMode(mode & 0777)
	if mode&04000 != 0 {
		m |= os.ModeSetuid
	}
	if mode&02000 != 0 {
		m |= os.ModeSetgid
	}
	if mode&01000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

// Portable Linux-mode contracts: File cases compose the actual read/stat helper
// and classifier, not a fault-injected public File call or native Windows stat.
func TestFDStatDownstreamFrozenWithoutReference(t *testing.T) {
	dbPath := os.Getenv("LIBMAGIC_PARITY_DB")
	if dbPath == "" {
		bin := filepath.Dir(testMagicPath(t))
		dbPath = filepath.Join(bin, "custom.mgc") + ":" + filepath.Join(bin, "magic.mgc")
	}
	db, err := OpenDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range softprobe.FDStatCases() {
		t.Run(c.Name, func(t *testing.T) {
			original, err := hex.DecodeString(c.Data)
			if err != nil {
				t.Fatal(err)
			}
			after := make([]byte, c.NewSize)
			copy(after, original)
			for which, want := range c.Want {
				var value string
				var err error
				if which < 2 {
					reader := frozenStatReader{Reader: bytes.NewReader(after),
						info: frozenFileInfo{mode: frozenPosixMode(c.NewMode), size: c.NewSize}}
					data, info, readErr := readMagicFile(reader)
					if readErr != nil {
						t.Fatal(readErr)
					}
					prefix := ""
					if which == 0 {
						prefix = permissionPrefix(frozenPosixMode(c.OldMode))
					}
					value, err = db.identifyBuffer(data, which == 1, prefix, reader,
						info.Size(), info.Mode().Perm()&0111 != 0, info.Mode().IsRegular())
					if err == nil && which == 0 {
						value = withPrefix(prefix, value)
					}
					value, err = magicResult(value, err)
				} else if which == 2 {
					value, err = db.Buffer(original)
				} else {
					value, err = db.BufferMIMEType(original)
				}
				errText := ""
				if err != nil {
					errText = err.Error()
				}
				if value != want.Value || errText != want.Error || (err != nil) != want.Failed {
					t.Errorf("API %d %q/%v, native %+v", which, value, err, want)
				}
			}
		})
	}
}
