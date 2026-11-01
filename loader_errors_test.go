package libmagic

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenBytesReportsFILE541CheckBufferErrors(t *testing.T) {
	data, err := os.ReadFile(testMagicPath(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		edit func([]byte)
		want string
	}{
		{
			name: "bad magic",
			edit: func(data []byte) { data[0] ^= 0xff },
			want: "libmagic: bad magic in `buffer'",
		},
		{
			name: "unsupported version",
			edit: func(data []byte) { binary.LittleEndian.PutUint32(data[4:8], 99) },
			want: "libmagic: File 5.41 supports only version 16 magic files. `buffer' is version 99",
		},
		{
			name: "size",
			edit: func([]byte) {},
			want: "libmagic: Size of `buffer'",
		},
		{
			name: "entries",
			edit: func(data []byte) { binary.LittleEndian.PutUint32(data[8:12], 0) },
			want: "libmagic: Inconsistent entries in `buffer'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mutated := append([]byte(nil), data...)
			tc.edit(mutated)
			if tc.name == "size" {
				mutated = append(mutated, 0)
			}
			_, err := OpenBytes(mutated)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OpenBytes error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestOpenDatabaseReportsFILE541NamedCheckBufferErrors(t *testing.T) {
	data, err := os.ReadFile(testMagicPath(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "broken.mgc")

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "too small",
			data: make([]byte, 7),
			want: "file `" + path + "' is too small",
		},
		{
			name: "bad magic",
			data: mutateDatabase(data, func(data []byte) { data[0] ^= 0xff }),
			want: "bad magic in `" + path + "'",
		},
		{
			name: "unsupported version",
			data: mutateDatabase(data, func(data []byte) {
				binary.LittleEndian.PutUint32(data[4:8], 99)
			}),
			want: "File 5.41 supports only version 16 magic files. `" + path + "' is version 99",
		},
		{
			name: "size",
			data: append(append([]byte(nil), data...), 0),
			want: "Size of `" + path + "'",
		},
		{
			name: "entries",
			data: mutateDatabase(data, func(data []byte) {
				binary.LittleEndian.PutUint32(data[8:12], 0)
			}),
			want: "Inconsistent entries in `" + path + "'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := OpenDatabase(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OpenDatabase error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestOpenDatabaseSkipsInvalidCompiledPath(t *testing.T) {
	data, err := os.ReadFile(testMagicPath(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.mgc")
	if err := os.WriteFile(bad, make([]byte, 7), 0600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.mgc")
	if err := os.WriteFile(good, data, 0600); err != nil {
		t.Fatal(err)
	}

	db, err := OpenDatabase(bad + ":" + good)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Buffer([]byte("plain text\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("valid fallback database produced an empty description")
	}
}

func TestOpenDatabaseDirectorySkipsHiddenEntries(t *testing.T) {
	data, err := os.ReadFile(testMagicPath(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".hidden.mgc"), make([]byte, 7), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.mgc"), data, 0600); err != nil {
		t.Fatal(err)
	}

	db, err := OpenDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Buffer([]byte("plain text\n"))
	if err != nil || got == "" {
		t.Fatalf("directory database = %q/%v", got, err)
	}
}

func TestCompiledDatabaseOpenErrorKeepsMissingPathSkippable(t *testing.T) {
	missing := compiledDatabaseOpenError("missing.mgc", &os.PathError{
		Op:   "open",
		Path: "missing.mgc",
		Err:  os.ErrNotExist,
	})
	if missing != nil {
		t.Fatalf("missing path error = %v, want nil", missing)
	}

	permission := compiledDatabaseOpenError("denied.mgc", &os.PathError{
		Op:   "open",
		Path: "denied.mgc",
		Err:  os.ErrPermission,
	})
	if permission == nil || permission.Error() != "cannot read magic file `denied.mgc' (Permission denied)" {
		t.Fatalf("permission error = %v", permission)
	}
}

func mutateDatabase(data []byte, edit func([]byte)) []byte {
	mutated := append([]byte(nil), data...)
	edit(mutated)
	return mutated
}
