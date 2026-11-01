# go-libmagic

`go-libmagic` is a pure-Go implementation of libmagic/file identification.

Module path:

```text
github.com/yizhibenpao/go-libmagic
```

Install:

```bash
go get github.com/yizhibenpao/go-libmagic
```

Example:

```go
package main

import (
	"fmt"
	"log"

	libmagic "github.com/yizhibenpao/go-libmagic"
)

func main() {
	db, err := libmagic.OpenDatabase("magic.mgc")
	if err != nil {
		log.Fatal(err)
	}

	description, err := db.File("example.bin")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(description)
}
```

The package also provides `OpenBytes`, `Buffer`, `FileMIMEType`, and
`BufferMIMEType`, plus the compatibility helpers `Open`, `GetFiletype`,
`GetMimetype`, and `Close`.

The standalone repository contains the pure-Go runtime, tests, internal
packages, and the compiled `testdata/magic.mgc` test database. The original
`cmpcgo` directory is intentionally excluded: it is a native Cgo comparison
harness with assumptions about the parent project and is not required by the
pure-Go library.

The implementation is based on the `file/file` source at commit
`eb754ace19fed5481d8142426543100a2d6bae4e`. Original source notices are
retained, and the corresponding upstream license is included in `LICENSE`.

Verification:

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go vet ./...
```
