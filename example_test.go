package libmagic_test

import (
	"fmt"
	"os"

	libmagic "github.com/yizhibenpao/go-libmagic"
)

func ExampleOpenBytes() {
	data, err := os.ReadFile("testdata/magic.mgc")
	if err != nil {
		panic(err)
	}

	db, err := libmagic.OpenBytes(data)
	if err != nil {
		panic(err)
	}

	description, err := db.Buffer([]byte("hello"))
	if err != nil {
		panic(err)
	}

	fmt.Println(description != "")
	// Output: true
}
