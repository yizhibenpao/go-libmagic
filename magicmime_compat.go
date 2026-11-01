package libmagic

import (
	"errors"
	"sync"
)

var (
	decMu    sync.Mutex
	magicLib *Database
	mimeLib  *Database
)

// Open keeps the package-level API used by the scanner's former magicmime
// adapter. It loads two independent databases so the description handle does
// not follow symlinks while the MIME handle does.
func Open(magicPath string) error {
	decMu.Lock()
	defer decMu.Unlock()
	if magicLib != nil || mimeLib != nil {
		return errors.New("cannot open; magic mime db is already open")
	}
	var db *Database
	var err error
	if magicPath == "" {
		db, err = openDefaultDatabase()
	} else {
		db, err = OpenDatabase(magicPath)
	}
	if err != nil {
		return err
	}
	magicLib = db
	if magicPath == "" {
		mimeLib, err = openDefaultDatabase()
	} else {
		mimeLib, err = OpenDatabase(magicPath)
	}
	if err != nil {
		return err
	}
	return nil
}

func GetFiletype(filename string) (string, error) {
	decMu.Lock()
	defer decMu.Unlock()
	return magicLib.File(filename)
}

func GetMimetype(filename string) (string, error) {
	decMu.Lock()
	defer decMu.Unlock()
	return mimeLib.FileMIMEType(filename)
}

func Close() {
	magicLib = nil
	mimeLib = nil
}
