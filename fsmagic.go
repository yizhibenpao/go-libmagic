/*
 * Copyright (c) Ian F. Darwin 1986-1995.
 * Software written by Ian F. Darwin and others;
 * maintained 1995-present by Christos Zoulas and others.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

package libmagic

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type pathProbe struct {
	path   string
	prefix string
}

// probePath follows FILE5_41 fsmagic.c with the scanner's two flag sets:
// MAGIC_NONE for descriptions; MAGIC_MIME_TYPE|MAGIC_SYMLINK|MAGIC_ERROR
// for MIME. A special result stops before opening the file.
func probePath(path string, follow bool) (*pathProbe, string, error) {
	stat := os.Lstat
	if follow {
		stat = os.Stat
	}
	info, err := stat(path)
	if err != nil {
		if follow {
			return nil, "", fmt.Errorf("cannot stat `%s' (%s)", path, systemError(err))
		}
		return nil, filesystemString(fmt.Sprintf("cannot open `%s' (%s)", path, systemError(err))), nil
	}
	prefix := ""
	if !follow {
		prefix = permissionPrefix(info.Mode())
	}
	special := func(desc, mime string) (*pathProbe, string, error) {
		if follow {
			return nil, mime, nil
		}
		if prefix != "" {
			desc = prefix + ", " + desc
		}
		return nil, filesystemString(desc), nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, readErr := os.Readlink(path)
		if readErr != nil {
			return special(fmt.Sprintf("unreadable symlink `%s' (%s)", path, systemError(readErr)), "inode/symlink")
		}
		if _, statErr := os.Stat(path); statErr != nil {
			return nil, filesystemString("broken symbolic link to " + target), nil
		}
		return special("symbolic link to "+target, "inode/symlink")
	}

	mode := info.Mode()
	switch {
	case mode.IsDir():
		return special("directory", "inode/directory")
	case mode&os.ModeNamedPipe != 0:
		return special("fifo (named pipe)", "inode/fifo")
	case mode&os.ModeSocket != 0:
		return special("socket", "inode/socket")
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		return special("character special"+deviceSuffix(info), "inode/chardevice")
	case mode&os.ModeDevice != 0:
		return special("block special"+deviceSuffix(info), "inode/blockdevice")
	}
	if !mode.IsRegular() {
		return nil, "", fmt.Errorf("invalid mode 0%o", mode)
	}
	if info.Size() == 0 {
		return special("empty", "inode/x-empty")
	}
	return &pathProbe{path: path, prefix: prefix}, "", nil
}

func permissionPrefix(mode os.FileMode) string {
	var parts []string
	if mode&os.ModeSetuid != 0 {
		parts = append(parts, "setuid")
	}
	if mode&os.ModeSetgid != 0 {
		parts = append(parts, "setgid")
	}
	if mode&os.ModeSticky != 0 {
		parts = append(parts, "sticky")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}

func withPrefix(prefix, result string) string {
	if prefix == "" || result == "" {
		return result
	}
	return prefix + " " + result
}

// libc's C-locale strerror uses initial capitals, unlike syscall.Errno.Error.
func systemError(err error) string {
	for errors.Unwrap(err) != nil {
		err = errors.Unwrap(err)
	}
	message := err.Error()
	if len(message) > 0 && message[0] >= 'a' && message[0] <= 'z' {
		message = string(message[0]-'a'+'A') + message[1:]
	}
	return message
}

// magicmime never calls setlocale, so file_getbuffer uses C-locale isprint.
func filesystemString(s string) string {
	var result strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= 32 && s[i] < 127 {
			result.WriteByte(s[i])
		} else {
			fmt.Fprintf(&result, "\\%03o", s[i])
		}
	}
	return result.String()
}

func unreadableDescription(path string, info os.FileInfo) string {
	var result strings.Builder
	if pathAccessible(path, 2) {
		result.WriteString("writable, ")
	}
	if pathAccessible(path, 1) {
		result.WriteString("executable, ")
	}
	if info.Mode().IsRegular() {
		result.WriteString("regular file, ")
	}
	result.WriteString("no read permission")
	return result.String()
}
