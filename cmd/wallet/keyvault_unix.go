// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether fi belongs to the user the wallet runs as (any
// owner when that is root): a key file another user could have written is
// never restored.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || os.Geteuid() == 0 || int(st.Uid) == os.Geteuid()
}

// openNoFollow opens path for reading without following a symlink in its
// last element, so the file checked is the file read.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
