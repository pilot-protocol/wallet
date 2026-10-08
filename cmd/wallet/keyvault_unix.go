// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether fi belongs to the user the wallet runs as, or,
// when that is root, to root or the owner of $HOME: a key file another user
// could have written is never restored.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	euid := os.Geteuid()
	if int(st.Uid) == euid {
		return true
	}
	if euid != 0 {
		return false
	}
	if st.Uid == 0 {
		return true
	}
	if h, err := os.Stat(os.Getenv("HOME")); err == nil {
		if hs, ok := h.Sys().(*syscall.Stat_t); ok && hs.Uid == st.Uid {
			return true
		}
	}
	return false
}

// openNoFollow opens path for reading without following a symlink in its
// last element, so the file checked is the file read.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
