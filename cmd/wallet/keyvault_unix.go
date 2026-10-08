// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether fi belongs to the user the wallet runs as: a key
// file another user could have written is never restored.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) == os.Getuid()
}
