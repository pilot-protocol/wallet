// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

import (
	"io/fs"
	"os"
)

func ownedByMe(fs.FileInfo) bool { return true }

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
