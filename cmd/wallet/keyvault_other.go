// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

import "io/fs"

func ownedByMe(fs.FileInfo) bool { return true }
