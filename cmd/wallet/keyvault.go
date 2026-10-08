// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// keyVault keeps the wallet's identity files from being lost with its install
// dir, and brings an old key back instead of minting a new one.
//
// The identity files live in the install dir ($APP, ~/.pilot/apps/
// io.pilot.wallet). That dir goes away on `pilotctl appstore uninstall`, and a
// pilotctl older than v1.13.10 deleted it on every upgrade too. The wallet then
// created a fresh key on its next start, and funds sent to the old address were
// out of reach. So on every start the wallet mirrors each identity file into a
// dir of its own outside the install dir, and before it would create a key it
// looks for the old one: in that mirror first, then in the backups pilotctl
// keeps of replaced or uninstalled installs. A key is created only when no copy
// exists anywhere.
//
// Nothing here ever deletes a key. A mirror copy that differs from the live
// file is kept under a replaced-<time> name before the live one takes its
// place.
type keyVault struct {
	dir    string   // the mirror; "" turns the vault off
	extra  []string // other dirs to search for an old copy, newest-first order is worked out per file
	logger *log.Logger
}

// newKeyVault is the vault for an identity file kept in installDir: the mirror
// in dir, and pilotctl's backups of this app as further places to look. Its
// backups are kept per app under <backup root>/<app id>/<stamp>-v<version>/:
// $PILOT_APPSTORE_BACKUP_ROOT, else app-backups beside the install root, and,
// when those fail, .app-backups inside the install root or a
// <app id>.previous-<stamp> dir beside the install.
func newKeyVault(dir, installDir string, logger *log.Logger) *keyVault {
	appID := filepath.Base(installDir)
	root := filepath.Dir(installDir)
	v := &keyVault{dir: dir, logger: logger}
	if r := os.Getenv("PILOT_APPSTORE_BACKUP_ROOT"); r != "" {
		v.extra = append(v.extra, filepath.Join(r, appID))
	}
	v.extra = append(v.extra,
		filepath.Join(filepath.Dir(root), "app-backups", appID),
		filepath.Join(root, ".app-backups", appID),
	)
	return v
}

// defaultKeyVaultDir is ~/.pilot/keys/io.pilot.wallet.
func defaultKeyVaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".pilot", "keys", "io.pilot.wallet")
}

// restore puts back the identity file at path from the newest copy that valid
// accepts, when path does not exist. It reports where the copy came from ("" =
// nothing restored: path exists, or no copy was found and a new key will be
// created). valid loads a candidate the way the wallet will, so a corrupt or
// unrelated file is never put in place of a missing key.
func (v *keyVault) restore(path string, valid func(string) error) (string, error) {
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	for _, src := range v.candidates(filepath.Base(path), filepath.Dir(path)) {
		if err := copyKeyFile(src, path); err != nil {
			v.logger.Printf("key vault: could not restore %s from %s: %v", path, src, err)
			continue
		}
		if err := valid(path); err != nil {
			v.logger.Printf("key vault: %s is not a usable key (%v); trying older copies", src, err)
			_ = os.Remove(path) // the copy just made, nothing else
			continue
		}
		v.logger.Printf("key vault: %s was missing; restored the existing key from %s", path, src)
		return src, nil
	}
	return "", nil
}

// candidates lists the copies of an identity file named name, best first: the
// mirror, then pilotctl's backups newest first, then a <app id>.previous-*
// dir beside the install.
func (v *keyVault) candidates(name, installDir string) []string {
	var out []string
	if v.dir != "" {
		if p := filepath.Join(v.dir, name); isRegular(p) {
			out = append(out, p)
		}
	}
	type found struct {
		path string
		mod  time.Time
	}
	var backups []found
	add := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			backups = append(backups, found{p, fi.ModTime()})
		}
	}
	for _, d := range v.extra {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				add(filepath.Join(d, e.Name(), name))
			}
		}
	}
	if matches, err := filepath.Glob(installDir + ".previous*"); err == nil {
		for _, m := range matches {
			add(filepath.Join(m, name))
		}
	}
	sort.SliceStable(backups, func(i, j int) bool { return backups[i].mod.After(backups[j].mod) })
	for _, b := range backups {
		out = append(out, b.path)
	}
	return out
}

// keep mirrors the identity file at path into the vault. A mirror copy holding
// a different key is kept, renamed, before the live file takes its place.
func (v *keyVault) keep(path string) error {
	if v.dir == "" {
		return nil
	}
	live, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(v.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(v.dir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(v.dir, filepath.Base(path))
	if old, err := os.ReadFile(dst); err == nil {
		if bytes.Equal(old, live) {
			return nil
		}
		kept := fmt.Sprintf("%s.replaced-%s", dst, time.Now().UTC().Format("20060102T150405Z"))
		if err := os.Rename(dst, kept); err != nil {
			return fmt.Errorf("keep the previous copy: %w", err)
		}
		v.logger.Printf("key vault: %s differs from the copy kept before; the old copy is kept as %s", path, kept)
	}
	return writeKeyFile(dst, live)
}

func isRegular(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// copyKeyFile copies src to dst (mode 0600), failing if dst exists.
func copyKeyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(dst); err == nil {
		return fs.ErrExist
	}
	return writeKeyFile(dst, b)
}

// writeKeyFile writes b to path atomically with mode 0600: a temp file in the
// same dir, synced, then renamed over.
func writeKeyFile(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // gone after the rename; cleans up a failure
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
