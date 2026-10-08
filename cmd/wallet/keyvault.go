// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
// The mirror is kept per install path (<vault>/<dir name>-<hash of its path>),
// so a second wallet with other paths (a dev run, a test) never sees or
// replaces this one's keys.
//
// Nothing here deletes or overwrites a key without a copy: a mirror copy that
// differs from the live file is first linked to a unique replaced-<time> name;
// a restore links the validated copy into place, which fails rather than
// replace a file that appeared meanwhile.
type keyVault struct {
	dir     string   // the mirror for this install path; "" turns it off
	backups []string // pilotctl's backup dirs for this app
	install string   // the install dir; <install>.previous-* are searched too
	logger  *log.Logger
}

// newKeyVault is the vault for identity files kept in installDir: its mirror
// under vaultRoot (empty = no mirror), and pilotctl's backups of this app,
// which are kept per app under <backup root>/<app id>/<stamp>-v<version>/:
// $PILOT_APPSTORE_BACKUP_ROOT, else app-backups beside the install root, and,
// when those fail, .app-backups inside the install root or an
// <app id>.previous-<stamp> dir beside the install.
func newKeyVault(vaultRoot, installDir string, logger *log.Logger) *keyVault {
	if abs, err := filepath.Abs(installDir); err == nil {
		installDir = abs
	}
	appID := filepath.Base(installDir)
	root := filepath.Dir(installDir)
	v := &keyVault{install: installDir, logger: logger}
	if vaultRoot != "" {
		sum := sha256.Sum256([]byte(installDir))
		v.dir = filepath.Join(vaultRoot, appID+"-"+hex.EncodeToString(sum[:])[:12])
	}
	if r := os.Getenv("PILOT_APPSTORE_BACKUP_ROOT"); r != "" {
		v.backups = append(v.backups, filepath.Join(r, appID))
	}
	v.backups = append(v.backups,
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

// restore puts back the identity file at path from the best copy that valid
// accepts, when path does not exist, and reports where it came from ("" =
// nothing restored: path exists, or no copy was found and a new key will be
// created). valid loads a candidate the way the wallet will, so a corrupt or
// unrelated file is never put in place of a missing key.
func (v *keyVault) restore(path string, valid func(string) error) (string, error) {
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	name := filepath.Base(path)
	cands := v.candidates(name)
	for i, src := range cands {
		placed, err := v.restoreFrom(src, path, valid)
		if err != nil {
			v.logger.Printf("key vault: not restoring %s from %s: %v", path, src, err)
			continue
		}
		if !placed {
			return "", nil // the file appeared meanwhile: leave it
		}
		v.logger.Printf("key vault: %s was missing; restored the existing key from %s", path, src)
		v.warnDifferentCopies(path, cands[i+1:], valid)
		return src, nil
	}
	return "", nil
}

// restoreFrom validates src in a temp file beside path and links it into
// place. It reports false, with no error, when path appeared meanwhile.
func (v *keyVault) restoreFrom(src, path string, valid func(string) error) (bool, error) {
	fi, err := os.Lstat(src)
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, errors.New("not a regular file")
	}
	if !ownedByMe(fi) {
		return false, errors.New("owned by another user")
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	tmp, err := writeTemp(dir, filepath.Base(path), b)
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp) }() // the temp name only; path keeps its link
	if err := valid(tmp); err != nil {
		return false, fmt.Errorf("not a usable key: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		v.logger.Printf("key vault: %s was readable by others (mode %#o); restored as 0600", src, fi.Mode().Perm())
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// warnDifferentCopies logs every other usable copy holding a different key
// than the one just restored to path: they are kept, not used, and the
// operator should know.
func (v *keyVault) warnDifferentCopies(path string, others []string, valid func(string) error) {
	live, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, o := range others {
		fi, err := os.Lstat(o)
		if err != nil || !fi.Mode().IsRegular() || !ownedByMe(fi) {
			continue
		}
		b, err := os.ReadFile(o)
		if err != nil || bytes.Equal(b, live) {
			continue
		}
		tmp, err := writeTemp(filepath.Dir(path), filepath.Base(path), b)
		if err != nil {
			continue
		}
		ok := valid(tmp) == nil
		_ = os.Remove(tmp)
		if ok {
			v.logger.Printf("key vault: WARNING: %s holds a different key than the one restored to %s; it is kept, not used", o, path)
		}
	}
}

// candidates lists the copies of an identity file named name, best first: the
// mirror, then pilotctl's backups newest first (by the stamp that starts each
// backup's dir name, else its mtime; newer name first on a tie).
func (v *keyVault) candidates(name string) []string {
	var out []string
	if v.dir != "" {
		if p := filepath.Join(v.dir, name); exists(p) {
			out = append(out, p)
		}
	}
	type found struct {
		path, dir string
		when      time.Time
	}
	var backups []found
	add := func(dir string) {
		p := filepath.Join(dir, name)
		fi, err := os.Lstat(p)
		if err != nil {
			return
		}
		when := fi.ModTime()
		if t, ok := backupStamp(filepath.Base(dir)); ok {
			when = t
		}
		backups = append(backups, found{p, filepath.Base(dir), when})
	}
	for _, d := range v.backups {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				add(filepath.Join(d, e.Name()))
			}
		}
	}
	if matches, err := filepath.Glob(v.install + ".previous-*"); err == nil {
		for _, m := range matches {
			add(m)
		}
	}
	add(v.install + ".previous")
	sort.SliceStable(backups, func(i, j int) bool {
		if !backups[i].when.Equal(backups[j].when) {
			return backups[i].when.After(backups[j].when)
		}
		return backups[i].dir > backups[j].dir
	})
	for _, b := range backups {
		out = append(out, b.path)
	}
	return out
}

// backupStamp parses the UTC stamp pilotctl starts a backup's dir name with
// (20060102T150405.000000000Z, then -v<version>), or that follows
// ".previous-" in a dir it had to leave beside the install.
func backupStamp(dir string) (time.Time, bool) {
	if i := strings.Index(dir, ".previous-"); i >= 0 {
		dir = dir[i+len(".previous-"):]
	}
	if i := strings.Index(dir, "Z"); i > 0 {
		if t, err := time.Parse("20060102T150405.000000000Z", dir[:i+1]); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// keep mirrors the identity file at path into the vault. A mirror copy holding
// a different key is first linked to a unique replaced-<time> name; a mirror
// copy that cannot be read is left alone and keep fails.
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
	for attempt := 0; attempt < 3; attempt++ {
		old, err := os.ReadFile(dst)
		switch {
		case err == nil && bytes.Equal(old, live):
			return nil
		case err == nil:
			kept, err := linkUnique(dst, dst+".replaced-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
			if err != nil {
				return fmt.Errorf("keep the previous copy: %w", err)
			}
			v.logger.Printf("key vault: WARNING: %s holds a different key than the copy kept before; the old copy is kept as %s", path, kept)
			tmp, err := writeTemp(v.dir, filepath.Base(dst), live)
			if err != nil {
				return err
			}
			return os.Rename(tmp, dst) // the old bytes are kept under their replaced- name
		case errors.Is(err, fs.ErrNotExist):
			tmp, err := writeTemp(v.dir, filepath.Base(dst), live)
			if err != nil {
				return err
			}
			err = os.Link(tmp, dst)
			_ = os.Remove(tmp)
			if errors.Is(err, fs.ErrExist) {
				continue // another start wrote it meanwhile: compare again
			}
			return err
		default:
			return fmt.Errorf("the copy kept at %s cannot be read (%v); left as it is", dst, err)
		}
	}
	return fmt.Errorf("the copy kept at %s keeps changing; left as it is", dst)
}

// linkUnique links src to name, or to name-1, name-2, … when taken, and
// returns the name used. A link never replaces an existing file.
func linkUnique(src, name string) (string, error) {
	for i := 0; i < 100; i++ {
		n := name
		if i > 0 {
			n = fmt.Sprintf("%s-%d", name, i)
		}
		err := os.Link(src, n)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("no free name for %s", name)
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// writeTemp writes b to a new 0600 temp file in dir, synced, and returns its
// name.
func writeTemp(dir, base string, b []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	fail := func(err error) (string, error) {
		tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}
