// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	root    string   // the vault root ("" = no mirror)
	appID   string   // the install dir's name
	dir     string   // the mirror for this install path; "" turns it off
	backups []string // pilotctl's backup dirs for this app
	install string   // the install dir; <install>.previous[-*] are searched too
	logger  *log.Logger
}

// errNotAKeyCopy marks a candidate that is not a usable copy of the key: not a
// regular file of this user's, or not a key. The next candidate is tried. Any
// other error (a copy that cannot be read or put in place) stops the restore:
// the wallet then exits and the daemon retries, rather than starting on a new
// or older key while the right one is on disk.
var errNotAKeyCopy = errors.New("not a usable copy of the key")

// linkFile makes a hard link; a test seam for filesystems without them.
var linkFile = os.Link

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
	v := &keyVault{root: vaultRoot, appID: appID, install: installDir, logger: logger}
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
// path exists, or no copy exists anywhere and a new key may be created).
// valid loads a candidate the way the wallet will, so a corrupt or unrelated
// file is never put in place of a missing key.
//
// It returns an error, and the wallet does not start, when a copy cannot be
// read or put in place, and when copies of this key exist that it does not
// restore from (another install path's mirror): a new key is created only
// when there is no copy at all.
func (v *keyVault) restore(path string, valid func(string) error) (string, error) {
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	name := filepath.Base(path)
	cands := v.candidates(name)
	for i, src := range cands {
		placed, err := v.restoreFrom(src, path, valid)
		if errors.Is(err, errNotAKeyCopy) {
			v.logger.Printf("key vault: skipping %s: %v", src, err)
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%s is missing and the copy at %s could not be restored: %w", path, src, err)
		}
		if !placed {
			return "", nil // the file appeared meanwhile: leave it
		}
		v.logger.Printf("key vault: %s was missing; restored the existing key from %s", path, src)
		v.warnDifferentCopies(path, cands[i+1:], valid)
		return src, nil
	}
	if others := v.otherCopies(name, filepath.Dir(path), valid); len(others) > 0 {
		return "", fmt.Errorf("%s is missing, and copies of it exist for another install path: %s. Not creating a new key: copy the right one to %s, or move these away to start over",
			path, strings.Join(others, ", "), path)
	}
	return "", nil
}

// restoreFrom validates src in a temp file beside path and puts it in place
// without replacing anything: a hard link, or an exclusive create where links
// are not supported. It reports false, with no error, when path appeared
// meanwhile, and errNotAKeyCopy for a candidate that is not this user's key.
func (v *keyVault) restoreFrom(src, path string, valid func(string) error) (bool, error) {
	f, err := openNoFollow(src)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || isSymlinkErr(src) {
			return false, fmt.Errorf("%w: %v", errNotAKeyCopy, err)
		}
		return false, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return false, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return false, fmt.Errorf("%w: not a regular file", errNotAKeyCopy)
	}
	if !ownedByMe(fi) {
		f.Close()
		return false, fmt.Errorf("%w: owned by another user", errNotAKeyCopy)
	}
	b, err := io.ReadAll(f)
	f.Close()
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
	defer func() { _ = os.Remove(tmp) }() // the temp name only
	if err := valid(tmp); err != nil {
		return false, fmt.Errorf("%w: %v", errNotAKeyCopy, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		v.logger.Printf("key vault: %s was readable by others (mode %#o); restored as 0600", src, fi.Mode().Perm())
	}
	return placeExclusive(tmp, path, b)
}

// placeExclusive puts the bytes b, already written to tmp, at path without
// replacing a file there: a hard link of tmp, or, where hard links are not
// supported, an exclusive create of path written and synced. It reports
// false, with no error, when path exists.
func placeExclusive(tmp, path string, b []byte) (bool, error) {
	err := linkFile(tmp, path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrExist) {
		return false, nil
	}
	return createExclusive(path, b)
}

// createExclusive creates path (0600, failing if it exists) holding b, synced.
func createExclusive(path string, b []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(path) // the partial file this call created, nothing else
		return false, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(path)
		return false, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return false, err
	}
	return true, nil
}

// isSymlinkErr reports whether p is a symlink (an O_NOFOLLOW open of it fails
// with ELOOP, or EMLINK on some systems).
func isSymlinkErr(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&fs.ModeSymlink != 0
}

// otherCopies lists usable copies of name kept for this app under another
// install path, and a copy at the vault root itself: never restored from (a
// different install's key), but the reason not to create a new one.
func (v *keyVault) otherCopies(name, liveDir string, valid func(string) error) []string {
	if v.root == "" {
		return nil
	}
	paths, _ := filepath.Glob(filepath.Join(v.root, v.appID+"-*", name))
	paths = append(paths, filepath.Join(v.root, name))
	var out []string
	for _, p := range paths {
		if filepath.Dir(p) == v.dir {
			continue
		}
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || !ownedByMe(fi) {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			out = append(out, p) // unreadable, but a copy: still a reason to stop
			continue
		}
		tmp, err := writeTemp(liveDir, name, b)
		if err != nil {
			out = append(out, p)
			continue
		}
		ok := valid(tmp) == nil
		_ = os.Remove(tmp)
		if ok {
			out = append(out, p)
		}
	}
	return out
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
			placed, err := placeExclusive(tmp, dst, live)
			_ = os.Remove(tmp)
			if err != nil {
				return err
			}
			if !placed {
				continue // another start wrote it meanwhile: compare again
			}
			return nil
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
		err := linkFile(src, n)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			b, rerr := os.ReadFile(src)
			if rerr != nil {
				return "", rerr
			}
			placed, cerr := createExclusive(n, b)
			if cerr != nil {
				return "", cerr
			}
			if placed {
				return n, nil
			}
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
