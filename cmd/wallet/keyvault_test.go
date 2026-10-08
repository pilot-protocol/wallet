// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/wallet/pkg/evm"
	"github.com/pilot-protocol/wallet/pkg/wallet"
)

// vaultFixture is a home dir laid out like a node's: the install dir
// (~/.pilot/apps/io.pilot.wallet), the vault (~/.pilot/keys/io.pilot.wallet)
// and pilotctl's backups (~/.pilot/app-backups/io.pilot.wallet).
type vaultFixture struct {
	install, vaultDir, backups string
	v                          *keyVault
}

func newVaultFixture(t *testing.T) *vaultFixture {
	t.Helper()
	t.Setenv("PILOT_APPSTORE_BACKUP_ROOT", "")
	home := t.TempDir()
	f := &vaultFixture{
		install:  filepath.Join(home, ".pilot", "apps", "io.pilot.wallet"),
		vaultDir: filepath.Join(home, ".pilot", "keys", "io.pilot.wallet"),
		backups:  filepath.Join(home, ".pilot", "app-backups", "io.pilot.wallet"),
	}
	if err := os.MkdirAll(f.install, 0o700); err != nil {
		t.Fatal(err)
	}
	f.v = newKeyVault(f.vaultDir, f.install, log.New(io.Discard, "", 0))
	return f
}

func validEVM(p string) error { _, err := evm.LoadEVMSigner(p); return err }

func walletValid(p string) error { _, err := wallet.LoadLocalSigner(p); return err }

func walletLoadOrCreate(p string) (*wallet.LocalSigner, error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	return wallet.LoadOrCreateLocalSigner(p)
}

// newEVMKey creates an EVM identity file at path, as the wallet does on first
// start, and returns its address.
func newEVMKey(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := evm.LoadOrCreateEVMSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	return s.Address().String()
}

func evmAddr(t *testing.T, path string) string {
	t.Helper()
	s, err := evm.LoadEVMSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	return s.Address().String()
}

// Uninstall removes the install dir with the key in it. On its next start the
// wallet used to create a new key, and funds at the old address were out of
// reach. The key kept in the vault comes back instead.
func TestKeyVaultBringsTheKeyBackAfterTheInstallDirIsGone(t *testing.T) {
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	addr := newEVMKey(t, path)
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(f.v.dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("vault dir: %v, mode %v; want 0700", err, fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Join(f.v.dir, "identity-evm.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault copy: %v; want mode 0600", err)
	}

	if err := os.RemoveAll(f.install); err != nil { // the uninstall
		t.Fatal(err)
	}
	src, err := f.v.restore(path, validEVM)
	if err != nil || src != filepath.Join(f.v.dir, "identity-evm.json") {
		t.Fatalf("restore = %q, %v; want it from the vault", src, err)
	}
	if got := evmAddr(t, path); got != addr {
		t.Fatalf("restored address %s, want the old %s", got, addr)
	}
	// What the wallet does next: load, not create.
	s, err := evm.LoadOrCreateEVMSigner(path)
	if err != nil || s.Address().String() != addr {
		t.Fatalf("wallet would start with %v (%v), want %s", s, err, addr)
	}
}

// A node whose wallet predates the vault has no vault copy, but pilotctl keeps
// the dirs it replaces or uninstalls. The newest copy there comes back.
func TestKeyVaultBringsTheKeyBackFromPilotctlBackups(t *testing.T) {
	f := newVaultFixture(t)
	older := filepath.Join(f.backups, "20260901T000000.000000000Z-v0.3.2", "identity-evm.json")
	newer := filepath.Join(f.backups, "20261001T000000.000000000Z-v0.3.3", "identity-evm.json")
	newEVMKey(t, older)
	want := newEVMKey(t, newer)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(older, old, old); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(f.install, "identity-evm.json")
	if _, err := f.v.restore(path, validEVM); err != nil {
		t.Fatal(err)
	}
	if got := evmAddr(t, path); got != want {
		t.Fatalf("restored %s, want the newest backup's %s", got, want)
	}
}

// A copy that does not load as a key is never put in place of a missing one.
func TestKeyVaultSkipsACorruptCopy(t *testing.T) {
	f := newVaultFixture(t)
	if err := os.MkdirAll(f.v.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.v.dir, "identity-evm.json"), []byte("{not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := newEVMKey(t, filepath.Join(f.backups, "20261001T000000.000000000Z-v0.3.3", "identity-evm.json"))

	path := filepath.Join(f.install, "identity-evm.json")
	if _, err := f.v.restore(path, validEVM); err != nil {
		t.Fatal(err)
	}
	if got := evmAddr(t, path); got != want {
		t.Fatalf("restored %s, want the valid backup's %s", got, want)
	}
}

// The vault never overwrites a different key: the old copy is kept, renamed.
func TestKeyVaultNeverLosesADifferentKey(t *testing.T) {
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	first := newEVMKey(t, path)
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	second := newEVMKey(t, path) // a different key in the install dir
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	if got := evmAddr(t, filepath.Join(f.v.dir, "identity-evm.json")); got != second {
		t.Fatalf("vault holds %s, want the live key %s", got, second)
	}
	matches, _ := filepath.Glob(filepath.Join(f.v.dir, "identity-evm.json.replaced-*"))
	if len(matches) != 1 {
		t.Fatalf("kept copies %v, want the first key kept once", matches)
	}
	if got := evmAddr(t, matches[0]); got != first {
		t.Fatalf("kept copy holds %s, want the first key %s", got, first)
	}
}

// A key in place is left alone, and with nothing to restore from, nothing is
// restored (the wallet then creates its first key, as before).
func TestKeyVaultLeavesAnExistingKeyAlone(t *testing.T) {
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	if src, err := f.v.restore(path, validEVM); err != nil || src != "" {
		t.Fatalf("restore with no copies = %q, %v; want nothing", src, err)
	}
	addr := newEVMKey(t, path)
	newEVMKey(t, filepath.Join(f.backups, "20261001T000000.000000000Z-v0.3.3", "identity-evm.json"))
	if src, err := f.v.restore(path, validEVM); err != nil || src != "" {
		t.Fatalf("restore over an existing key = %q, %v; want nothing", src, err)
	}
	if got := evmAddr(t, path); got != addr {
		t.Fatalf("existing key replaced: %s, want %s", got, addr)
	}
}

// The ed25519 identity is kept and restored the same way.
func TestKeyVaultCoversTheOverlayIdentity(t *testing.T) {
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity.json")
	s, err := walletLoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.install); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.restore(path, walletValid); err != nil {
		t.Fatal(err)
	}
	s2, err := walletLoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(string(s.PublicKey()), string(s2.PublicKey())) {
		t.Fatal("the overlay identity came back as a different key")
	}
}

// Each install path has its own mirror: a second wallet with other paths (a
// dev run, a test) neither gets this one's key nor replaces its copy.
func TestKeyVaultMirrorIsPerInstallPath(t *testing.T) {
	f := newVaultFixture(t)
	real := filepath.Join(f.install, "identity-evm.json")
	realAddr := newEVMKey(t, real)
	if err := f.v.keep(real); err != nil {
		t.Fatal(err)
	}
	devDir := filepath.Join(filepath.Dir(f.install), "..", "..", "dev", "wallet")
	dev := newKeyVault(f.vaultDir, devDir, log.New(io.Discard, "", 0))
	if dev.dir == f.v.dir {
		t.Fatalf("two install paths share the mirror %s", dev.dir)
	}
	devKey := filepath.Join(devDir, "identity-evm.json")
	if src, err := dev.restore(devKey, validEVM); err != nil || src != "" {
		t.Fatalf("the dev wallet was given a copy (%q, %v); want a new key of its own", src, err)
	}
	newEVMKey(t, devKey)
	if err := dev.keep(devKey); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.install); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.restore(real, validEVM); err != nil {
		t.Fatal(err)
	}
	if got := evmAddr(t, real); got != realAddr {
		t.Fatalf("restored %s, want this install's own key %s", got, realAddr)
	}
}

// A mirror copy that cannot be read is never overwritten: keep fails.
func TestKeyVaultKeepLeavesAnUnreadableCopy(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads mode-000 files")
	}
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	newEVMKey(t, path)
	if err := os.MkdirAll(f.v.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(f.v.dir, "identity-evm.json")
	if err := os.WriteFile(locked, []byte("someone's key"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
	if err := f.v.keep(path); err == nil {
		t.Fatal("keep replaced a copy it could not read")
	}
	_ = os.Chmod(locked, 0o600)
	if b, _ := os.ReadFile(locked); string(b) != "someone's key" {
		t.Fatalf("the unreadable copy was changed: %q", b)
	}
}

// Keys replaced within the same second each keep a copy of their own.
func TestKeyVaultReplacedCopiesNeverCollide(t *testing.T) {
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	var addrs []string
	for i := 0; i < 3; i++ {
		_ = os.Remove(path)
		addrs = append(addrs, newEVMKey(t, path))
		if err := f.v.keep(path); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]bool{evmAddr(t, filepath.Join(f.v.dir, "identity-evm.json")): true}
	matches, _ := filepath.Glob(filepath.Join(f.v.dir, "identity-evm.json.replaced-*"))
	for _, m := range matches {
		got[evmAddr(t, m)] = true
	}
	for _, a := range addrs {
		if !got[a] {
			t.Fatalf("key %s is gone from the vault (have %v)", a, got)
		}
	}
}

// A restore never replaces a key file that appeared while it ran.
func TestKeyVaultRestoreNeverOverwritesAKeyThatAppeared(t *testing.T) {
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	newEVMKey(t, path)
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var appeared string
	racing := func(p string) error {
		if appeared == "" { // another start creates the key during validation
			appeared = newEVMKey(t, path)
		}
		return validEVM(p)
	}
	if src, err := f.v.restore(path, racing); err != nil || src != "" {
		t.Fatalf("restore = %q, %v; want it to stand back", src, err)
	}
	if got := evmAddr(t, path); got != appeared {
		t.Fatalf("the key that appeared was replaced: %s, want %s", got, appeared)
	}
}

// Backups are ordered by the stamp pilotctl names them with, not by mtime.
func TestKeyVaultPrefersTheNewestBackupByItsStamp(t *testing.T) {
	f := newVaultFixture(t)
	older := filepath.Join(f.backups, "20260901T000000.000000000Z-v0.3.2", "identity-evm.json")
	newer := filepath.Join(f.backups, "20261001T000000.000000000Z-v0.3.3", "identity-evm.json")
	newEVMKey(t, older)
	want := newEVMKey(t, newer)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(newer, old, old); err != nil { // the newer backup has the older mtime
		t.Fatal(err)
	}
	path := filepath.Join(f.install, "identity-evm.json")
	if _, err := f.v.restore(path, validEVM); err != nil {
		t.Fatal(err)
	}
	if got := evmAddr(t, path); got != want {
		t.Fatalf("restored %s, want the newest stamp's %s", got, want)
	}
}

// A symlink in the backups, or a dir that only starts like a previous
// install, is not a copy of this wallet's key.
func TestKeyVaultIgnoresSymlinksAndLookalikeDirs(t *testing.T) {
	f := newVaultFixture(t)
	elsewhere := filepath.Join(t.TempDir(), "planted.json")
	newEVMKey(t, elsewhere)
	link := filepath.Join(f.backups, "20261001T000000.000000000Z-v0.3.3", "identity-evm.json")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	newEVMKey(t, filepath.Join(f.install+".previouslyinstalled", "identity-evm.json"))
	path := filepath.Join(f.install, "identity-evm.json")
	if src, err := f.v.restore(path, validEVM); err != nil || src != "" {
		t.Fatalf("restore = %q, %v; want nothing restored", src, err)
	}
}

// When the copy restored and another usable copy disagree, it says so.
func TestKeyVaultWarnsWhenCopiesDisagree(t *testing.T) {
	f := newVaultFixture(t)
	var logs strings.Builder
	f.v.logger = log.New(&logs, "", 0)
	path := filepath.Join(f.install, "identity-evm.json")
	newEVMKey(t, path)
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	newEVMKey(t, filepath.Join(f.backups, "20261001T000000.000000000Z-v0.3.3", "identity-evm.json"))
	if err := os.RemoveAll(f.install); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.restore(path, validEVM); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "WARNING") || !strings.Contains(logs.String(), "holds a different key") {
		t.Fatalf("no warning about the disagreeing copy:\n%s", logs.String())
	}
}

// A copy that cannot be read is not "no copy": the restore stops with an
// error (the wallet exits, the daemon retries) rather than restoring an older
// key or letting a new one be created.
func TestKeyVaultStopsOnACopyItCannotRead(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads mode-000 files")
	}
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	newEVMKey(t, path)
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	newEVMKey(t, filepath.Join(f.backups, "20260901T000000.000000000Z-v0.3.2", "identity-evm.json")) // an older key
	mirror := filepath.Join(f.v.dir, "identity-evm.json")
	if err := os.Chmod(mirror, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(mirror, 0o600) })
	if err := os.RemoveAll(f.install); err != nil {
		t.Fatal(err)
	}
	if src, err := f.v.restore(path, validEVM); err == nil {
		t.Fatalf("restore went on past an unreadable copy (restored %q)", src)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("a key was placed although the right copy could not be read")
	}
}

// Where hard links are not supported (some network and FUSE homes), the copy
// is still put in place, exclusively, and kept.
func TestKeyVaultWorksWithoutHardLinks(t *testing.T) {
	f := newVaultFixture(t)
	prev := linkFile
	linkFile = func(string, string) error { return os.ErrPermission }
	t.Cleanup(func() { linkFile = prev })
	path := filepath.Join(f.install, "identity-evm.json")
	addr := newEVMKey(t, path)
	if err := f.v.keep(path); err != nil {
		t.Fatalf("keep without hard links: %v", err)
	}
	if err := os.RemoveAll(f.install); err != nil {
		t.Fatal(err)
	}
	if src, err := f.v.restore(path, validEVM); err != nil || src == "" {
		t.Fatalf("restore without hard links = %q, %v", src, err)
	}
	if got := evmAddr(t, path); got != addr {
		t.Fatalf("restored %s, want %s", got, addr)
	}
}

// A copy kept under another install path (HOME moved, another app root) is
// not restored, but it stops a new key from being created.
func TestKeyVaultWillNotCreateAKeyWhileAnotherCopyExists(t *testing.T) {
	f := newVaultFixture(t)
	other := newKeyVault(f.vaultDir, filepath.Join(t.TempDir(), "old-home", ".pilot", "apps", "io.pilot.wallet"), log.New(io.Discard, "", 0))
	oldKey := filepath.Join(other.install, "identity-evm.json")
	newEVMKey(t, oldKey)
	if err := other.keep(oldKey); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.install, "identity-evm.json")
	_, err := f.v.restore(path, validEVM)
	if err == nil || !strings.Contains(err.Error(), other.dir) {
		t.Fatalf("restore = %v; want it to refuse, naming %s", err, other.dir)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("another install's key was put in place")
	}
}

// A mirror dir the wallet cannot search is not "no copy": the restore stops
// (the wallet exits) rather than let a new key be created beside the old one.
func TestKeyVaultStopsWhenItCannotSearchTheMirror(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root searches mode-000 dirs")
	}
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	newEVMKey(t, path)
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.install); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.v.dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.v.dir, 0o700) })
	if src, err := f.v.restore(path, validEVM); err == nil {
		t.Fatalf("restore went on with the mirror unsearchable (restored %q)", src)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("a key was placed although the mirror could not be searched")
	}
}

// A backup is not restored when a copy kept under another install path holds
// a different key: which one is right is in doubt.
func TestKeyVaultWillNotRestoreOverADisagreeingCopyElsewhere(t *testing.T) {
	f := newVaultFixture(t)
	other := newKeyVault(f.vaultDir, filepath.Join(t.TempDir(), "old-home", ".pilot", "apps", "io.pilot.wallet"), log.New(io.Discard, "", 0))
	oldKey := filepath.Join(other.install, "identity-evm.json")
	newEVMKey(t, oldKey)
	if err := other.keep(oldKey); err != nil {
		t.Fatal(err)
	}
	newEVMKey(t, filepath.Join(f.backups, "20261001T000000.000000000Z-v0.3.3", "identity-evm.json")) // a different key
	path := filepath.Join(f.install, "identity-evm.json")
	if _, err := f.v.restore(path, validEVM); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("restore = %v; want it to refuse over the disagreeing copy", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("a key was placed although another copy disagrees")
	}
}

// A copy kept under another install path that holds the same key as the copy
// restored is no conflict, even when the identity file's dir does not exist yet.
func TestKeyVaultRestoresWhenACopyElsewhereAgrees(t *testing.T) {
	f := newVaultFixture(t)
	path := filepath.Join(f.install, "identity-evm.json")
	addr := newEVMKey(t, path)
	other := newKeyVault(f.vaultDir, filepath.Join(t.TempDir(), "old-home", ".pilot", "apps", "io.pilot.wallet"), log.New(io.Discard, "", 0))
	oldKey := filepath.Join(other.install, "identity-evm.json")
	if err := os.MkdirAll(other.install, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldKey, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := other.keep(oldKey); err != nil {
		t.Fatal(err)
	}
	if err := f.v.keep(path); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.install); err != nil { // the dir itself is gone
		t.Fatal(err)
	}
	if src, err := f.v.restore(path, validEVM); err != nil || src == "" {
		t.Fatalf("restore = %q, %v; want the agreeing copy restored", src, err)
	}
	if got := evmAddr(t, path); got != addr {
		t.Fatalf("restored %s, want %s", got, addr)
	}
}
