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
	if fi, err := os.Stat(f.vaultDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("vault dir: %v, mode %v; want 0700", err, fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Join(f.vaultDir, "identity-evm.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault copy: %v; want mode 0600", err)
	}

	if err := os.RemoveAll(f.install); err != nil { // the uninstall
		t.Fatal(err)
	}
	src, err := f.v.restore(path, validEVM)
	if err != nil || src != filepath.Join(f.vaultDir, "identity-evm.json") {
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
	if err := os.MkdirAll(f.vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.vaultDir, "identity-evm.json"), []byte("{not a key"), 0o600); err != nil {
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
	if got := evmAddr(t, filepath.Join(f.vaultDir, "identity-evm.json")); got != second {
		t.Fatalf("vault holds %s, want the live key %s", got, second)
	}
	matches, _ := filepath.Glob(filepath.Join(f.vaultDir, "identity-evm.json.replaced-*"))
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
