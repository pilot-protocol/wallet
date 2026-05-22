package wallet

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateLocalSignerCreatesIfAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "identity.json")
	s, err := LoadOrCreateLocalSigner(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(s.PublicKey()) != 32 {
		t.Fatalf("pubkey size: %d", len(s.PublicKey()))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("identity file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("identity mode: %o, want 0600", info.Mode().Perm())
	}
}

func TestLoadOrCreateLocalSignerRoundtrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	first, err := LoadOrCreateLocalSigner(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := LoadOrCreateLocalSigner(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !bytesEqual(first.PublicKey(), second.PublicKey()) {
		t.Errorf("pubkey mismatch across load/load")
	}

	// Sign with first, verify same signature from second.
	msg := []byte("test message")
	sig1, _ := first.Sign(msg)
	sig2, _ := second.Sign(msg)
	if !bytesEqual(sig1, sig2) {
		t.Errorf("signatures differ — keys not deterministic")
	}
}

func TestLoadLocalSignerMissingFile(t *testing.T) {
	_, err := LoadLocalSigner(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("want os.ErrNotExist, got %v", err)
	}
}

func TestLoadLocalSignerRejectsMismatchedPubkey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if _, err := LoadOrCreateLocalSigner(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Tamper: replace pubkey field with a different (but valid-shape) hex.
	bad := []byte(`{"seed":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"deadbeef00000000000000000000000000000000000000000000000000000000","created_at":"2025-01-01T00:00:00Z"}`)
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("write tamper: %v", err)
	}
	_, err := LoadLocalSigner(path)
	if err == nil || !contains(err.Error(), "disagrees") {
		t.Errorf("want pubkey-mismatch error, got %v", err)
	}
}

// TestLoadLocalSignerRefusesWorldReadable confirms the wallet refuses
// to load an identity file whose perms expose the seed to other local
// users. Matches OpenSSH's threat model — a chmod 0644 must NOT
// silently work, since the seed lets any reader impersonate the wallet.
func TestLoadLocalSignerRefusesWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if _, err := LoadOrCreateLocalSigner(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := LoadLocalSigner(path)
	if err == nil {
		t.Fatal("LoadLocalSigner accepted 0644 identity — should have refused")
	}
	if !contains(err.Error(), "permissions") || !contains(err.Error(), "chmod 0600") {
		t.Errorf("error %q should mention permissions + chmod 0600 hint", err.Error())
	}
	// And the LoadOrCreate path must propagate the same refusal,
	// not silently regenerate (which would destroy the user's key).
	if _, err := LoadOrCreateLocalSigner(path); err == nil {
		t.Error("LoadOrCreate silently accepted 0644 — would silently destroy a real key")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
