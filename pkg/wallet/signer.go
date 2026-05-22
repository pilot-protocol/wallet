package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LocalSigner is an Ed25519 signer that holds its private key in process
// memory. Used for tests and for standalone wallet operation; in the
// integrated runtime the daemon's key.sign IPC replaces this.
type LocalSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// NewLocalSigner generates a fresh Ed25519 keypair.
func NewLocalSigner() (*LocalSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &LocalSigner{pub: pub, priv: priv}, nil
}

// LocalSignerFromSeed reconstructs a signer from a 32-byte seed —
// useful for tests that want determinism.
func LocalSignerFromSeed(seed []byte) (*LocalSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("seed must be ed25519.SeedSize")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &LocalSigner{pub: priv.Public().(ed25519.PublicKey), priv: priv}, nil
}

// PublicKey returns the 32-byte Ed25519 public key.
func (s *LocalSigner) PublicKey() []byte { return append([]byte(nil), s.pub...) }

// Sign returns the 64-byte Ed25519 signature over msg.
func (s *LocalSigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

// identityFile is the on-disk shape of a persisted signer. The seed
// regenerates both halves of the ed25519 keypair so storing it alone is
// sufficient; the pubkey field is for human inspection.
type identityFile struct {
	Seed      string `json:"seed"`      // 32-byte hex
	Pubkey    string `json:"pubkey"`    // 32-byte hex
	CreatedAt string `json:"created_at"`
}

// LoadOrCreateLocalSigner reads a persisted identity from path, or
// generates and writes a fresh one if the file doesn't exist. The file
// is created with mode 0600. Parent directories are created if needed.
//
// This is the standalone-wallet equivalent of the daemon's HKDF-derived
// per-app key: same idea (one keypair, persisted to disk), but the user
// owns the file directly rather than going through the daemon broker.
func LoadOrCreateLocalSigner(path string) (*LocalSigner, error) {
	if path == "" {
		return nil, errors.New("identity path required")
	}
	if s, err := LoadLocalSigner(path); err == nil {
		return s, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// Generate fresh and persist.
	signer, err := NewLocalSigner()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	if err := saveLocalSigner(path, signer); err != nil {
		return nil, fmt.Errorf("persist identity: %w", err)
	}
	return signer, nil
}

// LoadLocalSigner reads and parses an identity file. Returns os.ErrNotExist
// if the file is missing — callers wanting create-on-absent should use
// LoadOrCreateLocalSigner.
//
// The file must be mode 0600 (owner-only). Anything broader is treated
// as a config error and refused, the same way OpenSSH refuses
// world-readable private keys. Without this check a `chmod 644` on the
// identity file would silently let any local user read the seed and
// impersonate the wallet.
func LoadLocalSigner(path string) (*LocalSigner, error) {
	if info, err := os.Stat(path); err == nil {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("identity %s: permissions %#o expose the seed to other users — chmod 0600 to fix", path, perm)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f identityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse identity %s: %w", path, err)
	}
	seed, err := hex.DecodeString(f.Seed)
	if err != nil {
		return nil, fmt.Errorf("decode seed in %s: %w", path, err)
	}
	signer, err := LocalSignerFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("invalid seed in %s: %w", path, err)
	}
	// Defensive: confirm the recorded pubkey matches the derived one,
	// so a tampered file with mismatched seed/pubkey is caught.
	if f.Pubkey != "" {
		want, err := hex.DecodeString(f.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey in %s: %w", path, err)
		}
		if !bytesEqual(want, signer.pub) {
			return nil, fmt.Errorf("identity %s: pubkey field disagrees with derived key", path)
		}
	}
	return signer, nil
}

func saveLocalSigner(path string, s *LocalSigner) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}
	seed := s.priv.Seed()
	f := identityFile{
		Seed:      hex.EncodeToString(seed),
		Pubkey:    hex.EncodeToString(s.pub),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	// Write to a tmp then rename — never leave a half-written identity file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
