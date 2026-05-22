// Package evm implements the EVM-side cryptography the wallet uses to
// produce x402-compatible payments: secp256k1 keys, keccak256-based
// Ethereum addresses, EIP-712 typed data hashing for EIP-3009
// transferWithAuthorization, and ecrecover-based verification.
//
// No on-chain RPC happens here — this package is pure cryptography.
// The RPC client lives in package evm/chain so it can be swapped or
// mocked without dragging network code into the signer's tests.
package evm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Address is a 20-byte Ethereum address. Always rendered lowercase-hex
// with the "0x" prefix when shown to humans; raw 20-byte form is what
// the EIP-3009 typed data hashing uses.
type Address [20]byte

// String renders the address as 0x-prefixed lowercase hex.
func (a Address) String() string { return "0x" + hex.EncodeToString(a[:]) }

// Hex is the same as String, named to match common Ethereum APIs.
func (a Address) Hex() string { return a.String() }

// MarshalJSON renders as a hex string so manifests and audit rows stay
// human-readable.
func (a Address) MarshalJSON() ([]byte, error) { return json.Marshal(a.String()) }

// UnmarshalJSON accepts a hex string (with or without the 0x prefix).
func (a *Address) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := ParseAddress(s)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// ParseAddress parses a hex string (with or without 0x prefix) into an
// Address. Returns an error if the input is not exactly 20 bytes.
func ParseAddress(s string) (Address, error) {
	var a Address
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if len(s) != 40 {
		return a, fmt.Errorf("evm: address must be 20 bytes (40 hex chars), got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return a, fmt.Errorf("evm: address hex: %w", err)
	}
	copy(a[:], b)
	return a, nil
}

// EVMSigner holds a secp256k1 private key and its derived EVM address.
// The private key never leaves the daemon process in production; for
// the standalone wallet binary it's loaded from disk via
// LoadOrCreateEVMSigner with strict 0600 file mode.
type EVMSigner struct {
	priv *secp.PrivateKey
	addr Address
}

// NewEVMSigner generates a fresh secp256k1 keypair and derives its
// Ethereum address.
func NewEVMSigner() (*EVMSigner, error) {
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("evm: gen key: %w", err)
	}
	return signerFromPriv(priv), nil
}

// EVMSignerFromSeed reconstructs a signer from a 32-byte private key.
func EVMSignerFromSeed(seed []byte) (*EVMSigner, error) {
	if len(seed) != 32 {
		return nil, errors.New("evm: seed must be 32 bytes")
	}
	priv := secp.PrivKeyFromBytes(seed)
	return signerFromPriv(priv), nil
}

func signerFromPriv(priv *secp.PrivateKey) *EVMSigner {
	pub := priv.PubKey()
	// EVM address = last 20 bytes of keccak256(uncompressed_pubkey[1:])
	// SerializeUncompressed gives us 0x04 || X(32) || Y(32); we drop
	// the 0x04 prefix per Ethereum convention.
	uncompressed := pub.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	digest := h.Sum(nil)
	var addr Address
	copy(addr[:], digest[12:])
	return &EVMSigner{priv: priv, addr: addr}
}

// Address returns the signer's EVM address.
func (s *EVMSigner) Address() Address { return s.addr }

// PublicKey returns the uncompressed secp256k1 public key (65 bytes,
// 0x04 || X || Y). Used by ecrecover round-trips and serialization.
func (s *EVMSigner) PublicKey() []byte { return s.priv.PubKey().SerializeUncompressed() }

// PrivateKeyBytes returns the 32-byte raw private key. Caller is
// responsible for zeroing memory; in production code the daemon
// avoids ever exposing this byte slice outside the wallet process.
func (s *EVMSigner) PrivateKeyBytes() []byte { return s.priv.Serialize() }

// SignDigest signs a 32-byte digest with the signer's key and returns
// a 65-byte signature in Ethereum's canonical R || S || V format,
// where V is 27 or 28 (the legacy Ethereum convention).
//
// digest is the keccak256 of whatever the caller wants to sign — for
// EIP-3009 that's the EIP-712 typed-data digest produced by
// EIP3009Digest below.
func (s *EVMSigner) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("evm: digest must be 32 bytes")
	}
	// ecdsa.SignCompact returns 65 bytes: V (1) || R (32) || S (32).
	// We rearrange to Ethereum's expected R || S || V layout.
	compact := ecdsa.SignCompact(s.priv, digest, false)
	if len(compact) != 65 {
		return nil, fmt.Errorf("evm: unexpected sig len %d", len(compact))
	}
	v := compact[0]
	// dcrec V uses 27 + recid; map to Ethereum legacy 27/28 if needed.
	if v < 27 {
		v += 27
	}
	out := make([]byte, 65)
	copy(out[:32], compact[1:33])  // R
	copy(out[32:64], compact[33:]) // S
	out[64] = v
	return out, nil
}

// Recover recovers the EVM address that signed digest with signature.
// Returns ErrBadSignature if the signature shape is wrong or recovery
// fails. The recovered address can be compared with the expected from-
// address to verify the signer's identity.
func Recover(digest, signature []byte) (Address, error) {
	if len(digest) != 32 {
		return Address{}, errors.New("evm: digest must be 32 bytes")
	}
	if len(signature) != 65 {
		return Address{}, errors.New("evm: signature must be 65 bytes")
	}
	// Rebuild dcrec's V || R || S compact format.
	v := signature[64]
	if v >= 27 {
		v -= 27
	}
	compact := make([]byte, 65)
	compact[0] = v + 27 // dcrec wants 27 + recid for non-compressed
	copy(compact[1:33], signature[:32])
	copy(compact[33:], signature[32:64])
	pub, _, err := ecdsa.RecoverCompact(compact, digest)
	if err != nil {
		return Address{}, fmt.Errorf("evm: recover: %w", err)
	}
	uncompressed := pub.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	digestPub := h.Sum(nil)
	var addr Address
	copy(addr[:], digestPub[12:])
	return addr, nil
}

// ── persistence ────────────────────────────────────────────────────────

// identityFile is the on-disk shape of a persisted EVM signer. Same
// shape as the Ed25519 identity file for symmetry, with the addition
// of the derived EVM address (so humans can see it without re-deriving).
type identityFile struct {
	Type      string `json:"type"`       // "evm-secp256k1"
	Seed      string `json:"seed"`       // 32-byte hex
	Address   string `json:"address"`    // 0x-prefixed EVM address
	CreatedAt string `json:"created_at"` // RFC3339
}

// LoadOrCreateEVMSigner reads a persisted EVM signer from path, or
// generates a fresh one if the file doesn't exist. 0600 mode, parent
// dirs created as needed. Idempotent.
func LoadOrCreateEVMSigner(path string) (*EVMSigner, error) {
	if path == "" {
		return nil, errors.New("evm: identity path required")
	}
	if s, err := LoadEVMSigner(path); err == nil {
		return s, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	signer, err := NewEVMSigner()
	if err != nil {
		return nil, err
	}
	if err := saveEVMSigner(path, signer); err != nil {
		return nil, fmt.Errorf("evm: persist: %w", err)
	}
	return signer, nil
}

// LoadEVMSigner reads an existing identity file. Returns os.ErrNotExist
// if absent; callers wanting create-on-absent use LoadOrCreateEVMSigner.
//
// The file must be mode 0600 (owner-only). Anything broader is refused —
// see LoadLocalSigner in pkg/wallet for the same rationale (an EVM
// secp256k1 seed lets any reader move funds, so the OpenSSH-style
// permissions check is non-optional).
func LoadEVMSigner(path string) (*EVMSigner, error) {
	if info, err := os.Stat(path); err == nil {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("evm: identity %s: permissions %#o expose the seed to other users — chmod 0600 to fix", path, perm)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f identityFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("evm: parse identity %s: %w", path, err)
	}
	if f.Type != "" && f.Type != "evm-secp256k1" {
		return nil, fmt.Errorf("evm: identity %s is type %q, want evm-secp256k1", path, f.Type)
	}
	seed, err := hex.DecodeString(f.Seed)
	if err != nil {
		return nil, fmt.Errorf("evm: decode seed: %w", err)
	}
	signer, err := EVMSignerFromSeed(seed)
	if err != nil {
		return nil, err
	}
	if f.Address != "" {
		want, err := ParseAddress(f.Address)
		if err != nil {
			return nil, fmt.Errorf("evm: identity %s address field: %w", path, err)
		}
		if want != signer.addr {
			return nil, fmt.Errorf("evm: identity %s: address field %s disagrees with derived %s", path, want, signer.addr)
		}
	}
	return signer, nil
}

func saveEVMSigner(path string, s *EVMSigner) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("evm: mkdir: %w", err)
	}
	f := identityFile{
		Type:      "evm-secp256k1",
		Seed:      hex.EncodeToString(s.PrivateKeyBytes()),
		Address:   s.addr.String(),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// RandomNonce returns a 32-byte cryptographically random nonce for use
// in EIP-3009 authorizations. Each authorization MUST use a unique
// nonce — the USDC contract tracks consumed nonces per from-address.
func RandomNonce() ([32]byte, error) {
	var n [32]byte
	_, err := rand.Read(n[:])
	return n, err
}

// Keccak256 is a tiny helper for tests + EIP-3009 hashing.
func Keccak256(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
