package evm

import (
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── address derivation ─────────────────────────────────────────────────

func TestAddressFromKnownPrivateKey(t *testing.T) {
	// Vitalik's well-known test vector: privkey 1 → known address.
	// privkey 0x000…001 (32 bytes) → address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
	seed, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	s, err := EVMSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	want := "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	if s.Address().String() != want {
		t.Errorf("address: %s, want %s", s.Address(), want)
	}
}

func TestParseAddress(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", false},
		{"7e5f4552091a69125d5dfcb7b8c2659029395bdf", "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", false}, // no prefix
		{"0X7E5F4552091A69125D5DFCB7B8C2659029395BDF", "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", false}, // uppercase
		{"short", "", true},
		{"0xshort", "", true},
		{"0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "", true}, // not hex
	}
	for _, c := range cases {
		got, err := ParseAddress(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseAddress(%q): want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAddress(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("ParseAddress(%q): %s, want %s", c.in, got, c.want)
		}
	}
}

// ── sign/recover roundtrip ──────────────────────────────────────────────

func TestSignAndRecoverRoundtrip(t *testing.T) {
	signer, err := NewEVMSigner()
	if err != nil {
		t.Fatal(err)
	}
	digest := Keccak256([]byte("hello x402"))
	sig, err := signer.SignDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len: %d, want 65", len(sig))
	}
	recovered, err := Recover(digest, sig)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != signer.Address() {
		t.Errorf("recovered %s, want %s", recovered, signer.Address())
	}
}

func TestRecoverRejectsTamperedSignature(t *testing.T) {
	signer, _ := NewEVMSigner()
	digest := Keccak256([]byte("x"))
	sig, _ := signer.SignDigest(digest)
	// Flip a bit in r
	sig[5] ^= 0xFF
	recovered, _ := Recover(digest, sig)
	if recovered == signer.Address() {
		t.Error("tampered signature still recovered to signer — that's a hole")
	}
}

func TestRecoverRejectsWrongDigest(t *testing.T) {
	signer, _ := NewEVMSigner()
	sig, _ := signer.SignDigest(Keccak256([]byte("a")))
	recovered, _ := Recover(Keccak256([]byte("b")), sig)
	if recovered == signer.Address() {
		t.Error("recovered same address against different digest")
	}
}

// ── EIP-3009 typed data hashing ─────────────────────────────────────────

func TestTransferWithAuthorizationTypeHash(t *testing.T) {
	// Cross-check the typehash constant against the standard string.
	want := Keccak256([]byte(
		"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
	))
	if hex.EncodeToString(TransferWithAuthorizationTypeHash) != hex.EncodeToString(want) {
		t.Errorf("type hash drifted: %x vs %x", TransferWithAuthorizationTypeHash, want)
	}
}

func TestUSDCDomainKnownChains(t *testing.T) {
	wantName := map[uint64]string{
		ChainEthereumMainnet: "USD Coin",
		ChainBaseMainnet:     "USD Coin",
		ChainPolygonMainnet:  "USD Coin",
		ChainBaseSepolia:     "USDC", // Circle's testnet deployment differs
	}
	for chainID, name := range wantName {
		d, err := USDCDomain(chainID)
		if err != nil {
			t.Fatalf("USDCDomain(%d): %v", chainID, err)
		}
		if d.Name != name || d.Version != "2" || d.ChainID != chainID {
			t.Errorf("domain for chain %d wrong: %+v (want name %q)", chainID, d, name)
		}
		// Separator must be 32 bytes.
		sep := d.Separator()
		if len(sep) != 32 {
			t.Errorf("chain %d separator len %d", chainID, len(sep))
		}
	}
}

// TestUSDCDomainSeparatorsMatchOnChain pins Domain.Separator() for every
// supported chain to the value the deployed USDC contract returns from
// DOMAIN_SEPARATOR() (fetched via eth_call, 2026-07-29). If any of these
// fail, signatures produced for that chain are unverifiable on-chain —
// this is the regression test for the Base Sepolia "USD Coin"/"USDC"
// domain-name mismatch.
func TestUSDCDomainSeparatorsMatchOnChain(t *testing.T) {
	onChain := map[uint64]string{
		ChainEthereumMainnet: "06c37168a7db5138defc7866392bb87a741f9b3d104deb5094588ce041cae335",
		ChainBaseMainnet:     "02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f",
		ChainPolygonMainnet:  "caa2ce1a5703ccbe253a34eb3166df60a705c561b44b192061e28f2a985be2ca",
		ChainBaseSepolia:     "71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818",
	}
	for chainID, want := range onChain {
		d, err := USDCDomain(chainID)
		if err != nil {
			t.Fatalf("USDCDomain(%d): %v", chainID, err)
		}
		if got := hex.EncodeToString(d.Separator()); got != want {
			t.Errorf("chain %d separator %s, on-chain DOMAIN_SEPARATOR() is %s", chainID, got, want)
		}
	}
}

func TestUSDCDomainRejectsUnknownChain(t *testing.T) {
	_, err := USDCDomain(999999)
	if err == nil {
		t.Error("expected error for unknown chain")
	}
	// The error message must name the actual chain id — otherwise a caller
	// seeing "unknown chain id" in a log has no idea WHICH chain failed.
	if err != nil && !strings.Contains(err.Error(), "999999") {
		t.Errorf("error must include the specific chain id, got %q", err.Error())
	}
}

func TestEIP3009SignVerifyRoundtrip(t *testing.T) {
	signer, _ := NewEVMSigner()
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	nonce, _ := RandomNonce()
	auth := TransferAuth{
		From:        signer.Address(),
		To:          to,
		Value:       big.NewInt(1_000_000), // 1.0 USDC (6 decimals)
		ValidAfter:  Uint64(0),
		ValidBefore: Uint64(99_999_999_999),
		Nonce:       nonce,
	}
	domain, _ := USDCDomain(ChainBaseSepolia)

	sig, err := signer.SignTransferAuth(domain, auth)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Errorf("sig len %d, want 65", len(sig))
	}
	if err := VerifyTransferAuth(domain, auth, sig); err != nil {
		t.Errorf("verify same domain+auth: %v", err)
	}
}

func TestEIP3009VerifyRejectsTamperedValue(t *testing.T) {
	signer, _ := NewEVMSigner()
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	nonce, _ := RandomNonce()
	auth := TransferAuth{
		From:        signer.Address(),
		To:          to,
		Value:       big.NewInt(1_000_000),
		ValidAfter:  Uint64(0),
		ValidBefore: Uint64(99_999_999_999),
		Nonce:       nonce,
	}
	domain, _ := USDCDomain(ChainBaseSepolia)
	sig, _ := signer.SignTransferAuth(domain, auth)

	auth.Value = big.NewInt(99_999_999) // recipient tries to claim more
	if err := VerifyTransferAuth(domain, auth, sig); err == nil {
		t.Error("verify accepted tampered value — would let receiver steal funds")
	}
}

func TestEIP3009VerifyRejectsTamperedTo(t *testing.T) {
	signer, _ := NewEVMSigner()
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	nonce, _ := RandomNonce()
	auth := TransferAuth{
		From:        signer.Address(),
		To:          to,
		Value:       big.NewInt(1_000_000),
		ValidAfter:  Uint64(0),
		ValidBefore: Uint64(99_999_999_999),
		Nonce:       nonce,
	}
	domain, _ := USDCDomain(ChainBaseSepolia)
	sig, _ := signer.SignTransferAuth(domain, auth)

	// Attacker rewrites the recipient (to themselves).
	evil, _ := ParseAddress("0x000000000000000000000000000000000000ABCD")
	auth.To = evil
	if err := VerifyTransferAuth(domain, auth, sig); err == nil {
		t.Error("verify accepted tampered to — fund-redirection hole")
	}
}

func TestEIP3009VerifyRejectsWrongChainDomain(t *testing.T) {
	signer, _ := NewEVMSigner()
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	nonce, _ := RandomNonce()
	auth := TransferAuth{
		From:        signer.Address(),
		To:          to,
		Value:       big.NewInt(1_000_000),
		ValidAfter:  Uint64(0),
		ValidBefore: Uint64(99_999_999_999),
		Nonce:       nonce,
	}
	mainnet, _ := USDCDomain(ChainEthereumMainnet)
	base, _ := USDCDomain(ChainBaseMainnet)

	sig, _ := signer.SignTransferAuth(mainnet, auth)
	// A replay on a different chain (the cross-chain attack EIP-712 is designed to stop)
	if err := VerifyTransferAuth(base, auth, sig); err == nil {
		t.Error("verify allowed cross-chain replay — EIP-712 domain separation broken")
	}
}

func TestEIP3009SignerMustMatchFrom(t *testing.T) {
	signer, _ := NewEVMSigner()
	other, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	nonce, _ := RandomNonce()
	auth := TransferAuth{
		From:        other, // not signer.Address()
		To:          signer.Address(),
		Value:       big.NewInt(1),
		ValidAfter:  Uint64(0),
		ValidBefore: Uint64(99_999_999_999),
		Nonce:       nonce,
	}
	domain, _ := USDCDomain(ChainBaseSepolia)
	if _, err := signer.SignTransferAuth(domain, auth); err == nil {
		t.Error("signer let us sign a TransferAuth claiming a different from-address")
	}
}

// ── identity file persistence ──────────────────────────────────────────

func TestLoadOrCreateEVMSignerRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm-identity.json")
	first, err := LoadOrCreateEVMSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("identity mode: %o", info.Mode().Perm())
	}
	second, err := LoadOrCreateEVMSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.Address() != second.Address() {
		t.Errorf("address differs across reload: %s vs %s", first.Address(), second.Address())
	}
	// Sign with both and confirm signatures are over a deterministic
	// digest produce verifiable recovery to the same address.
	digest := Keccak256([]byte("roundtrip"))
	sig1, _ := first.SignDigest(digest)
	sig2, _ := second.SignDigest(digest)
	r1, _ := Recover(digest, sig1)
	r2, _ := Recover(digest, sig2)
	if r1 != r2 {
		t.Errorf("recovered different addresses from reloaded signer")
	}
}

func TestLoadEVMSignerMissing(t *testing.T) {
	_, err := LoadEVMSigner(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("want os.ErrNotExist, got %v", err)
	}
}

func TestLoadEVMSignerRejectsTamperedAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.json")
	s, _ := LoadOrCreateEVMSigner(path)
	original := s.Address().String()
	// Swap the recorded address with a different but valid-length one,
	// without changing the seed. Load should detect the mismatch.
	wrong := "0x" + strings.Repeat("ab", 20)
	if wrong == original {
		t.Fatal("test setup: wrong address happened to equal real one")
	}
	raw, _ := os.ReadFile(path)
	body := strings.Replace(string(raw), original, wrong, 1)
	if body == string(raw) {
		t.Fatal("test setup: address replacement made no change")
	}
	_ = os.WriteFile(path, []byte(body), 0o600)
	_, err := LoadEVMSigner(path)
	if err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Errorf("want tampered-address error, got %v", err)
	}
}

// TestLoadEVMSignerRefusesWorldReadable mirrors the LocalSigner check —
// an EVM seed can move USDC on-chain, so a chmod 0644 on the identity
// file must NOT silently load (per OpenSSH's threat model).
func TestLoadEVMSignerRefusesWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.json")
	if _, err := LoadOrCreateEVMSigner(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := LoadEVMSigner(path)
	if err == nil {
		t.Fatal("LoadEVMSigner accepted 0644 identity — should have refused")
	}
	if !strings.Contains(err.Error(), "permissions") || !strings.Contains(err.Error(), "chmod 0600") {
		t.Errorf("error %q should mention permissions + chmod 0600 hint", err.Error())
	}
	if _, err := LoadOrCreateEVMSigner(path); err == nil {
		t.Error("LoadOrCreate silently accepted 0644 — would silently destroy a real key")
	}
}

func TestRandomNonceIsRandom(t *testing.T) {
	a, _ := RandomNonce()
	b, _ := RandomNonce()
	if a == b {
		t.Error("two nonces collided — RNG broken")
	}
}
