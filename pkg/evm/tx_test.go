package evm

import (
	"encoding/hex"
	"math/big"
	"os"
	"testing"
)

// A well-known test key (Hardhat's first), never funded on mainnet.
const hardhatKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func referenceTx(t *testing.T) (Tx1559, *EVMSigner) {
	t.Helper()
	seed, _ := hex.DecodeString(hardhatKey)
	s, err := EVMSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	usdc, _ := ParseAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	payee, _ := ParseAddress("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")
	return Tx1559{ChainID: 8453, Nonce: 7, MaxPriorityFee: big.NewInt(1_000_000), MaxFee: big.NewInt(50_000_000),
		Gas: big.NewInt(80_000), To: usdc, Value: big.NewInt(0), Data: TransferData(payee, big.NewInt(250000))}, s
}

// The raw transaction must match what an independent signer produces for
// the same fields: Python's eth-account, through tools/txref.py, whose hex
// TX_REFERENCE carries:
//
//	TX_REFERENCE=$(uv run -q --with eth-account==0.13.4 python tools/txref.py) go test ./pkg/evm/
func TestTx1559MatchesReference(t *testing.T) {
	want := os.Getenv("TX_REFERENCE")
	if want == "" {
		t.Skip("TX_REFERENCE not set (tools/txref.py prints it)")
	}
	tx, s := referenceTx(t)
	raw, _, err := tx.Sign(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := "0x" + hex.EncodeToString(raw); got != want {
		t.Fatalf("raw tx differs:\n got %s\nwant %s", got, want)
	}
}

// Without the reference: the signature recovers to the signer, and the
// encoding is a type-2 transaction for the USDC contract.
func TestTx1559SignsAsTheWallet(t *testing.T) {
	tx, s := referenceTx(t)
	raw, hash, err := tx.Sign(s)
	if err != nil || raw[0] != 0x02 || len(hash) != 32 {
		t.Fatalf("sign: %v %x", err, raw[:1])
	}
	if s.Address().Hex() != "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" {
		t.Fatalf("the test key's address: %s", s.Address().Hex())
	}
	sig, _ := s.SignDigest(tx.SigningHash())
	if got, err := Recover(tx.SigningHash(), sig); err != nil || got != s.Address() {
		t.Fatalf("recovered %s, want %s (%v)", got.Hex(), s.Address().Hex(), err)
	}
	if hex.EncodeToString(TransferData(s.Address(), big.NewInt(1))[:4]) != "a9059cbb" {
		t.Fatal("the transfer selector")
	}
}
