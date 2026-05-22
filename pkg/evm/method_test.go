package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

// fixedContract builds a payment.Contract a wallet would actually try
// to satisfy: 1 USDC to a specific recipient, expiring in 5 minutes.
func fixedContract(to Address) payment.Contract {
	return payment.Contract{
		ID:              "ctr-" + to.Hex()[2:10],
		Amount:          1_000_000, // 1.0 USDC
		Asset:           "USDC",
		RecipientAddr:   to.Hex(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		Nonce:           "0x" + strings.Repeat("a1", 32),
		AcceptedMethods: []string{EVMMethodID},
	}
}

func newMethod(t *testing.T) *EVMMethod {
	t.Helper()
	signer, err := NewEVMSigner()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewEVMMethod(signer, ChainBaseSepolia, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEVMMethodSatisfyRoundtrip(t *testing.T) {
	m := newMethod(t)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := fixedContract(to)

	receipt, err := m.Satisfy(context.Background(), c)
	if err != nil {
		t.Fatalf("satisfy: %v", err)
	}
	if receipt.MethodID != EVMMethodID {
		t.Errorf("method id: %q, want %q", receipt.MethodID, EVMMethodID)
	}
	if receipt.ContractID != c.ID {
		t.Errorf("contract id: %q, want %q", receipt.ContractID, c.ID)
	}

	// Anyone with the receipt can re-verify without talking to the wallet.
	if err := m.Verify(context.Background(), c, receipt); err != nil {
		t.Errorf("verify own receipt: %v", err)
	}
}

func TestEVMMethodVerifyRejectsTamperedReceipt(t *testing.T) {
	m := newMethod(t)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := fixedContract(to)
	receipt, _ := m.Satisfy(context.Background(), c)

	// Tamper the value in the payload.
	var p ReceiptPayload
	_ = json.Unmarshal(receipt.Payload, &p)
	p.Value = "9999999999"
	bad, _ := json.Marshal(p)
	receipt.Payload = bad

	if err := m.Verify(context.Background(), c, receipt); err == nil {
		t.Error("verify accepted tampered value")
	}
}

func TestEVMMethodVerifyRejectsTamperedRecipient(t *testing.T) {
	m := newMethod(t)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := fixedContract(to)
	receipt, _ := m.Satisfy(context.Background(), c)

	var p ReceiptPayload
	_ = json.Unmarshal(receipt.Payload, &p)
	p.To, _ = ParseAddress("0x000000000000000000000000000000000000DEAD")
	bad, _ := json.Marshal(p)
	receipt.Payload = bad

	if err := m.Verify(context.Background(), c, receipt); err == nil {
		t.Error("verify accepted tampered recipient — fund-redirection hole")
	}
}

func TestEVMMethodVerifyRejectsWrongMethodID(t *testing.T) {
	m := newMethod(t)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := fixedContract(to)
	receipt, _ := m.Satisfy(context.Background(), c)
	receipt.MethodID = "io.someone.else/v1"
	if err := m.Verify(context.Background(), c, receipt); err == nil {
		t.Error("verify accepted wrong method id")
	}
}

func TestEVMMethodVerifyDetectsCrossChainReplay(t *testing.T) {
	// Sign on Base Sepolia, then have a verifier configured for Base
	// Mainnet check it. The signature should NOT validate — that's
	// the entire point of EIP-712 domain separation.
	signer, _ := NewEVMSigner()
	m1, _ := NewEVMMethod(signer, ChainBaseSepolia, nil)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := fixedContract(to)
	receipt, _ := m1.Satisfy(context.Background(), c)

	// Simulate the recipient verifying the receipt's embedded chain id
	// against a wallet that they expected to be on a different chain.
	// We do that by editing the payload's chain_id (keeping the
	// signature) — the verifier must catch the mismatch via ecrecover.
	var p ReceiptPayload
	_ = json.Unmarshal(receipt.Payload, &p)
	p.ChainID = ChainBaseMainnet
	// swap the token too so the new chain id has a real USDC contract
	tok, _ := USDCAddress(ChainBaseMainnet)
	p.Token = tok
	bad, _ := json.Marshal(p)
	receipt.Payload = bad

	m2, _ := NewEVMMethod(signer, ChainBaseMainnet, nil)
	if err := m2.Verify(context.Background(), c, receipt); err == nil {
		t.Error("verify accepted a Base Sepolia receipt under Base Mainnet domain")
	}
}

func TestEVMMethodSatisfyRejectsNonUSDC(t *testing.T) {
	m := newMethod(t)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := fixedContract(to)
	c.Asset = "ETH"
	_, err := m.Satisfy(context.Background(), c)
	if !errors.Is(err, payment.ErrCannotSatisfy) {
		t.Errorf("want ErrCannotSatisfy for non-USDC, got %v", err)
	}
}

func TestEVMMethodSatisfyRejectsBadRecipient(t *testing.T) {
	m := newMethod(t)
	c := fixedContract(Address{})
	c.RecipientAddr = "0xnotanaddress"
	_, err := m.Satisfy(context.Background(), c)
	if err == nil {
		t.Error("satisfy accepted malformed recipient address")
	}
}

func TestEVMMethodReceiptPayloadIsSelfContained(t *testing.T) {
	// Once a receipt is produced, anyone who can parse it can verify
	// it locally — they don't need the original Contract. The
	// embedded (from, to, value, validAfter, validBefore, nonce,
	// chain_id, token, v/r/s) is sufficient.
	m := newMethod(t)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := fixedContract(to)
	receipt, _ := m.Satisfy(context.Background(), c)

	p, err := ParseReceiptPayload(receipt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if p.From != m.Address() {
		t.Errorf("from: %s, want %s", p.From, m.Address())
	}
	if p.To != to {
		t.Errorf("to: %s, want %s", p.To, to)
	}
	if p.ChainID != ChainBaseSepolia {
		t.Errorf("chain id: %d", p.ChainID)
	}

	// Rebuild a domain + auth from the payload and verify
	// independently of the EVMMethod instance.
	domain, _ := USDCDomain(p.ChainID)
	value := mustBigInt(p.Value)
	validAfter := mustBigInt(p.ValidAfter)
	validBefore := mustBigInt(p.ValidBefore)
	nonceBytes, _ := hex.DecodeString(strings.TrimPrefix(p.Nonce, "0x"))
	var nonce [32]byte
	copy(nonce[:], nonceBytes)
	auth := TransferAuth{From: p.From, To: p.To, Value: value, ValidAfter: validAfter, ValidBefore: validBefore, Nonce: nonce}

	rBytes, _ := hex.DecodeString(strings.TrimPrefix(p.R, "0x"))
	sBytes, _ := hex.DecodeString(strings.TrimPrefix(p.S, "0x"))
	sig := append(append(rBytes, sBytes...), p.V)

	if err := VerifyTransferAuth(domain, auth, sig); err != nil {
		t.Errorf("independent verify: %v", err)
	}
}

func mustBigInt(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}
