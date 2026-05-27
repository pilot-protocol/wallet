package wallet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

// newTestWallet returns a wallet with a fresh Ed25519 signer + memory store.
func newTestWallet(t *testing.T, addr Address) *Wallet {
	t.Helper()
	signer, err := NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return NewInMemory(addr, signer)
}

// TestContractMatchesWallet covers both branches.
func TestContractMatchesWallet(t *testing.T) {
	t.Parallel()
	// Empty AcceptedMethods → match.
	if !contractMatchesWallet(payment.Contract{}) {
		t.Error("empty AcceptedMethods should match")
	}
	// Contains our method ID → match.
	if !contractMatchesWallet(payment.Contract{
		AcceptedMethods: []string{"other", MockMethodID, "third"},
	}) {
		t.Error("contains MockMethodID → match")
	}
	// Doesn't contain → no match.
	if contractMatchesWallet(payment.Contract{
		AcceptedMethods: []string{"other-only"},
	}) {
		t.Error("no MockMethodID → no match")
	}
}

// TestContractToChallenge converts every field.
func TestContractToChallenge(t *testing.T) {
	t.Parallel()
	exp := time.Now().Add(time.Hour)
	c := payment.Contract{
		ID:            "contract-1",
		RecipientAddr: "0:0001.0001.0001",
		Amount:        42,
		Asset:         "USDC",
		Nonce:         "nonce-x",
		ExpiresAt:     exp,
		Memo:          "test memo",
	}
	got := contractToChallenge(c)
	if got.ID != "contract-1" {
		t.Errorf("ID = %q", got.ID)
	}
	if Address(got.RecipientAddr) != Address("0:0001.0001.0001") {
		t.Errorf("RecipientAddr = %q", got.RecipientAddr)
	}
	if got.Amount != 42 {
		t.Errorf("Amount = %d", got.Amount)
	}
	if got.Asset != "USDC" {
		t.Errorf("Asset = %q", got.Asset)
	}
	if got.Nonce != "nonce-x" {
		t.Errorf("Nonce = %q", got.Nonce)
	}
	if !got.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v", got.ExpiresAt)
	}
	if got.Memo != "test memo" {
		t.Errorf("Memo = %q", got.Memo)
	}
}

// TestWalletMethod_IDAndCannotSatisfy covers basic accessors.
func TestWalletMethod_IDAndCannotSatisfy(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	m := w.Method()
	if m.ID() != MockMethodID {
		t.Errorf("ID = %q", m.ID())
	}

	// Contract with non-matching method → ErrCannotSatisfy.
	c := payment.Contract{ID: "x", AcceptedMethods: []string{"foreign"}}
	if _, err := m.Satisfy(context.Background(), c); !errors.Is(err, payment.ErrCannotSatisfy) {
		t.Errorf("Satisfy(non-matching): want ErrCannotSatisfy, got %v", err)
	}
}

// TestWalletMethod_VerifyWrongMethodID covers the early-rejection branch.
func TestWalletMethod_VerifyWrongMethodID(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	err := w.Method().Verify(context.Background(),
		payment.Contract{ID: "x"},
		payment.Receipt{MethodID: "wrong-id"})
	if err == nil || !strings.Contains(err.Error(), "wrong method_id") {
		t.Errorf("err = %v", err)
	}
}

// TestWalletMethod_VerifyBadPayload covers the JSON-unmarshal branch.
func TestWalletMethod_VerifyBadPayload(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	err := w.Method().Verify(context.Background(),
		payment.Contract{ID: "x"},
		payment.Receipt{MethodID: MockMethodID, Payload: []byte("not json")})
	if err == nil {
		t.Error("expected JSON decode error")
	}
}

// TestWalletEscrow_HoldRequiresIDAndKey covers the two validation
// short-circuits in Hold.
func TestWalletEscrow_HoldRequiresIDAndKey(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	e := w.Escrow()
	if e.ID() != EscrowID {
		t.Errorf("ID = %q", e.ID())
	}

	// Empty contract ID.
	_, err := e.Hold(context.Background(), payment.Contract{}, []byte("k"))
	if err == nil {
		t.Error("expected error on empty contract ID")
	}
	// Empty key.
	_, err = e.Hold(context.Background(), payment.Contract{ID: "c"}, nil)
	if err == nil {
		t.Error("expected error on empty key")
	}
}

// TestWalletEscrow_HoldRedeemRoundtrip drives the full happy path.
func TestWalletEscrow_HoldRedeemRoundtrip(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	e := w.Escrow()
	ctx := context.Background()

	// Construct a contract that the wallet can Satisfy.
	contract := payment.Contract{
		ID:              "test-contract",
		AcceptedMethods: []string{MockMethodID},
		RecipientAddr:   string(addrAlice),
		Amount:          0, // 0 amount keeps spend-cap out of play
		Asset:           "TEST",
		Nonce:           "n",
		ExpiresAt:       time.Now().Add(time.Hour),
		Memo:            "m",
	}

	// Hold a key.
	k := []byte("secret-key-12345")
	ref, err := e.Hold(ctx, contract, k)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if ref.EscrowID != EscrowID {
		t.Errorf("ref.EscrowID = %q", ref.EscrowID)
	}
	if ref.ContractID != "test-contract" {
		t.Errorf("ref.ContractID = %q", ref.ContractID)
	}
	if got := e.HeldCount(); got != 1 {
		t.Errorf("HeldCount = %d, want 1", got)
	}

	// Hold same contract again → duplicate error.
	if _, err := e.Hold(ctx, contract, k); err == nil {
		t.Error("expected duplicate-hold error")
	}

	// Build a Receipt that Verify accepts: ask Method.Satisfy to make one.
	receipt, err := w.Method().Satisfy(ctx, contract)
	if err != nil {
		t.Fatalf("Satisfy: %v", err)
	}

	// Redeem with wrong EscrowID.
	if _, err := e.Redeem(ctx, payment.EscrowRef{EscrowID: "wrong"}, receipt); err == nil {
		t.Error("expected wrong-escrow-id error")
	}

	// Redeem happy path.
	gotK, err := e.Redeem(ctx, ref, receipt)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if string(gotK) != "secret-key-12345" {
		t.Errorf("redeemed key = %q", gotK)
	}
	if got := e.HeldCount(); got != 0 {
		t.Errorf("HeldCount after Redeem = %d, want 0", got)
	}

	// Second redeem → ErrEscrowConsumed.
	if _, err := e.Redeem(ctx, ref, receipt); !errors.Is(err, payment.ErrEscrowConsumed) {
		t.Errorf("second Redeem: want ErrEscrowConsumed, got %v", err)
	}
}

// TestWalletEscrow_RedeemNotFound covers the not-found branch.
func TestWalletEscrow_RedeemNotFound(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	e := w.Escrow()
	_, err := e.Redeem(context.Background(),
		payment.EscrowRef{EscrowID: EscrowID, ContractID: "never-held"},
		payment.Receipt{MethodID: MockMethodID})
	if !errors.Is(err, payment.ErrEscrowNotFound) {
		t.Errorf("want ErrEscrowNotFound, got %v", err)
	}
}
