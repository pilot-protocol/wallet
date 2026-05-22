package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
	"github.com/pilot-protocol/wallet/pkg/evm"
)

func newDualWallet(t *testing.T) *Wallet {
	t.Helper()
	internal, err := NewLocalSigner()
	if err != nil {
		t.Fatal(err)
	}
	evmSigner, err := evm.NewEVMSigner()
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWithEVM(Address("0:0001.0001.0001"), internal, NewMemoryStore(), EVMConfig{
		Signer:  evmSigner,
		ChainID: evm.ChainBaseSepolia,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func TestDualMethodsHaveDistinctIDs(t *testing.T) {
	w := newDualWallet(t)
	mockID := w.Method().ID()
	evmID := w.EVMMethod().ID()
	if mockID == evmID {
		t.Errorf("methods collide: both %q", mockID)
	}
	if mockID != "io.pilot.wallet-mock/v1" {
		t.Errorf("mock method id drifted: %q", mockID)
	}
	if evmID != "io.pilot.wallet/v1" {
		t.Errorf("evm method id drifted: %q", evmID)
	}
}

func TestEVMMethodOnDualWalletProducesUsableReceipts(t *testing.T) {
	w := newDualWallet(t)
	to, _ := evm.ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := payment.Contract{
		ID:              "ctr-dual-1",
		Amount:          1_000_000,
		Asset:           "USDC",
		RecipientAddr:   to.Hex(),
		ExpiresAt:       time.Now().Add(time.Minute),
		Nonce:           "ctr-dual-nonce",
		AcceptedMethods: []string{evm.EVMMethodID},
	}
	r, err := w.EVMMethod().Satisfy(context.Background(), c)
	if err != nil {
		t.Fatalf("satisfy: %v", err)
	}
	if err := w.EVMMethod().Verify(context.Background(), c, r); err != nil {
		t.Errorf("self-verify: %v", err)
	}
}

func TestPlainWalletHasNoEVMBinding(t *testing.T) {
	signer, _ := NewLocalSigner()
	w := NewInMemory(Address("0:0001.0001.0001"), signer)
	defer w.Close()

	if w.HasEVM() {
		t.Error("plain wallet should not have EVM")
	}
	if w.EVMMethod() != nil {
		t.Error("plain wallet EVMMethod should be nil")
	}
	if w.HasEVMRPC() {
		t.Error("plain wallet should not have EVM RPC")
	}
	zero := evm.Address{}
	if w.EVMAddress() != zero {
		t.Error("plain wallet EVMAddress should be zero")
	}
}

// TestSatisfyEVMHonorsSpendCap is the EVM-side mirror of
// TestPayHonorsSpendCap: a 100-USDC/24h cap blocks an over-the-limit
// EIP-3009 signing even though the EVM path goes through a different
// signer + Satisfy entry point. Without this, an attacker that
// can't pass IPC-side caps could just call wallet.evm.satisfy and
// move on-chain USDC unconstrained.
func TestSatisfyEVMHonorsSpendCap(t *testing.T) {
	w := newDualWallet(t)
	w.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 100, Window: 24 * time.Hour})
	to, _ := evm.ParseAddress("0x000000000000000000000000000000000000bEEF")
	mkContract := func(id string, amount uint64) payment.Contract {
		return payment.Contract{
			ID:              id,
			Amount:          amount,
			Asset:           "USDC",
			RecipientAddr:   to.Hex(),
			ExpiresAt:       time.Now().Add(time.Minute),
			Nonce:           id + "-nonce",
			AcceptedMethods: []string{evm.EVMMethodID},
		}
	}

	// 60 USDC — inside cap.
	if _, err := w.SatisfyEVM(context.Background(), mkContract("ctr1", 60)); err != nil {
		t.Fatalf("first SatisfyEVM: %v", err)
	}
	// 60 USDC again — would push to 120/100; must refuse.
	_, err := w.SatisfyEVM(context.Background(), mkContract("ctr2", 60))
	if err == nil {
		t.Fatal("second SatisfyEVM accepted, want ErrSpendCapExceeded")
	}
	// 40 USDC — exactly fills the remaining headroom.
	if _, err := w.SatisfyEVM(context.Background(), mkContract("ctr3", 40)); err != nil {
		t.Fatalf("third SatisfyEVM (= remaining): %v", err)
	}
	// 1 USDC — cap is full.
	if _, err := w.SatisfyEVM(context.Background(), mkContract("ctr4", 1)); err == nil {
		t.Errorf("fourth SatisfyEVM accepted, want cap-exceeded")
	}
}

// TestSpendCapsAreSharedAcrossIPCAndEVM proves that mixing surfaces
// doesn't let a caller dodge the cap — a Pay against the IPC ledger
// consumes the same headroom a SatisfyEVM would.
func TestSpendCapsAreSharedAcrossIPCAndEVM(t *testing.T) {
	w := newDualWallet(t)
	w.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 50, Window: 24 * time.Hour})
	// Top up the internal ledger so Pay's balance check doesn't kick first.
	if _, err := w.Topup("USDC", 1000, "dev"); err != nil {
		t.Fatal(err)
	}

	// IPC Pay of 30 — inside cap, leaves 20.
	other, _ := NewLocalSigner()
	receiver := NewInMemory("0:0001.0002.0002", other)
	defer receiver.Close()
	ch, err := receiver.Request(30, "USDC", time.Hour, "ipc-leg")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Pay(ch); err != nil {
		t.Fatalf("ipc pay: %v", err)
	}

	// EVM Satisfy of 25 — would take total to 55/50, must refuse.
	to, _ := evm.ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := payment.Contract{
		ID:              "ctr-shared",
		Amount:          25,
		Asset:           "USDC",
		RecipientAddr:   to.Hex(),
		ExpiresAt:       time.Now().Add(time.Minute),
		Nonce:           "shared-nonce",
		AcceptedMethods: []string{evm.EVMMethodID},
	}
	if _, err := w.SatisfyEVM(context.Background(), c); err == nil {
		t.Error("EVM Satisfy accepted, want cap-exceeded — caps must be shared")
	}
}

func TestEVMBalanceWithoutRPCReturnsZero(t *testing.T) {
	w := newDualWallet(t) // no RPC configured
	bal, err := w.EVMBalance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bal.Sign() != 0 {
		t.Errorf("balance without RPC: %s, want 0", bal)
	}
}
