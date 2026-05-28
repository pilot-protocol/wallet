package wallet

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

func TestCloneArgs_CopiesMap(t *testing.T) {
	t.Parallel()
	src := map[string]any{"a": 1, "b": "two"}
	dst := cloneArgs(src)
	if len(dst) != 2 {
		t.Errorf("len = %d, want 2", len(dst))
	}
	// Mutating dst must not affect src.
	dst["a"] = 999
	if src["a"] != 1 {
		t.Error("cloneArgs did not isolate src")
	}
}

func TestCloneArgs_EmptyAndNil(t *testing.T) {
	t.Parallel()
	if got := cloneArgs(nil); got == nil || len(got) != 0 {
		t.Errorf("cloneArgs(nil) = %v", got)
	}
	if got := cloneArgs(map[string]any{}); got == nil || len(got) != 0 {
		t.Errorf("cloneArgs(empty) = %v", got)
	}
}

func TestParsePaywallSpec_Happy(t *testing.T) {
	t.Parallel()
	amt, asset, err := parsePaywallSpec("100 USDC")
	if err != nil {
		t.Fatalf("parsePaywallSpec: %v", err)
	}
	if amt != 100 {
		t.Errorf("amt = %d", amt)
	}
	if asset != "USDC" {
		t.Errorf("asset = %q", asset)
	}
}

func TestParsePaywallSpec_BadShape(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"100",
		"100 USDC extra",
		"abc USDC",
		"0 USDC",
	}
	for _, c := range cases {
		if _, _, err := parsePaywallSpec(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestCanonicalContractAD_RoundtripsThroughJSON(t *testing.T) {
	t.Parallel()
	c := payment.Contract{
		ID:        "test-1",
		Amount:    42,
		Asset:     "USDC",
		ExpiresAt: time.Unix(1700000000, 0),
	}
	body, err := canonicalContractAD(c)
	if err != nil {
		t.Fatalf("canonicalContractAD: %v", err)
	}
	var got payment.Contract
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != "test-1" || got.Amount != 42 {
		t.Errorf("got %+v", got)
	}
}

func TestEVMChainID_NoBinding(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	if got := w.EVMChainID(); got != 0 {
		t.Errorf("EVMChainID = %d, want 0", got)
	}
}

func TestEVMToken_NoBinding(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	// Zero value of evm.Address is empty bytes.
	got := w.EVMToken()
	for _, b := range got {
		if b != 0 {
			t.Errorf("EVMToken should be zero for no-binding: %v", got)
			return
		}
	}
}

func TestSpendCaps_DefaultEmpty(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	if got := w.SpendCaps(); len(got) != 0 {
		t.Errorf("SpendCaps = %v, want empty", got)
	}
}

func TestSpendCaps_SetAndGetRoundtrip(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	caps := []SpendCap{
		{Asset: "USDC", Limit: 1000, Window: time.Hour},
	}
	w.SetSpendCaps(caps...)
	got := w.SpendCaps()
	if len(got) != 1 || got[0].Limit != 1000 {
		t.Errorf("got %v", got)
	}
}

func TestWallet_Address(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	if got := w.Address(); got != addrAlice {
		t.Errorf("Address = %q, want %q", got, addrAlice)
	}
}

func TestMemoryStore_GetIssued(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	defer s.Close()
	ch := &Challenge{ID: "c1", Amount: 1, Asset: "USDC", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.SaveIssued(ch); err != nil {
		t.Fatalf("SaveIssued: %v", err)
	}
	got, err := s.GetIssued("c1")
	if err != nil || got == nil {
		t.Fatalf("GetIssued = (%v, %v)", got, err)
	}
	if got.Amount != 1 {
		t.Errorf("Amount = %d", got.Amount)
	}
	// Missing returns (nil, nil) — convention in this store.
	miss, err := s.GetIssued("no-such")
	if err == nil && miss != nil {
		t.Errorf("GetIssued(no-such) = %v", miss)
	}
}

func TestMemoryStore_IsSettled_DefaultFalse(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	defer s.Close()
	settled, err := s.IsSettled("never-existed")
	if err != nil {
		t.Fatalf("IsSettled: %v", err)
	}
	if settled {
		t.Error("IsSettled fresh: want false")
	}
}

// TestEVMAccessors_WithBinding drives the non-nil-evm branch of
// EVMAddress / EVMChainID / EVMToken so coverage isn't pinned at the
// nil-binding shortcut path alone.
func TestEVMAccessors_WithBinding(t *testing.T) {
	w := newDualWallet(t) // binds an EVM signer + chain id
	defer w.Close()
	addr := w.EVMAddress()
	zero := [20]byte{}
	if addr == zero {
		t.Errorf("EVMAddress with binding should be non-zero, got zero")
	}
	if got := w.EVMChainID(); got == 0 {
		t.Errorf("EVMChainID with binding should be non-zero, got 0")
	}
	// EVMToken on a dual wallet may legitimately be zero (mock method),
	// just confirm the call doesn't panic and returns 20 bytes.
	tok := w.EVMToken()
	if len(tok) != 20 {
		t.Errorf("EVMToken: got %d bytes, want 20", len(tok))
	}
}
