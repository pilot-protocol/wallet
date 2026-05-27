package wallet

import (
	"path/filepath"
	"testing"
	"time"
)

// TestRequest_ValidationBranches covers the three early-return errors
// in Wallet.Request: zero amount, empty asset, non-positive expiresIn.
func TestRequest_ValidationBranches(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()

	if _, err := w.Request(0, "USDC", time.Minute, ""); err == nil {
		t.Error("expected error for amount=0")
	}
	if _, err := w.Request(10, "", time.Minute, ""); err == nil {
		t.Error("expected error for empty asset")
	}
	if _, err := w.Request(10, "USDC", 0, ""); err == nil {
		t.Error("expected error for expiresIn=0")
	}
}

// TestTopup_ValidationBranches covers Topup's three early-return errors:
// zero amount, empty asset, empty source.
func TestTopup_ValidationBranches(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()

	if _, err := w.Topup("USDC", 0, "dev"); err == nil {
		t.Error("expected error for amount=0")
	}
	if _, err := w.Topup("", 10, "dev"); err == nil {
		t.Error("expected error for empty asset")
	}
	if _, err := w.Topup("USDC", 10, ""); err == nil {
		t.Error("expected error for empty source")
	}
}

// TestSQLiteStore_GetIssuedRoundtrip covers the sqlite GetIssued path
// (previously 0% — only the memory store's GetIssued had a test).
func TestSQLiteStore_GetIssuedRoundtrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "issued.db")
	s, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore: %v", err)
	}
	defer s.Close()

	ch := &Challenge{
		ID:        "issued-1",
		Amount:    100,
		Asset:     "USDC",
		Nonce:     "n",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.SaveIssued(ch); err != nil {
		t.Fatalf("SaveIssued: %v", err)
	}
	got, err := s.GetIssued("issued-1")
	if err != nil {
		t.Fatalf("GetIssued: %v", err)
	}
	if got == nil || got.ID != "issued-1" || got.Amount != 100 {
		t.Errorf("got %+v", got)
	}

	// Missing → nil, nil.
	missing, err := s.GetIssued("no-such")
	if err != nil {
		t.Errorf("GetIssued(missing) err: %v", err)
	}
	if missing != nil {
		t.Errorf("GetIssued(missing) = %+v, want nil", missing)
	}
}

// TestSQLiteStore_IsSettled covers the sqlite IsSettled path (previously
// 0%). Starts at false, becomes true after a full Pay→Settle dance, and
// stays true.
func TestSQLiteStore_IsSettled(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "settled.db")
	s, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore: %v", err)
	}
	defer s.Close()

	settled, err := s.IsSettled("never-existed")
	if err != nil {
		t.Fatalf("IsSettled(absent): %v", err)
	}
	if settled {
		t.Error("IsSettled(absent) = true, want false")
	}

	// Drive a real settle via the wallet.
	signer, _ := NewLocalSigner()
	alice := New(addrAlice, signer, s)

	otherSigner, _ := NewLocalSigner()
	bob := NewInMemory(addrBob, otherSigner)
	defer bob.Close()
	if _, err := bob.Topup("USDC", 500, "dev"); err != nil {
		t.Fatal(err)
	}
	ch, err := alice.Request(100, "USDC", time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	sa, err := bob.Pay(ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Settle(ch, sa); err != nil {
		t.Fatalf("Settle: %v", err)
	}

	settled, err = s.IsSettled(ch.ID)
	if err != nil {
		t.Fatalf("IsSettled(after settle): %v", err)
	}
	if !settled {
		t.Error("IsSettled(after settle) = false, want true")
	}
}
