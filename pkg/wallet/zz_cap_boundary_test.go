// SPDX-License-Identifier: AGPL-3.0-or-later

package wallet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
	"github.com/pilot-protocol/wallet/pkg/evm"
	"github.com/pilot-protocol/wallet/pkg/settlerclient"
)

// An x402 contract that omits Asset is denominated in the chain's USDC
// — that is the only token the EVM signer will authorize. The cap
// check must resolve it the same way the signer does, otherwise a
// USDC-scoped cap never matches and never fires.
func TestSatisfyEVMEmptyAssetIsCappedAsUSDC(t *testing.T) {
	w := newDualWallet(t)
	w.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 1_000_000, Window: 24 * time.Hour})

	to, err := evm.ParseAddress("0x000000000000000000000000000000000000bEEF")
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	c := payment.Contract{
		ID:            "ctr-empty-asset",
		Amount:        5_000_000, // 5x the cap
		Asset:         "",        // omitted → USDC
		RecipientAddr: to.Hex(),
		ExpiresAt:     time.Now().Add(time.Minute),
		Nonce:         "ctr-empty-asset-nonce",
	}
	if _, err := w.SatisfyEVM(context.Background(), c); !errors.Is(err, ErrSpendCapExceeded) {
		t.Fatalf("over-cap empty-asset satisfy err = %v, want ErrSpendCapExceeded", err)
	}
	if used := w.SpentInWindow("USDC", 24*time.Hour); used != 0 {
		t.Fatalf("rejected satisfy consumed budget: used=%d, want 0", used)
	}
}

// A within-cap empty-asset satisfy must book its spend against USDC so
// the next one sees the reduced budget.
func TestSatisfyEVMEmptyAssetRecordsAgainstUSDC(t *testing.T) {
	w := newDualWallet(t)
	w.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 1_500_000, Window: 24 * time.Hour})

	to, err := evm.ParseAddress("0x000000000000000000000000000000000000bEEF")
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	mk := func(id string) payment.Contract {
		return payment.Contract{
			ID:            id,
			Amount:        1_000_000,
			Asset:         "",
			RecipientAddr: to.Hex(),
			ExpiresAt:     time.Now().Add(time.Minute),
			Nonce:         id,
		}
	}
	if _, err := w.SatisfyEVM(context.Background(), mk("ctr-1")); err != nil {
		t.Fatalf("first satisfy: %v", err)
	}
	if used := w.SpentInWindow("USDC", 24*time.Hour); used != 1_000_000 {
		t.Fatalf("spend not booked against USDC: used=%d, want 1000000", used)
	}
	if _, err := w.SatisfyEVM(context.Background(), mk("ctr-2")); !errors.Is(err, ErrSpendCapExceeded) {
		t.Fatalf("second satisfy err = %v, want ErrSpendCapExceeded", err)
	}
}

// hangingSettler accepts connections and never answers, so a call
// stays outstanding until its deadline fires.
func hangingSettler(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	conns := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		close(conns)
		for c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// The settler round-trip must not be made while capMu is held: other
// cap-gated paths (and plain introspection) have to stay responsive
// while a transfer is outstanding. The in-flight amount still has to
// count against the cap, so check-and-claim remains a single atomic
// step and a second transfer can't spend the same budget.
func TestSettlerTransferReleasesCapLockDuringRoundTrip(t *testing.T) {
	s, err := NewLocalSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	w := NewInMemory(addrBob, s)
	defer w.Close()
	w.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 100, Window: 24 * time.Hour})

	spub, _, _ := ed25519.GenerateKey(rand.Reader)
	w.SetSettler(settlerclient.New(hangingSettler(t), spub))

	to := make([]byte, ed25519.PublicKeySize)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	inflight := make(chan error, 1)
	go func() {
		_, err := w.SettlerTransfer(ctx, to, "USDC", 60, "", 0)
		inflight <- err
	}()

	// Wait for the reservation to be booked, which happens before the
	// round-trip starts. SpentInWindow takes capMu, so this also proves
	// the lock is available while the call is outstanding.
	deadline := time.Now().Add(3 * time.Second)
	for {
		observed := make(chan Amount, 1)
		go func() { observed <- w.SpentInWindow("USDC", 24*time.Hour) }()
		var used Amount
		select {
		case used = <-observed:
		case <-time.After(2 * time.Second):
			t.Fatal("SpentInWindow blocked: capMu is held across the settler round-trip")
		}
		if used == 60 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("in-flight transfer never reserved its budget: used=%d, want 60", used)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The outstanding 60 must gate a second transfer: 60+60 > 100.
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shortCancel()
	if _, err := w.SettlerTransfer(shortCtx, to, "USDC", 60, "", 0); !errors.Is(err, ErrSpendCapExceeded) {
		t.Fatalf("second transfer err = %v, want ErrSpendCapExceeded (in-flight budget double-spent)", err)
	}

	// The first transfer never lands, so its reservation is returned.
	if err := <-inflight; err == nil {
		t.Fatal("transfer against a silent settler succeeded, want a network error")
	}
	if used := w.SpentInWindow("USDC", 24*time.Hour); used != 0 {
		t.Fatalf("failed transfer kept its reservation: used=%d, want 0", used)
	}
}
