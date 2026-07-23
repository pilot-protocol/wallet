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

	"github.com/pilot-protocol/wallet/pkg/settlerclient"
)

func TestSettlerTransferHonorsSpendCap(t *testing.T) {
	s, _ := NewLocalSigner()
	w := NewInMemory(addrBob, s)
	defer w.Close()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	w.clock = func() time.Time { return now }
	w.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 100, Window: 24 * time.Hour})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	spub, _, _ := ed25519.GenerateKey(rand.Reader)
	w.SetSettler(settlerclient.New(addr, spub))

	to := make([]byte, ed25519.PublicKeySize)
	ctx := context.Background()

	_, err = w.SettlerTransfer(ctx, to, "USDC", 150, "", 0)
	if !errors.Is(err, ErrSpendCapExceeded) {
		t.Fatalf("over-cap transfer err = %v, want ErrSpendCapExceeded", err)
	}
	if used := w.SpentInWindow("USDC", 24*time.Hour); used != 0 {
		t.Fatalf("cap-rejected transfer consumed budget: used=%d, want 0", used)
	}

	_, err = w.SettlerTransfer(ctx, to, "USDC", 50, "", 0)
	if err == nil {
		t.Fatal("transfer to a closed settler succeeded, want a network error")
	}
	if errors.Is(err, ErrSpendCapExceeded) {
		t.Fatalf("within-cap transfer wrongly hit the cap: %v", err)
	}
	if used := w.SpentInWindow("USDC", 24*time.Hour); used != 0 {
		t.Fatalf("failed transfer consumed budget: used=%d, want 0", used)
	}
}
