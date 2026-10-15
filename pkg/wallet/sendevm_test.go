package wallet

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/pilot-protocol/wallet/pkg/evm"
)

// A transfer is signed by the wallet's own key, for its own USDC token,
// within the spend cap, and refused when the host asks for something
// wrong: no recipient, itself, nothing, or gas and fees out of bounds.
func TestSignUSDCTransfer(t *testing.T) {
	w := newDualWallet(t)
	w.SetSpendCaps(SpendCap{Asset: "USDC", Limit: 3_000_000, Window: 24 * time.Hour})
	ctx := context.Background()
	chain := w.EVMChainID()
	to, _ := evm.ParseAddress("0x000000000000000000000000000000000000bEEF")
	ok := func() TransferTx {
		return TransferTx{To: to, Amount: big.NewInt(2_000_000), Nonce: 3, Gas: big.NewInt(80_000),
			MaxFee: big.NewInt(50_000_000), MaxPriorityFee: big.NewInt(1_000_000)}
	}
	raw, hash, err := w.SignUSDCTransferOn(ctx, chain, ok())
	if err != nil || len(hash) != 32 || raw[0] != 0x02 {
		t.Fatalf("sign: %v", err)
	}
	// It is the same transaction, signed by this wallet, to its token contract.
	tx := evm.Tx1559{ChainID: chain, Nonce: 3, MaxPriorityFee: big.NewInt(1_000_000), MaxFee: big.NewInt(50_000_000), Gas: big.NewInt(80_000),
		To: w.EVMTokenFor(chain), Value: big.NewInt(0), Data: evm.TransferData(to, big.NewInt(2_000_000))}
	if want := evm.Keccak256(raw); string(want) != string(hash) {
		t.Fatal("the hash is not the raw transaction's")
	}
	// Exactly that transaction, signed by this wallet's key (signing is
	// deterministic, RFC 6979).
	if want, _, err := tx.Sign(w.evmByChain[chain].signer); err != nil || string(want) != string(raw) {
		t.Fatalf("not the expected transaction: %v", err)
	}
	// Over the cap: 2 + 2 > 3 USDC.
	if _, _, err := w.SignUSDCTransferOn(ctx, chain, ok()); !errors.Is(err, ErrSpendCapExceeded) {
		t.Fatalf("over the cap: %v", err)
	}
	bad := map[string]func(*TransferTx){
		"no recipient":     func(x *TransferTx) { x.To = evm.Address{} },
		"to itself":        func(x *TransferTx) { x.To = w.EVMAddress() },
		"nothing":          func(x *TransferTx) { x.Amount = big.NewInt(0) },
		"too much gas":     func(x *TransferTx) { x.Gas = big.NewInt(300_000) },
		"an absurd fee":    func(x *TransferTx) { x.MaxFee = big.NewInt(200_000_000_000) },
		"priority > fee":   func(x *TransferTx) { x.MaxPriorityFee = big.NewInt(60_000_000) },
		"an unknown chain": nil,
	}
	for name, f := range bad {
		x := ok()
		x.Amount = big.NewInt(1)
		c := chain
		if f == nil {
			c = 999999
		} else {
			f(&x)
		}
		if _, _, err := w.SignUSDCTransferOn(ctx, c, x); !errors.Is(err, ErrBadTransfer) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
