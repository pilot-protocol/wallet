package walletipc

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/wallet/pkg/wallet"
)

const (
	addrAlice wallet.Address = "0:0001.0001.0001"
	addrBob   wallet.Address = "0:0001.0002.0002"
)

// servedWallet returns a connection to a wallet served over net.Pipe.
// The serve goroutine exits when the conn is closed.
func servedWallet(t *testing.T, addr wallet.Address) (net.Conn, *wallet.Wallet) {
	t.Helper()
	s, _ := wallet.NewLocalSigner()
	w := wallet.NewInMemory(addr, s)
	t.Cleanup(func() { _ = w.Close() })

	cc, sc := net.Pipe()
	t.Cleanup(func() { _ = cc.Close() })
	t.Cleanup(func() { _ = sc.Close() })

	go func() { _ = ipc.Serve(context.Background(), sc, NewDispatcher(w)) }()
	return cc, w
}

func TestRegistersAllMethods(t *testing.T) {
	s, _ := wallet.NewLocalSigner()
	w := wallet.NewInMemory(addrAlice, s)
	defer w.Close()

	d := NewDispatcher(w)
	got := map[string]bool{}
	for _, m := range d.Methods() {
		got[m] = true
	}
	for _, m := range AllMethods {
		if !got[m] {
			t.Errorf("method %q not registered", m)
		}
	}
	if len(d.Methods()) != len(AllMethods) {
		t.Errorf("methods: %v, want %v", d.Methods(), AllMethods)
	}
}

func TestAddressOverIPC(t *testing.T) {
	conn, _ := servedWallet(t, addrAlice)
	var resp AddressResp
	if err := ipc.Call(conn, MethodAddress, nil, &resp); err != nil {
		t.Fatalf("address call: %v", err)
	}
	if resp.Address != addrAlice {
		t.Errorf("address: got %q, want %q", resp.Address, addrAlice)
	}
}

func TestBalanceAndTopupOverIPC(t *testing.T) {
	conn, _ := servedWallet(t, addrAlice)

	var bal BalanceResp
	if err := ipc.Call(conn, MethodBalance, BalanceReq{Asset: "USDC"}, &bal); err != nil {
		t.Fatalf("balance: %v", err)
	}
	if bal.Amount != 0 {
		t.Errorf("initial balance: %d, want 0", bal.Amount)
	}

	var topup TopupResp
	if err := ipc.Call(conn, MethodTopup, TopupReq{Asset: "USDC", Amount: 500, Source: "dev:faucet"}, &topup); err != nil {
		t.Fatalf("topup: %v", err)
	}
	if topup.Transaction == nil || topup.Transaction.Kind != wallet.TxTopup || topup.Transaction.Amount != 500 {
		t.Errorf("topup tx: %+v", topup.Transaction)
	}

	if err := ipc.Call(conn, MethodBalance, BalanceReq{Asset: "USDC"}, &bal); err != nil {
		t.Fatalf("balance after topup: %v", err)
	}
	if bal.Amount != 500 {
		t.Errorf("post-topup balance: %d, want 500", bal.Amount)
	}
}

// TestSpendCapsOverIPC exercises the wallet.spend_caps introspection
// method added for UIs / agents that want live cap usage without
// reading cap-state.jsonl off disk. Configures one cap, spends part
// of it, queries via IPC and asserts the live `Used` + `Remaining`
// reflect the spend.
func TestSpendCapsOverIPC(t *testing.T) {
	conn, w := servedWallet(t, addrBob)
	w.SetSpendCaps(wallet.SpendCap{
		Asset:  "USDC",
		Limit:  100,
		Window: 24 * time.Hour,
	})

	// No spend yet — Used should be 0, Remaining the full Limit.
	var resp SpendCapsResp
	if err := ipc.Call(conn, MethodSpendCaps, nil, &resp); err != nil {
		t.Fatalf("spend_caps: %v", err)
	}
	if len(resp.Caps) != 1 {
		t.Fatalf("got %d caps, want 1: %+v", len(resp.Caps), resp.Caps)
	}
	c := resp.Caps[0]
	if c.Asset != "USDC" || c.Limit != 100 || c.WindowSec != 24*3600 {
		t.Errorf("cap shape: %+v", c)
	}
	if c.Used != 0 || c.RemainingRaw != 100 {
		t.Errorf("pre-spend used=%d remaining=%d, want 0/100", c.Used, c.RemainingRaw)
	}

	// Spend 40 via the canonical Pay → wallet records via recordSpendLocked.
	otherSigner, _ := wallet.NewLocalSigner()
	alice := wallet.NewInMemory(addrAlice, otherSigner)
	defer alice.Close()
	if _, err := w.Topup("USDC", 100, "dev"); err != nil {
		t.Fatal(err)
	}
	ch, _ := alice.Request(40, "USDC", time.Hour, "spend40")
	if _, err := w.Pay(ch); err != nil {
		t.Fatalf("pay: %v", err)
	}

	// Re-query — Used should reflect 40, Remaining 60.
	var after SpendCapsResp
	if err := ipc.Call(conn, MethodSpendCaps, nil, &after); err != nil {
		t.Fatal(err)
	}
	if after.Caps[0].Used != 40 || after.Caps[0].RemainingRaw != 60 {
		t.Errorf("post-spend used=%d remaining=%d, want 40/60",
			after.Caps[0].Used, after.Caps[0].RemainingRaw)
	}
}

// TestBalancesOverIPC tops up two assets, then asks for the full
// balance snapshot in one call — exercises the wallet.balances method
// added for "show all my assets" UIs.
func TestBalancesOverIPC(t *testing.T) {
	conn, _ := servedWallet(t, addrAlice)

	var empty BalancesResp
	if err := ipc.Call(conn, MethodBalances, nil, &empty); err != nil {
		t.Fatalf("balances on empty wallet: %v", err)
	}
	if empty.Balances == nil {
		t.Errorf("empty wallet returned nil map, want empty map")
	}
	if len(empty.Balances) != 0 {
		t.Errorf("empty wallet returned %d entries, want 0", len(empty.Balances))
	}

	for _, top := range []TopupReq{
		{Asset: "USDC", Amount: 500, Source: "dev:faucet"},
		{Asset: "EUR", Amount: 250, Source: "dev:faucet"},
	} {
		if err := ipc.Call(conn, MethodTopup, top, &TopupResp{}); err != nil {
			t.Fatalf("topup %s: %v", top.Asset, err)
		}
	}

	var got BalancesResp
	if err := ipc.Call(conn, MethodBalances, nil, &got); err != nil {
		t.Fatalf("balances after topups: %v", err)
	}
	if got.Balances["USDC"] != 500 {
		t.Errorf("USDC balance: %d, want 500", got.Balances["USDC"])
	}
	if got.Balances["EUR"] != 250 {
		t.Errorf("EUR balance: %d, want 250", got.Balances["EUR"])
	}
	if len(got.Balances) != 2 {
		t.Errorf("balance count: %d, want 2 (got %+v)", len(got.Balances), got.Balances)
	}
}

// TestFullPayDanceOverIPC is the canonical end-to-end test: two wallets,
// each served over its own IPC connection, complete a request →
// pay → settle dance through the wire only.
func TestFullPayDanceOverIPC(t *testing.T) {
	aliceConn, _ := servedWallet(t, addrAlice)
	bobConn, _ := servedWallet(t, addrBob)

	// 1) Bob tops up out of band.
	if err := ipc.Call(bobConn, MethodTopup, TopupReq{Asset: "USDC", Amount: 1000, Source: "dev:faucet"}, &TopupResp{}); err != nil {
		t.Fatalf("bob topup: %v", err)
	}

	// 2) Alice issues a payment challenge.
	var reqResp RequestResp
	if err := ipc.Call(aliceConn, MethodRequest, RequestReq{
		Amount:           250,
		Asset:            "USDC",
		ExpiresInSeconds: 60,
		Memo:             "lunch",
	}, &reqResp); err != nil {
		t.Fatalf("alice request: %v", err)
	}
	if reqResp.Challenge == nil {
		t.Fatal("nil challenge")
	}

	// 3) Bob pays the challenge — produces a SignedAuth, debits bob.
	var payResp PayResp
	if err := ipc.Call(bobConn, MethodPay, PayReq{Challenge: reqResp.Challenge}, &payResp); err != nil {
		t.Fatalf("bob pay: %v", err)
	}
	if payResp.SignedAuth == nil {
		t.Fatal("nil signed_auth")
	}

	var bobBal BalanceResp
	_ = ipc.Call(bobConn, MethodBalance, BalanceReq{Asset: "USDC"}, &bobBal)
	if bobBal.Amount != 750 {
		t.Errorf("bob balance after pay: %d, want 750", bobBal.Amount)
	}

	// 4) Alice verifies, then settles — credits alice.
	var ver VerifyResp
	if err := ipc.Call(aliceConn, MethodVerify, VerifyReq{
		Challenge:  reqResp.Challenge,
		SignedAuth: payResp.SignedAuth,
	}, &ver); err != nil {
		t.Fatalf("alice verify: %v", err)
	}
	if !ver.OK {
		t.Error("verify returned ok=false on a valid signed_auth")
	}

	var setResp SettleResp
	if err := ipc.Call(aliceConn, MethodSettle, SettleReq{
		Challenge:  reqResp.Challenge,
		SignedAuth: payResp.SignedAuth,
	}, &setResp); err != nil {
		t.Fatalf("alice settle: %v", err)
	}
	if setResp.Transaction == nil || setResp.Transaction.Amount != 250 {
		t.Errorf("settle tx: %+v", setResp.Transaction)
	}

	var aliceBal BalanceResp
	_ = ipc.Call(aliceConn, MethodBalance, BalanceReq{Asset: "USDC"}, &aliceBal)
	if aliceBal.Amount != 250 {
		t.Errorf("alice balance after settle: %d, want 250", aliceBal.Amount)
	}

	// 5) Replay attempt — alice settling again returns a server error
	// containing "already settled".
	err := ipc.Call(aliceConn, MethodSettle, SettleReq{
		Challenge:  reqResp.Challenge,
		SignedAuth: payResp.SignedAuth,
	}, &SettleResp{})
	var srvErr *ipc.ErrServerError
	if !errors.As(err, &srvErr) || !strings.Contains(srvErr.Msg, "already settled") {
		t.Errorf("want already-settled server error, got %v", err)
	}
}

func TestVerifyRejectsTamperedAmountOverIPC(t *testing.T) {
	aliceConn, _ := servedWallet(t, addrAlice)
	bobConn, _ := servedWallet(t, addrBob)

	_ = ipc.Call(bobConn, MethodTopup, TopupReq{Asset: "USDC", Amount: 1000, Source: "dev"}, &TopupResp{})

	var reqResp RequestResp
	_ = ipc.Call(aliceConn, MethodRequest, RequestReq{Amount: 100, Asset: "USDC", ExpiresInSeconds: 60}, &reqResp)

	var payResp PayResp
	_ = ipc.Call(bobConn, MethodPay, PayReq{Challenge: reqResp.Challenge}, &payResp)

	// Tamper.
	payResp.SignedAuth.Amount = 99999

	err := ipc.Call(aliceConn, MethodVerify, VerifyReq{
		Challenge:  reqResp.Challenge,
		SignedAuth: payResp.SignedAuth,
	}, &VerifyResp{})
	var srvErr *ipc.ErrServerError
	if !errors.As(err, &srvErr) || !strings.Contains(srvErr.Msg, "challenge mismatch") {
		t.Errorf("want challenge mismatch, got %v", err)
	}
}

func TestHistoryOverIPC(t *testing.T) {
	conn, _ := servedWallet(t, addrAlice)

	_ = ipc.Call(conn, MethodTopup, TopupReq{Asset: "USDC", Amount: 100, Source: "dev"}, &TopupResp{})
	_ = ipc.Call(conn, MethodTopup, TopupReq{Asset: "EUR", Amount: 50, Source: "dev"}, &TopupResp{})

	var hist HistoryResp
	if err := ipc.Call(conn, MethodHistory, HistoryReq{}, &hist); err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist.Transactions) != 2 {
		t.Errorf("all history: got %d, want 2", len(hist.Transactions))
	}

	if err := ipc.Call(conn, MethodHistory, HistoryReq{Asset: "USDC"}, &hist); err != nil {
		t.Fatalf("history filter: %v", err)
	}
	if len(hist.Transactions) != 1 || hist.Transactions[0].Asset != "USDC" {
		t.Errorf("USDC-only history: %+v", hist.Transactions)
	}
}
