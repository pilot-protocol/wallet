package walletipc

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/wallet/pkg/wallet"
)

// TestHistoryOverIPC_TimeBounds drives the Since/Before time-bound
// branches on historyHandler — previously uncovered. Tops up multiple
// times across distinct timestamps and filters via SinceUnixNano and
// BeforeUnixNano.
func TestHistoryOverIPC_TimeBounds(t *testing.T) {
	s, _ := wallet.NewLocalSigner()
	w := wallet.NewInMemory("0:0001.0001.0001", s)
	defer w.Close()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	go func() { _ = ipc.Serve(context.Background(), sc, NewDispatcher(w)) }()

	// Five topups with measurable gaps.
	for i := 0; i < 5; i++ {
		if err := ipc.Call(cc, MethodTopup, TopupReq{
			Asset: "USDC", Amount: wallet.Amount(1 + i), Source: "dev",
		}, &TopupResp{}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Read everything to get timestamps.
	var all HistoryResp
	if err := ipc.Call(cc, MethodHistory, HistoryReq{}, &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Transactions) != 5 {
		t.Fatalf("all = %d, want 5", len(all.Transactions))
	}
	mid := all.Transactions[2].Timestamp.UnixNano()

	// Since: only entries newer than mid.
	var since HistoryResp
	if err := ipc.Call(cc, MethodHistory, HistoryReq{
		SinceUnixNano: mid,
	}, &since); err != nil {
		t.Fatal(err)
	}
	for _, tx := range since.Transactions {
		if tx.Timestamp.UnixNano() < mid {
			t.Errorf("Since filter included older tx: ts=%d, mid=%d",
				tx.Timestamp.UnixNano(), mid)
		}
	}

	// Before: only entries older than mid.
	var before HistoryResp
	if err := ipc.Call(cc, MethodHistory, HistoryReq{
		BeforeUnixNano: mid,
	}, &before); err != nil {
		t.Fatal(err)
	}
	for _, tx := range before.Transactions {
		if tx.Timestamp.UnixNano() >= mid {
			t.Errorf("Before filter included newer tx: ts=%d, mid=%d",
				tx.Timestamp.UnixNano(), mid)
		}
	}
}

// TestDecodeEmptyPayloadIsValid covers the decode() empty-payload
// short-circuit by issuing a balances call with no payload.
func TestDecodeEmptyPayloadIsValid(t *testing.T) {
	t.Parallel()
	s, _ := wallet.NewLocalSigner()
	w := wallet.NewInMemory("0:0001.0001.0001", s)
	defer w.Close()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	go func() { _ = ipc.Serve(context.Background(), sc, NewDispatcher(w)) }()

	var resp BalancesResp
	if err := ipc.Call(cc, MethodBalances, nil, &resp); err != nil {
		t.Fatalf("balances with no payload: %v", err)
	}
}

// TestRequestHandler_ZeroExpiresInRejected covers the explicit
// validation branch in requestHandler.
func TestRequestHandler_ZeroExpiresInRejected(t *testing.T) {
	t.Parallel()
	s, _ := wallet.NewLocalSigner()
	w := wallet.NewInMemory("0:0001.0001.0001", s)
	defer w.Close()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	go func() { _ = ipc.Serve(context.Background(), sc, NewDispatcher(w)) }()

	err := ipc.Call(cc, MethodRequest, RequestReq{
		Amount:           100,
		Asset:            "USDC",
		ExpiresInSeconds: 0,
	}, &RequestResp{})
	if err == nil {
		t.Error("expected server error for ExpiresInSeconds=0")
	}
}

// TestDecodeBadJSONPayloadRejected covers the JSON-unmarshal error
// branch in decode() by sending malformed args.
func TestDecodeBadJSONPayloadRejected(t *testing.T) {
	t.Parallel()
	s, _ := wallet.NewLocalSigner()
	w := wallet.NewInMemory("0:0001.0001.0001", s)
	defer w.Close()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	go func() { _ = ipc.Serve(context.Background(), sc, NewDispatcher(w)) }()

	// Send a request with a payload that doesn't match the expected
	// shape: BalanceReq wants {asset:string}, give it {asset:42}.
	bad := json.RawMessage(`{"asset": 42}`)
	err := ipc.Call(cc, MethodBalance, bad, &BalanceResp{})
	if err == nil {
		t.Error("expected decode error for type-mismatched payload")
	}
}
