package walletipc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/app-store/pkg/payment"
	"github.com/pilot-protocol/wallet/pkg/evm"
	"github.com/pilot-protocol/wallet/pkg/wallet"
)

// servedEVMWallet builds a wallet with EVM enabled (optionally with a
// mock RPC endpoint), serves it over net.Pipe, returns the client side
// connection.
func servedEVMWallet(t *testing.T, rpcEndpoint string) (net.Conn, *wallet.Wallet) {
	t.Helper()
	s, _ := wallet.NewLocalSigner()
	evmSigner, err := evm.NewEVMSigner()
	if err != nil {
		t.Fatal(err)
	}
	w, err := wallet.NewWithEVM(addrAlice, s, wallet.NewMemoryStore(), wallet.EVMConfig{
		Signer:      evmSigner,
		ChainID:     evm.ChainBaseSepolia,
		RPCEndpoint: rpcEndpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	cc, sc := net.Pipe()
	t.Cleanup(func() { _ = cc.Close() })
	t.Cleanup(func() { _ = sc.Close() })

	go func() { _ = ipc.Serve(context.Background(), sc, NewDispatcher(w)) }()
	return cc, w
}

func TestEVMAddressOverIPC(t *testing.T) {
	conn, w := servedEVMWallet(t, "")
	var resp EVMAddressResp
	if err := ipc.Call(conn, MethodEVMAddress, nil, &resp); err != nil {
		t.Fatalf("evm.address: %v", err)
	}
	if !strings.EqualFold(resp.Address, w.EVMAddress().Hex()) {
		t.Errorf("address: %s, want %s", resp.Address, w.EVMAddress().Hex())
	}
	if resp.ChainID != evm.ChainBaseSepolia {
		t.Errorf("chain id: %d", resp.ChainID)
	}
	if resp.Token == "" || !strings.HasPrefix(resp.Token, "0x") {
		t.Errorf("token: %q", resp.Token)
	}
}

func TestEVMBalanceWithoutRPC(t *testing.T) {
	conn, _ := servedEVMWallet(t, "") // no RPC endpoint
	var resp EVMBalanceResp
	if err := ipc.Call(conn, MethodEVMBalance, nil, &resp); err != nil {
		t.Fatalf("evm.balance: %v", err)
	}
	if resp.RPCEnabled {
		t.Errorf("RPCEnabled true with no endpoint")
	}
	if resp.Balance != "0" {
		t.Errorf("balance without rpc: %s, want 0", resp.Balance)
	}
}

func TestEVMBalanceWithMockRPC(t *testing.T) {
	// Mock RPC that returns 5 USDC = 5_000_000 (6 decimals).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		resp := struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int64  `json:"id"`
			Result  string `json:"result"`
		}{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  "0x" + new(big.Int).SetUint64(5_000_000).Text(16),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	conn, _ := servedEVMWallet(t, srv.URL)
	var resp EVMBalanceResp
	if err := ipc.Call(conn, MethodEVMBalance, nil, &resp); err != nil {
		t.Fatalf("evm.balance: %v", err)
	}
	if !resp.RPCEnabled {
		t.Error("RPCEnabled false despite endpoint")
	}
	if resp.Balance != "5000000" {
		t.Errorf("balance: %s, want 5000000", resp.Balance)
	}
}

func TestEVMSatisfyVerifyOverIPC(t *testing.T) {
	conn, w := servedEVMWallet(t, "")

	// Build a contract demanding 1 USDC, addressed at someone's
	// random EVM receive address.
	to, _ := evm.ParseAddress("0x000000000000000000000000000000000000bEEF")
	contract := payment.Contract{
		ID:              "ctr-evm-1",
		Amount:          1_000_000, // 1.0 USDC
		Asset:           "USDC",
		RecipientAddr:   to.Hex(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		Nonce:           "0x" + hex.EncodeToString(make([]byte, 32)),
		AcceptedMethods: []string{evm.EVMMethodID},
	}

	// Satisfy via wallet.evm.satisfy.
	var satResp struct {
		Receipt payment.Receipt `json:"receipt"`
	}
	if err := ipc.Call(conn, MethodEVMSatisfy, struct {
		Contract payment.Contract `json:"contract"`
	}{Contract: contract}, &satResp); err != nil {
		t.Fatalf("satisfy: %v", err)
	}
	if satResp.Receipt.MethodID != evm.EVMMethodID {
		t.Errorf("receipt method id: %q", satResp.Receipt.MethodID)
	}

	// Verify the receipt via wallet.evm.verify.
	var verResp EVMVerifyResp
	if err := ipc.Call(conn, MethodEVMVerify, struct {
		Contract payment.Contract `json:"contract"`
		Receipt  payment.Receipt  `json:"receipt"`
	}{Contract: contract, Receipt: satResp.Receipt}, &verResp); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verResp.OK {
		t.Error("verify returned ok=false on a freshly-signed receipt")
	}

	// Independently verify by reconstructing from the payload — proves
	// the IPC didn't drop any field the receiver needs.
	p, err := evm.ParseReceiptPayload(satResp.Receipt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if p.From != w.EVMAddress() {
		t.Errorf("from %s, want %s", p.From, w.EVMAddress())
	}
}

func TestEVMVerifyRejectsTamperedReceiptOverIPC(t *testing.T) {
	conn, _ := servedEVMWallet(t, "")

	to, _ := evm.ParseAddress("0x000000000000000000000000000000000000bEEF")
	contract := payment.Contract{
		ID:              "ctr-evm-tamper",
		Amount:          1_000_000,
		Asset:           "USDC",
		RecipientAddr:   to.Hex(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		Nonce:           "0x" + hex.EncodeToString(make([]byte, 32)),
		AcceptedMethods: []string{evm.EVMMethodID},
	}
	var satResp struct {
		Receipt payment.Receipt `json:"receipt"`
	}
	_ = ipc.Call(conn, MethodEVMSatisfy, struct {
		Contract payment.Contract `json:"contract"`
	}{Contract: contract}, &satResp)

	// Tamper the value in the receipt payload.
	var p evm.ReceiptPayload
	_ = json.Unmarshal(satResp.Receipt.Payload, &p)
	p.Value = "999999999"
	tampered, _ := json.Marshal(p)
	satResp.Receipt.Payload = tampered

	err := ipc.Call(conn, MethodEVMVerify, struct {
		Contract payment.Contract `json:"contract"`
		Receipt  payment.Receipt  `json:"receipt"`
	}{Contract: contract, Receipt: satResp.Receipt}, &EVMVerifyResp{})
	var srvErr *ipc.ErrServerError
	if !errors.As(err, &srvErr) {
		t.Fatalf("want server error, got %v", err)
	}
}

func TestEVMMethodsAbsentWithoutEVMBinding(t *testing.T) {
	// Build a plain wallet (no EVM binding) and confirm the wallet.evm.*
	// methods are NOT registered. The IPC layer returns "method not
	// found" cleanly.
	s, _ := wallet.NewLocalSigner()
	w := wallet.NewInMemory(addrAlice, s)
	defer w.Close()

	if w.HasEVM() {
		t.Fatal("plain wallet should not have EVM")
	}

	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	go func() { _ = ipc.Serve(context.Background(), sc, NewDispatcher(w)) }()

	err := ipc.Call(cc, MethodEVMAddress, nil, &EVMAddressResp{})
	var srvErr *ipc.ErrServerError
	if !errors.As(err, &srvErr) || !strings.Contains(srvErr.Msg, "method not found") {
		t.Errorf("want method-not-found, got %v", err)
	}
}
