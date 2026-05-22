package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

// fixtureReceipt builds a Receipt the way EVMMethod.Satisfy would.
func fixtureReceipt(t *testing.T) (payment.Receipt, ReceiptPayload) {
	t.Helper()
	signer, _ := NewEVMSigner()
	method, _ := NewEVMMethod(signer, ChainBaseSepolia, nil)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := payment.Contract{
		ID:              "ctr-broadcast-1",
		Amount:          1_000_000,
		Asset:           "USDC",
		RecipientAddr:   to.Hex(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		Nonce:           "0x" + strings.Repeat("aa", 32),
		AcceptedMethods: []string{EVMMethodID},
	}
	r, err := method.Satisfy(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := ParseReceiptPayload(r.Payload)
	return r, p
}

func TestEncodeTransferWithAuthorizationShape(t *testing.T) {
	_, p := fixtureReceipt(t)
	data, err := EncodeTransferWithAuthorization(p)
	if err != nil {
		t.Fatal(err)
	}
	// 4 byte selector + 9 args × 32 bytes = 4 + 288 = 292
	if len(data) != 4+9*32 {
		t.Errorf("calldata length: %d, want %d", len(data), 4+9*32)
	}
	// Selector must match.
	if !bytesEqualSlice(data[:4], TransferWithAuthorizationSelector) {
		t.Errorf("selector: %x, want %x", data[:4], TransferWithAuthorizationSelector)
	}
}

func TestEncodeTransferWithAuthorizationKnownVector(t *testing.T) {
	// Build a fully deterministic payload and assert the encoded
	// calldata's structural fields match. This isn't a real on-chain
	// signature — we just want to confirm the ABI layout is correct.
	from, _ := ParseAddress("0x1111111111111111111111111111111111111111")
	to, _ := ParseAddress("0x2222222222222222222222222222222222222222")
	token, _ := ParseAddress("0x3333333333333333333333333333333333333333")
	nonce := strings.Repeat("11", 32)
	r := strings.Repeat("22", 32)
	s := strings.Repeat("33", 32)
	p := ReceiptPayload{
		From: from, To: to, Token: token,
		Value: "1000000", ValidAfter: "0", ValidBefore: "9999999999",
		Nonce: "0x" + nonce,
		R:     "0x" + r,
		S:     "0x" + s,
		V:     28,
		ChainID: ChainBaseSepolia,
	}
	data, err := EncodeTransferWithAuthorization(p)
	if err != nil {
		t.Fatal(err)
	}

	// Offset 4 = from (32 bytes, last 20 = from address).
	if !bytesEqualSlice(data[4+12:4+32], from[:]) {
		t.Errorf("from slot wrong: %x", data[4:4+32])
	}
	// Offset 36 = to.
	if !bytesEqualSlice(data[36+12:36+32], to[:]) {
		t.Errorf("to slot wrong: %x", data[36:36+32])
	}
	// Offset 68 = value (uint256, big-endian). 1_000_000 = 0xF4240.
	wantValue := abiUint256(big.NewInt(1_000_000))
	if !bytesEqualSlice(data[68:68+32], wantValue) {
		t.Errorf("value slot: %x, want %x", data[68:68+32], wantValue)
	}
	// Offset 164 = nonce (bytes32, unpadded).
	nonceBytes, _ := hex.DecodeString(nonce)
	if !bytesEqualSlice(data[164:164+32], nonceBytes) {
		t.Errorf("nonce slot: %x", data[164:164+32])
	}
	// Offset 196 = v (uint8 left-padded).
	if data[196+31] != 28 {
		t.Errorf("v: %d, want 28", data[196+31])
	}
}

func TestEncodeTransferWithAuthorizationHexPrefix(t *testing.T) {
	_, p := fixtureReceipt(t)
	hexStr, err := EncodeTransferWithAuthorizationHex(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hexStr, "0x") {
		t.Errorf("hex output missing 0x prefix: %q", hexStr[:8])
	}
}

func TestBroadcasterCalldataForReceiptChainMismatch(t *testing.T) {
	receipt, _ := fixtureReceipt(t)
	// Receipt is on Base Sepolia; broadcaster pinned to Base mainnet.
	b := NewBroadcaster(nil, ChainBaseMainnet)
	_, _, err := b.CalldataForReceipt(receipt)
	if err == nil || !strings.Contains(err.Error(), "chain") {
		t.Errorf("want chain-mismatch error, got %v", err)
	}
}

func TestBroadcasterCalldataForReceiptRoundtrip(t *testing.T) {
	receipt, _ := fixtureReceipt(t)
	b := NewBroadcaster(nil, ChainBaseSepolia)
	token, hexStr, err := b.CalldataForReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	wantToken, _ := USDCAddress(ChainBaseSepolia)
	if token != wantToken {
		t.Errorf("token: %s, want %s", token, wantToken)
	}
	if !strings.HasPrefix(hexStr, "0x") || len(hexStr) != 2+2*(4+9*32) {
		t.Errorf("calldata shape: len=%d", len(hexStr))
	}
}

func TestBroadcasterRejectsWrongMethodID(t *testing.T) {
	receipt, _ := fixtureReceipt(t)
	receipt.MethodID = "io.someone.else/v1"
	b := NewBroadcaster(nil, ChainBaseSepolia)
	_, _, err := b.CalldataForReceipt(receipt)
	if err == nil || !strings.Contains(err.Error(), "method_id") {
		t.Errorf("want method-id error, got %v", err)
	}
}

func TestBroadcasterSubmitRawTransaction(t *testing.T) {
	wantTxHash := "0x" + strings.Repeat("ab", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     int64    `json:"id"`
			Method string   `json:"method"`
			Params []string `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Method != "eth_sendRawTransaction" {
			t.Errorf("unexpected method %q", req.Method)
		}
		_ = json.NewEncoder(w).Encode(struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int64  `json:"id"`
			Result  string `json:"result"`
		}{JSONRPC: "2.0", ID: req.ID, Result: wantTxHash})
	}))
	defer srv.Close()
	rpc := NewClient(srv.URL, nil)
	b := NewBroadcaster(rpc, ChainBaseSepolia)
	hash, err := b.SubmitTransferWithAuthorization(context.Background(), "0xdeadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if hash != wantTxHash {
		t.Errorf("tx hash: %s, want %s", hash, wantTxHash)
	}
}

func TestBroadcasterSubmitErrorsPropagate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(body, &req)
		_ = json.NewEncoder(w).Encode(struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int64  `json:"id"`
			Error   any    `json:"error"`
		}{
			JSONRPC: "2.0", ID: req.ID,
			Error: map[string]any{"code": -32000, "message": "nonce too low"},
		})
	}))
	defer srv.Close()
	rpc := NewClient(srv.URL, nil)
	b := NewBroadcaster(rpc, ChainBaseSepolia)
	_, err := b.SubmitTransferWithAuthorization(context.Background(), "0xdeadbeef")
	if err == nil || !strings.Contains(err.Error(), "nonce too low") {
		t.Errorf("want RPC error propagated, got %v", err)
	}
}

func TestBroadcasterSubmitRequiresRPC(t *testing.T) {
	b := NewBroadcaster(nil, ChainBaseSepolia)
	_, err := b.SubmitTransferWithAuthorization(context.Background(), "0xdeadbeef")
	if err == nil {
		t.Error("expected error when no RPC configured")
	}
}

func TestDecodeIntent(t *testing.T) {
	receipt, p := fixtureReceipt(t)
	intent, err := DecodeIntent(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if intent.From != p.From || intent.To != p.To {
		t.Errorf("intent addresses: %+v vs payload %+v", intent, p)
	}
	wantValue, _ := new(big.Int).SetString(p.Value, 10)
	if intent.Value.Cmp(wantValue) != 0 {
		t.Errorf("intent value %s, want %s", intent.Value, wantValue)
	}
	if intent.ChainID != p.ChainID {
		t.Errorf("intent chain: %d, want %d", intent.ChainID, p.ChainID)
	}
}

func TestDecodeIntentRejectsWrongMethodID(t *testing.T) {
	receipt, _ := fixtureReceipt(t)
	receipt.MethodID = "io.other/v1"
	_, err := DecodeIntent(receipt)
	if err == nil {
		t.Error("expected error for wrong method id")
	}
}

func TestTransferWithAuthorizationSelectorStable(t *testing.T) {
	// Cross-check the selector against the spec.
	want := Keccak256(
		[]byte("transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"),
	)[:4]
	if !bytesEqualSlice(TransferWithAuthorizationSelector, want) {
		t.Errorf("selector drifted: %x vs %x", TransferWithAuthorizationSelector, want)
	}
}

// bytesEqualSlice compares two byte slices without dragging in a stdlib helper.
func bytesEqualSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// silence unused error import if testing/json combos vary.
var _ = errors.New
