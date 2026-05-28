package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockRPC returns an httptest.Server that responds to JSON-RPC requests
// using the supplied handler. Each request gets the standard envelope
// stripped and re-wrapped automatically — the handler only sees the
// method + raw params and returns the result.
func mockRPC(t *testing.T, handler func(method string, params json.RawMessage) (any, error)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req rpcRequest
		_ = json.Unmarshal(body, &req)
		rawParams, _ := json.Marshal(req.Params)
		result, err := handler(req.Method, rawParams)
		var resp rpcResponse
		resp.JSONRPC = "2.0"
		resp.ID = req.ID
		if err != nil {
			resp.Error = &rpcError{Code: -32000, Message: err.Error()}
		} else {
			rb, _ := json.Marshal(result)
			resp.Result = rb
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestClientChainID(t *testing.T) {
	srv := mockRPC(t, func(method string, _ json.RawMessage) (any, error) {
		if method != "eth_chainId" {
			t.Errorf("unexpected method %q", method)
		}
		return uint64ToHex(ChainBaseSepolia), nil
	})
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	id, err := c.ChainID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != ChainBaseSepolia {
		t.Errorf("chain id %d, want %d", id, ChainBaseSepolia)
	}
}

func TestClientGasPrice(t *testing.T) {
	srv := mockRPC(t, func(method string, _ json.RawMessage) (any, error) {
		return bigIntToHex(big.NewInt(1_500_000_000)), nil
	})
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	p, err := c.GasPrice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Cmp(big.NewInt(1_500_000_000)) != 0 {
		t.Errorf("gas price %s, want 1500000000", p)
	}
}

func TestClientBalanceOf(t *testing.T) {
	holder, _ := ParseAddress("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
	token, _ := USDCAddress(ChainBaseSepolia)
	balance := big.NewInt(123_456_789) // 123.456789 USDC

	srv := mockRPC(t, func(method string, params json.RawMessage) (any, error) {
		if method != "eth_call" {
			t.Errorf("unexpected method %q", method)
		}
		// params is [{to, data}, "latest"]
		var p []any
		_ = json.Unmarshal(params, &p)
		if len(p) != 2 {
			t.Errorf("eth_call params: %d, want 2", len(p))
		}
		call := p[0].(map[string]any)
		if !strings.EqualFold(call["to"].(string), token.Hex()) {
			t.Errorf("eth_call to=%v, want %s", call["to"], token.Hex())
		}
		data := call["data"].(string)
		// Should be 0x70a08231 + abi-padded holder address
		want := "0x70a08231" + hex.EncodeToString(abiAddress(holder))
		if !strings.EqualFold(data, want) {
			t.Errorf("eth_call data: %s, want %s", data, want)
		}
		return bigIntToHex(balance), nil
	})
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	got, err := c.BalanceOf(context.Background(), token, holder)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(balance) != 0 {
		t.Errorf("balance: %s, want %s", got, balance)
	}
}

func TestClientBalanceOfZero(t *testing.T) {
	srv := mockRPC(t, func(method string, _ json.RawMessage) (any, error) { return "0x0", nil })
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	holder, _ := ParseAddress("0x0000000000000000000000000000000000000001")
	token, _ := USDCAddress(ChainBaseSepolia)
	got, err := c.BalanceOf(context.Background(), token, holder)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sign() != 0 {
		t.Errorf("balance: %s, want 0", got)
	}
}

func TestClientHandlesRPCError(t *testing.T) {
	srv := mockRPC(t, func(method string, _ json.RawMessage) (any, error) {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	})
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	_, err := c.ChainID(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid params") {
		t.Errorf("want invalid-params error, got %v", err)
	}
}

func TestClientHandlesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = w.Write([]byte("temporarily down"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	_, err := c.ChainID(context.Background())
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("want http 503 error, got %v", err)
	}
}

func TestSendRawTransaction(t *testing.T) {
	srv := mockRPC(t, func(method string, params json.RawMessage) (any, error) {
		if method != "eth_sendRawTransaction" {
			t.Errorf("unexpected method %q", method)
		}
		return "0x" + strings.Repeat("ab", 32), nil
	})
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	hash, err := c.SendRawTransaction(context.Background(), "0xdeadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "0x") || len(hash) != 66 {
		t.Errorf("tx hash shape: %q", hash)
	}
}

func TestHexHelpersRoundtrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 0xff, 12345, 1 << 40} {
		if got, _ := hexToUint64(uint64ToHex(n)); got != n {
			t.Errorf("uint64 roundtrip %d → %s → %d", n, uint64ToHex(n), got)
		}
	}
	for _, s := range []string{"0", "1", "deadbeef", "ffffffffffffffff"} {
		v, _ := new(big.Int).SetString(s, 16)
		got, _ := hexToBigInt(bigIntToHex(v))
		if got.Cmp(v) != 0 {
			t.Errorf("bigint roundtrip %s → %s → %s", v, bigIntToHex(v), got)
		}
	}
}

// TestHexHelpers_ErrorPaths covers each rejection branch of hexToUint64
// and hexToBigInt: missing 0x prefix, non-hex characters, value too
// large for uint64.
func TestHexHelpers_ErrorPaths(t *testing.T) {
	t.Parallel()
	if _, err := hexToUint64("no-prefix"); err == nil {
		t.Error("hexToUint64 should reject input without 0x prefix")
	}
	if _, err := hexToUint64("0xZZZZ"); err == nil {
		t.Error("hexToUint64 should reject non-hex characters")
	}
	// 17-digit hex value overflows uint64.
	if _, err := hexToUint64("0x10000000000000000"); err == nil {
		t.Error("hexToUint64 should reject value too large for uint64")
	}
	if _, err := hexToBigInt("no-prefix"); err == nil {
		t.Error("hexToBigInt should reject input without 0x prefix")
	}
	if _, err := hexToBigInt("0xZZZZ"); err == nil {
		t.Error("hexToBigInt should reject non-hex characters")
	}
	// Empty-after-prefix returns 0 cleanly for both.
	if got, err := hexToUint64("0x"); err != nil || got != 0 {
		t.Errorf("hexToUint64(0x) = (%d, %v), want (0, nil)", got, err)
	}
	if got, err := hexToBigInt("0x"); err != nil || got == nil || got.Sign() != 0 {
		t.Errorf("hexToBigInt(0x) = (%v, %v), want (0, nil)", got, err)
	}
}
