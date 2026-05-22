package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Client is a minimal JSON-RPC 2.0 client over HTTP. Only the methods
// the wallet actually needs are implemented; an open-ended Call lets
// callers extend for one-off methods without growing this file.
type Client struct {
	endpoint string
	http     *http.Client
	nextID   atomic.Int64
}

// NewClient builds a client targeting endpoint (typically an Alchemy /
// Infura URL, a Base/Base-Sepolia public RPC, or a local devnet). The
// passed http.Client is used as-is; pass nil for a sane default.
func NewClient(endpoint string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{endpoint: endpoint, http: hc}
}

// Endpoint returns the configured RPC URL, for logging / inspection.
func (c *Client) Endpoint() string { return c.endpoint }

// rpcRequest is the on-wire JSON-RPC 2.0 envelope.
type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// Call invokes one JSON-RPC method and unmarshals the result into out.
// Pass nil for out if the caller only cares whether the call succeeded.
func (c *Client) Call(ctx context.Context, method string, params any, out any) error {
	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      c.nextID.Add(1),
		Method:  method,
		Params:  params,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("rpc marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rpc request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("rpc transport: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rpc http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var r rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("rpc decode: %w", err)
	}
	if r.Error != nil {
		return r.Error
	}
	if out != nil {
		if err := json.Unmarshal(r.Result, out); err != nil {
			return fmt.Errorf("rpc result decode: %w", err)
		}
	}
	return nil
}

// ChainID returns the chain id reported by the RPC endpoint. Useful
// for a sanity check that the wallet's configured chain matches what
// the RPC actually serves.
func (c *Client) ChainID(ctx context.Context) (uint64, error) {
	var hexStr string
	if err := c.Call(ctx, "eth_chainId", []any{}, &hexStr); err != nil {
		return 0, err
	}
	return hexToUint64(hexStr)
}

// GasPrice returns the RPC's reported eth_gasPrice in wei.
func (c *Client) GasPrice(ctx context.Context) (*big.Int, error) {
	var hexStr string
	if err := c.Call(ctx, "eth_gasPrice", []any{}, &hexStr); err != nil {
		return nil, err
	}
	return hexToBigInt(hexStr)
}

// BalanceOf calls ERC20 `balanceOf(address)` on the token contract
// and returns the holder's token balance. Returns 0 if the holder
// has no balance entry.
func (c *Client) BalanceOf(ctx context.Context, token Address, holder Address) (*big.Int, error) {
	// balanceOf(address) selector = first 4 bytes of keccak256("balanceOf(address)")
	selector := Keccak256([]byte("balanceOf(address)"))[:4]
	data := append([]byte{}, selector...)
	data = append(data, abiAddress(holder)...)
	payload := map[string]string{
		"to":   token.Hex(),
		"data": "0x" + hex.EncodeToString(data),
	}
	var hexStr string
	if err := c.Call(ctx, "eth_call", []any{payload, "latest"}, &hexStr); err != nil {
		return nil, err
	}
	return hexToBigInt(hexStr)
}

// SendRawTransaction broadcasts a signed transaction's RLP-encoded
// bytes (as hex with 0x prefix) and returns the resulting transaction
// hash. The wallet doesn't currently *build* raw transactions —
// transferWithAuthorization is meant to be broadcast by the recipient
// — but the surface is here for completeness and for future on-chain
// settlement flows the wallet might originate.
func (c *Client) SendRawTransaction(ctx context.Context, rawTxHex string) (string, error) {
	var hash string
	if err := c.Call(ctx, "eth_sendRawTransaction", []any{rawTxHex}, &hash); err != nil {
		return "", err
	}
	return hash, nil
}

// ── hex helpers ────────────────────────────────────────────────────────

func hexToUint64(s string) (uint64, error) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return 0, fmt.Errorf("rpc: expected 0x-prefixed hex, got %q", s)
	}
	raw := s[2:]
	if raw == "" {
		return 0, nil
	}
	// big.Int handles odd-length hex cleanly.
	n, ok := new(big.Int).SetString(raw, 16)
	if !ok {
		return 0, fmt.Errorf("rpc: bad hex %q", s)
	}
	if !n.IsUint64() {
		return 0, fmt.Errorf("rpc: value too large for uint64: %s", s)
	}
	return n.Uint64(), nil
}

func hexToBigInt(s string) (*big.Int, error) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil, fmt.Errorf("rpc: expected 0x-prefixed hex, got %q", s)
	}
	raw := s[2:]
	if raw == "" {
		return big.NewInt(0), nil
	}
	n, ok := new(big.Int).SetString(raw, 16)
	if !ok {
		return nil, fmt.Errorf("rpc: bad hex %q", s)
	}
	return n, nil
}

// uint64ToHex is the inverse — handy for tests that need to construct
// canonical RPC reply bodies.
func uint64ToHex(n uint64) string { return "0x" + new(big.Int).SetUint64(n).Text(16) }

// bigIntToHex is the inverse for *big.Int values.
func bigIntToHex(n *big.Int) string {
	if n == nil || n.Sign() == 0 {
		return "0x0"
	}
	return "0x" + n.Text(16)
}

// Errors that callers commonly want to test for.
var (
	ErrChainMismatch = errors.New("evm: RPC chain id does not match configured chain")
)
