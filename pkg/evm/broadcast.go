package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

// Broadcaster turns a verified Receipt into on-chain calldata and
// (optionally) submits it via the configured RPC.
//
// The wallet's payer side produces signed authorizations; the
// recipient is responsible for taking those signatures on-chain. This
// helper is the recipient-side piece: encode the calldata for
// transferWithAuthorization, hand it to a relayer / their own wallet
// for actual tx submission, or use SubmitTransferWithAuthorization to
// post a raw-tx call through the RPC (assumes the recipient has
// otherwise prepared a signed tx — the MVP is calldata only).
type Broadcaster struct {
	rpc   *Client
	chain uint64
}

// NewBroadcaster constructs a Broadcaster bound to an RPC client and
// chain id. The chain id is used only for sanity checks against the
// receipt's embedded chain id.
func NewBroadcaster(rpc *Client, chain uint64) *Broadcaster {
	return &Broadcaster{rpc: rpc, chain: chain}
}

// TransferWithAuthorizationSelector is the first four bytes of the
// keccak256 of the canonical function signature:
//
//	transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)
//
// Pre-computed so callers can validate against it without doing the
// hash themselves.
var TransferWithAuthorizationSelector = Keccak256(
	[]byte("transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"),
)[:4]

// EncodeTransferWithAuthorization returns the ABI-encoded calldata for
// a transferWithAuthorization call against the token contract embedded
// in the Receipt. Output is the raw bytes; callers prepending "0x" get
// a directly-usable eth_call / eth_estimateGas / eth_sendRawTransaction
// data field.
//
// Argument layout (each is 32 bytes, in order):
//
//	from      (address, left-padded)
//	to        (address, left-padded)
//	value     (uint256)
//	validAfter  (uint256)
//	validBefore (uint256)
//	nonce     (bytes32)
//	v         (uint8, left-padded)
//	r         (bytes32)
//	s         (bytes32)
func EncodeTransferWithAuthorization(p ReceiptPayload) ([]byte, error) {
	value, ok := new(big.Int).SetString(p.Value, 10)
	if !ok {
		return nil, fmt.Errorf("evm broadcast: bad value %q", p.Value)
	}
	validAfter, ok := new(big.Int).SetString(p.ValidAfter, 10)
	if !ok {
		return nil, fmt.Errorf("evm broadcast: bad validAfter %q", p.ValidAfter)
	}
	validBefore, ok := new(big.Int).SetString(p.ValidBefore, 10)
	if !ok {
		return nil, fmt.Errorf("evm broadcast: bad validBefore %q", p.ValidBefore)
	}
	nonce, err := hexBytes(p.Nonce, 32)
	if err != nil {
		return nil, fmt.Errorf("evm broadcast: nonce: %w", err)
	}
	r, err := hexBytes(p.R, 32)
	if err != nil {
		return nil, fmt.Errorf("evm broadcast: r: %w", err)
	}
	s, err := hexBytes(p.S, 32)
	if err != nil {
		return nil, fmt.Errorf("evm broadcast: s: %w", err)
	}

	var buf []byte
	buf = append(buf, TransferWithAuthorizationSelector...)
	buf = append(buf, abiAddress(p.From)...)
	buf = append(buf, abiAddress(p.To)...)
	buf = append(buf, abiUint256(value)...)
	buf = append(buf, abiUint256(validAfter)...)
	buf = append(buf, abiUint256(validBefore)...)
	buf = append(buf, nonce...)             // bytes32 is already 32 bytes — no padding needed
	buf = append(buf, abiUint8(p.V)...)     // uint8 left-padded to 32
	buf = append(buf, r...)                 // bytes32
	buf = append(buf, s...)                 // bytes32
	return buf, nil
}

// EncodeTransferWithAuthorizationHex is a convenience wrapper that
// returns the calldata as a "0x..."-prefixed hex string ready for the
// RPC's `data` field.
func EncodeTransferWithAuthorizationHex(p ReceiptPayload) (string, error) {
	b, err := EncodeTransferWithAuthorization(p)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(b), nil
}

// CalldataForReceipt is the most common Broadcaster entry point: parse
// a payment.Receipt, validate it matches the bound chain, and return
// (to_contract, calldata_hex). The caller plugs (to_contract,
// calldata_hex) into whatever signs and submits the actual transaction.
func (b *Broadcaster) CalldataForReceipt(r payment.Receipt) (token Address, calldataHex string, err error) {
	if r.MethodID != EVMMethodID {
		return Address{}, "", fmt.Errorf("evm broadcast: wrong method_id %q", r.MethodID)
	}
	p, err := ParseReceiptPayload(r.Payload)
	if err != nil {
		return Address{}, "", fmt.Errorf("evm broadcast: parse: %w", err)
	}
	if b.chain != 0 && p.ChainID != b.chain {
		return Address{}, "", fmt.Errorf("evm broadcast: receipt chain %d != broadcaster chain %d", p.ChainID, b.chain)
	}
	hex, err := EncodeTransferWithAuthorizationHex(p)
	if err != nil {
		return Address{}, "", err
	}
	return p.Token, hex, nil
}

// SubmitTransferWithAuthorization broadcasts a pre-signed raw
// transaction whose calldata is the receipt's transferWithAuthorization
// encoding. The caller must have built and signed the transaction
// already (set the to-address to the token contract, set data to the
// EncodeTransferWithAuthorization result, set gas/nonce/fees/sig per
// chain). This helper just routes through eth_sendRawTransaction.
//
// For callers that don't have their own tx-builder, the typical flow
// is to call CalldataForReceipt to get (token_addr, data), then hand
// those off to a meta-transaction relayer (Gelato, ERC-4337 bundler,
// or an internal service) that builds + signs + broadcasts.
func (b *Broadcaster) SubmitTransferWithAuthorization(ctx context.Context, signedRawTxHex string) (string, error) {
	if b.rpc == nil {
		return "", fmt.Errorf("evm broadcast: no RPC configured")
	}
	if !strings.HasPrefix(signedRawTxHex, "0x") && !strings.HasPrefix(signedRawTxHex, "0X") {
		signedRawTxHex = "0x" + signedRawTxHex
	}
	return b.rpc.SendRawTransaction(ctx, signedRawTxHex)
}

// ReceiptIntent is a small introspection helper that decodes a Receipt
// into a human-readable summary of the payment it authorizes. UIs use
// this to show "You are about to pay X to Y on chain Z" before
// asking the user to settle.
type ReceiptIntent struct {
	From    Address
	To      Address
	Value   *big.Int
	Token   Address
	ChainID uint64
	// ValidBefore is the EIP-3009 authorization deadline. After this
	// instant the chain rejects the transfer. Zero means the receipt
	// did not pin one (legacy or malformed). UIs should warn the user
	// when this is close (<60s) and refuse to broadcast once past.
	ValidBefore time.Time
}

// Decimals returns the token's decimal precision by consulting the
// chain-aware registry in chains.go (USDC + USDT today on Ethereum
// mainnet, Base mainnet, Base Sepolia where applicable). Unknown
// tokens fall back to 18 (the EVM default) — over-fractionalizes
// but never silently strips precision.
func (r ReceiptIntent) Decimals() int {
	if t, ok := LookupToken(r.ChainID, r.Token); ok {
		return t.Decimals
	}
	return 18
}

// TokenSymbol returns a short human label by consulting the registry.
// Falls back to the abbreviated hex address ("0xABCD…1234") for tokens
// the registry doesn't recognize — never panics on unknowns.
func (r ReceiptIntent) TokenSymbol() string {
	if t, ok := LookupToken(r.ChainID, r.Token); ok {
		return t.Symbol
	}
	return shortAddr(r.Token)
}

// FormattedAmount renders the value with the token's decimal precision,
// e.g. "1.000000 USDC" for 1_000_000 raw on a USDC chain.
func (r ReceiptIntent) FormattedAmount() string {
	if r.Value == nil {
		return "0 " + r.TokenSymbol()
	}
	dec := r.Decimals()
	if dec <= 0 {
		return r.Value.String() + " " + r.TokenSymbol()
	}
	// Scale: 1.0 USDC at dec=6 → "1.000000". We always print the full
	// fractional precision so a UI can always see exactly what's signed.
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(dec)), nil)
	whole := new(big.Int).Quo(r.Value, scale)
	frac := new(big.Int).Mod(r.Value, scale)
	fracStr := frac.String()
	// Left-pad to `dec` width.
	for len(fracStr) < dec {
		fracStr = "0" + fracStr
	}
	return fmt.Sprintf("%s.%s %s", whole.String(), fracStr, r.TokenSymbol())
}

// ChainName returns a friendly label for known chains, or "chain-N"
// (e.g. "chain-12345") for unknowns.
func (r ReceiptIntent) ChainName() string {
	switch r.ChainID {
	case ChainEthereumMainnet:
		return "Ethereum Mainnet"
	case ChainBaseMainnet:
		return "Base Mainnet"
	case ChainBaseSepolia:
		return "Base Sepolia"
	default:
		return fmt.Sprintf("chain-%d", r.ChainID)
	}
}

// String renders the intent as a single line: "1.000000 USDC from
// 0xABCD…1234 to 0x9999…ZZZZ on Base Sepolia". UIs use this for the
// confirm-payment prompt.
func (r ReceiptIntent) String() string {
	return fmt.Sprintf("%s from %s to %s on %s",
		r.FormattedAmount(),
		shortAddr(r.From),
		shortAddr(r.To),
		r.ChainName(),
	)
}

// shortAddr abbreviates an Ethereum address for human display.
// 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf → 0x7e5f…5bdf
func shortAddr(a Address) string {
	s := a.Hex()
	if len(s) < 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}

// DecodeIntent parses a Receipt and returns its high-level intent
// without performing any on-chain action. Stateless.
func DecodeIntent(r payment.Receipt) (ReceiptIntent, error) {
	if r.MethodID != EVMMethodID {
		return ReceiptIntent{}, fmt.Errorf("evm broadcast: wrong method_id %q", r.MethodID)
	}
	p, err := ParseReceiptPayload(r.Payload)
	if err != nil {
		return ReceiptIntent{}, err
	}
	value, ok := new(big.Int).SetString(p.Value, 10)
	if !ok {
		return ReceiptIntent{}, fmt.Errorf("evm broadcast: bad value %q", p.Value)
	}
	intent := ReceiptIntent{
		From: p.From, To: p.To, Value: value,
		Token: p.Token, ChainID: p.ChainID,
	}
	// ValidBefore is "decimal unix seconds" in the payload. A parse
	// failure is non-fatal here — the on-chain transferWithAuthorization
	// call still enforces the bound — but a UI loses the expiry warning.
	if vb, ok := new(big.Int).SetString(p.ValidBefore, 10); ok && vb.Sign() > 0 && vb.IsInt64() {
		intent.ValidBefore = time.Unix(vb.Int64(), 0)
	}
	return intent, nil
}

// ExpiresIn is the remaining lifetime of the authorization relative to
// now. Returns a non-positive duration once expired (or when the
// receipt did not pin a ValidBefore). UIs can pair this with String()
// for a "Pay 1.000000 USDC … (expires in 4m32s)" prompt.
func (r ReceiptIntent) ExpiresIn(now time.Time) time.Duration {
	if r.ValidBefore.IsZero() {
		return 0
	}
	return r.ValidBefore.Sub(now)
}

// Expired returns true iff the receipt has a ValidBefore in the past
// relative to `now`. Receipts without a ValidBefore are treated as
// non-expired (the on-chain call will enforce its own bound) — this
// answers "should I refuse to broadcast?", not "is this a fresh sig?".
func (r ReceiptIntent) Expired(now time.Time) bool {
	if r.ValidBefore.IsZero() {
		return false
	}
	return !now.Before(r.ValidBefore)
}

// abiUint8 left-pads a single byte into a 32-byte ABI slot.
func abiUint8(v uint8) []byte {
	out := make([]byte, 32)
	out[31] = v
	return out
}

// _ = json import marker — broadcast.go uses json indirectly through
// the receipt payload parser; kept here so the import isn't pruned.
var _ = json.Marshal
