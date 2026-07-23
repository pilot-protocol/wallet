// Package walletipc is the wire surface of the wallet app — request/reply
// types and an ipc.Dispatcher that routes the published wallet.* methods
// to the underlying pkg/wallet logic.
//
// This package is the *only* place pkg/wallet meets the IPC layer. Keeps
// pkg/wallet free of any app-store dependency, so the wallet library is
// usable standalone (tests, embedded use) without bringing in ipc framing.
package walletipc

import "github.com/pilot-protocol/wallet/pkg/wallet"

// Method names match the manifest's `exposes` list and the daemon's
// `ipc.call:wallet.<method>` grants. Keep these constants in sync with
// the manifest at /manifest.json.
const (
	MethodBalance    = "wallet.balance"
	MethodBalances   = "wallet.balances"
	MethodAddress    = "wallet.address"
	MethodRequest    = "wallet.request"
	MethodPay        = "wallet.pay"
	MethodVerify     = "wallet.verify"
	MethodSettle     = "wallet.settle"
	MethodTopup      = "wallet.topup"
	MethodHistory    = "wallet.history"
	MethodSpendCaps  = "wallet.spend_caps"

	// EVM / x402 surface — only registered when the wallet was
	// constructed with EVM support. Callers can probe via Has() in
	// dispatcher_evm.go before invoking.
	MethodEVMAddress = "wallet.evm.address"
	MethodEVMBalance = "wallet.evm.balance"
	MethodEVMSatisfy = "wallet.evm.satisfy"
	MethodEVMVerify  = "wallet.evm.verify"
	MethodEVMChains  = "wallet.evm.chains"

	// Settler surface — only registered when the wallet was wired
	// with a settler client at startup. Routes IPC calls through
	// pkg/settlerclient against the configured TCP endpoint.
	MethodSettlerIdentity = "wallet.settler.identity"
	MethodSettlerBalance  = "wallet.settler.balance"
	MethodSettlerHistory  = "wallet.settler.history"
	MethodSettlerTransfer = "wallet.settler.transfer"
)

// AllMethods is the canonical set the dispatcher registers. Used by
// tests and by the daemon when it cross-references the manifest's
// exposed-methods set against what the wallet binary actually serves.
var AllMethods = []string{
	MethodBalance, MethodBalances, MethodAddress, MethodRequest, MethodPay,
	MethodVerify, MethodSettle, MethodTopup, MethodHistory, MethodSpendCaps,
}

// AllEVMMethods is the extra set the dispatcher registers when the
// wallet has EVM support. NewDispatcher returns AllMethods + (this set
// when applicable).
var AllEVMMethods = []string{
	MethodEVMAddress, MethodEVMBalance, MethodEVMSatisfy, MethodEVMVerify, MethodEVMChains,
}

// AllSettlerMethods is the wallet-side settler surface. Like AllEVMMethods,
// these are registered conditionally — a wallet started without a
// settler endpoint omits them so callers get "method not found"
// rather than a misleading wire-error from a half-configured client.
var AllSettlerMethods = []string{
	MethodSettlerIdentity, MethodSettlerBalance, MethodSettlerHistory, MethodSettlerTransfer,
}

// ── balance ──────────────────────────────────────────────────────────────

type BalanceReq struct {
	Asset wallet.Asset `json:"asset"`
}
type BalanceResp struct {
	Asset  wallet.Asset  `json:"asset"`
	Amount wallet.Amount `json:"amount"`
}

// BalancesResp returns a snapshot of every non-zero asset balance. Empty
// map (not nil) when the wallet is empty so JSON clients don't have to
// special-case null. Useful for "show me all my assets" UIs that would
// otherwise need to know the asset list a-priori.
type BalancesResp struct {
	Balances map[wallet.Asset]wallet.Amount `json:"balances"`
}

// ── address ──────────────────────────────────────────────────────────────

type AddressResp struct {
	Address wallet.Address `json:"address"`
}

// ── request ──────────────────────────────────────────────────────────────

type RequestReq struct {
	Amount           wallet.Amount `json:"amount"`
	Asset            wallet.Asset  `json:"asset"`
	ExpiresInSeconds int64         `json:"expires_in_seconds"`
	Memo             string        `json:"memo,omitempty"`
}

// RequestResp wraps the Challenge so future fields (e.g. quote, fees)
// can be added without breaking the wire.
type RequestResp struct {
	Challenge *wallet.Challenge `json:"challenge"`
}

// ── pay ──────────────────────────────────────────────────────────────────

type PayReq struct {
	Challenge *wallet.Challenge `json:"challenge"`
}
type PayResp struct {
	SignedAuth *wallet.SignedAuth `json:"signed_auth"`
}

// ── verify ───────────────────────────────────────────────────────────────

type VerifyReq struct {
	Challenge  *wallet.Challenge  `json:"challenge"`
	SignedAuth *wallet.SignedAuth `json:"signed_auth"`
}
type VerifyResp struct {
	OK bool `json:"ok"`
}

// ── settle ───────────────────────────────────────────────────────────────

type SettleReq struct {
	Challenge  *wallet.Challenge  `json:"challenge"`
	SignedAuth *wallet.SignedAuth `json:"signed_auth"`
}
type SettleResp struct {
	Transaction *wallet.Transaction `json:"transaction"`
}

// ── topup ────────────────────────────────────────────────────────────────

type TopupReq struct {
	Asset  wallet.Asset  `json:"asset"`
	Amount wallet.Amount `json:"amount"`
	Source string        `json:"source"`
}
type TopupResp struct {
	Transaction *wallet.Transaction `json:"transaction"`
}

// ── history ──────────────────────────────────────────────────────────────

type HistoryReq struct {
	Limit          int           `json:"limit,omitempty"`
	SinceUnixNano  int64         `json:"since_unix_nano,omitempty"`
	BeforeUnixNano int64         `json:"before_unix_nano,omitempty"` // cursor: pass the oldest tx timestamp from the prior page
	Asset          wallet.Asset  `json:"asset,omitempty"`
	Kind           wallet.TxKind `json:"kind,omitempty"`
}
type HistoryResp struct {
	Transactions []wallet.Transaction `json:"transactions"`
}

// ── spend caps ──────────────────────────────────────────────────────────

// SpendCapUsage is one row in the wallet.spend_caps response: the cap
// configuration plus its current rolling-window consumption. Mirrors
// what `pilotctl appstore caps` shows from the on-disk side, but
// pulled live from the running wallet so UIs see real-time state
// (the on-disk JSONL only flushes per Sync).
type SpendCapUsage struct {
	Asset        wallet.Asset  `json:"asset"`
	Target       string        `json:"target,omitempty"` // sign-purpose from the manifest (e.g. "x402-auth"); distinguishes caps that otherwise look identical
	Limit        wallet.Amount `json:"limit"`
	WindowSec    int64         `json:"window_sec"`
	Used         wallet.Amount `json:"used"`
	RemainingRaw int64         `json:"remaining"` // signed so an over-limit (shouldn't happen with enforcement) is visible
}

type SpendCapsResp struct {
	Caps []SpendCapUsage `json:"caps"`
}

// ── evm ──────────────────────────────────────────────────────────────────
//
// The wallet.evm.* methods are only registered when the wallet was
// constructed with NewWithEVM. On a wallet without an EVM binding,
// these methods are absent — callers get a "method not found" reply.

// Multichain extension: every EVM request now accepts an optional
// `chain_id` field. Omitted (or 0) means "use the primary chain"
// (the first one configured at startup) — preserves the single-chain
// shape callers wrote against v0.3.1. Non-zero routes to that chain's
// binding, with a "chain X not configured" error when missing.

type EVMAddressReq struct {
	ChainID uint64 `json:"chain_id,omitempty"`
}

type EVMAddressResp struct {
	Address string `json:"address"`  // 0x-prefixed lowercase hex
	ChainID uint64 `json:"chain_id"` // e.g. 8453 for Base mainnet
	Token   string `json:"token"`    // 0x-prefixed token contract address
}

type EVMBalanceReq struct {
	ChainID uint64 `json:"chain_id,omitempty"`
}

type EVMBalanceResp struct {
	Address    string `json:"address"`
	ChainID    uint64 `json:"chain_id"`
	Token      string `json:"token"`
	Balance    string `json:"balance"`     // decimal string of token-smallest-unit
	RPCEnabled bool   `json:"rpc_enabled"` // false → "balance" is 0 because we have no RPC, not because the address is empty
}

// EVMSatisfyReq wraps a payment.Contract verbatim. Receivers send this
// to ask the wallet to produce a signed EIP-3009 receipt.
type EVMSatisfyReq struct {
	ChainID  uint64 `json:"chain_id,omitempty"`
	Contract any    `json:"contract"` // payment.Contract — typed loosely here to avoid an import cycle; the handler deserializes properly.
}

type EVMSatisfyResp struct {
	Receipt any `json:"receipt"` // payment.Receipt
}

type EVMVerifyReq struct {
	ChainID  uint64 `json:"chain_id,omitempty"`
	Contract any    `json:"contract"` // payment.Contract
	Receipt  any    `json:"receipt"`  // payment.Receipt
}

type EVMVerifyResp struct {
	OK bool `json:"ok"`
}

// EVMChainsResp lists every chain this wallet is configured for. The
// `chains` array preserves the order configured at startup; the
// `primary` field repeats the first entry for callers that only need
// the default. Operators use this to discover what chain IDs the
// dispatcher accepts before sending a satisfy/balance request.
type EVMChainsResp struct {
	Primary uint64        `json:"primary"`
	Chains  []ChainConfig `json:"chains"`
}

type ChainConfig struct {
	ChainID    uint64 `json:"chain_id"`
	Token      string `json:"token"`
	RPCEnabled bool   `json:"rpc_enabled"`
}

// ── settler ──────────────────────────────────────────────────────────────
//
// IPC request/response types for wallet.settler.*. The wallet's own
// pubkey is implicit: every method operates against the wallet's
// signer, so callers never specify "account" — the wallet uses its
// own.

type SettlerIdentityReq struct{}

type SettlerIdentityResp struct {
	Endpoint       string `json:"endpoint"`
	SettlerPubkey  string `json:"settler_pubkey"`
	HasOperator    bool   `json:"has_operator"`
	OperatorPubkey string `json:"operator_pubkey,omitempty"`
}

type SettlerBalanceReq struct {
	Asset string `json:"asset"`
}

type SettlerBalanceResp struct {
	Account string `json:"account"` // wallet's own ed25519 pubkey, hex
	Asset   string `json:"asset"`
	Amount  uint64 `json:"amount"`
}

type SettlerHistoryReq struct {
	Limit int `json:"limit,omitempty"`
}

type SettlerHistoryResp struct {
	Transactions []SettlerTransaction `json:"transactions"`
}

type SettlerTransaction struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Asset      string `json:"asset"`
	Amount     uint64 `json:"amount"`
	From       string `json:"from,omitempty"`
	To         string `json:"to"`
	Nonce      string `json:"nonce,omitempty"`
	Timestamp  string `json:"timestamp"` // RFC3339
	OperatorOK bool   `json:"operator_ok,omitempty"`
}

type SettlerTransferReq struct {
	To               string `json:"to"`                // hex ed25519 pubkey
	Asset            string `json:"asset"`             // e.g. "USDC"
	Amount           uint64 `json:"amount"`            // smallest unit
	Memo             string `json:"memo,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"` // 0 → 5 min default
}

type SettlerTransferResp struct {
	Transaction SettlerTransaction `json:"transaction"`
}
