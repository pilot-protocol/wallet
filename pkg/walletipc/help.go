package walletipc

import (
	"context"
	"encoding/json"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/wallet/pkg/wallet"
)

// MethodHelp is the app-store discovery contract: every app answers
// <ns>.help with its methods and their params, so an agent can call the
// wallet correctly without reading the source.
const MethodHelp = "wallet.help"

// Version is the app version wallet.help reports. cmd/wallet sets it from
// its own Version, which a test pins to manifest.json's app_version.
var Version = "dev"

type helpMethod struct {
	Method   string            `json:"method"`
	Summary  string            `json:"summary"`
	Params   map[string]string `json:"params,omitempty"`
	Duration string            `json:"duration"`
}

var helpCore = []helpMethod{
	{MethodAddress, "This wallet's Pilot payment address.", nil, "fast"},
	{MethodBalance, "Balance of one asset.", map[string]string{"asset": "string (required) — asset code, e.g. \"PILOT\""}, "fast"},
	{MethodBalances, "Balances of every asset this wallet holds.", nil, "fast"},
	{MethodSpendCaps, "Configured spend caps with their live rolling-window usage.", nil, "fast"},
	{MethodHistory, "Transaction history, newest first.", map[string]string{
		"limit": "int — page size", "before_unix_nano": "int — cursor: the oldest timestamp from the prior page",
		"since_unix_nano": "int — only newer transactions", "asset": "string — filter by asset", "kind": "string — filter by transaction kind"}, "fast"},
	{MethodRequest, "Create a payment challenge for a peer to pay.", map[string]string{
		"amount": "int (required) — amount in the asset's smallest unit", "asset": "string (required)",
		"expires_in_seconds": "int (required) — challenge lifetime", "memo": "string — shown to the payer"}, "fast"},
	{MethodPay, "Sign a payment authorization for a challenge. Enforced against spend caps.", map[string]string{"challenge": "object (required) — from the payee's wallet.request"}, "fast"},
	{MethodVerify, "Check a signed authorization against its challenge without settling.", map[string]string{"challenge": "object (required)", "signed_auth": "object (required) — from wallet.pay"}, "fast"},
	{MethodSettle, "Verify and settle a signed authorization into this wallet.", map[string]string{"challenge": "object (required)", "signed_auth": "object (required)"}, "fast"},
	{MethodTopup, "Credit this wallet from an external source.", map[string]string{"asset": "string (required)", "amount": "int (required) — amount in the asset's smallest unit", "source": "string (required) — where the funds came from"}, "fast"},
}

var helpEVM = []helpMethod{
	{MethodEVMChains, "EVM chains this wallet is configured for (USDC on Base, Ethereum, Polygon by default).", nil, "fast"},
	{MethodEVMAddress, "This wallet's EVM address on a chain.", map[string]string{"chain_id": "int — omit for the primary chain"}, "fast"},
	{MethodEVMBalance, "USDC balance on a chain.", map[string]string{"chain_id": "int — omit for the primary chain"}, "med"},
	{MethodEVMSatisfy, "Pay an x402 payment contract with an EIP-3009 authorization. Enforced against spend caps.", map[string]string{"contract": "object (required) — the x402 payment contract", "chain_id": "int"}, "med"},
	{MethodEVMVerify, "Verify an x402 receipt against its contract.", map[string]string{"contract": "object (required)", "receipt": "object (required)", "chain_id": "int"}, "med"},
}

var helpSettler = []helpMethod{
	{MethodSettlerIdentity, "The settler this wallet is wired to, and its identity.", nil, "fast"},
	{MethodSettlerBalance, "This wallet's balance held at the settler.", map[string]string{"asset": "string — asset symbol"}, "fast"},
	{MethodSettlerHistory, "This wallet's settler transaction history.", map[string]string{"limit": "int — page size"}, "fast"},
	{MethodSettlerTransfer, "Transfer through the settler. Enforced against spend caps.", map[string]string{"to": "string (required) — recipient's hex ed25519 pubkey", "asset": "string (required), e.g. \"USDC\"", "amount": "int (required) — smallest unit", "memo": "string", "expires_in_seconds": "int — default 300"}, "med"},
}

func helpHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
		methods := append([]helpMethod{}, helpCore...)
		if w.HasEVM() {
			methods = append(methods, helpEVM...)
		}
		if w.HasSettler() {
			methods = append(methods, helpSettler...)
		}
		methods = append(methods, helpMethod{MethodHelp, "This list.", nil, "fast"})
		return encode(map[string]any{
			"app":         "io.pilot.wallet",
			"version":     Version,
			"description": "Pilot's reference wallet: pay and get paid between agents (Pilot challenge/authorization flow) and pay x402 USDC contracts on EVM chains, all under per-asset spend caps.",
			"methods":     methods,
		})
	}
}
