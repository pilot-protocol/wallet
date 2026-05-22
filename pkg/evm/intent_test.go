package evm

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

func TestReceiptIntentFormattedAmountUSDC(t *testing.T) {
	usdc, _ := USDCAddress(ChainBaseSepolia)
	intent := ReceiptIntent{
		Token:   usdc,
		Value:   big.NewInt(1_500_000), // 1.5 USDC
		ChainID: ChainBaseSepolia,
	}
	got := intent.FormattedAmount()
	if got != "1.500000 USDC" {
		t.Errorf("FormattedAmount: %q, want %q", got, "1.500000 USDC")
	}
}

func TestReceiptIntentFormattedAmountSubUnit(t *testing.T) {
	usdc, _ := USDCAddress(ChainBaseSepolia)
	intent := ReceiptIntent{
		Token:   usdc,
		Value:   big.NewInt(42), // 0.000042 USDC
		ChainID: ChainBaseSepolia,
	}
	got := intent.FormattedAmount()
	if got != "0.000042 USDC" {
		t.Errorf("FormattedAmount: %q, want %q", got, "0.000042 USDC")
	}
}

func TestReceiptIntentFormattedAmountZero(t *testing.T) {
	intent := ReceiptIntent{}
	got := intent.FormattedAmount()
	if !strings.Contains(got, "0") {
		t.Errorf("FormattedAmount with nil Value: %q", got)
	}
}

func TestReceiptIntentChainName(t *testing.T) {
	cases := map[uint64]string{
		ChainEthereumMainnet: "Ethereum Mainnet",
		ChainBaseMainnet:     "Base Mainnet",
		ChainBaseSepolia:     "Base Sepolia",
		999999:               "chain-999999",
	}
	for chain, want := range cases {
		got := ReceiptIntent{ChainID: chain}.ChainName()
		if got != want {
			t.Errorf("chain %d: ChainName=%q, want %q", chain, got, want)
		}
	}
}

func TestReceiptIntentDecimalsKnownToken(t *testing.T) {
	for _, chain := range []uint64{ChainEthereumMainnet, ChainBaseMainnet, ChainBaseSepolia} {
		usdc, _ := USDCAddress(chain)
		intent := ReceiptIntent{Token: usdc, ChainID: chain}
		if intent.Decimals() != 6 {
			t.Errorf("USDC on chain %d: Decimals=%d, want 6", chain, intent.Decimals())
		}
		if intent.TokenSymbol() != "USDC" {
			t.Errorf("USDC on chain %d: TokenSymbol=%q, want USDC", chain, intent.TokenSymbol())
		}
	}
}

// TestReceiptIntentRecognizesUSDT exercises the multi-token registry:
// USDT on ETH mainnet and Base mainnet must resolve to symbol="USDT"
// and decimals=6. Without this entry, payment UIs would render a
// non-USDC receipt as `1234567 raw to 0xdAC1…1ec7` instead of
// `1.234567 USDT` — same data, much worse signal-to-noise.
func TestReceiptIntentRecognizesUSDT(t *testing.T) {
	for _, c := range []struct {
		chain uint64
		addr  string
	}{
		{ChainEthereumMainnet, "0xdAC17F958D2ee523a2206206994597C13D831ec7"},
		{ChainBaseMainnet, "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"},
	} {
		token, err := ParseAddress(c.addr)
		if err != nil {
			t.Fatalf("parse %s: %v", c.addr, err)
		}
		intent := ReceiptIntent{Token: token, ChainID: c.chain}
		if got := intent.TokenSymbol(); got != "USDT" {
			t.Errorf("USDT on chain %d: TokenSymbol=%q, want USDT", c.chain, got)
		}
		if got := intent.Decimals(); got != 6 {
			t.Errorf("USDT on chain %d: Decimals=%d, want 6", c.chain, got)
		}
	}
}

// TestLookupTokenIsChainAware confirms cross-chain isolation: a USDC
// contract address from one chain must NOT resolve on a different
// chain's namespace. Same hex deployed on two chains can have wildly
// different contracts — the registry has to keep them separate.
func TestLookupTokenIsChainAware(t *testing.T) {
	usdcBase, _ := USDCAddress(ChainBaseMainnet)
	// Asking for Base-USDC's address on the Ethereum chain id must miss.
	if _, ok := LookupToken(ChainEthereumMainnet, usdcBase); ok {
		t.Errorf("Base-USDC contract should not resolve as a known token on Ethereum mainnet")
	}
	// And asking on the right chain must hit.
	if _, ok := LookupToken(ChainBaseMainnet, usdcBase); !ok {
		t.Errorf("Base-USDC contract should resolve on Base mainnet")
	}
}

func TestReceiptIntentDecimalsUnknownToken(t *testing.T) {
	// Random token contract → unknown — defaults to 18 decimals.
	unknown, _ := ParseAddress("0x1234567890123456789012345678901234567890")
	intent := ReceiptIntent{Token: unknown}
	if intent.Decimals() != 18 {
		t.Errorf("unknown token Decimals=%d, want 18 (EVM default)", intent.Decimals())
	}
	// Token symbol falls back to the short address form.
	got := intent.TokenSymbol()
	if !strings.Contains(got, "0x1234") || !strings.Contains(got, "…") {
		t.Errorf("TokenSymbol on unknown: %q (expected short-address form)", got)
	}
}

func TestReceiptIntentStringRendersFullSummary(t *testing.T) {
	from, _ := ParseAddress("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	usdc, _ := USDCAddress(ChainBaseSepolia)
	intent := ReceiptIntent{
		From:    from,
		To:      to,
		Value:   big.NewInt(2_500_000),
		Token:   usdc,
		ChainID: ChainBaseSepolia,
	}
	got := intent.String()
	// Should contain the formatted amount, both short addresses, and the chain name.
	for _, must := range []string{"2.500000 USDC", "0x7e5f", "0x0000", "Base Sepolia"} {
		if !strings.Contains(got, must) {
			t.Errorf("String() %q missing %q", got, must)
		}
	}
}

func TestReceiptIntentEndToEnd(t *testing.T) {
	// Real signed receipt → DecodeIntent → human-readable summary.
	signer, _ := NewEVMSigner()
	method, _ := NewEVMMethod(signer, ChainBaseSepolia, nil)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	c := payment.Contract{
		ID:              "ctr-intent",
		Amount:          750_000, // 0.75 USDC
		Asset:           "USDC",
		RecipientAddr:   to.Hex(),
		ExpiresAt:       time.Now().Add(time.Minute),
		Nonce:           strings.Repeat("a", 64),
		AcceptedMethods: []string{EVMMethodID},
	}
	r, err := method.Satisfy(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := DecodeIntent(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(intent.String(), "0.750000 USDC") {
		t.Errorf("end-to-end summary lacks expected amount: %q", intent.String())
	}
	if !strings.Contains(intent.String(), "Base Sepolia") {
		t.Errorf("end-to-end summary lacks chain name: %q", intent.String())
	}
}

// TestReceiptIntentExpiration exercises the ValidBefore round-trip: a
// signed receipt with a 1-minute window should decode to an intent
// whose ExpiresIn is positive (and Expired is false). Once we advance
// past ValidBefore, Expired flips to true and ExpiresIn goes
// non-positive.
func TestReceiptIntentExpiration(t *testing.T) {
	signer, _ := NewEVMSigner()
	method, _ := NewEVMMethod(signer, ChainBaseSepolia, nil)
	to, _ := ParseAddress("0x000000000000000000000000000000000000bEEF")
	deadline := time.Now().Add(time.Minute)
	c := payment.Contract{
		ID:              "ctr-expiry",
		Amount:          1_000_000,
		Asset:           "USDC",
		RecipientAddr:   to.Hex(),
		ExpiresAt:       deadline,
		Nonce:           strings.Repeat("b", 64),
		AcceptedMethods: []string{EVMMethodID},
	}
	r, err := method.Satisfy(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := DecodeIntent(r)
	if err != nil {
		t.Fatal(err)
	}

	if intent.ValidBefore.IsZero() {
		t.Fatal("expected ValidBefore to round-trip from receipt")
	}
	// ValidBefore is unix seconds — truncated, so allow a 1s slack
	// either way relative to the original deadline.
	if diff := intent.ValidBefore.Sub(deadline); diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("ValidBefore drifted from deadline by %s (intent=%v, deadline=%v)",
			diff, intent.ValidBefore, deadline)
	}

	now := deadline.Add(-30 * time.Second)
	if intent.Expired(now) {
		t.Errorf("Expired=true 30s before deadline")
	}
	if d := intent.ExpiresIn(now); d <= 0 {
		t.Errorf("ExpiresIn before deadline: %s, want positive", d)
	}

	after := deadline.Add(time.Second)
	if !intent.Expired(after) {
		t.Errorf("Expired=false 1s after deadline")
	}
	if d := intent.ExpiresIn(after); d > 0 {
		t.Errorf("ExpiresIn after deadline: %s, want non-positive", d)
	}
}

func TestReceiptIntentExpirationNoValidBefore(t *testing.T) {
	// A ReceiptIntent with no ValidBefore should never report as expired
	// (callers should rely on the on-chain bound in that case).
	intent := ReceiptIntent{}
	if intent.Expired(time.Now()) {
		t.Errorf("Expired=true for intent with no ValidBefore")
	}
	if d := intent.ExpiresIn(time.Now()); d != 0 {
		t.Errorf("ExpiresIn=%s for intent with no ValidBefore, want 0", d)
	}
}
