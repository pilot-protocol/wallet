package evm

import "fmt"

// Well-known chain ids and USDC contract addresses. Hardcoded so the
// wallet doesn't depend on a config file for the common case; advanced
// users can override via manifest or env when running against an
// unlisted network.

const (
	// ChainID values per chainlist.org.
	ChainEthereumMainnet uint64 = 1
	ChainBaseMainnet     uint64 = 8453
	ChainBaseSepolia     uint64 = 84532
)

// USDC contract addresses. Keep these as string constants and parse on
// demand so the package has no init-time hard failure if hex parsing
// somehow disagrees.
const (
	usdcEthereumMainnet = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	usdcBaseMainnet     = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	usdcBaseSepolia     = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
)

// USDCAddress returns the USDC contract address for a known chain id,
// or an error if the chain isn't recognized. Callers running against
// a custom or local devnet should construct the Domain manually.
func USDCAddress(chainID uint64) (Address, error) {
	var s string
	switch chainID {
	case ChainEthereumMainnet:
		s = usdcEthereumMainnet
	case ChainBaseMainnet:
		s = usdcBaseMainnet
	case ChainBaseSepolia:
		s = usdcBaseSepolia
	default:
		return Address{}, errChainUnknown(chainID)
	}
	return ParseAddress(s)
}

// USDCDomain returns the EIP-712 Domain for USDC on chainID, ready to
// pass to EIP3009Digest. USDC's EIP-712 domain uses name="USD Coin"
// and version="2" on every chain (verified against the deployed FiatToken
// contracts).
func USDCDomain(chainID uint64) (Domain, error) {
	addr, err := USDCAddress(chainID)
	if err != nil {
		return Domain{}, err
	}
	return Domain{
		Name:              "USD Coin",
		Version:           "2",
		ChainID:           chainID,
		VerifyingContract: addr,
	}, nil
}

type errUnknownChain struct{ id uint64 }

func (e errUnknownChain) Error() string {
	return fmt.Sprintf("evm: unknown chain id %d; pass Domain explicitly or add to chains.go", e.id)
}

// ChainID returns the unrecognized chain id, so callers can `errors.As`
// into errUnknownChain (or this exported method) and react — e.g. log
// the specific id, prompt the user to add support, etc.
func (e errUnknownChain) ChainID() uint64 { return e.id }

func errChainUnknown(id uint64) error { return errUnknownChain{id: id} }

// ── token registry ─────────────────────────────────────────────────────
//
// Known ERC-20 contracts beyond USDC. Used by ReceiptIntent's UX layer
// (Decimals / TokenSymbol) to render multi-token receipts without each
// caller maintaining its own table. Entries are keyed by (chainID,
// contract address) so the same symbol on different chains is treated
// as a distinct entry — which it is, since different chains can have
// different decimals or even different on-chain implementations under
// the same nominal symbol.

// KnownToken is one row of the multi-token registry.
type KnownToken struct {
	Symbol   string
	Decimals int
}

// USDT contract addresses. Same Ethereum-mainnet address most explorers
// list; Base mainnet's bridged USDT uses the canonical Tether-deployed
// contract. Base Sepolia has no canonical USDT — omit until a real
// deployment lands.
const (
	usdtEthereumMainnet = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
	usdtBaseMainnet     = "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"
)

// knownTokens is built lazily on first lookup so a hex-parse failure
// in any one entry doesn't crash the binary at init time.
var knownTokens = func() map[uint64]map[Address]KnownToken {
	add := func(out map[uint64]map[Address]KnownToken, chain uint64, addr string, info KnownToken) {
		parsed, err := ParseAddress(addr)
		if err != nil {
			return
		}
		if out[chain] == nil {
			out[chain] = map[Address]KnownToken{}
		}
		out[chain][parsed] = info
	}
	out := map[uint64]map[Address]KnownToken{}
	for _, e := range []struct {
		chain uint64
		addr  string
		info  KnownToken
	}{
		{ChainEthereumMainnet, usdcEthereumMainnet, KnownToken{"USDC", 6}},
		{ChainBaseMainnet, usdcBaseMainnet, KnownToken{"USDC", 6}},
		{ChainBaseSepolia, usdcBaseSepolia, KnownToken{"USDC", 6}},
		{ChainEthereumMainnet, usdtEthereumMainnet, KnownToken{"USDT", 6}},
		{ChainBaseMainnet, usdtBaseMainnet, KnownToken{"USDT", 6}},
	} {
		add(out, e.chain, e.addr, e.info)
	}
	return out
}()

// LookupToken returns the (symbol, decimals, found) tuple for a token
// contract on a specific chain. Chain-aware: the same contract address
// on a different chain is treated as unknown — which is correct, since
// the same hex string typically routes to different deployments per chain.
//
// UIs that want a graceful fallback can use this to switch between
// "render as 1.234 USDC" and "render as 1234 raw to 0xabcd…ef01".
func LookupToken(chainID uint64, contract Address) (KnownToken, bool) {
	if perChain, ok := knownTokens[chainID]; ok {
		if t, ok := perChain[contract]; ok {
			return t, true
		}
	}
	return KnownToken{}, false
}
