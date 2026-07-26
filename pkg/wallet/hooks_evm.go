package wallet

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
	"github.com/pilot-protocol/wallet/pkg/evm"
)

// evmBinding bundles the EVM-side wallet state. nil-valued in a Wallet
// that was constructed without an EVM signer.
type evmBinding struct {
	signer  *evm.EVMSigner
	method  *evm.EVMMethod
	rpc     *evm.Client // may be nil — wallet still works for sign/verify, just can't read on-chain balance
	chainID uint64
}

// EVMConfig configures the EVM side of a wallet at construction.
type EVMConfig struct {
	// Signer is the secp256k1 keypair used for EIP-3009 signing.
	// Required.
	Signer *evm.EVMSigner

	// ChainID selects the chain the wallet targets. Use the
	// well-known constants in pkg/evm (ChainBaseMainnet,
	// ChainBaseSepolia, ChainEthereumMainnet).
	ChainID uint64

	// TokenOverride optionally pins a non-USDC ERC-20 contract. nil
	// resolves to the canonical USDC address for ChainID. The
	// wallet's payment.Method currently only supports USDC, but the
	// binding accepts arbitrary tokens for forward-compatibility.
	TokenOverride *evm.Address

	// RPCEndpoint is the JSON-RPC URL the wallet uses for balance
	// reads (and optionally broadcast). Leave empty to skip RPC —
	// the wallet still produces valid signatures, just can't answer
	// "what's my balance".
	RPCEndpoint string

	// HTTPClient is forwarded to the RPC client. nil uses a default.
	HTTPClient *http.Client
}

// NewWithEVM constructs a wallet with both the internal ledger
// (existing semantics) AND a single-chain EVM x402 binding enabled.
// Thin wrapper over NewWithEVMs for callers that only need one chain.
func NewWithEVM(addr Address, signer Signer, store Store, cfg EVMConfig) (*Wallet, error) {
	return NewWithEVMs(addr, signer, store, []EVMConfig{cfg})
}

// NewWithEVMs is the multichain constructor. The same secp256k1 key
// (cfg.Signer) is reused across every entry — an EVM address is
// chain-agnostic, so reusing the key is the canonical pattern, not a
// security trade-off. Each entry produces its own evm.EVMMethod
// (bound to that chain's USDC contract + EIP-712 domain) and its own
// optional RPC client.
//
// The first entry becomes the "primary" chain — what HasEVM(),
// EVMAddress() (the parameterless legacy form), EVMChainID(),
// EVMToken(), and EVMBalance() (parameterless) report. Per-chain
// callers use the parameterised siblings (EVMAddressFor, EVMBalanceFor)
// or SatisfyEVM (which routes by contract.ChainID).
//
// Every cfg in the slice must carry the same Signer — wallet-wide
// signer uniqueness keeps the cap-bookkeeping single-threaded and the
// on-chain address reproducible across reboots.
func NewWithEVMs(addr Address, signer Signer, store Store, cfgs []EVMConfig) (*Wallet, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("wallet: NewWithEVMs needs at least one EVMConfig")
	}
	if cfgs[0].Signer == nil {
		return nil, errors.New("wallet: EVMConfig[0].Signer required")
	}
	primarySigner := cfgs[0].Signer
	w := New(addr, signer, store)
	w.evmByChain = make(map[uint64]*evmBinding, len(cfgs))
	for i, cfg := range cfgs {
		if cfg.Signer == nil {
			return nil, fmt.Errorf("wallet: EVMConfig[%d].Signer required", i)
		}
		if cfg.Signer.Address() != primarySigner.Address() {
			return nil, fmt.Errorf("wallet: EVMConfig[%d] uses a different signer than [0]; all chains must share one key", i)
		}
		method, err := evm.NewEVMMethod(cfg.Signer, cfg.ChainID, cfg.TokenOverride)
		if err != nil {
			return nil, fmt.Errorf("wallet: EVMConfig[%d]: %w", i, err)
		}
		b := &evmBinding{
			signer:  cfg.Signer,
			method:  method,
			chainID: cfg.ChainID,
		}
		if cfg.RPCEndpoint != "" {
			b.rpc = evm.NewClient(cfg.RPCEndpoint, cfg.HTTPClient)
		}
		w.evmByChain[cfg.ChainID] = b
		if i == 0 {
			w.evm = b
		}
	}
	return w, nil
}

// HasEVM reports whether the wallet was constructed with EVM support.
func (w *Wallet) HasEVM() bool { return w.evm != nil }

// EVMMethod returns the wallet's x402 payment.Method, or nil if the
// wallet was built without EVM support.
func (w *Wallet) EVMMethod() *evm.EVMMethod {
	if w.evm == nil {
		return nil
	}
	return w.evm.method
}

// EVMAddress returns the wallet's on-chain receive address (the EVM
// address derived from the EVM signer), or the zero address if no EVM
// binding is configured.
func (w *Wallet) EVMAddress() evm.Address {
	if w.evm == nil {
		return evm.Address{}
	}
	return w.evm.signer.Address()
}

// EVMChainID returns the configured chain id, or 0 if no EVM binding.
func (w *Wallet) EVMChainID() uint64 {
	if w.evm == nil {
		return 0
	}
	return w.evm.chainID
}

// EVMToken returns the configured ERC-20 token contract address.
func (w *Wallet) EVMToken() evm.Address {
	if w.evm == nil {
		return evm.Address{}
	}
	return w.evm.method.Token()
}

// EVMBalance reads the wallet's on-chain USDC balance via the
// configured RPC. Returns (0, nil) if no RPC is configured — callers
// distinguish "zero balance" from "no chain access" via HasEVMRPC.
func (w *Wallet) EVMBalance(ctx context.Context) (*big.Int, error) {
	if w.evm == nil || w.evm.rpc == nil {
		return big.NewInt(0), nil
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}
	return w.evm.rpc.BalanceOf(ctx, w.evm.method.Token(), w.evm.signer.Address())
}

// HasEVMRPC reports whether an RPC endpoint was configured for the
// PRIMARY chain. The multichain sibling HasEVMRPCFor(chainID) checks
// a specific chain.
func (w *Wallet) HasEVMRPC() bool {
	return w.evm != nil && w.evm.rpc != nil
}

// EVMChainIDs returns every configured chain id, sorted ascending so
// `pilotctl appstore call wallet.evm.chains` produces stable output.
// nil/empty when no EVM bindings exist.
func (w *Wallet) EVMChainIDs() []uint64 {
	if len(w.evmByChain) == 0 {
		return nil
	}
	out := make([]uint64, 0, len(w.evmByChain))
	for id := range w.evmByChain {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HasEVMChain reports whether the wallet has a binding for chainID.
func (w *Wallet) HasEVMChain(chainID uint64) bool {
	if w.evmByChain == nil {
		return false
	}
	_, ok := w.evmByChain[chainID]
	return ok
}

// HasEVMRPCFor reports whether the per-chain RPC client is set.
func (w *Wallet) HasEVMRPCFor(chainID uint64) bool {
	b := w.evmByChain[chainID]
	return b != nil && b.rpc != nil
}

// EVMTokenFor returns the ERC-20 contract address for the supplied
// chain (or the zero address if the chain isn't configured).
func (w *Wallet) EVMTokenFor(chainID uint64) evm.Address {
	b := w.evmByChain[chainID]
	if b == nil {
		return evm.Address{}
	}
	return b.method.Token()
}

// EVMBalanceFor reads the wallet's balance on chainID via that chain's
// RPC client. Returns (0, nil) if RPC isn't configured for that chain,
// (0, ErrEVMChainUnknown) if the chain isn't configured at all — the
// caller distinguishes "no RPC, but configured" from "this wallet
// doesn't speak that chain" via HasEVMChain.
func (w *Wallet) EVMBalanceFor(ctx context.Context, chainID uint64) (*big.Int, error) {
	b := w.evmByChain[chainID]
	if b == nil {
		return big.NewInt(0), fmt.Errorf("wallet: chain %d not configured", chainID)
	}
	if b.rpc == nil {
		return big.NewInt(0), nil
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}
	return b.rpc.BalanceOf(ctx, b.method.Token(), b.signer.Address())
}

// EVMMethodFor returns the per-chain payment.Method. nil for chains
// the wallet doesn't know about. Used by the IPC dispatcher when the
// caller specifies a chain_id.
func (w *Wallet) EVMMethodFor(chainID uint64) *evm.EVMMethod {
	b := w.evmByChain[chainID]
	if b == nil {
		return nil
	}
	return b.method
}

// SatisfyEVM is the cap-aware entry point for producing an EIP-3009
// payment receipt against this wallet's EVM signer. It mirrors what
// the manifest's `key.sign:evm-eip3009` grant constrains: the same
// rolling-window cap that gates Pay (for the IPC ledger surface)
// also gates this method, so an attacker can't dodge a cap by
// switching from the internal ledger to on-chain.
//
// Wire path: walletipc.evmSatisfyHandler → Wallet.SatisfyEVM →
// EVMMethod.Satisfy. Pre-cap-enforcement callers that reached into
// EVMMethod() directly still work but bypass the cap — they SHOULD
// migrate. The IPC dispatcher is migrated as part of this change.
func (w *Wallet) SatisfyEVM(ctx context.Context, c payment.Contract) (payment.Receipt, error) {
	if w.evm == nil {
		return payment.Receipt{}, errors.New("wallet.evm.satisfy: no EVM method bound")
	}
	return w.SatisfyEVMOn(ctx, w.evm.chainID, c)
}

// DefaultEVMAsset is the asset an EVM payment contract denominates in
// when it leaves the Asset field empty. The EVM signer only ever
// produces EIP-3009 authorizations against the chain's USDC contract,
// so an unset Asset means USDC.
const DefaultEVMAsset Asset = "USDC"

// NormalizeEVMAsset resolves a contract's Asset field to the symbol the
// EVM signer actually operates on. An empty field resolves to
// DefaultEVMAsset; anything else is passed through untouched (the
// signer rejects assets it can't produce). Cap accounting and the
// signer must agree on this value, so both sides call through here.
func NormalizeEVMAsset(asset string) Asset {
	if asset == "" {
		return DefaultEVMAsset
	}
	return Asset(asset)
}

// SatisfyEVMOn is the multichain entry point. The caller passes the
// chain id explicitly — the IPC dispatcher exposes this as an
// optional `chain_id` field on wallet.evm.satisfy. Caps are checked
// against the same wallet-wide spendLog as SatisfyEVM and Pay so a
// multichain wallet can't dodge a cap by switching chains.
//
// The contract's Asset is resolved through NormalizeEVMAsset before
// either the cap check or the signer sees it, so both accounts for the
// same asset regardless of how the caller spelled it.
func (w *Wallet) SatisfyEVMOn(ctx context.Context, chainID uint64, c payment.Contract) (payment.Receipt, error) {
	binding := w.evmByChain[chainID]
	if binding == nil {
		return payment.Receipt{}, fmt.Errorf("wallet.evm.satisfy: chain %d not configured", chainID)
	}
	asset := NormalizeEVMAsset(c.Asset)
	c.Asset = string(asset)
	w.capMu.Lock()
	defer w.capMu.Unlock()
	if err := w.checkSpendCapLocked(asset, Amount(c.Amount)); err != nil {
		return payment.Receipt{}, err
	}
	receipt, err := binding.method.Satisfy(ctx, c)
	if err != nil {
		return payment.Receipt{}, err
	}
	w.recordSpendLocked(asset, Amount(c.Amount))
	return receipt, nil
}
