package wallet

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
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
// (existing semantics) AND the EVM x402 binding enabled.
func NewWithEVM(addr Address, signer Signer, store Store, cfg EVMConfig) (*Wallet, error) {
	if cfg.Signer == nil {
		return nil, errors.New("wallet: EVMConfig.Signer required")
	}
	method, err := evm.NewEVMMethod(cfg.Signer, cfg.ChainID, cfg.TokenOverride)
	if err != nil {
		return nil, fmt.Errorf("wallet: build EVMMethod: %w", err)
	}
	binding := &evmBinding{
		signer:  cfg.Signer,
		method:  method,
		chainID: cfg.ChainID,
	}
	if cfg.RPCEndpoint != "" {
		binding.rpc = evm.NewClient(cfg.RPCEndpoint, cfg.HTTPClient)
	}
	w := New(addr, signer, store)
	w.evm = binding
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

// HasEVMRPC reports whether an RPC endpoint was configured. Callers
// use this to tell "no balance because chain access disabled" apart
// from "no balance because the address actually holds nothing".
func (w *Wallet) HasEVMRPC() bool {
	return w.evm != nil && w.evm.rpc != nil
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
	// Cap check + signing + record-on-success all happen under capMu
	// to keep concurrent SatisfyEVM/Pay calls consistent against the
	// shared spendLog (caps are wallet-wide, not per-surface).
	w.capMu.Lock()
	defer w.capMu.Unlock()
	if err := w.checkSpendCapLocked(Asset(c.Asset), Amount(c.Amount)); err != nil {
		return payment.Receipt{}, err
	}
	receipt, err := w.evm.method.Satisfy(ctx, c)
	if err != nil {
		return payment.Receipt{}, err
	}
	w.recordSpendLocked(Asset(c.Asset), Amount(c.Amount))
	return receipt, nil
}
