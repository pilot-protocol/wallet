package walletipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/app-store/pkg/payment"
	"github.com/pilot-protocol/wallet/pkg/wallet"
)

// RegisterEVM adds the wallet.evm.* methods to an existing dispatcher
// when w has EVM support. Called by NewDispatcher after the
// non-EVM methods are wired so a single dispatcher serves both
// surfaces transparently.
//
// Safe to call on a wallet without EVM support — it's a no-op.
//
// Multichain: every handler accepts an optional `chain_id` field on
// its request. Omitted (or 0) means "use the primary chain" — the
// first one passed to NewWithEVMs. A non-zero chain_id routes to that
// chain's binding, with a clean error if the wallet wasn't configured
// for it. wallet.evm.chains lets callers discover the set.
func RegisterEVM(d *ipc.Dispatcher, w *wallet.Wallet) {
	if !w.HasEVM() {
		return
	}
	d.Register(MethodEVMAddress, evmAddressHandler(w))
	d.Register(MethodEVMBalance, evmBalanceHandler(w))
	d.Register(MethodEVMSatisfy, evmSatisfyHandler(w))
	d.Register(MethodEVMVerify, evmVerifyHandler(w))
	d.Register(MethodEVMChains, evmChainsHandler(w))
}

// chainOrPrimary returns the requested chain id when non-zero, or the
// wallet's primary chain when zero. Tied to one helper so a future
// change (e.g. preferred-chain selection from spend caps) lives in
// one place.
func chainOrPrimary(w *wallet.Wallet, req uint64) uint64 {
	if req != 0 {
		return req
	}
	return w.EVMChainID()
}

// decodeChainID extracts the optional chain_id field from a request
// payload without forcing a stricter typed Unmarshal — keeps the
// handler tolerant of clients that don't include the field.
func decodeChainID(payload json.RawMessage) (uint64, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	var probe struct {
		ChainID uint64 `json:"chain_id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return 0, fmt.Errorf("decode chain_id: %w", err)
	}
	return probe.ChainID, nil
}

func evmAddressHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, env *ipc.Envelope) (json.RawMessage, error) {
		reqChain, err := decodeChainID(env.Payload)
		if err != nil {
			return nil, err
		}
		chainID := chainOrPrimary(w, reqChain)
		if !w.HasEVMChain(chainID) {
			return nil, fmt.Errorf("wallet.evm.address: chain %d not configured", chainID)
		}
		return encode(EVMAddressResp{
			Address: w.EVMAddress().Hex(),
			ChainID: chainID,
			Token:   w.EVMTokenFor(chainID).Hex(),
		})
	}
}

func evmBalanceHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, env *ipc.Envelope) (json.RawMessage, error) {
		reqChain, err := decodeChainID(env.Payload)
		if err != nil {
			return nil, err
		}
		chainID := chainOrPrimary(w, reqChain)
		if !w.HasEVMChain(chainID) {
			return nil, fmt.Errorf("wallet.evm.balance: chain %d not configured", chainID)
		}
		balance, err := w.EVMBalanceFor(ctx, chainID)
		if err != nil {
			return nil, fmt.Errorf("wallet.evm.balance: %w", err)
		}
		return encode(EVMBalanceResp{
			Address:    w.EVMAddress().Hex(),
			ChainID:    chainID,
			Token:      w.EVMTokenFor(chainID).Hex(),
			Balance:    balance.String(),
			RPCEnabled: w.HasEVMRPCFor(chainID),
		})
	}
}

func evmSatisfyHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		// Decode the request as a typed payment.Contract — the api.go
		// shape uses `any` to avoid cycles, but we re-decode strictly here.
		var inner struct {
			ChainID  uint64           `json:"chain_id"`
			Contract payment.Contract `json:"contract"`
		}
		if err := json.Unmarshal(req.Payload, &inner); err != nil {
			return nil, fmt.Errorf("decode satisfy req: %w", err)
		}
		chainID := chainOrPrimary(w, inner.ChainID)
		// Route through Wallet.SatisfyEVMOn so the same rolling-window
		// spend cap that gates Pay also gates on-chain receipts, even
		// when the caller targets a non-primary chain.
		receipt, err := w.SatisfyEVMOn(ctx, chainID, inner.Contract)
		if err != nil {
			return nil, err
		}
		return encode(struct {
			Receipt payment.Receipt `json:"receipt"`
		}{Receipt: receipt})
	}
}

func evmVerifyHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var inner struct {
			ChainID  uint64           `json:"chain_id"`
			Contract payment.Contract `json:"contract"`
			Receipt  payment.Receipt  `json:"receipt"`
		}
		if err := json.Unmarshal(req.Payload, &inner); err != nil {
			return nil, fmt.Errorf("decode verify args: %w", err)
		}
		chainID := chainOrPrimary(w, inner.ChainID)
		method := w.EVMMethodFor(chainID)
		if method == nil {
			return nil, errors.New("wallet.evm.verify: no EVM method bound")
		}
		if err := method.Verify(ctx, inner.Contract, inner.Receipt); err != nil {
			return nil, err
		}
		return encode(EVMVerifyResp{OK: true})
	}
}

func evmChainsHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
		ids := w.EVMChainIDs()
		out := EVMChainsResp{
			Primary: w.EVMChainID(),
			Chains:  make([]ChainConfig, 0, len(ids)),
		}
		for _, id := range ids {
			out.Chains = append(out.Chains, ChainConfig{
				ChainID:    id,
				Token:      w.EVMTokenFor(id).Hex(),
				RPCEnabled: w.HasEVMRPCFor(id),
			})
		}
		return encode(out)
	}
}
