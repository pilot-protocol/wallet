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
func RegisterEVM(d *ipc.Dispatcher, w *wallet.Wallet) {
	if !w.HasEVM() {
		return
	}
	d.Register(MethodEVMAddress, evmAddressHandler(w))
	d.Register(MethodEVMBalance, evmBalanceHandler(w))
	d.Register(MethodEVMSatisfy, evmSatisfyHandler(w))
	d.Register(MethodEVMVerify, evmVerifyHandler(w))
}

func evmAddressHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
		return encode(EVMAddressResp{
			Address: w.EVMAddress().Hex(),
			ChainID: w.EVMChainID(),
			Token:   w.EVMToken().Hex(),
		})
	}
}

func evmBalanceHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
		balance, err := w.EVMBalance(ctx)
		if err != nil {
			return nil, fmt.Errorf("wallet.evm.balance: %w", err)
		}
		return encode(EVMBalanceResp{
			Address:    w.EVMAddress().Hex(),
			ChainID:    w.EVMChainID(),
			Token:      w.EVMToken().Hex(),
			Balance:    balance.String(),
			RPCEnabled: w.HasEVMRPC(),
		})
	}
}

func evmSatisfyHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		// Decode the request as a typed payment.Contract — the api.go
		// shape uses `any` to avoid cycles, but we re-decode strictly here.
		var inner struct {
			Contract payment.Contract `json:"contract"`
		}
		if err := json.Unmarshal(req.Payload, &inner); err != nil {
			return nil, fmt.Errorf("decode contract: %w", err)
		}
		// Route through Wallet.SatisfyEVM so the same rolling-window
		// spend cap that gates Pay also gates on-chain receipts.
		// Calling EVMMethod().Satisfy directly bypasses the cap and
		// is reserved for tests that explicitly want unchecked signing.
		receipt, err := w.SatisfyEVM(ctx, inner.Contract)
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
			Contract payment.Contract `json:"contract"`
			Receipt  payment.Receipt  `json:"receipt"`
		}
		if err := json.Unmarshal(req.Payload, &inner); err != nil {
			return nil, fmt.Errorf("decode verify args: %w", err)
		}
		method := w.EVMMethod()
		if method == nil {
			return nil, errors.New("wallet.evm.verify: no EVM method bound")
		}
		if err := method.Verify(ctx, inner.Contract, inner.Receipt); err != nil {
			return nil, err
		}
		return encode(EVMVerifyResp{OK: true})
	}
}
