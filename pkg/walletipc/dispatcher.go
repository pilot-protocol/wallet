package walletipc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/wallet/pkg/wallet"
)

// NewDispatcher returns an ipc.Dispatcher with every wallet.* method bound
// to the given wallet. Hand it to ipc.Serve.
//
// When the wallet was constructed with EVM support (via NewWithEVM),
// the wallet.evm.* methods are also registered. Otherwise they're
// absent and callers get a clean "method not found" reply.
func NewDispatcher(w *wallet.Wallet) *ipc.Dispatcher {
	d := ipc.NewDispatcher()
	d.Register(MethodBalance, balanceHandler(w))
	d.Register(MethodBalances, balancesHandler(w))
	d.Register(MethodAddress, addressHandler(w))
	d.Register(MethodSpendCaps, spendCapsHandler(w))
	d.Register(MethodRequest, requestHandler(w))
	d.Register(MethodPay, payHandler(w))
	d.Register(MethodVerify, verifyHandler(w))
	d.Register(MethodSettle, settleHandler(w))
	d.Register(MethodTopup, topupHandler(w))
	d.Register(MethodHistory, historyHandler(w))
	RegisterEVM(d, w)
	RegisterSettler(d, w)
	return d
}

func balanceHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var args BalanceReq
		if err := decode(req, &args); err != nil {
			return nil, err
		}
		return encode(BalanceResp{Asset: args.Asset, Amount: w.Balance(args.Asset)})
	}
}

// spendCapsHandler returns the wallet's currently-configured caps
// alongside their live rolling-window usage. Mirrors what
// `pilotctl appstore caps <id>` shows but goes through the running
// wallet so UIs see in-memory state (the on-disk cap-state.jsonl is
// the durable backstop; this is the cheap real-time read).
func spendCapsHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
		caps := w.SpendCaps()
		out := make([]SpendCapUsage, 0, len(caps))
		for _, c := range caps {
			used := w.SpentInWindow(c.Asset, c.Window)
			out = append(out, SpendCapUsage{
				Asset:        c.Asset,
				Target:       c.Target,
				Limit:        c.Limit,
				WindowSec:    int64(c.Window.Seconds()),
				Used:         used,
				RemainingRaw: int64(c.Limit) - int64(used),
			})
		}
		return encode(SpendCapsResp{Caps: out})
	}
}

func balancesHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
		bs := w.Balances()
		if bs == nil {
			bs = map[wallet.Asset]wallet.Amount{}
		}
		return encode(BalancesResp{Balances: bs})
	}
}

func addressHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
		return encode(AddressResp{Address: w.Address()})
	}
}

func requestHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var args RequestReq
		if err := decode(req, &args); err != nil {
			return nil, err
		}
		if args.ExpiresInSeconds <= 0 {
			return nil, fmt.Errorf("expires_in_seconds must be > 0")
		}
		ch, err := w.Request(args.Amount, args.Asset, time.Duration(args.ExpiresInSeconds)*time.Second, args.Memo)
		if err != nil {
			return nil, err
		}
		return encode(RequestResp{Challenge: ch})
	}
}

func payHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var args PayReq
		if err := decode(req, &args); err != nil {
			return nil, err
		}
		sa, err := w.Pay(args.Challenge)
		if err != nil {
			return nil, err
		}
		return encode(PayResp{SignedAuth: sa})
	}
}

func verifyHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var args VerifyReq
		if err := decode(req, &args); err != nil {
			return nil, err
		}
		if err := w.Verify(args.Challenge, args.SignedAuth); err != nil {
			return nil, err
		}
		return encode(VerifyResp{OK: true})
	}
}

func settleHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var args SettleReq
		if err := decode(req, &args); err != nil {
			return nil, err
		}
		tx, err := w.Settle(args.Challenge, args.SignedAuth)
		if err != nil {
			return nil, err
		}
		return encode(SettleResp{Transaction: tx})
	}
}

func topupHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var args TopupReq
		if err := decode(req, &args); err != nil {
			return nil, err
		}
		tx, err := w.Topup(args.Asset, args.Amount, args.Source)
		if err != nil {
			return nil, err
		}
		return encode(TopupResp{Transaction: tx})
	}
}

func historyHandler(w *wallet.Wallet) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var args HistoryReq
		if err := decode(req, &args); err != nil {
			return nil, err
		}
		f := wallet.HistoryFilter{
			Limit: args.Limit,
			Asset: args.Asset,
			Kind:  args.Kind,
		}
		if args.SinceUnixNano > 0 {
			f.Since = time.Unix(0, args.SinceUnixNano)
		}
		if args.BeforeUnixNano > 0 {
			f.Before = time.Unix(0, args.BeforeUnixNano)
		}
		return encode(HistoryResp{Transactions: w.History(f)})
	}
}

// decode unmarshals req.Payload into out. Empty payload is valid and
// leaves out at its zero value.
func decode(req *ipc.Envelope, out any) error {
	if len(req.Payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(req.Payload, out); err != nil {
		return fmt.Errorf("decode %s args: %w", req.Method, err)
	}
	return nil
}

// encode marshals v as the reply payload.
func encode(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode reply: %w", err)
	}
	return b, nil
}
