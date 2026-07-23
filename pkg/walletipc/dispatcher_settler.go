// SPDX-License-Identifier: AGPL-3.0-or-later

package walletipc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/wallet/pkg/wallet"
)

// RegisterSettler adds the wallet.settler.* methods to an existing
// dispatcher when w has a settler client wired. Safe to call on a
// wallet without a settler — it's a no-op.
//
// The wallet's own ed25519 pubkey is implicit on every call: the
// settler keys accounts by pubkey, the wallet IS its pubkey, so
// callers never thread an "account" parameter through.
func RegisterSettler(d *ipc.Dispatcher, w *wallet.Wallet) {
	if !w.HasSettler() {
		return
	}
	d.Register(MethodSettlerIdentity, settlerIdentityHandler(w))
	d.Register(MethodSettlerBalance, settlerBalanceHandler(w))
	d.Register(MethodSettlerHistory, settlerHistoryHandler(w))
	d.Register(MethodSettlerTransfer, settlerTransferHandler(w))
}

func settlerIdentityHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, _ *ipc.Envelope) (json.RawMessage, error) {
		id, err := w.SettlerIdentity(ctx)
		if err != nil {
			return nil, fmt.Errorf("wallet.settler.identity: %w", err)
		}
		ep := ""
		if c := w.Settler(); c != nil {
			ep = c.Endpoint()
		}
		return encode(SettlerIdentityResp{
			Endpoint:       ep,
			SettlerPubkey:  id.SettlerPubkey,
			HasOperator:    id.HasOperator,
			OperatorPubkey: id.OperatorPubkey,
		})
	}
}

func settlerBalanceHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, env *ipc.Envelope) (json.RawMessage, error) {
		var req SettlerBalanceReq
		if len(env.Payload) > 0 {
			if err := json.Unmarshal(env.Payload, &req); err != nil {
				return nil, fmt.Errorf("decode req: %w", err)
			}
		}
		if req.Asset == "" {
			return nil, errors.New("wallet.settler.balance: asset required")
		}
		amt, err := w.SettlerBalance(ctx, req.Asset)
		if err != nil {
			return nil, err
		}
		return encode(SettlerBalanceResp{
			Account: hex.EncodeToString(w.SignerPublicKey()),
			Asset:   req.Asset,
			Amount:  amt,
		})
	}
}

func settlerHistoryHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, env *ipc.Envelope) (json.RawMessage, error) {
		var req SettlerHistoryReq
		if len(env.Payload) > 0 {
			_ = json.Unmarshal(env.Payload, &req)
		}
		rows, err := w.SettlerHistory(ctx, req.Limit)
		if err != nil {
			return nil, err
		}
		out := SettlerHistoryResp{
			Transactions: make([]SettlerTransaction, len(rows)),
		}
		for i, r := range rows {
			out.Transactions[i] = SettlerTransaction{
				ID:         r.ID,
				Kind:       r.Kind,
				Asset:      r.Asset,
				Amount:     r.Amount,
				From:       r.From,
				To:         r.To,
				Nonce:      r.Nonce,
				Timestamp:  r.Timestamp.Format(time.RFC3339Nano),
				OperatorOK: r.OperatorOK,
			}
		}
		return encode(out)
	}
}

func settlerTransferHandler(w *wallet.Wallet) ipc.Handler {
	return func(ctx context.Context, env *ipc.Envelope) (json.RawMessage, error) {
		var req SettlerTransferReq
		if err := json.Unmarshal(env.Payload, &req); err != nil {
			return nil, fmt.Errorf("decode req: %w", err)
		}
		if req.Asset == "" || req.Amount == 0 || req.To == "" {
			return nil, errors.New("wallet.settler.transfer: to, asset and amount > 0 required")
		}
		toBytes, err := hex.DecodeString(req.To)
		if err != nil {
			return nil, fmt.Errorf("to: %w", err)
		}
		var expiresIn time.Duration
		if req.ExpiresInSeconds > 0 {
			expiresIn = time.Duration(req.ExpiresInSeconds) * time.Second
		}
		tx, err := w.SettlerTransfer(ctx, toBytes, req.Asset, req.Amount, req.Memo, expiresIn)
		if err != nil {
			return nil, err
		}
		return encode(SettlerTransferResp{
			Transaction: SettlerTransaction{
				ID:        tx.ID,
				Kind:      tx.Kind,
				Asset:     tx.Asset,
				Amount:    tx.Amount,
				From:      tx.From,
				To:        tx.To,
				Nonce:     tx.Nonce,
				Timestamp: tx.Timestamp.Format(time.RFC3339Nano),
			},
		})
	}
}
