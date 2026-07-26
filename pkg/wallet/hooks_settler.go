// SPDX-License-Identifier: AGPL-3.0-or-later

package wallet

import (
	"context"
	"errors"
	"time"

	"github.com/pilot-protocol/wallet/pkg/settlerclient"
)

// SetSettler installs a settler client on the wallet. Called once
// at startup; passing nil disables every wallet.settler.* method.
// The wallet does NOT take ownership of the client beyond holding a
// reference — concurrent use across goroutines is safe because
// the settlerclient.Client opens a fresh TCP connection per call.
func (w *Wallet) SetSettler(c *settlerclient.Client) {
	w.settler = c
}

// HasSettler reports whether the wallet was configured with a
// settler client.
func (w *Wallet) HasSettler() bool { return w.settler != nil }

// Settler returns the configured client (or nil).
func (w *Wallet) Settler() *settlerclient.Client { return w.settler }

// SettlerBalance returns this wallet's own balance at the settler.
// The wallet's ed25519 pubkey identifies the account; assetSymbol
// (e.g. "USDC") selects the per-asset ledger.
func (w *Wallet) SettlerBalance(ctx context.Context, assetSymbol string) (uint64, error) {
	if w.settler == nil {
		return 0, errors.New("wallet.settler: no settler configured")
	}
	return w.settler.Balance(ctx, w.signer.PublicKey(), assetSymbol)
}

// SettlerHistory returns this wallet's recent ledger activity.
// Passing limit=0 falls back to the settler's default (100).
func (w *Wallet) SettlerHistory(ctx context.Context, limit int) ([]settlerclient.Transaction, error) {
	if w.settler == nil {
		return nil, errors.New("wallet.settler: no settler configured")
	}
	return w.settler.History(ctx, w.signer.PublicKey(), limit)
}

// SettlerTransfer signs a TransferAuth with this wallet's key and
// submits it to the settler. The settler verifies the signature
// against this wallet's pubkey before debiting.
func (w *Wallet) SettlerTransfer(
	ctx context.Context,
	to []byte,
	asset string,
	amount uint64,
	memo string,
	expiresIn time.Duration,
) (settlerclient.Transaction, error) {
	if w.settler == nil {
		return settlerclient.Transaction{}, errors.New("wallet.settler: no settler configured")
	}
	a := Asset(asset)
	amt := Amount(amount)

	// Check and claim the budget in one capMu acquisition, then drop
	// the lock for the settler round-trip so a slow or hung settler
	// doesn't stall every other cap-gated path on this wallet. The
	// reservation keeps the check-then-record pair atomic: it already
	// counts against the cap, so a concurrent caller can't be granted
	// budget this transfer is holding.
	w.capMu.Lock()
	if err := w.checkSpendCapLocked(a, amt); err != nil {
		w.capMu.Unlock()
		return settlerclient.Transaction{}, err
	}
	reservation := w.reserveSpendLocked(a, amt)
	w.capMu.Unlock()

	tx, err := w.settler.Transfer(ctx, w.signer, to, asset, amount, memo, expiresIn)

	w.capMu.Lock()
	w.releaseReservationLocked(reservation)
	if err == nil {
		// Settled: convert the reservation into a permanent (and, when
		// a cap-state file is configured, durable) record.
		w.recordSpendLocked(a, amt)
	}
	w.capMu.Unlock()

	if err != nil {
		return settlerclient.Transaction{}, err
	}
	return tx, nil
}

// SettlerIdentity asks the settler for its self-declared identity.
func (w *Wallet) SettlerIdentity(ctx context.Context) (settlerclient.IdentityResp, error) {
	if w.settler == nil {
		return settlerclient.IdentityResp{}, errors.New("wallet.settler: no settler configured")
	}
	return w.settler.Identity(ctx)
}

// SignerPublicKey returns the wallet's own ed25519 pubkey. Used by
// the IPC dispatcher when constructing settler queries — the wallet
// is its pubkey, so callers shouldn't have to thread it through
// every request.
func (w *Wallet) SignerPublicKey() []byte {
	return w.signer.PublicKey()
}
