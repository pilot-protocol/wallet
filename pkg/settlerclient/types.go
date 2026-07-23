// SPDX-License-Identifier: AGPL-3.0-or-later

package settlerclient

import "time"

// Signer is the minimal interface the client needs from the wallet's
// signing primitive. wallet.Wallet's Signer field already matches it,
// so a wallet that wants to relay through the settler does
// `client.Transfer(ctx, walletSigner, ...)` directly.
type Signer interface {
	PublicKey() []byte
	Sign(msg []byte) ([]byte, error)
}

// Wire shapes mirror settler/pkg/settlerapi/api.go. Duplicated here
// to keep the client package free of a hard dependency on the
// settler repo — adding a go.mod require for it would couple every
// wallet build to the settler's release cadence.

type IdentityResp struct {
	SettlerPubkey  string `json:"settler_pubkey"`
	HasOperator    bool   `json:"has_operator"`
	OperatorPubkey string `json:"operator_pubkey,omitempty"`
}

type BalanceReq struct {
	Account string `json:"account"`
	Asset   string `json:"asset"`
}

type BalanceResp struct {
	Account string `json:"account"`
	Asset   string `json:"asset"`
	Amount  uint64 `json:"amount"`
}

type TransferAuth struct {
	PayerPubkey string    `json:"payer_pubkey"`
	To          string    `json:"to"`
	Asset       string    `json:"asset"`
	Amount      uint64    `json:"amount"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
	Signature   string    `json:"signature"`
}

type TransferReq struct {
	Auth TransferAuth `json:"auth"`
}

type TransferResp struct {
	Transaction Transaction `json:"transaction"`
}

type HistoryReq struct {
	Account string `json:"account"`
	Limit   int    `json:"limit,omitempty"`
}

type HistoryResp struct {
	Transactions []Transaction `json:"transactions"`
}

// Transaction is one row of the settler's audit log.
type Transaction struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Asset      string    `json:"asset"`
	Amount     uint64    `json:"amount"`
	From       string    `json:"from,omitempty"`
	To         string    `json:"to"`
	Nonce      string    `json:"nonce,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	OperatorOK bool      `json:"operator_ok,omitempty"`
}
