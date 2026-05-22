// Package wallet implements the io.pilot.wallet app — an agent-native
// payment rail in the x402 shape. Plugs into the daemon's broker via IPC
// once the runtime is integrated; standalone-runnable for tests.
package wallet

import "time"

// Asset is an opaque currency tag. The wallet does not interpret the value;
// the publisher decides what assets it supports (e.g. "USDC", "USD", "ETH").
type Asset string

// Amount is in minor units (cents for USD/USDC, wei for ETH, etc.). uint64
// gives us plenty of headroom and rules out negative balances at the type
// level — debits are subtracted, errors flagged if overflow.
type Amount uint64

// Address is a pilot 48-bit address in canonical text form
// ("N:NNNN.HHHH.LLLL"). Opaque to the wallet — handed in by the caller.
type Address string

// Challenge is what a recipient issues to ask for payment. Sent to the
// payer out of band (typically as the body of an HTTP 402). The recipient
// keeps a copy keyed by ID so it can match an incoming SignedAuth.
type Challenge struct {
	ID            string    `json:"id"`
	RecipientAddr Address   `json:"recipient_addr"`
	Amount        Amount    `json:"amount"`
	Asset         Asset     `json:"asset"`
	Nonce         string    `json:"nonce"`
	ExpiresAt     time.Time `json:"expires_at"`
	Memo          string    `json:"memo,omitempty"`
}

// SignedAuth is what the payer returns: a signature, by the payer's
// per-purpose key, over the canonical encoding of the Challenge plus the
// payer's address. The recipient verifies locally — no round-trip needed.
type SignedAuth struct {
	ChallengeID   string    `json:"challenge_id"`
	PayerAddr     Address   `json:"payer_addr"`
	PayerPubkey   []byte    `json:"payer_pubkey"`
	Amount        Amount    `json:"amount"`
	Asset         Asset     `json:"asset"`
	Nonce         string    `json:"nonce"`
	ExpiresAt     time.Time `json:"expires_at"`
	RecipientAddr Address   `json:"recipient_addr"`
	Signature     []byte    `json:"signature"`
}

// TxKind enumerates the directions a transaction can take in the local ledger.
type TxKind string

const (
	TxPay     TxKind = "pay"     // outbound: payer debits
	TxReceive TxKind = "receive" // inbound: recipient credits
	TxTopup   TxKind = "topup"   // inbound: balance bump from an external source
)

// Transaction is a single ledger entry. The wallet keeps these as an
// append-only history; they are what `wallet.history` returns.
type Transaction struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Kind        TxKind    `json:"kind"`
	Asset       Asset     `json:"asset"`
	Amount      Amount    `json:"amount"`
	PeerAddr    Address   `json:"peer_addr,omitempty"`
	ChallengeID string    `json:"challenge_id,omitempty"`
	Source      string    `json:"source,omitempty"` // for topups: where the funds came from
	Memo        string    `json:"memo,omitempty"`
}

// Signer abstracts the actual signing key. In production this is backed by
// the daemon's `key.sign(purpose, payload)` IPC call against the wallet's
// HKDF-derived `pilot/app/io.pilot.wallet/sign/x402-auth` subkey. In tests
// it's a local Ed25519 keypair.
type Signer interface {
	// PublicKey returns the 32-byte Ed25519 public key the receiver will
	// use to verify signatures produced here.
	PublicKey() []byte
	// Sign returns the 64-byte Ed25519 signature over msg.
	Sign(msg []byte) ([]byte, error)
}

// HistoryFilter narrows what History returns.
//
// Since and Before form an open interval (Since, Before) on the
// transaction timestamp: Since includes txs at-or-after; Before
// includes txs strictly-before. For cursor-style pagination
// (newest-first), callers pass Before = oldest-tx-on-prior-page to
// fetch the next older page.
type HistoryFilter struct {
	Limit  int
	Since  time.Time
	Before time.Time
	Asset  Asset  // empty = all
	Kind   TxKind // empty = all
}
