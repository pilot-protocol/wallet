package wallet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pilot-protocol/wallet/pkg/settlerclient"
)

// ErrInsufficientBalance is returned when a Pay would drive the balance below zero.
var ErrInsufficientBalance = errors.New("insufficient balance")

// ErrChallengeExpired is returned when a Challenge's ExpiresAt is in the past.
var ErrChallengeExpired = errors.New("challenge expired")

// ErrChallengeMismatch is returned when a SignedAuth does not match the Challenge
// it claims to authorize (any field disagrees).
var ErrChallengeMismatch = errors.New("challenge mismatch")

// ErrBadSignature is returned when ed25519.Verify fails on a SignedAuth.
var ErrBadSignature = errors.New("bad signature")

// ErrAlreadySettled is returned when Settle is called twice for the same challenge.
var ErrAlreadySettled = errors.New("challenge already settled")

// ErrUnknownChallenge is returned when Settle references a challenge the wallet didn't issue.
var ErrUnknownChallenge = errors.New("unknown challenge")

// ErrSpendCapExceeded is returned by Pay when the requested amount
// would push the rolling-window spend total for the asset over the
// wallet's configured SpendCap. Includes the relevant cap parameters
// in the error string so the caller can show the user "you've used
// 90 of 100 USDC today; this 20-USDC payment would exceed it".
var ErrSpendCapExceeded = errors.New("spend cap exceeded")

// Wallet is the local state for one installed `io.pilot.wallet`. Each
// user-host pair runs exactly one. Ledger persistence flows through the
// Store; Wallet itself is stateless beyond the address + signer + clock
// + the lazily-constructed Escrow + the optional EVM binding.
//
// The wallet hosts two payment.Method implementations side by side:
//
//   - WalletMethod (id "io.pilot.wallet-mock/v1") — internal ledger
//     backed by the Ed25519 signer; used for tests and offline flows.
//
//   - WalletEVMMethod (id "io.pilot.wallet/v1") — real x402 EIP-3009
//     authorizations signed by the EVM signer; on-chain-verifiable.
//
// The EVM binding is optional: construct with NewWithEVM to enable it,
// or stick with New for an internal-ledger-only wallet.
type Wallet struct {
	addr   Address
	signer Signer
	store  Store
	clock  func() time.Time

	// escrow is the wallet's payment.Escrow binding, lazily created on
	// first Wallet.Escrow() call.
	escrowOnce sync.Once
	escrow     *WalletEscrow

	// evm holds the (optional) primary on-chain wallet state. nil when
	// the wallet was constructed without an EVM signer. The primary
	// binding is reported by the parameterless legacy accessors
	// (EVMAddress / EVMChainID / EVMBalance) so single-chain callers
	// keep working unchanged. Multichain callers either iterate
	// evmByChain or pass an explicit chainID to the parameterised
	// siblings. Concrete type lives in hooks_evm.go.
	evm *evmBinding

	// evmByChain is the multichain registry: chainID → binding.
	// Always includes evm (the primary) when evm != nil. Nil when no
	// EVM support is configured. Built once at construction in
	// NewWithEVMs and read-only after that, so no mutex needed.
	evmByChain map[uint64]*evmBinding

	// settler is the (optional) client for the canonical credit-
	// ledger service. nil = wallet runs in local-only mode (the
	// existing internal sqlite ledger is authoritative for "balance"
	// / "pay" / "settle"). When set, wallet.settler.* IPC methods
	// route their queries + signed transfers through this client.
	settler *settlerclient.Client

	// Spend cap state — declared in spendcap.go, fields here for
	// embedding so the cap check + recordSpend can stay atomic via
	// one mutex. capMu guards both `caps` and `spendLog`. Both are
	// zero-value-correct (no caps, empty log) so existing callers
	// of New() get the no-cap behavior preserved.
	capMu         sync.Mutex
	caps          []SpendCap
	spendLog      []spendRecord
	capStateFile  string // when set, recordSpendLocked also appends a JSONL line here so caps survive wallet restart
}

// New returns a wallet bound to a pilot address, a signer, and a Store.
// Caller owns the Store; call wallet.Close() to release it.
func New(addr Address, signer Signer, store Store) *Wallet {
	return &Wallet{
		addr:   addr,
		signer: signer,
		store:  store,
		clock:  time.Now,
	}
}

// NewInMemory is a convenience constructor that backs the wallet with a
// fresh memory store. Useful for tests and short-lived contexts.
func NewInMemory(addr Address, signer Signer) *Wallet {
	return New(addr, signer, NewMemoryStore())
}

// Close releases the backing Store.
func (w *Wallet) Close() error { return w.store.Close() }

// Address returns the wallet's pilot address.
func (w *Wallet) Address() Address { return w.addr }

// Balance returns the current balance for an asset. Unknown assets return 0.
func (w *Wallet) Balance(a Asset) Amount {
	bal, _ := w.store.Balance(a)
	return bal
}

// Balances returns a snapshot of all non-zero asset balances.
func (w *Wallet) Balances() map[Asset]Amount {
	bs, _ := w.store.Balances()
	if bs == nil {
		return map[Asset]Amount{}
	}
	return bs
}

// Request issues a new payment Challenge and persists it so a later Settle
// can confirm the wallet actually issued it.
func (w *Wallet) Request(amount Amount, asset Asset, expiresIn time.Duration, memo string) (*Challenge, error) {
	if amount == 0 {
		return nil, errors.New("amount must be > 0")
	}
	if asset == "" {
		return nil, errors.New("asset required")
	}
	if expiresIn <= 0 {
		return nil, errors.New("expiresIn must be > 0")
	}
	nonce, err := randHex(16)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	id, err := randHex(16)
	if err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	ch := &Challenge{
		ID:            id,
		RecipientAddr: w.addr,
		Amount:        amount,
		Asset:         asset,
		Nonce:         nonce,
		ExpiresAt:     w.clock().Add(expiresIn),
		Memo:          memo,
	}
	if err := w.store.SaveIssued(ch); err != nil {
		return nil, fmt.Errorf("persist issued: %w", err)
	}
	return ch, nil
}

// Pay accepts a Challenge from a payer's perspective: signs the canonical
// bytes, debits the local balance, appends a history row, and returns a
// SignedAuth the recipient can verify.
//
// The signature is computed before the debit; on ErrInsufficientBalance the
// signature is discarded (never returned). Pay's mutation is atomic via the
// Store's RecordPay.
func (w *Wallet) Pay(ch *Challenge) (*SignedAuth, error) {
	if ch == nil {
		return nil, errors.New("nil challenge")
	}
	if w.clock().After(ch.ExpiresAt) {
		return nil, ErrChallengeExpired
	}
	// Enforce manifest-declared rolling-window spend caps before
	// signing. Holding capMu through the recordSpendLocked call
	// below keeps the check + record atomic against concurrent Pay
	// calls; the Store's RecordPay is also atomic, but if that
	// fails we never call recordSpendLocked (so the cap usage
	// stays consistent with the ledger).
	w.capMu.Lock()
	if err := w.checkSpendCapLocked(ch.Asset, ch.Amount); err != nil {
		w.capMu.Unlock()
		return nil, err
	}

	canon := canonicalBytes(ch, w.addr)
	sig, err := w.signer.Sign(canon)
	if err != nil {
		w.capMu.Unlock()
		return nil, fmt.Errorf("sign: %w", err)
	}

	txID, _ := randHex(16)
	tx := Transaction{
		ID:          txID,
		Timestamp:   w.clock(),
		Kind:        TxPay,
		Asset:       ch.Asset,
		Amount:      ch.Amount,
		PeerAddr:    ch.RecipientAddr,
		ChallengeID: ch.ID,
		Memo:        ch.Memo,
	}
	if err := w.store.RecordPay(tx); err != nil {
		w.capMu.Unlock()
		return nil, err
	}
	w.recordSpendLocked(ch.Asset, ch.Amount)
	w.capMu.Unlock()

	return &SignedAuth{
		ChallengeID:   ch.ID,
		PayerAddr:     w.addr,
		PayerPubkey:   w.signer.PublicKey(),
		Amount:        ch.Amount,
		Asset:         ch.Asset,
		Nonce:         ch.Nonce,
		ExpiresAt:     ch.ExpiresAt,
		RecipientAddr: ch.RecipientAddr,
		Signature:     sig,
	}, nil
}

// Verify checks a SignedAuth against the Challenge it claims to satisfy.
// Returns nil on a valid pair, a typed error otherwise. Does not mutate
// any state — call Settle to commit.
func (w *Wallet) Verify(ch *Challenge, sa *SignedAuth) error {
	if ch == nil || sa == nil {
		return errors.New("nil challenge or signed_auth")
	}
	if w.clock().After(ch.ExpiresAt) {
		return ErrChallengeExpired
	}
	if sa.ChallengeID != ch.ID ||
		sa.Amount != ch.Amount ||
		sa.Asset != ch.Asset ||
		sa.Nonce != ch.Nonce ||
		!sa.ExpiresAt.Equal(ch.ExpiresAt) ||
		sa.RecipientAddr != ch.RecipientAddr {
		return ErrChallengeMismatch
	}
	if len(sa.PayerPubkey) != ed25519.PublicKeySize || len(sa.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	canon := canonicalBytes(ch, sa.PayerAddr)
	if !ed25519.Verify(ed25519.PublicKey(sa.PayerPubkey), canon, sa.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Settle credits the recipient's balance for a previously-issued, verified
// Challenge. Idempotent-fail: a second call with the same ChallengeID
// returns ErrAlreadySettled, never a double credit.
func (w *Wallet) Settle(ch *Challenge, sa *SignedAuth) (*Transaction, error) {
	if err := w.Verify(ch, sa); err != nil {
		return nil, err
	}

	txID, _ := randHex(16)
	tx := Transaction{
		ID:          txID,
		Timestamp:   w.clock(),
		Kind:        TxReceive,
		Asset:       ch.Asset,
		Amount:      ch.Amount,
		PeerAddr:    sa.PayerAddr,
		ChallengeID: ch.ID,
		Memo:        ch.Memo,
	}
	if err := w.store.RecordSettle(tx, ch.ID); err != nil {
		return nil, err
	}
	return &tx, nil
}

// Topup credits the wallet from an external source. In the integrated
// runtime this is gated by a `wallet.topup:<source>` grant (e.g. only the
// settlement notary affiliate, or only `dev:faucet` in test mode); the
// wallet layer accepts unconditionally and the daemon enforces.
func (w *Wallet) Topup(asset Asset, amount Amount, source string) (*Transaction, error) {
	if amount == 0 {
		return nil, errors.New("amount must be > 0")
	}
	if asset == "" {
		return nil, errors.New("asset required")
	}
	if source == "" {
		return nil, errors.New("source required")
	}
	txID, _ := randHex(16)
	tx := Transaction{
		ID:        txID,
		Timestamp: w.clock(),
		Kind:      TxTopup,
		Asset:     asset,
		Amount:    amount,
		Source:    source,
	}
	if err := w.store.RecordTopup(tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

// History returns ledger entries in newest-first order, filtered as
// requested. A zero filter returns everything.
func (w *Wallet) History(f HistoryFilter) []Transaction {
	out, _ := w.store.History(f)
	return out
}

// canonicalBytes is the message the payer signs and the recipient verifies.
// Order matters and must be stable — any change is a wire-incompatibility.
//
// Layout (all big-endian, length-prefixed where variable):
//   challenge_id || amount(uint64) || asset || nonce || expires_at(unix nano int64)
//   || recipient_addr || payer_addr
func canonicalBytes(ch *Challenge, payer Address) []byte {
	var buf bytes.Buffer
	writeLP := func(s string) {
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(s)))
		buf.WriteString(s)
	}
	writeLP(ch.ID)
	_ = binary.Write(&buf, binary.BigEndian, uint64(ch.Amount))
	writeLP(string(ch.Asset))
	writeLP(ch.Nonce)
	_ = binary.Write(&buf, binary.BigEndian, ch.ExpiresAt.UnixNano())
	writeLP(string(ch.RecipientAddr))
	writeLP(string(payer))
	return buf.Bytes()
}

func sortHistoryDesc(txs []Transaction) {
	sort.Slice(txs, func(i, j int) bool { return txs[i].Timestamp.After(txs[j].Timestamp) })
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
