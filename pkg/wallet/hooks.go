package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

// WalletMethod is the wallet's payment.Method implementation. Method ID
// "io.pilot.wallet/v1" — the same ID receivers verify against. The
// payload of a Receipt is the JSON-encoded SignedAuth produced by the
// existing Pay flow.
type WalletMethod struct{ w *Wallet }

// Method returns the wallet's payment.Method binding. The Wallet holds
// no other state; the binding is just a pointer wrapper.
func (w *Wallet) Method() *WalletMethod { return &WalletMethod{w: w} }

// MockMethodID is the canonical ID for the wallet's internal-ledger
// Method — the offline/dev/test backend. The real x402 EVM Method is
// io.pilot.wallet/v1 (see pkg/evm.EVMMethodID); this one is for tests
// and offline flows that don't want to touch any chain.
const MockMethodID = "io.pilot.wallet-mock/v1"

func (m *WalletMethod) ID() string { return MockMethodID }

// Satisfy translates a payment.Contract into the wallet's internal
// Challenge, signs it, and wraps the SignedAuth as a Receipt.
func (m *WalletMethod) Satisfy(_ context.Context, c payment.Contract) (payment.Receipt, error) {
	if !contractMatchesWallet(c) {
		return payment.Receipt{}, payment.ErrCannotSatisfy
	}
	ch := contractToChallenge(c)
	sa, err := m.w.Pay(&ch)
	if err != nil {
		return payment.Receipt{}, fmt.Errorf("wallet method satisfy: %w", err)
	}
	body, err := json.Marshal(sa)
	if err != nil {
		return payment.Receipt{}, fmt.Errorf("wallet method satisfy: marshal: %w", err)
	}
	return payment.Receipt{
		ContractID: c.ID,
		MethodID:   MockMethodID,
		Payload:    body,
	}, nil
}

// Verify decodes the SignedAuth payload and runs the existing wallet
// Verify logic. Stateless — no replay-detection here (the Escrow side
// gates that via consumed-on-redeem).
func (m *WalletMethod) Verify(_ context.Context, c payment.Contract, r payment.Receipt) error {
	if r.MethodID != MockMethodID {
		return fmt.Errorf("wallet method verify: wrong method_id %q", r.MethodID)
	}
	var sa SignedAuth
	if err := json.Unmarshal(r.Payload, &sa); err != nil {
		return fmt.Errorf("wallet method verify: decode signed_auth: %w", err)
	}
	ch := contractToChallenge(c)
	return m.w.Verify(&ch, &sa)
}

// contractMatchesWallet decides whether this WalletMethod can attempt a
// Satisfy. AcceptedMethods (if non-empty) must include MockMethodID. No
// further filtering yet — assets are method-internal (USDC, EUR, …)
// and the Pay path will surface its own ErrInsufficientBalance.
func contractMatchesWallet(c payment.Contract) bool {
	if len(c.AcceptedMethods) == 0 {
		return true
	}
	for _, id := range c.AcceptedMethods {
		if id == MockMethodID {
			return true
		}
	}
	return false
}

func contractToChallenge(c payment.Contract) Challenge {
	return Challenge{
		ID:            c.ID,
		RecipientAddr: Address(c.RecipientAddr),
		Amount:        Amount(c.Amount),
		Asset:         Asset(c.Asset),
		Nonce:         c.Nonce,
		ExpiresAt:     c.ExpiresAt,
		Memo:          c.Memo,
	}
}

// ─── WalletEscrow ──────────────────────────────────────────────────────

// WalletEscrow is the wallet's payment.Escrow implementation. Holds K
// in process memory keyed by contract.ID. Releases on a verified
// Receipt; marks consumed to prevent replay.
//
// One WalletEscrow per Wallet — Wallet.Escrow() returns the canonical
// binding.
type WalletEscrow struct {
	w  *Wallet
	mu sync.Mutex
	// held is the active escrow set. consumed contract IDs are kept in
	// a separate set so a late Redeem produces ErrEscrowConsumed rather
	// than ErrEscrowNotFound.
	held     map[string]heldKey
	consumed map[string]struct{}
}

// Escrow returns the wallet's payment.Escrow binding. Constructed lazily
// the first time it's asked for.
func (w *Wallet) Escrow() *WalletEscrow {
	w.escrowOnce.Do(func() {
		w.escrow = &WalletEscrow{
			w:        w,
			held:     map[string]heldKey{},
			consumed: map[string]struct{}{},
		}
	})
	return w.escrow
}

type heldKey struct {
	K        []byte
	Contract payment.Contract
	HeldAt   time.Time
}

// EscrowID is the canonical ID the wallet's escrow registers under.
const EscrowID = "io.pilot.wallet/escrow-v1"

func (e *WalletEscrow) ID() string { return EscrowID }

// Hold stashes K under the contract's ID. The returned EscrowRef
// includes the wallet's own pilot address as the endpoint a recipient
// would dial to Redeem.
func (e *WalletEscrow) Hold(_ context.Context, c payment.Contract, k []byte) (payment.EscrowRef, error) {
	if c.ID == "" {
		return payment.EscrowRef{}, errors.New("wallet escrow hold: contract id required")
	}
	if len(k) == 0 {
		return payment.EscrowRef{}, errors.New("wallet escrow hold: empty key")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, dup := e.held[c.ID]; dup {
		return payment.EscrowRef{}, fmt.Errorf("wallet escrow hold: contract %s already held", c.ID)
	}
	cp := make([]byte, len(k))
	copy(cp, k)
	e.held[c.ID] = heldKey{K: cp, Contract: c, HeldAt: time.Now()}
	return payment.EscrowRef{
		EscrowID:   EscrowID,
		Endpoint:   string(e.w.addr),
		Token:      c.ID,
		ContractID: c.ID,
	}, nil
}

// Redeem verifies the receipt against the held contract and, on success,
// returns K and marks the contract consumed. A second redeem returns
// ErrEscrowConsumed.
func (e *WalletEscrow) Redeem(ctx context.Context, ref payment.EscrowRef, r payment.Receipt) ([]byte, error) {
	if ref.EscrowID != EscrowID {
		return nil, fmt.Errorf("wallet escrow redeem: wrong escrow_id %q", ref.EscrowID)
	}
	e.mu.Lock()
	if _, dup := e.consumed[ref.ContractID]; dup {
		e.mu.Unlock()
		return nil, payment.ErrEscrowConsumed
	}
	h, ok := e.held[ref.ContractID]
	if !ok {
		e.mu.Unlock()
		return nil, payment.ErrEscrowNotFound
	}
	e.mu.Unlock()

	// Verify the receipt against the contract via the wallet's own
	// Method. (Other Methods could be plugged in later — for now the
	// wallet only accepts its own method ID for self-held escrow.)
	if err := e.w.Method().Verify(ctx, h.Contract, r); err != nil {
		return nil, fmt.Errorf("wallet escrow redeem: verify: %w", err)
	}

	// Note: we don't call Settle here — that flow expects the recipient
	// to have issued the challenge, but in the paywall scheme the
	// *sender* issued it. We just credit balance from the contract.
	// (For MVP we accept the receipt's signature as enough; the actual
	// balance bookkeeping happens via Settle in non-paywall flows. A
	// later tick can fold both into one path.)

	e.mu.Lock()
	delete(e.held, ref.ContractID)
	e.consumed[ref.ContractID] = struct{}{}
	k := make([]byte, len(h.K))
	copy(k, h.K)
	// Zero the held copy for hygiene.
	for i := range h.K {
		h.K[i] = 0
	}
	e.mu.Unlock()
	return k, nil
}

// HeldCount returns the number of active (not-yet-redeemed) escrowed
// keys. Useful for tests and operator observability.
func (e *WalletEscrow) HeldCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.held)
}

// ─── Hook callbacks ────────────────────────────────────────────────────

// HookPreSendMessage is the wallet's contribution to send-message.pre.
// When args["paywall"] is set, it transforms args["data"] (base64) into
// a SealedEnvelope (also base64) and stashes K in the wallet's Escrow.
// When args["paywall"] is empty or missing the args pass through.
//
// args is shaped by the caller (the daemon's send-message primitive
// wrapper):
//
//	{
//	  "peer":   "<pilot addr>",
//	  "data":   "<base64 plaintext body>",
//	  "paywall": "100 USDC",                  // optional
//	  "method":  "io.pilot.wallet/v1",        // optional
//	  "escrow":  "io.pilot.wallet/escrow-v1", // optional
//	  "memo":    "...",                       // optional
//	}
//
// Returned args mutate "data" (now a SealedEnvelope) and add
// "paywalled": true and "contract_id": "<id>".
func (w *Wallet) HookPreSendMessage(ctx context.Context, args map[string]any) (map[string]any, error) {
	spec, _ := args["paywall"].(string)
	if strings.TrimSpace(spec) == "" {
		return args, nil
	}

	peerStr, _ := args["peer"].(string)
	if peerStr == "" {
		return nil, errors.New("paywall: peer addr required")
	}
	plaintextB64, _ := args["data"].(string)
	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("paywall: data not base64: %w", err)
	}

	amount, asset, err := parsePaywallSpec(spec)
	if err != nil {
		return nil, err
	}

	methodID, _ := args["method"].(string)
	if methodID == "" {
		methodID = MockMethodID
	}
	escrowID, _ := args["escrow"].(string)
	if escrowID == "" {
		escrowID = EscrowID
	}
	memo, _ := args["memo"].(string)

	contractID, err := randHex(16)
	if err != nil {
		return nil, fmt.Errorf("paywall: contract id: %w", err)
	}
	nonce, err := randHex(16)
	if err != nil {
		return nil, fmt.Errorf("paywall: nonce: %w", err)
	}
	contract := payment.Contract{
		ID:              contractID,
		Amount:          uint64(amount),
		Asset:           string(asset),
		RecipientAddr:   peerStr,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Nonce:           nonce,
		AcceptedMethods: []string{methodID},
		AcceptedEscrows: []string{escrowID},
		Memo:            memo,
	}

	// Seal the body. Default chacha20-poly1305; AD binds the contract
	// metadata so a tampered envelope decrypts to garbage (rejected by
	// the AEAD).
	seal := payment.DefaultSeal()
	K, err := payment.RandomKey(seal)
	if err != nil {
		return nil, err
	}
	sealNonce, err := payment.RandomNonce(seal)
	if err != nil {
		return nil, err
	}
	ad, err := canonicalContractAD(contract)
	if err != nil {
		return nil, err
	}
	ciphertext, err := seal.Encrypt(plaintext, K, sealNonce, ad)
	if err != nil {
		return nil, fmt.Errorf("paywall: encrypt: %w", err)
	}

	ref, err := w.Escrow().Hold(ctx, contract, K)
	if err != nil {
		return nil, fmt.Errorf("paywall: hold: %w", err)
	}

	env := payment.SealedEnvelope{
		Contract:   contract,
		EscrowRef:  ref,
		SealID:     seal.ID(),
		Ciphertext: ciphertext,
		Nonce:      sealNonce,
		SenderAddr: string(w.addr),
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("paywall: marshal envelope: %w", err)
	}

	out := cloneArgs(args)
	out["data"] = base64.StdEncoding.EncodeToString(envBytes)
	out["paywalled"] = true
	out["contract_id"] = contractID
	return out, nil
}

// HookPostRecvMessage is the wallet's contribution to recv.post. If the
// incoming body parses as a SealedEnvelope, it tags args with
// "sealed":true and surfaces contract_id + the EscrowRef so the
// recipient can decide whether to redeem. The body itself is left in
// place — redemption is a separate, explicit step.
func (w *Wallet) HookPostRecvMessage(_ context.Context, args map[string]any) (map[string]any, error) {
	dataB64, _ := args["data"].(string)
	if dataB64 == "" {
		return args, nil
	}
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return args, nil
	}
	var env payment.SealedEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return args, nil
	}
	if env.Contract.ID == "" || env.SealID == "" || len(env.Ciphertext) == 0 {
		return args, nil
	}

	out := cloneArgs(args)
	out["sealed"] = true
	out["contract_id"] = env.Contract.ID
	out["contract_amount"] = env.Contract.Amount
	out["contract_asset"] = env.Contract.Asset
	out["escrow_id"] = env.EscrowRef.EscrowID
	out["escrow_endpoint"] = env.EscrowRef.Endpoint
	return out, nil
}

// ─── helpers ───────────────────────────────────────────────────────────

func cloneArgs(a map[string]any) map[string]any {
	out := make(map[string]any, len(a))
	for k, v := range a {
		out[k] = v
	}
	return out
}

// parsePaywallSpec parses "100 USDC" → (100, USDC). Accepts amount and
// asset separated by any whitespace; rejects empty or mismatched.
func parsePaywallSpec(s string) (Amount, Asset, error) {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("paywall: spec %q must be '<amount> <asset>'", s)
	}
	n, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("paywall: amount %q: %w", parts[0], err)
	}
	if n == 0 {
		return 0, "", errors.New("paywall: amount must be > 0")
	}
	return Amount(n), Asset(parts[1]), nil
}

// canonicalContractAD returns a stable byte representation of the
// contract for AEAD associated-data. Tampering with any contract field
// changes the AD and breaks decryption.
func canonicalContractAD(c payment.Contract) ([]byte, error) {
	// json.Marshal of the Contract gives us a deterministic-enough AD
	// for now; per the architecture's signing-canonical-form notes we
	// would normalize ordering for a long-term wire commitment. For the
	// MVP we tolerate Go's default field order because contracts are
	// re-marshalled on both sides from the same Contract struct.
	return json.Marshal(c)
}
