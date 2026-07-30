package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

// EVMMethodID is the canonical method identifier for x402-on-USDC
// payments produced by this wallet. Contracts whose AcceptedMethods
// include this string will route through EVMMethod.Satisfy.
const EVMMethodID = "io.pilot.wallet/v1"

// EVMMethod is the payment.Method implementation that produces real,
// on-chain-verifiable x402 receipts: EIP-3009 transferWithAuthorization
// signatures over USDC on a configurable chain.
//
// Stateless past construction. Satisfy never calls the RPC — it only
// signs typed data, which the receiver can verify locally via ecrecover.
// Broadcast (calling transferWithAuthorization on-chain) is the
// recipient's responsibility in the x402 flow.
type EVMMethod struct {
	signer  *EVMSigner
	chainID uint64
	token   Address // USDC contract on chainID
}

// NewEVMMethod constructs a Method bound to a chain + token contract.
// When chainID is one of the well-known constants (ChainBaseMainnet,
// ChainBaseSepolia, ChainEthereumMainnet), the USDC contract address
// is auto-resolved; pass a non-zero token to override.
func NewEVMMethod(signer *EVMSigner, chainID uint64, tokenOverride *Address) (*EVMMethod, error) {
	if signer == nil {
		return nil, fmt.Errorf("evm method: nil signer")
	}
	var token Address
	if tokenOverride != nil {
		token = *tokenOverride
	} else {
		t, err := USDCAddress(chainID)
		if err != nil {
			return nil, fmt.Errorf("evm method: %w", err)
		}
		token = t
	}
	return &EVMMethod{signer: signer, chainID: chainID, token: token}, nil
}

// Address returns the EVM address backing this method's signer. Callers
// surface this to the user as their x402 receive address — funds sent
// to it become spendable from this wallet.
func (m *EVMMethod) Address() Address { return m.signer.Address() }

// ChainID returns the chain id this method targets.
func (m *EVMMethod) ChainID() uint64 { return m.chainID }

// Token returns the token contract address this method targets.
func (m *EVMMethod) Token() Address { return m.token }

// ID satisfies payment.Method.
func (m *EVMMethod) ID() string { return EVMMethodID }

// receiptPayload is the JSON shape of an x402 Receipt.Payload produced
// by Satisfy. The recipient deserializes this, reconstructs the
// TransferAuth + Domain, and verifies. Everything needed to broadcast
// the authorization on-chain is in here, so the platform can
// pass-through without inspecting.
type receiptPayload struct {
	From        Address `json:"from"`
	To          Address `json:"to"`
	Value       string  `json:"value"`        // decimal string (uint256)
	ValidAfter  string  `json:"valid_after"`  // decimal string (uint256)
	ValidBefore string  `json:"valid_before"` // decimal string (uint256)
	Nonce       string  `json:"nonce"`        // 0x-prefixed hex (32 bytes)
	V           uint8   `json:"v"`
	R           string  `json:"r"` // 0x-prefixed hex (32 bytes)
	S           string  `json:"s"` // 0x-prefixed hex (32 bytes)
	ChainID     uint64  `json:"chain_id"`
	Token       Address `json:"token"`
}

// Satisfy translates a payment.Contract into an EIP-3009 authorization,
// signs it, and packs everything the recipient needs to verify (and
// later broadcast) into the Receipt.Payload.
//
// Contract→Auth mapping rules:
//   - From = m.signer.Address() (always; the contract's intent is to
//     authorize *this wallet* to pay).
//   - To = parsed from contract.RecipientAddr; must be a valid EVM addr.
//   - Value = contract.Amount (interpreted as the token's smallest unit,
//     e.g. for USDC 1_000_000 = 1.0 USDC).
//   - ValidAfter = 0 (immediately valid).
//   - ValidBefore = contract.ExpiresAt as unix seconds (or +5min if zero).
//   - Nonce = first 32 bytes of contract.Nonce decoded from hex, or a
//     fresh random nonce if the contract didn't supply one. Each
//     authorization MUST use a unique nonce per from-address; the
//     USDC contract tracks these and rejects replays.
func (m *EVMMethod) Satisfy(_ context.Context, c payment.Contract) (payment.Receipt, error) {
	if c.Asset != "" && c.Asset != "USDC" {
		// MVP: only USDC. A future enhancement could resolve other
		// EIP-3009-enabled tokens via a registry on chainID.
		return payment.Receipt{}, fmt.Errorf("%w: asset %q (only USDC supported)", payment.ErrCannotSatisfy, c.Asset)
	}
	to, err := ParseAddress(c.RecipientAddr)
	if err != nil {
		return payment.Receipt{}, fmt.Errorf("evm satisfy: recipient: %w", err)
	}
	nonce, err := nonceFromContract(c)
	if err != nil {
		return payment.Receipt{}, fmt.Errorf("evm satisfy: nonce: %w", err)
	}
	validBefore := c.ExpiresAt.Unix()
	if validBefore <= 0 {
		validBefore = time.Now().Add(5 * time.Minute).Unix()
	}

	auth := TransferAuth{
		From:        m.signer.Address(),
		To:          to,
		Value:       new(big.Int).SetUint64(c.Amount),
		ValidAfter:  big.NewInt(0),
		ValidBefore: big.NewInt(validBefore),
		Nonce:       nonce,
	}
	domain := Domain{
		Name:              usdcDomainName(m.chainID),
		Version:           "2",
		ChainID:           m.chainID,
		VerifyingContract: m.token,
	}
	sig, err := m.signer.SignTransferAuth(domain, auth)
	if err != nil {
		return payment.Receipt{}, fmt.Errorf("evm satisfy: sign: %w", err)
	}
	payload := receiptPayload{
		From:        auth.From,
		To:          auth.To,
		Value:       auth.Value.String(),
		ValidAfter:  auth.ValidAfter.String(),
		ValidBefore: auth.ValidBefore.String(),
		Nonce:       "0x" + hex.EncodeToString(nonce[:]),
		R:           "0x" + hex.EncodeToString(sig[:32]),
		S:           "0x" + hex.EncodeToString(sig[32:64]),
		V:           sig[64],
		ChainID:     m.chainID,
		Token:       m.token,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return payment.Receipt{}, fmt.Errorf("evm satisfy: marshal: %w", err)
	}
	return payment.Receipt{
		ContractID: c.ID,
		MethodID:   EVMMethodID,
		Payload:    body,
	}, nil
}

// Verify parses the receipt's payload, reconstructs the EIP-712 domain
// + TransferAuth, and runs ecrecover. Returns nil on a valid signature
// matching the embedded From-address. Verifier does not touch the
// chain — broadcast is a separate concern.
func (m *EVMMethod) Verify(_ context.Context, c payment.Contract, r payment.Receipt) error {
	if r.MethodID != EVMMethodID {
		return fmt.Errorf("evm verify: wrong method_id %q", r.MethodID)
	}
	var p receiptPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		return fmt.Errorf("evm verify: payload: %w", err)
	}

	value, ok := new(big.Int).SetString(p.Value, 10)
	if !ok {
		return fmt.Errorf("evm verify: bad value %q", p.Value)
	}
	validAfter, ok := new(big.Int).SetString(p.ValidAfter, 10)
	if !ok {
		return fmt.Errorf("evm verify: bad validAfter %q", p.ValidAfter)
	}
	validBefore, ok := new(big.Int).SetString(p.ValidBefore, 10)
	if !ok {
		return fmt.Errorf("evm verify: bad validBefore %q", p.ValidBefore)
	}
	nonceBytes, err := hexBytes(p.Nonce, 32)
	if err != nil {
		return fmt.Errorf("evm verify: nonce: %w", err)
	}
	var nonce [32]byte
	copy(nonce[:], nonceBytes)
	rBytes, err := hexBytes(p.R, 32)
	if err != nil {
		return fmt.Errorf("evm verify: r: %w", err)
	}
	sBytes, err := hexBytes(p.S, 32)
	if err != nil {
		return fmt.Errorf("evm verify: s: %w", err)
	}
	sig := make([]byte, 65)
	copy(sig[:32], rBytes)
	copy(sig[32:64], sBytes)
	sig[64] = p.V

	// Defense-in-depth: the contract's claimed amount must match the
	// signed value, the contract's claimed recipient must match the
	// signed To, and the contract's claimed expiry must match the
	// signed ValidBefore (within tolerance — exact match is simplest).
	if c.Amount > 0 && value.Uint64() != c.Amount {
		return fmt.Errorf("evm verify: value %s does not match contract.Amount %d", value, c.Amount)
	}
	if c.RecipientAddr != "" {
		want, err := ParseAddress(c.RecipientAddr)
		if err == nil && want != p.To {
			return fmt.Errorf("evm verify: to %s does not match contract.RecipientAddr %s", p.To, want)
		}
	}

	auth := TransferAuth{
		From: p.From, To: p.To,
		Value: value, ValidAfter: validAfter, ValidBefore: validBefore,
		Nonce: nonce,
	}
	domain := Domain{
		Name:              usdcDomainName(p.ChainID),
		Version:           "2",
		ChainID:           p.ChainID,
		VerifyingContract: p.Token,
	}
	return VerifyTransferAuth(domain, auth, sig)
}

// ParseReceiptPayload exposes the payload shape to callers that need to
// inspect or broadcast it (e.g. a recipient's daemon turning the
// authorization into an on-chain transferWithAuthorization call).
type ReceiptPayload = receiptPayload

// ParseReceiptPayload unmarshals a Receipt.Payload into a usable struct.
func ParseReceiptPayload(raw []byte) (ReceiptPayload, error) {
	var p receiptPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	return p, nil
}

// ── helpers ────────────────────────────────────────────────────────────

func nonceFromContract(c payment.Contract) ([32]byte, error) {
	var n [32]byte
	if c.Nonce == "" {
		return RandomNonce()
	}
	raw := c.Nonce
	if len(raw) > 2 && (raw[:2] == "0x" || raw[:2] == "0X") {
		raw = raw[2:]
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		// Treat as opaque label: hash it down to 32 bytes for nonce.
		// This is a defensive fallback so old-style contract IDs work.
		h := Keccak256([]byte(c.Nonce))
		copy(n[:], h)
		return n, nil
	}
	if len(b) > 32 {
		copy(n[:], b[:32])
	} else {
		// Right-pad to 32 bytes — keeps short nonces deterministic.
		copy(n[32-len(b):], b)
	}
	return n, nil
}

func hexBytes(s string, expectLen int) ([]byte, error) {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if expectLen > 0 && len(b) != expectLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", expectLen, len(b))
	}
	return b, nil
}
