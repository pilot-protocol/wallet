// Package settlerclient is the wallet's thin client for the
// pilot-protocol/settler credit-ledger service.
//
// The settler holds the canonical balances. A wallet that wants to:
//
//   - move credits to another agent → produce a signed TransferAuth
//     locally with its own ed25519 key, submit to the settler over
//     TCP, wait for the transaction id.
//   - read its own balance → ledger.balance over the same TCP socket.
//   - see history → ledger.history.
//
// The client speaks the same length-prefixed JSON envelope used by
// app-store/pkg/ipc (see ipc.WriteFrame / ReadFrame). One client
// instance is one short-lived TCP connection per call — simple,
// matches the IPC dispatcher's connection-per-request behaviour, and
// keeps TLS bringup straightforward to add later.
//
// Trust:
//
//   - settlerPubkey is the embedded trust anchor. The client doesn't
//     yet verify settler-signed receipts (the v1 settler doesn't sign
//     responses), but the pubkey lets a caller assert "I'm talking to
//     the settler I expected" via ledger.identity at dial time.
//   - The settler verifies the payer's signature on every transfer,
//     so a mitm can't forge a transfer from your account without
//     your private key.
package settlerclient

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Client targets one settler endpoint. Safe for concurrent use —
// each call dials a fresh TCP connection.
type Client struct {
	endpoint     string        // e.g. "136.113.97.205:9100"
	settlerPub   ed25519.PublicKey
	dialTimeout  time.Duration
	callTimeout  time.Duration
}

// New constructs a client. endpoint must be host:port. settlerPub
// can be nil; when set, VerifyIdentity is the helper that asserts
// the live settler advertises the same pubkey we were configured for.
func New(endpoint string, settlerPub ed25519.PublicKey) *Client {
	return &Client{
		endpoint:    endpoint,
		settlerPub:  settlerPub,
		dialTimeout: 3 * time.Second,
		callTimeout: 8 * time.Second,
	}
}

// Endpoint returns the configured TCP endpoint.
func (c *Client) Endpoint() string { return c.endpoint }

// Identity calls ledger.identity. Returns the settler's advertised
// pubkey, the operator status, and (when present) the operator's
// pubkey. Wallets call this once at startup to verify the trust
// anchor matches.
func (c *Client) Identity(ctx context.Context) (IdentityResp, error) {
	var out IdentityResp
	if err := c.call(ctx, "ledger.identity", nil, &out); err != nil {
		return IdentityResp{}, err
	}
	return out, nil
}

// VerifyIdentity returns nil when the configured settler endpoint
// advertises the embedded trust anchor pubkey. Called once at
// wallet startup to surface a misconfiguration loudly.
func (c *Client) VerifyIdentity(ctx context.Context) error {
	if len(c.settlerPub) != ed25519.PublicKeySize {
		return nil // no trust anchor configured — caller opts in
	}
	resp, err := c.Identity(ctx)
	if err != nil {
		return fmt.Errorf("settler identity probe: %w", err)
	}
	pub, err := hex.DecodeString(resp.SettlerPubkey)
	if err != nil {
		return fmt.Errorf("settler returned malformed pubkey hex: %w", err)
	}
	if !equalPubkey(ed25519.PublicKey(pub), c.settlerPub) {
		return fmt.Errorf("settler pubkey mismatch: anchor=%s live=%s",
			hex.EncodeToString(c.settlerPub), resp.SettlerPubkey)
	}
	return nil
}

// Balance returns the account's current balance for the asset. A
// missing-account error is NOT raised here — the settler returns
// amount=0 for unknown accounts so wallets can poll without
// special-casing first-touch users.
func (c *Client) Balance(ctx context.Context, account ed25519.PublicKey, asset string) (uint64, error) {
	req := BalanceReq{Account: hex.EncodeToString(account), Asset: asset}
	var out BalanceResp
	if err := c.call(ctx, "ledger.balance", req, &out); err != nil {
		return 0, err
	}
	return out.Amount, nil
}

// History returns up to `limit` transactions touching the account.
// Pass limit=0 for the settler's default (100).
func (c *Client) History(ctx context.Context, account ed25519.PublicKey, limit int) ([]Transaction, error) {
	req := HistoryReq{Account: hex.EncodeToString(account), Limit: limit}
	var out HistoryResp
	if err := c.call(ctx, "ledger.history", req, &out); err != nil {
		return nil, err
	}
	return out.Transactions, nil
}

// Transfer signs a TransferAuth with `signer` and submits it. The
// signer must be the ed25519 key whose pubkey is in `from` — the
// settler verifies the signature against the from-key, so passing
// the wrong signer will fail at the settler with ErrBadSignature.
func (c *Client) Transfer(
	ctx context.Context,
	signer Signer,
	to ed25519.PublicKey,
	asset string,
	amount uint64,
	memo string,
	expiresIn time.Duration,
) (Transaction, error) {
	if len(to) != ed25519.PublicKeySize {
		return Transaction{}, errors.New("settler client: to must be a 32-byte ed25519 pubkey")
	}
	if amount == 0 {
		return Transaction{}, errors.New("settler client: amount must be > 0")
	}
	nonce, err := randomNonce()
	if err != nil {
		return Transaction{}, err
	}
	if expiresIn <= 0 {
		expiresIn = 5 * time.Minute
	}
	expiresAt := time.Now().Add(expiresIn).UTC()
	from := signer.PublicKey()
	payload := canonicalTransferPayload(from, to, asset, amount, nonce, expiresAt)
	sig, err := signer.Sign(payload)
	if err != nil {
		return Transaction{}, fmt.Errorf("sign transfer: %w", err)
	}
	auth := TransferAuth{
		PayerPubkey: hex.EncodeToString(from),
		To:          hex.EncodeToString(to),
		Asset:       asset,
		Amount:      amount,
		Nonce:       hex.EncodeToString(nonce),
		ExpiresAt:   expiresAt,
		Signature:   hex.EncodeToString(sig),
	}
	var out TransferResp
	if err := c.call(ctx, "ledger.transfer", TransferReq{Auth: auth}, &out); err != nil {
		return Transaction{}, err
	}
	return out.Transaction, nil
}

// canonicalTransferPayload reproduces the byte layout the settler's
// ledger.TransferAuth.SigningPayload builds. Must stay in lockstep
// with settler/pkg/ledger/signing.go — any field-order or framing
// change there has to land here too. The format is intentionally
// language-agnostic (length-prefixed strings + big-endian integers)
// so a Python or Swift client can reproduce it from first principles.
func canonicalTransferPayload(payerKey, toKey []byte, asset string, amount uint64, nonce []byte, expiresAt time.Time) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, []byte("settler.transfer")...)
	buf = append(buf, 0)
	buf = append(buf, payerKey...)
	buf = append(buf, toKey...)
	buf = appendLP(buf, []byte(asset))
	var amt [8]byte
	binary.BigEndian.PutUint64(amt[:], amount)
	buf = append(buf, amt[:]...)
	buf = appendLP(buf, []byte(hex.EncodeToString(nonce)))
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiresAt.Unix()))
	buf = append(buf, exp[:]...)
	return buf
}

func appendLP(dst, b []byte) []byte {
	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(len(b)))
	dst = append(dst, ln[:]...)
	return append(dst, b...)
}

func equalPubkey(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := range a {
		x |= a[i] ^ b[i]
	}
	return x == 0
}

// ── transport ─────────────────────────────────────────────────────────

// envelope matches the wire shape ipc.Envelope marshals to. We don't
// import app-store/pkg/ipc here to keep the client free of the
// dispatcher's plumbing — the wire format is the only thing we share.
type envelope struct {
	Type    string          `json:"type"`
	ReqID   string          `json:"req_id"`
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// call dials, writes the request frame, reads the reply, decodes the
// payload into out (when non-nil). Errors get surfaced verbatim from
// the settler's `error` field; transport errors are wrapped.
func (c *Client) call(ctx context.Context, method string, args, out any) error {
	deadline := time.Now().Add(c.callTimeout)
	if ctxDl, ok := ctx.Deadline(); ok && ctxDl.Before(deadline) {
		deadline = ctxDl
	}

	dialer := &net.Dialer{Timeout: c.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", c.endpoint)
	if err != nil {
		return fmt.Errorf("settler dial %s: %w", c.endpoint, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	var payload json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("marshal %s args: %w", method, err)
		}
		payload = b
	}
	req := envelope{Type: "req", ReqID: newReqID(), Method: method, Payload: payload}
	if err := writeFrame(conn, req); err != nil {
		return fmt.Errorf("settler write: %w", err)
	}
	resp, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("settler read: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("settler: %s", resp.Error)
	}
	if out != nil && len(resp.Payload) > 0 {
		if err := json.Unmarshal(resp.Payload, out); err != nil {
			return fmt.Errorf("decode %s response: %w", method, err)
		}
	}
	return nil
}

func writeFrame(w io.Writer, env envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func readFrame(r io.Reader) (envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return envelope{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 1<<20 {
		return envelope{}, fmt.Errorf("settler client: bad frame length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return envelope{}, err
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return envelope{}, err
	}
	return env, nil
}
