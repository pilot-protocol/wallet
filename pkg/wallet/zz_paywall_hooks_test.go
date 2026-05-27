package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilot-protocol/app-store/pkg/payment"
)

// TestHookPreSendMessage_PassthroughWithoutPaywall covers the early
// return path: when args have no "paywall" key, the hook must return
// the args unchanged and never touch the escrow.
func TestHookPreSendMessage_PassthroughWithoutPaywall(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()

	in := map[string]any{
		"peer": "0:0001.0002.0002",
		"data": base64.StdEncoding.EncodeToString([]byte("hello")),
	}
	out, err := w.HookPreSendMessage(context.Background(), in)
	if err != nil {
		t.Fatalf("HookPreSendMessage: %v", err)
	}
	if _, ok := out["paywalled"]; ok {
		t.Errorf("paywalled flag set on non-paywall args: %v", out)
	}
	if out["data"] != in["data"] {
		t.Errorf("data was mutated on passthrough")
	}
	if w.Escrow().HeldCount() != 0 {
		t.Errorf("escrow was touched on passthrough: HeldCount=%d", w.Escrow().HeldCount())
	}
}

// TestHookPreSendMessage_PassthroughWithBlankPaywall covers the
// whitespace-only spec branch — that should also be a pass-through.
func TestHookPreSendMessage_PassthroughWithBlankPaywall(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()

	in := map[string]any{
		"peer":    "0:0001.0002.0002",
		"data":    base64.StdEncoding.EncodeToString([]byte("hi")),
		"paywall": "   ",
	}
	out, err := w.HookPreSendMessage(context.Background(), in)
	if err != nil {
		t.Fatalf("HookPreSendMessage: %v", err)
	}
	if _, ok := out["paywalled"]; ok {
		t.Error("paywalled flag set on blank-paywall args")
	}
}

// TestHookPreSendMessage_HappyPath drives the full seal-and-hold path
// and asserts the wallet's escrow now holds a key under the contract.
func TestHookPreSendMessage_HappyPath(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()

	plaintext := []byte("secret payload bytes")
	in := map[string]any{
		"peer":    "0:0001.0002.0002",
		"data":    base64.StdEncoding.EncodeToString(plaintext),
		"paywall": "100 USDC",
		"memo":    "test memo",
	}
	out, err := w.HookPreSendMessage(context.Background(), in)
	if err != nil {
		t.Fatalf("HookPreSendMessage: %v", err)
	}
	if got, _ := out["paywalled"].(bool); !got {
		t.Error("paywalled flag missing on happy path")
	}
	contractID, _ := out["contract_id"].(string)
	if contractID == "" {
		t.Error("contract_id missing on happy path")
	}

	// "data" must now decode as a SealedEnvelope, not as the original plaintext.
	sealedB64, _ := out["data"].(string)
	envBytes, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		t.Fatalf("envelope b64 decode: %v", err)
	}
	var env payment.SealedEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("envelope JSON decode: %v", err)
	}
	if env.Contract.ID != contractID {
		t.Errorf("envelope.Contract.ID = %q, want %q", env.Contract.ID, contractID)
	}
	if env.Contract.Amount != 100 || env.Contract.Asset != "USDC" {
		t.Errorf("envelope contract = %+v", env.Contract)
	}
	if string(env.Contract.RecipientAddr) != "0:0001.0002.0002" {
		t.Errorf("envelope recipient = %q", env.Contract.RecipientAddr)
	}
	if len(env.Ciphertext) == 0 {
		t.Error("envelope ciphertext is empty")
	}
	// Plaintext must not leak in either ciphertext or any args field.
	for k, v := range out {
		if s, ok := v.(string); ok && strings.Contains(s, string(plaintext)) {
			t.Errorf("plaintext leaked into args[%q]", k)
		}
	}

	// Escrow must hold exactly one key.
	if got := w.Escrow().HeldCount(); got != 1 {
		t.Errorf("HeldCount = %d, want 1", got)
	}
}

// TestHookPreSendMessage_MissingPeer covers the peer-required validation
// branch. Spec is set, but peer is absent.
func TestHookPreSendMessage_MissingPeer(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	_, err := w.HookPreSendMessage(context.Background(), map[string]any{
		"paywall": "100 USDC",
		"data":    base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err == nil || !strings.Contains(err.Error(), "peer") {
		t.Errorf("err = %v, want peer-required error", err)
	}
}

// TestHookPreSendMessage_BadBase64Data covers the data-decode failure
// branch.
func TestHookPreSendMessage_BadBase64Data(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	_, err := w.HookPreSendMessage(context.Background(), map[string]any{
		"paywall": "100 USDC",
		"peer":    "0:0001.0002.0002",
		"data":    "!!!not-base64!!!",
	})
	if err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("err = %v, want base64 decode error", err)
	}
}

// TestHookPreSendMessage_BadPaywallSpec covers the spec-parse failure.
func TestHookPreSendMessage_BadPaywallSpec(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	_, err := w.HookPreSendMessage(context.Background(), map[string]any{
		"paywall": "garbage",
		"peer":    "0:0001.0002.0002",
		"data":    base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err == nil {
		t.Error("expected spec-parse error")
	}
}

// TestHookPreSendMessage_CustomMethodAndEscrowIDs makes sure caller-
// supplied method/escrow IDs override the defaults — exercises both
// non-empty branches.
func TestHookPreSendMessage_CustomMethodAndEscrowIDs(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	out, err := w.HookPreSendMessage(context.Background(), map[string]any{
		"paywall": "1 USDC",
		"peer":    "0:0001.0002.0002",
		"data":    base64.StdEncoding.EncodeToString([]byte("x")),
		"method":  "custom-method",
		"escrow":  "custom-escrow",
	})
	if err != nil {
		t.Fatalf("HookPreSendMessage: %v", err)
	}
	envBytes, _ := base64.StdEncoding.DecodeString(out["data"].(string))
	var env payment.SealedEnvelope
	_ = json.Unmarshal(envBytes, &env)
	if len(env.Contract.AcceptedMethods) != 1 || env.Contract.AcceptedMethods[0] != "custom-method" {
		t.Errorf("AcceptedMethods = %v", env.Contract.AcceptedMethods)
	}
	if len(env.Contract.AcceptedEscrows) != 1 || env.Contract.AcceptedEscrows[0] != "custom-escrow" {
		t.Errorf("AcceptedEscrows = %v", env.Contract.AcceptedEscrows)
	}
}

// ─── HookPostRecvMessage ──────────────────────────────────────────────

// TestHookPostRecvMessage_NoDataPassthrough covers the empty-data branch.
func TestHookPostRecvMessage_NoDataPassthrough(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	in := map[string]any{"peer": "0:0001.0002.0002"}
	out, err := w.HookPostRecvMessage(context.Background(), in)
	if err != nil {
		t.Fatalf("HookPostRecvMessage: %v", err)
	}
	if _, ok := out["sealed"]; ok {
		t.Error("sealed flag set on no-data args")
	}
}

// TestHookPostRecvMessage_BadBase64Passthrough covers the b64-decode
// failure branch — must pass through silently (sealed=false) without
// returning an error.
func TestHookPostRecvMessage_BadBase64Passthrough(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	in := map[string]any{"data": "!!!not-base64!!!"}
	out, err := w.HookPostRecvMessage(context.Background(), in)
	if err != nil {
		t.Fatalf("err: %v (should pass through silently)", err)
	}
	if _, ok := out["sealed"]; ok {
		t.Error("sealed flag set on bad-b64 args")
	}
}

// TestHookPostRecvMessage_BadJSONPassthrough covers the JSON-unmarshal
// failure branch.
func TestHookPostRecvMessage_BadJSONPassthrough(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	in := map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("not json"))}
	out, err := w.HookPostRecvMessage(context.Background(), in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if _, ok := out["sealed"]; ok {
		t.Error("sealed flag set on bad-json args")
	}
}

// TestHookPostRecvMessage_IncompleteEnvelopePassthrough covers the
// missing-fields branch — a JSON-valid struct that lacks required
// sealed-envelope fields must NOT be flagged as sealed.
func TestHookPostRecvMessage_IncompleteEnvelopePassthrough(t *testing.T) {
	t.Parallel()
	w := newTestWallet(t, addrAlice)
	defer w.Close()
	in := map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(`{"contract":{"id":""}}`))}
	out, err := w.HookPostRecvMessage(context.Background(), in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if _, ok := out["sealed"]; ok {
		t.Error("sealed flag set on incomplete envelope")
	}
}

// TestHookPostRecvMessage_HappyPath round-trips: pre-send produces a
// sealed envelope, post-recv consumes it and exposes the contract
// metadata for the recipient to decide on redemption.
func TestHookPostRecvMessage_HappyPath(t *testing.T) {
	t.Parallel()
	sender := newTestWallet(t, addrAlice)
	defer sender.Close()
	receiver := newTestWallet(t, addrBob)
	defer receiver.Close()

	sealedArgs, err := sender.HookPreSendMessage(context.Background(), map[string]any{
		"paywall": "42 USDC",
		"peer":    string(addrBob),
		"data":    base64.StdEncoding.EncodeToString([]byte("payload")),
		"memo":    "happy-path",
	})
	if err != nil {
		t.Fatalf("pre-send: %v", err)
	}

	out, err := receiver.HookPostRecvMessage(context.Background(), map[string]any{
		"data": sealedArgs["data"],
	})
	if err != nil {
		t.Fatalf("post-recv: %v", err)
	}
	if sealed, _ := out["sealed"].(bool); !sealed {
		t.Errorf("sealed flag not set on a valid envelope: %v", out)
	}
	if got, _ := out["contract_id"].(string); got != sealedArgs["contract_id"].(string) {
		t.Errorf("contract_id mismatch: got %q, want %q",
			got, sealedArgs["contract_id"])
	}
	if got, _ := out["contract_asset"].(string); got != "USDC" {
		t.Errorf("contract_asset = %q", got)
	}
	if got, _ := out["escrow_id"].(string); got != EscrowID {
		t.Errorf("escrow_id = %q", got)
	}
	if got, _ := out["escrow_endpoint"].(string); got != string(addrAlice) {
		t.Errorf("escrow_endpoint = %q, want sender address %q", got, addrAlice)
	}
}
